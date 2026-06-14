package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
)

// --- UDP measurement state (kept separate from the HTTP request counters) ---
//
// UDP has no acknowledgement, so a successful Write only proves the datagram
// entered our local kernel send buffer — never that it reached, let alone was
// processed by, the target. The send-side counters (udpLocalSendAttempts /
// udpLocalSendFailures in globals.go) are deliberately named "local" for that
// reason and are kept OUT of successfulHits/successRate, which would otherwise
// pin a UDP run's "success rate" near 100% no matter what actually happened.
//
// The vars below add the missing half: a sampled send RATE, and — when a
// receiver agent is running on the target (see udp_receiver.go) — the LANDED
// rate and real packet loss. Loss is the only real measure of a UDP flood's
// effect; sent-count alone says nothing about what crossed the network.
var (
	udpSendPPS uint64 // sampled send rate, packets/sec (datagrams handed to the kernel)
	udpSendBPS uint64 // sampled send rate, bytes/sec

	// the direct flood's built-in aggregate packet-rate cap, published so a
	// tool-imposed ceiling isn't silently misread as the target's pps limit. The
	// dashboard flags it as "binding" when the measured send rate sits at the cap.
	udpPPSCap uint64

	// receiver-agent telemetry, populated by pollReceiverStats when -receiver-stats
	// points at a udp receiver running on the target.
	udpRecvActive uint64 // 1 when the receiver agent is reachable and reporting
	udpRecvPPS    uint64 // packets/sec the receiver is absorbing
	udpRecvBPS    uint64 // bytes/sec the receiver is absorbing
	udpLossPPM    uint64 // measured loss, parts-per-million of sent packets (0..1_000_000)

	udpModeActive uint64 // 1 when this run is a UDP-only flood (drives the UDP measurement dashboard + health path)
	udpMeasured   uint64 // 1 when target health is actually measurable (receiver reporting, or a UDP reply/ICMP seen)
)

// startUDPMeasurement kicks off the per-second rate sampler and, when a receiver
// agent endpoint is configured, the poller that turns its counters into landed
// rate + loss. Cheap; safe to leave running for the whole process lifetime.
func startUDPMeasurement(ctx context.Context, receiverStats string) {
	go udpRateSampler(ctx)
	if receiverStats != "" {
		go pollReceiverStats(ctx, receiverStats)
	}
}

// udpRateSampler converts the cumulative send counters into per-second rates
// once a second by differencing. A 1s tick means the delta IS the per-second
// rate, no division needed.
func udpRateSampler(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	var lastPkts, lastBytes uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// pps from the local UDP send counter; bps from totalBytesSent — the
			// sampler only runs in UDP-only mode (or when polling a receiver), so
			// totalBytesSent is all UDP here and needs no separate byte counter,
			// which keeps attacks.go untouched.
			p := atomic.LoadUint64(&udpLocalSendAttempts)
			b := atomic.LoadUint64(&totalBytesSent)
			atomic.StoreUint64(&udpSendPPS, p-lastPkts)
			atomic.StoreUint64(&udpSendBPS, b-lastBytes)
			lastPkts, lastBytes = p, b
		}
	}
}

// udpBatchSender issues one sendmmsg(2) per batch on Linux (via x/net/ipv4's
// WriteBatch), collapsing N per-packet syscalls into a single one. On platforms
// without sendmmsg it transparently degrades to a per-message send, and if the
// batched path is rejected for any reason it falls back permanently to plain
// per-packet Write — so it's correct everywhere and merely faster on Linux.
//
// This is the throughput fix: with one syscall per packet, the "max
// packet rate" stream measures OUR syscall rate, not the target's receive
// ceiling. Batching lifts that ceiling. Real source IPs, connected sockets —
// no spoofing, no raw sockets, no root.
type udpBatchSender struct {
	conn    *net.UDPConn
	pc      *ipv4.PacketConn
	msgs    []ipv4.Message
	payload []byte
	batchOK bool
}

func newUDPBatchSender(conn *net.UDPConn, batch int, payload []byte) *udpBatchSender {
	if batch < 1 {
		batch = 1
	}
	msgs := make([]ipv4.Message, batch)
	for i := range msgs {
		// All messages reference the same payload buffer: a flood sends identical
		// datagrams, so there's no need to copy per message.
		msgs[i] = ipv4.Message{Buffers: [][]byte{payload}}
	}
	return &udpBatchSender{conn: conn, pc: ipv4.NewPacketConn(conn), msgs: msgs, payload: payload, batchOK: true}
}

// sendN sends up to n datagrams and returns how many the kernel accepted. Addr
// is left nil because the socket is connected (net.DialUDP), so each datagram
// goes to the dialed peer.
func (s *udpBatchSender) sendN(n int) (int, error) {
	if n > len(s.msgs) {
		n = len(s.msgs)
	}
	if s.batchOK {
		sent, err := s.pc.WriteBatch(s.msgs[:n], 0)
		if err != nil {
			// Stop attempting batched writes after the first failure; don't re-send
			// here — the caller counts `sent` plus one failure for this round.
			s.batchOK = false
		}
		return sent, err
	}
	sent := 0
	for i := 0; i < n; i++ {
		if _, err := s.conn.Write(s.payload); err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

// udpProbeResult classifies a best-effort UDP health probe. Silence is its own
// category on purpose: a perfectly healthy UDP service may simply not reply to
// an unsolicited probe byte, so silence must NEVER be read as "down".
type udpProbeResult int

const (
	udpUnknown udpProbeResult = iota // no reply — could be healthy-but-silent or a filtered path
	udpOpen                          // a datagram came back — definitively reachable
	udpClosed                        // ICMP port-unreachable — something answered "closed"
)

func udpProbe(ctx context.Context, host, port string) udpProbeResult {
	d := net.Dialer{Timeout: time.Second}
	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(host, port))
	if err != nil {
		return udpUnknown
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(1200 * time.Millisecond))
	_, _ = conn.Write([]byte{0x00})
	buf := make([]byte, 64)
	_, rerr := conn.Read(buf)
	if rerr == nil {
		return udpOpen
	}
	if errors.Is(rerr, syscall.ECONNREFUSED) {
		return udpClosed
	}
	return udpUnknown
}

// udpHealthLoop replaces the HTTP health probe for a UDP-only run. The HTTP
// probe cannot see a UDP service: it would declare a healthy UDP target "down"
// after three misses (or measure an unrelated HTTP port on the same box). This
// loop instead:
//   - trusts the receiver agent when one is running (received traffic == target up),
//   - otherwise only ever declares "down" on an explicit ICMP port-unreachable,
//   - treats silence as UNMEASURED, never as down,
//   - keeps the control-host check so a saturated local uplink is still flagged.
func udpHealthLoop(ctx context.Context, target string) {
	host, port, _, err := parseTargetForUDP(target)
	if err != nil {
		return
	}
	controlClient := &http.Client{
		Timeout:   4 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			atomic.AddUint64(&healthCheckCount, 1)

			// 1) The receiver agent owns the verdict when present: if it's absorbing
			// packets, the target is reachable and taking our load.
			if atomic.LoadUint64(&udpRecvActive) == 1 {
				atomic.StoreUint64(&udpMeasured, 1)
				atomic.StoreUint64(&localCongestion, 0)
				if atomic.LoadUint64(&udpRecvPPS) > 0 {
					atomic.StoreUint64(&targetResponding, 1)
					atomic.AddUint64(&targetOKChecks, 1)
					atomic.StoreUint64(&consecutiveFailures, 0)
				}
				continue
			}

			// 2) No receiver: best-effort probe. Only an ICMP unreachable is strong
			// enough to count toward "down", and only if our own link is up.
			switch udpProbe(ctx, host, port) {
			case udpOpen:
				atomic.StoreUint64(&udpMeasured, 1)
				atomic.StoreUint64(&targetResponding, 1)
				atomic.AddUint64(&targetOKChecks, 1)
				atomic.StoreUint64(&consecutiveFailures, 0)
				atomic.StoreUint64(&localCongestion, 0)
			case udpClosed:
				if controlReachable(ctx, controlClient) {
					atomic.StoreUint64(&udpMeasured, 1)
					atomic.StoreUint64(&localCongestion, 0)
					cf := atomic.AddUint64(&consecutiveFailures, 1)
					if cf >= 3 && atomic.LoadUint64(&targetResponding) == 1 {
						atomic.StoreUint64(&targetResponding, 0)
						atomic.StoreUint64(&targetDownTime, uint64(time.Now().Unix()))
					}
				} else {
					atomic.AddUint64(&congestionChecks, 1)
					atomic.StoreUint64(&localCongestion, 1)
				}
			default: // udpUnknown — silence. Hold state; never down on silence alone.
				atomic.StoreUint64(&udpMeasured, 0)
				if controlReachable(ctx, controlClient) {
					atomic.StoreUint64(&localCongestion, 0)
				} else {
					atomic.AddUint64(&congestionChecks, 1)
					atomic.StoreUint64(&localCongestion, 1)
				}
			}
		}
	}
}
