package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// udpReceiverStats is the JSON the receiver agent serves and the sender polls.
// Cumulative counters (not rates) so the poller can difference them itself and
// be robust to a missed poll.
type udpReceiverStats struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// runUDPReceiver runs the binary as a measurement agent ON THE TARGET host. It
// listens for UDP on dataAddr, counts every datagram and byte the kernel
// actually delivers to it, and serves the cumulative counters as JSON on
// controlAddr (HTTP /stats) so the sending side can poll them and compute real
// loss. This is the measurement counterpart to the flood: sent-count alone says
// nothing about what crossed the network or what the target absorbed — this is
// what closes that gap.
//
// It blocks until SIGINT/SIGTERM. Only legitimate when you run it on a host you
// control; that's the whole point — it measures your own endpoint.
func runUDPReceiver(dataAddr, controlAddr string) error {
	if controlAddr == "" {
		controlAddr = ":9100"
	}
	pc, err := net.ListenPacket("udp", dataAddr)
	if err != nil {
		return fmt.Errorf("receiver: listen udp %s: %w", dataAddr, err)
	}
	defer pc.Close()

	var pkts, bytesRecv uint64

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Control endpoint: cumulative counters as JSON for the sender to poll.
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(udpReceiverStats{
			Packets: atomic.LoadUint64(&pkts),
			Bytes:   atomic.LoadUint64(&bytesRecv),
		})
	})
	srv := &http.Server{Addr: controlAddr, Handler: mux}
	go func() { _ = srv.ListenAndServe() }()
	go func() {
		<-ctx.Done()
		_ = srv.Close()
		_ = pc.Close()
	}()

	fmt.Printf("udp receiver listening on %s (udp); stats at http://%s/stats — Ctrl+C to stop\n", dataAddr, controlAddr)

	// Console heartbeat so a standalone receiver (no sender polling) is still useful.
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		var lastP, lastB uint64
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				p := atomic.LoadUint64(&pkts)
				b := atomic.LoadUint64(&bytesRecv)
				fmt.Printf("recv: %d pkt/s  %s/s  (total %d pkts, %s)\n",
					p-lastP, formatBytes(b-lastB), p, formatBytes(b))
				lastP, lastB = p, b
			}
		}
	}()

	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			fmt.Printf("\nudp receiver stopped: %d packets, %s total received\n",
				atomic.LoadUint64(&pkts), formatBytes(atomic.LoadUint64(&bytesRecv)))
			return nil
		default:
		}
		_ = pc.SetReadDeadline(time.Now().Add(time.Second))
		n, _, rerr := pc.ReadFrom(buf)
		if n > 0 {
			atomic.AddUint64(&pkts, 1)
			atomic.AddUint64(&bytesRecv, uint64(n))
		}
		if rerr != nil {
			if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
				continue // expected: the 1s read deadline so we can re-check ctx
			}
			if ctx.Err() != nil {
				return nil // conn closed on shutdown
			}
		}
	}
}

// pollReceiverStats polls a receiver agent's /stats endpoint once a second and
// turns the cumulative received counters into a landed pps/bps rate and a real
// loss figure (sent-but-not-received over sent), all published for the dashboard.
//
// The loss figure is a 1-second-window approximation: sender and receiver clocks
// aren't perfectly aligned and packets are in flight at the window edges, so a
// single window can read slightly high or low. The TREND is what's meaningful —
// sustained non-zero loss means the target (or the path) is dropping traffic.
func pollReceiverStats(ctx context.Context, statsURL string) {
	if !strings.HasPrefix(statsURL, "http://") && !strings.HasPrefix(statsURL, "https://") {
		statsURL = "http://" + statsURL
	}
	if !strings.HasSuffix(statsURL, "/stats") {
		statsURL = strings.TrimRight(statsURL, "/") + "/stats"
	}
	client := &http.Client{Timeout: 2 * time.Second}
	t := time.NewTicker(time.Second)
	defer t.Stop()

	var lastRecvPkts, lastRecvBytes, lastSentPkts uint64
	have := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			resp, err := client.Get(statsURL)
			if err != nil {
				atomic.StoreUint64(&udpRecvActive, 0)
				continue
			}
			var s udpReceiverStats
			derr := json.NewDecoder(resp.Body).Decode(&s)
			resp.Body.Close()
			if derr != nil {
				atomic.StoreUint64(&udpRecvActive, 0)
				continue
			}
			atomic.StoreUint64(&udpRecvActive, 1)

			sentNow := atomic.LoadUint64(&udpLocalSendAttempts)
			if have {
				recvDelta := s.Packets - lastRecvPkts
				byteDelta := s.Bytes - lastRecvBytes
				sentDelta := sentNow - lastSentPkts
				atomic.StoreUint64(&udpRecvPPS, recvDelta)
				atomic.StoreUint64(&udpRecvBPS, byteDelta)
				if recvDelta > 0 || byteDelta > 0 {
					recordTargetCollectorEvidence(recvDelta, byteDelta)
				}
				// loss over this window; clamp at 0 (received can momentarily exceed
				// sent-in-window due to in-flight packets / sampling skew).
				if sentDelta > 0 && sentDelta >= recvDelta {
					atomic.StoreUint64(&udpLossPPM, (sentDelta-recvDelta)*1_000_000/sentDelta)
				} else {
					atomic.StoreUint64(&udpLossPPM, 0)
				}
			}
			lastRecvPkts, lastRecvBytes, lastSentPkts = s.Packets, s.Bytes, sentNow
			have = true
		}
	}
}
