package main

import (
	"sync"
	"testing"
)

// proxy_pool_test.go covers the worker-facing ProxyPool health tracking added so
// dead proxies get retired from rotation instead of being handed to workers on
// every lap of the round-robin. the scrape/validate paths need live network access
// and are not exercised here.

// ---- ProxyPool.Report eviction ----

func newTestPool(proxies ...string) *ProxyPool {
	p := NewProxyPool()
	p.proxies = append([]string(nil), proxies...)
	return p
}

func TestProxyPool_EvictsAfterThreshold(t *testing.T) {
	p := newTestPool("http://a", "http://b")

	// first two failures accumulate strikes but must not evict yet
	for i := 0; i < proxyEvictionThreshold-1; i++ {
		if p.Report("http://a", false) {
			t.Fatalf("evicted after %d strikes, want eviction only at %d", i+1, proxyEvictionThreshold)
		}
	}
	// the threshold-th consecutive failure evicts
	if !p.Report("http://a", false) {
		t.Fatalf("proxy not evicted after %d strikes", proxyEvictionThreshold)
	}
	if got := p.GetProxyCount(); got != 1 {
		t.Errorf("proxy count = %d, want 1 after eviction", got)
	}
	if got := p.EvictedCount(); got != 1 {
		t.Errorf("evicted count = %d, want 1", got)
	}
	// the survivor is the one that was never struck
	if next := p.GetNext(); next != "http://b" {
		t.Errorf("GetNext = %q, want surviving proxy 'http://b'", next)
	}
}

func TestProxyPool_SuccessResetsStrikes(t *testing.T) {
	p := newTestPool("http://a", "http://b")

	// two strikes, then a success clears the count, eviction needs CONSECUTIVE
	// failures, so the proxy should survive two more strikes afterward.
	p.Report("http://a", false)
	p.Report("http://a", false)
	p.Report("http://a", true) // resets
	if p.Report("http://a", false) {
		t.Fatal("evicted on first strike after a success reset")
	}
	if p.Report("http://a", false) {
		t.Fatal("evicted on second strike after a success reset")
	}
	if got := p.EvictedCount(); got != 0 {
		t.Errorf("evicted count = %d, want 0 (success should have reset strikes)", got)
	}
}

func TestProxyPool_NeverEvictsLastProxy(t *testing.T) {
	p := newTestPool("http://only")

	// going down to zero proxies would silently fall back to the real IP, which is
	// worse than reusing a flaky proxy, so the last one is never evicted.
	for i := 0; i < proxyEvictionThreshold*3; i++ {
		if p.Report("http://only", false) {
			t.Fatal("evicted the last remaining proxy")
		}
	}
	if got := p.GetProxyCount(); got != 1 {
		t.Errorf("proxy count = %d, want 1 (last proxy retained)", got)
	}
}

func TestProxyPool_EmptyProxyIsNoOp(t *testing.T) {
	p := newTestPool("http://a", "http://b")
	// a direct connection reports an empty proxy string, must not panic or evict.
	for i := 0; i < proxyEvictionThreshold*2; i++ {
		if p.Report("", false) {
			t.Fatal("empty proxy string caused an eviction")
		}
	}
	if got := p.GetProxyCount(); got != 2 {
		t.Errorf("proxy count = %d, want 2 (empty reports are no-ops)", got)
	}
}

// ---- ProxyPool health-aware selection (1b) ----

func TestProxyPool_ScoreFavorsHealthy(t *testing.T) {
	p := newTestPool("good", "bad", "fresh")

	// "good": a clean record.
	for i := 0; i < 20; i++ {
		p.Report("good", true)
	}
	// "bad": a poor record, but interleaved so it never hits proxyEvictionThreshold
	// consecutive failures (we want it kept in the pool with a low score, not evicted).
	for i := 0; i < 20; i++ {
		p.Report("bad", false)
		p.Report("bad", false)
		p.Report("bad", true)
	}

	p.mu.RLock()
	defer p.mu.RUnlock()
	good := p.scoreLocked("good")
	fresh := p.scoreLocked("fresh") // never reported, optimistic 0.5 prior
	bad := p.scoreLocked("bad")
	if !(good > fresh && fresh > bad) {
		t.Errorf("score ordering wrong: good=%.3f fresh=%.3f bad=%.3f, want good > fresh > bad",
			good, fresh, bad)
	}
}

func TestProxyPool_SelectionPrefersHealthy(t *testing.T) {
	names := []string{"good", "b1", "b2", "b3", "b4", "b5", "b6", "b7"}
	p := newTestPool(names...)

	for i := 0; i < 50; i++ {
		p.Report("good", true)
	}
	for _, bad := range names[1:] {
		for i := 0; i < 50; i++ {
			p.Report(bad, false)
			p.Report(bad, false)
			p.Report(bad, true) // keep it from being evicted
		}
	}

	counts := map[string]int{}
	const n = 2000
	for i := 0; i < n; i++ {
		counts[p.GetNext()]++
	}
	// a blind round-robin would hand "good" out ~n/8 (12.5%) of the time. the
	// health aware best-of-K selection should return it far more often.
	if counts["good"] < n/4 {
		t.Errorf("healthy proxy selected %d/%d (%.1f%%), want > 25%% — health weighting isn't biasing selection",
			counts["good"], n, float64(counts["good"])/float64(n)*100)
	}
}

// TestProxyPool_ConcurrentReportAndGetNext exercises Report (write-locked slice
// mutation) racing GetNext (read-locked access) the way real workers do, so the
// race detector can flag any unsynchronized access.
func TestProxyPool_ConcurrentReportAndGetNext(t *testing.T) {
	proxies := make([]string, 0, 50)
	for i := 'a'; i <= 'z'; i++ {
		proxies = append(proxies, "http://"+string(i))
	}
	p := newTestPool(proxies...)

	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				next := p.GetNext()
				// report failures often so evictions actually happen under the race
				p.Report(next, i%4 != 0)
			}
		}(w)
	}
	wg.Wait()

	// the pool must never drain below its floor of one proxy.
	if got := p.GetProxyCount(); got < 1 {
		t.Errorf("proxy count = %d, want >= 1 (floor must hold under concurrency)", got)
	}
}
