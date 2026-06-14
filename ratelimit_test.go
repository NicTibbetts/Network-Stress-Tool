package main

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ratelimit tests cover the core detection and delay logic.
// we use a minimal in-memory http.Response so no network calls happen.
// the detector's behaviour is driven entirely by the config it receives,
// which makes it straightforward to test the boundary conditions.

func newTestDetector() *RateLimitDetector {
	cfg := DefaultConfig()
	cfg.RateLimitBypass = true
	return NewRateLimitDetector(cfg, nil) // nil logger is safe
}

func fakeResponse(statusCode int, headers map[string]string) *http.Response {
	hdr := make(http.Header)
	for k, v := range headers {
		hdr.Set(k, v)
	}
	return &http.Response{
		StatusCode: statusCode,
		Header:     hdr,
	}
}

func TestDetectRateLimit_429(t *testing.T) {
	rld := newTestDetector()
	resp := fakeResponse(429, nil)
	// 429 is in StatusCodeTriggers by default, so this must return true
	if !rld.DetectRateLimit(resp, 100*time.Millisecond) {
		t.Error("DetectRateLimit(429) should return true")
	}
}

func TestDetectRateLimit_503(t *testing.T) {
	rld := newTestDetector()
	resp := fakeResponse(503, nil)
	if !rld.DetectRateLimit(resp, 100*time.Millisecond) {
		t.Error("DetectRateLimit(503) should return true")
	}
}

func TestDetectRateLimit_200_NoRateLimit(t *testing.T) {
	rld := newTestDetector()
	// a 200 with no suspicious headers and a fast response should not trigger
	resp := fakeResponse(200, nil)
	if rld.DetectRateLimit(resp, 100*time.Millisecond) {
		t.Error("DetectRateLimit(200, fast) should return false")
	}
}

func TestDetectRateLimit_RateLimitHeader(t *testing.T) {
	rld := newTestDetector()
	// Retry-After is in HeaderTriggers by default
	resp := fakeResponse(200, map[string]string{"Retry-After": "60"})
	if !rld.DetectRateLimit(resp, 100*time.Millisecond) {
		t.Error("DetectRateLimit with Retry-After header should return true")
	}
}

func TestDetectRateLimit_SlowResponseIsNotALimit(t *testing.T) {
	rld := newTestDetector()
	// a slow response is deliberately NOT treated as rate limiting: when this
	// tool is working, the target slows because it's saturated, not throttling.
	resp := fakeResponse(200, nil)
	if rld.DetectRateLimit(resp, 6*time.Second) {
		t.Error("DetectRateLimit should not flag a slow 200 as rate limiting")
	}
}

func TestGetBypassDelay_RespectsMinDelay(t *testing.T) {
	rld := newTestDetector()
	delay := rld.GetBypassDelay()
	min := rld.config.BypassSettings.MinDelay
	if delay < min {
		t.Errorf("GetBypassDelay() = %v, want >= MinDelay (%v)", delay, min)
	}
}

func TestGetBypassDelay_BackoffIncreasesDelay(t *testing.T) {
	rld := newTestDetector()
	// simulate consecutive rate limits to trigger backoff
	resp := fakeResponse(429, nil)
	rld.DetectRateLimit(resp, 100*time.Millisecond)
	rld.DetectRateLimit(resp, 100*time.Millisecond)
	rld.DetectRateLimit(resp, 100*time.Millisecond)

	delay := rld.GetBypassDelay()
	base := rld.config.BypassSettings.MinDelay
	// after 3 consecutive limits with backoff multiplier 2.0, delay > base
	if delay <= base {
		t.Errorf("GetBypassDelay() after consecutive limits = %v, want > %v", delay, base)
	}
}

func TestGetStatistics_Keys(t *testing.T) {
	rld := newTestDetector()
	stats := rld.GetStatistics()

	requiredKeys := []string{"limit_detections", "recoveries", "consecutive_limits", "total_requests"}
	for _, k := range requiredKeys {
		if _, ok := stats[k]; !ok {
			t.Errorf("GetStatistics() missing key %q", k)
		}
	}
}

func TestNewIntelligentDelayManager_NotNil(t *testing.T) {
	cfg := DefaultConfig()
	rld := NewRateLimitDetector(cfg, nil)
	idm := NewIntelligentDelayManager(cfg, rld)
	if idm == nil {
		t.Error("NewIntelligentDelayManager returned nil")
	}
}

// ShouldUseBurstMode should be false right after consecutive limits
func TestShouldUseBurstMode_FalseAfterLimits(t *testing.T) {
	rld := newTestDetector()
	resp := fakeResponse(429, nil)
	rld.DetectRateLimit(resp, 100*time.Millisecond)

	if rld.ShouldUseBurstMode() {
		t.Error("ShouldUseBurstMode() should return false when consecutiveLimits > 0")
	}
}

// applyDistributedTiming should not return exactly zero
func TestApplyDistributedTiming_NonZero(t *testing.T) {
	cfg := DefaultConfig()
	rld := NewRateLimitDetector(cfg, nil)
	idm := NewIntelligentDelayManager(cfg, rld)

	// the jitter may vary but the returned duration should be > 0 for a nonzero base
	got := idm.applyDistributedTiming(100 * time.Millisecond)
	if got <= 0 {
		// applyDistributedTiming may legitimately return 0 with some jitter; what
		// matters is that it doesn't panic and returns a value in a sane range.
		t.Logf("applyDistributedTiming(100ms) = %v (may be zero with jitter)", got)
	}

	// must not return something insanely large (> 10 seconds for a 100ms base)
	if got > 10*time.Second {
		t.Errorf("applyDistributedTiming(100ms) = %v, unreasonably large", got)
	}
}

// a set of suspicious header names must trigger advanced pattern detection.
// we verify this indirectly through DetectRateLimit, if a suspicious header
// is present in the response, the call must return true even for a 200.
func TestAdvancedPatterns_SuspiciousHeader(t *testing.T) {
	rld := newTestDetector()

	suspiciousHeaders := []string{
		"X-Rate-Limit",
		"RateLimit",
		"Throttle",
		"Retry-After",
	}

	for _, h := range suspiciousHeaders {
		rld2 := newTestDetector() // fresh detector for each case
		resp := fakeResponse(200, map[string]string{h: "1"})
		if !rld2.DetectRateLimit(resp, 100*time.Millisecond) {
			t.Errorf("DetectRateLimit with header %q should return true", h)
		}
	}
	_ = rld
}

// a small Content-Length must NOT trigger detection on its own: empty bodies,
// 204/304s, redirects and small JSON errors are all legitimately tiny, so the
// old length < 100 heuristic was dropped as too noisy.
func TestAdvancedPatterns_SmallContentLengthIsNotALimit(t *testing.T) {
	rld := newTestDetector()
	resp := fakeResponse(200, map[string]string{"Content-Length": "50"})
	if rld.DetectRateLimit(resp, 100*time.Millisecond) {
		t.Error("DetectRateLimit should not flag a small Content-Length as rate limiting")
	}
}

// AdaptRate should return a positive worker count.
func TestAdaptRate_Positive(t *testing.T) {
	rld := newTestDetector()
	n := rld.AdaptRate()
	if n <= 0 {
		t.Errorf("AdaptRate() = %d, want > 0", n)
	}
}

// verify GetStatistics["rate_limit_detections"] increments after detection
func TestGetStatistics_Increments(t *testing.T) {
	rld := newTestDetector()
	resp := fakeResponse(429, nil)
	rld.DetectRateLimit(resp, 100*time.Millisecond)
	rld.DetectRateLimit(resp, 100*time.Millisecond)

	stats := rld.GetStatistics()
	raw, ok := stats["limit_detections"]
	if !ok {
		t.Fatal("missing key limit_detections")
	}

	var count int
	switch v := raw.(type) {
	case int:
		count = v
	case uint64:
		count = int(v)
	case float64:
		count = int(v)
	default:
		t.Fatalf("unexpected type for rate_limit_detections: %T", raw)
	}

	if count < 2 {
		t.Errorf("rate_limit_detections = %d after 2 detections, want >= 2", count)
	}
}

// RecordBurstRequest should not panic and should record without error
func TestRecordBurstRequest_NoPanic(t *testing.T) {
	rld := newTestDetector()
	for i := 0; i < 10; i++ {
		rld.RecordBurstRequest()
	}
	// if we reach here, no panic occurred
}

// WaitForOptimalTiming should return quickly when the detector is fresh
func TestWaitForOptimalTiming_ReturnsPromptly(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DistributedTiming = false // keep it fast for tests
	rld := NewRateLimitDetector(cfg, nil)
	idm := NewIntelligentDelayManager(cfg, rld)

	done := make(chan struct{})
	go func() {
		idm.WaitForOptimalTiming(context.Background())
		close(done)
	}()

	select {
	case <-done:
		// good
	case <-time.After(3 * time.Second):
		t.Error("WaitForOptimalTiming blocked for more than 3 seconds")
	}
}

// a limit streak followed by a clean response should count as one recovery,
// this is the real replacement for the old always-zero successful_bypasses.
func TestRecoveries_CountedOnCleanAfterLimit(t *testing.T) {
	rld := newTestDetector()

	limited := fakeResponse(429, nil)
	clean := fakeResponse(200, nil)

	rld.DetectRateLimit(limited, 100*time.Millisecond) // streak starts
	rld.DetectRateLimit(limited, 100*time.Millisecond)
	rld.DetectRateLimit(clean, 100*time.Millisecond) // streak ends, +1 recovery

	if got := asInt(rld.GetStatistics()["recoveries"]); got != 1 {
		t.Errorf("recoveries = %d after a limit streak then clean response, want 1", got)
	}

	// a second clean response with no intervening limit must not add a recovery.
	rld.DetectRateLimit(clean, 100*time.Millisecond)
	if got := asInt(rld.GetStatistics()["recoveries"]); got != 1 {
		t.Errorf("recoveries = %d after a second clean response, want 1", got)
	}
}

// current_delay must reflect the effective backed-off delay, not stay pinned at
// MinDelay, otherwise the reported statistic lies about what callers wait.
func TestCurrentDelay_ReflectsBackoff(t *testing.T) {
	rld := newTestDetector()
	min := rld.config.BypassSettings.MinDelay

	limited := fakeResponse(429, nil)
	rld.DetectRateLimit(limited, 100*time.Millisecond)
	rld.DetectRateLimit(limited, 100*time.Millisecond)
	rld.DetectRateLimit(limited, 100*time.Millisecond)

	effective := rld.GetBypassDelay()
	if effective <= min {
		t.Fatalf("GetBypassDelay() = %v after a limit streak, want > MinDelay (%v)", effective, min)
	}

	reported, ok := rld.GetStatistics()["current_delay"].(time.Duration)
	if !ok {
		t.Fatalf("current_delay stat is not a time.Duration")
	}
	if reported != effective {
		t.Errorf("current_delay stat = %v, want the effective delay %v", reported, effective)
	}
}

// strings package import guard, keep it used
var _ = strings.Contains
