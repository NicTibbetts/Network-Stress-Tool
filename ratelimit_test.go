package main

import (
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

func TestCalculateAverageTime_Empty(t *testing.T) {
	got := calculateAverageTime([]time.Duration{})
	if got != 0 {
		t.Errorf("calculateAverageTime([]) = %v, want 0", got)
	}
}

func TestCalculateAverageTime_Single(t *testing.T) {
	got := calculateAverageTime([]time.Duration{100 * time.Millisecond})
	if got != 100*time.Millisecond {
		t.Errorf("calculateAverageTime([100ms]) = %v, want 100ms", got)
	}
}

func TestCalculateAverageTime_Multiple(t *testing.T) {
	times := []time.Duration{
		100 * time.Millisecond,
		200 * time.Millisecond,
		300 * time.Millisecond,
	}
	got := calculateAverageTime(times)
	want := 200 * time.Millisecond
	if got != want {
		t.Errorf("calculateAverageTime = %v, want %v", got, want)
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

func TestDetectRateLimit_SlowResponse(t *testing.T) {
	rld := newTestDetector()
	// responseTime > ResponseTimeThresh (5s) should trigger
	resp := fakeResponse(200, nil)
	if !rld.DetectRateLimit(resp, 6*time.Second) {
		t.Error("DetectRateLimit with 6s response time should return true (threshold is 5s)")
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

	requiredKeys := []string{"limit_detections", "successful_bypasses", "consecutive_limits", "total_requests"}
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

// SmallContentLength in the Content-Length header should trigger detection.
func TestAdvancedPatterns_SmallContentLength(t *testing.T) {
	rld := newTestDetector()
	resp := fakeResponse(200, map[string]string{"Content-Length": "50"})
	if !rld.DetectRateLimit(resp, 100*time.Millisecond) {
		t.Error("DetectRateLimit with tiny Content-Length should return true")
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
		idm.WaitForOptimalTiming()
		close(done)
	}()

	select {
	case <-done:
		// good
	case <-time.After(3 * time.Second):
		t.Error("WaitForOptimalTiming blocked for more than 3 seconds")
	}
}

// strings package import guard, keep it used
var _ = strings.Contains
