package main

import (
	"context"
	"fmt"
	"math"
	mathrand "math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type RateLimitDetector struct {
	config *DemonConfig
	logger *Logger

	// Detection state. currentDelay holds the most recent effective delay
	// (base plus backoff plus jitter) so the reported statistic matches what
	// callers actually wait, not a constant.
	consecutiveLimits int
	lastLimitTime     time.Time
	currentDelay      time.Duration
	adaptiveRate      int

	// Pattern recognition
	responsePatterns map[string]int

	// Burst pacing
	burstCounter  int
	lastBurstTime time.Time

	// Statistics. recoveries counts the times a limit streak ended with a clean
	// response, that is a real, observable outcome of backing off.
	totalRequests   uint64
	limitDetections uint64
	recoveries      uint64

	mu sync.RWMutex
}

func NewRateLimitDetector(config *DemonConfig, logger *Logger) *RateLimitDetector {
	return &RateLimitDetector{
		config:           config,
		logger:           logger,
		currentDelay:     config.BypassSettings.MinDelay,
		adaptiveRate:     config.RequestRate,
		responsePatterns: make(map[string]int),
	}
}

// DetectRateLimit analyzes a response to decide whether the target is limiting
// us. it relies on explicit signals, the configured status codes and rate-limit
// headers, plus a couple of cheap header heuristics. it deliberately does not
// treat a slow response as a limit: when this tool is doing its job the target
// slows down because it's saturated, not because it's throttling, so latency is
// the wrong signal here.
func (rld *RateLimitDetector) DetectRateLimit(resp *http.Response, responseTime time.Duration) bool {
	rld.mu.Lock()

	rld.totalRequests++
	isRateLimited := false

	// Check status codes that indicate rate limiting
	for _, code := range rld.config.BypassSettings.StatusCodeTriggers {
		if resp.StatusCode == code {
			isRateLimited = true
			break
		}
	}

	// Check for rate limit headers
	if !isRateLimited {
		for _, header := range rld.config.BypassSettings.HeaderTriggers {
			if resp.Header.Get(header) != "" {
				isRateLimited = true
				break
			}
		}
	}

	// Header-name heuristics as a last resort
	if !isRateLimited {
		isRateLimited = rld.detectAdvancedPatterns(resp)
	}

	var logConsecutive int
	if isRateLimited {
		rld.limitDetections++
		rld.consecutiveLimits++
		rld.lastLimitTime = time.Now()
		logConsecutive = rld.consecutiveLimits
	} else {
		// a clean response after a streak of limits means the backoff worked and
		// the target is serving us again, that's a recovery worth recording.
		if rld.consecutiveLimits > 0 {
			rld.recoveries++
		}
		rld.consecutiveLimits = 0
	}

	rld.mu.Unlock()

	// log after releasing the lock. holding the detector's write lock across a
	// synchronous log write would stall every other worker behind file I/O.
	if isRateLimited && rld.logger != nil {
		rld.logger.Warning(fmt.Sprintf("[!] rate limit detected: status %d, response time %v, consecutive %d",
			resp.StatusCode, responseTime, logConsecutive))
	}

	return isRateLimited
}

// detectAdvancedPatterns applies cheap header heuristics as a best-effort signal
// when the status code and configured header triggers don't fire. it is not ML,
// just a keyword scan over header names plus a check for an unusually varied
// Server header. callers hold the write lock, it mutates responsePatterns.
func (rld *RateLimitDetector) detectAdvancedPatterns(resp *http.Response) bool {
	// Check for common rate limit keywords in header names
	suspiciousHeaders := []string{
		"X-Rate-Limit", "Rate-Limit", "X-RateLimit", "RateLimit",
		"Throttle", "Quota", "Retry-After", "Too-Many", "Limit-Exceeded",
	}

	for _, suspicious := range suspiciousHeaders {
		for headerName := range resp.Header {
			if strings.Contains(strings.ToLower(headerName), strings.ToLower(suspicious)) {
				return true
			}
		}
	}

	// Some rate-limiting proxies swap the Server header. A high variety across a
	// single run can indicate we're being shuffled between edge nodes.
	server := resp.Header.Get("Server")
	if server != "" {
		rld.responsePatterns[server]++
		if len(rld.responsePatterns) > 5 {
			return true
		}
	}

	return false
}

// GetBypassDelay returns the delay to apply before the next request, growing it
// with each consecutive limit and adding jitter so a fleet of workers doesn't
// march in lockstep. The base is always MinDelay (the backoff multiplies that,
// not the previous result, so the delay can't compound across calls). The final
// value is recorded in currentDelay so the reported statistic is the real one.
func (rld *RateLimitDetector) GetBypassDelay() time.Duration {
	rld.mu.Lock()
	defer rld.mu.Unlock()

	baseDelay := rld.config.BypassSettings.MinDelay

	// Apply backoff if recently rate limited
	if rld.consecutiveLimits > 0 {
		backoffMultiplier := math.Pow(rld.config.BypassSettings.BackoffMultiplier, float64(rld.consecutiveLimits))
		backoffDelay := time.Duration(float64(baseDelay) * backoffMultiplier)

		// Cap the maximum delay
		if backoffDelay > rld.config.BypassSettings.MaxDelay {
			backoffDelay = rld.config.BypassSettings.MaxDelay
		}

		baseDelay = backoffDelay
	}

	// Add jitter so concurrent workers spread out instead of synchronising
	variation := rld.config.BypassSettings.RandomVariation
	if variation > 0 {
		randomFactor := 1.0 + (mathrand.Float64()-0.5)*2*variation
		baseDelay = time.Duration(float64(baseDelay) * randomFactor)
	}

	// Ensure minimum delay
	if baseDelay < rld.config.BypassSettings.MinDelay {
		baseDelay = rld.config.BypassSettings.MinDelay
	}

	rld.currentDelay = baseDelay
	return baseDelay
}

// ShouldUseBurstMode determines if burst mode should be used
func (rld *RateLimitDetector) ShouldUseBurstMode() bool {
	rld.mu.RLock()
	defer rld.mu.RUnlock()

	// Don't burst if recently rate limited
	if rld.consecutiveLimits > 0 {
		return false
	}

	// Check if enough time has passed since last burst
	if time.Since(rld.lastBurstTime) < rld.config.BypassSettings.BurstInterval {
		return false
	}

	// Check if we haven't exceeded burst size
	return rld.burstCounter < rld.config.BypassSettings.BurstSize
}

// RecordBurstRequest records a request in burst mode
func (rld *RateLimitDetector) RecordBurstRequest() {
	rld.mu.Lock()
	defer rld.mu.Unlock()

	rld.burstCounter++
	if rld.burstCounter >= rld.config.BypassSettings.BurstSize {
		rld.lastBurstTime = time.Now()
		rld.burstCounter = 0
	}
}

// AdaptRate adjusts the request rate based on success/failure patterns
func (rld *RateLimitDetector) AdaptRate() int {
	rld.mu.Lock()
	defer rld.mu.Unlock()

	// Decrease rate if getting rate limited
	if rld.consecutiveLimits > 2 {
		rld.adaptiveRate = int(float64(rld.adaptiveRate) * 0.7) // Reduce by 30%
		if rld.adaptiveRate < 1 {
			rld.adaptiveRate = 1
		}
	} else if rld.consecutiveLimits == 0 && rld.totalRequests%100 == 0 {
		// Gradually increase rate if no recent limits
		rld.adaptiveRate = int(float64(rld.adaptiveRate) * 1.1) // Increase by 10%
		if rld.adaptiveRate > rld.config.RequestRate*2 {
			rld.adaptiveRate = rld.config.RequestRate * 2 // Cap at 2x original
		}
	}

	return rld.adaptiveRate
}

// GetStatistics returns bypass statistics
func (rld *RateLimitDetector) GetStatistics() map[string]interface{} {
	rld.mu.RLock()
	defer rld.mu.RUnlock()

	successRate := 0.0
	if rld.totalRequests > 0 {
		successRate = float64(rld.totalRequests-rld.limitDetections) / float64(rld.totalRequests) * 100
	}

	return map[string]interface{}{
		"total_requests":     rld.totalRequests,
		"limit_detections":   rld.limitDetections,
		"recoveries":         rld.recoveries,
		"success_rate":       successRate,
		"consecutive_limits": rld.consecutiveLimits,
		"current_delay":      rld.currentDelay,
		"adaptive_rate":      rld.adaptiveRate,
	}
}

// IntelligentDelayManager paces the global request stream. It uses a token
// bucket rather than a mutex held across a sleep: callers wait concurrently on
// the bucket instead of serialising behind whichever goroutine is sleeping.
type IntelligentDelayManager struct {
	config   *DemonConfig
	detector *RateLimitDetector
	limiter  *rate.Limiter
}

func NewIntelligentDelayManager(config *DemonConfig, detector *RateLimitDetector) *IntelligentDelayManager {
	start := config.BypassSettings.MinDelay
	if start <= 0 {
		start = time.Millisecond
	}
	return &IntelligentDelayManager{
		config:   config,
		detector: detector,
		limiter:  rate.NewLimiter(rate.Every(start), 1),
	}
}

// WaitForOptimalTiming blocks until the token bucket allows the next request.
// The bucket's rate tracks the detector's backoff, so it tightens as limits
// accumulate and relaxes as the target recovers. Because rate.Limiter is
// concurrency-safe and never holds a lock across the wait, many workers can be
// pacing at once without serialising behind each other.
func (idm *IntelligentDelayManager) WaitForOptimalTiming(ctx context.Context) {
	if !idm.config.RateLimitBypass {
		return
	}

	delay := idm.detector.GetBypassDelay()
	if idm.config.DistributedTiming {
		delay = idm.applyDistributedTiming(delay)
	}
	if delay <= 0 {
		return
	}

	idm.limiter.SetLimit(rate.Every(delay))
	_ = idm.limiter.WaitN(ctx, 1)
}

// applyDistributedTiming adds sophisticated timing patterns
func (idm *IntelligentDelayManager) applyDistributedTiming(baseDelay time.Duration) time.Duration {
	// Use various timing patterns to avoid detection
	patterns := []float64{
		1.0, // Normal timing
		0.5, // Faster burst
		2.0, // Slower timing
		1.5, // Moderate slow
		0.8, // Slightly faster
		3.0, // Much slower
	}

	pattern := patterns[mathrand.Intn(len(patterns))]
	return time.Duration(float64(baseDelay) * pattern)
}

