package main

import (
	"fmt"
	"math"
	mathrand "math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type RateLimitDetector struct {
	config *DemonConfig
	logger *Logger

	// Detection state
	consecutiveLimits int
	lastLimitTime     time.Time
	currentDelay      time.Duration
	adaptiveRate      int

	// Pattern recognition
	responsePatterns map[string]int
	timingPatterns   []time.Duration

	// Bypass strategies
	burstCounter  int
	lastBurstTime time.Time
	backoffLevel  int

	// Statistics
	totalRequests      uint64
	limitDetections    uint64
	successfulBypasses uint64

	mu sync.RWMutex
}

func NewRateLimitDetector(config *DemonConfig, logger *Logger) *RateLimitDetector {
	return &RateLimitDetector{
		config:           config,
		logger:           logger,
		currentDelay:     config.BypassSettings.MinDelay,
		adaptiveRate:     config.RequestRate,
		responsePatterns: make(map[string]int),
		timingPatterns:   make([]time.Duration, 0, 100),
	}
}

// DetectRateLimit analyzes response to detect rate limiting
func (rld *RateLimitDetector) DetectRateLimit(resp *http.Response, responseTime time.Duration) bool {
	rld.mu.Lock()
	defer rld.mu.Unlock()

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

	// Check response time threshold
	if !isRateLimited && responseTime > rld.config.BypassSettings.ResponseTimeThresh {
		isRateLimited = true
	}

	// Advanced pattern detection
	if !isRateLimited {
		isRateLimited = rld.detectAdvancedPatterns(resp, responseTime)
	}

	if isRateLimited {
		rld.limitDetections++
		rld.consecutiveLimits++
		rld.lastLimitTime = time.Now()

		if rld.logger != nil {
			rld.logger.Warning(fmt.Sprintf("[!] rate limit detected: Status: %d, Response time: %v, Consecutive: %d",
				resp.StatusCode, responseTime, rld.consecutiveLimits))
		}
	} else {
		rld.consecutiveLimits = 0
	}

	// Update timing patterns for machine learning
	rld.updateTimingPatterns(responseTime)

	return isRateLimited
}

// detectAdvancedPatterns uses ML-like pattern recognition to detect rate limiting
func (rld *RateLimitDetector) detectAdvancedPatterns(resp *http.Response, responseTime time.Duration) bool {
	// Analyze response body size patterns (rate limited responses are often smaller)
	contentLength := resp.Header.Get("Content-Length")
	if contentLength != "" {
		if length, err := strconv.Atoi(contentLength); err == nil && length < 100 {
			return true // Suspiciously small response
		}
	}

	// Check for common rate limit keywords in headers
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

	// Analyze server header patterns (some servers change behavior when rate limiting)
	server := resp.Header.Get("Server")
	if server != "" {
		rld.responsePatterns[server]++
		// If server header changes frequently, might indicate rate limiting proxy
		if len(rld.responsePatterns) > 5 {
			return true
		}
	}

	return false
}

// updateTimingPatterns maintains a rolling window of response times for analysis
func (rld *RateLimitDetector) updateTimingPatterns(responseTime time.Duration) {
	rld.timingPatterns = append(rld.timingPatterns, responseTime)

	// Keep only last 100 timings
	if len(rld.timingPatterns) > 100 {
		rld.timingPatterns = rld.timingPatterns[1:]
	}

	// Detect sudden response time increases (rate limiting symptom)
	if len(rld.timingPatterns) >= 10 {
		recent := rld.timingPatterns[len(rld.timingPatterns)-5:]
		earlier := rld.timingPatterns[len(rld.timingPatterns)-10 : len(rld.timingPatterns)-5]

		recentAvg := calculateAverageTime(recent)
		earlierAvg := calculateAverageTime(earlier)

		// If recent responses are 3x slower, might be rate limiting
		if recentAvg > earlierAvg*3 {
			// This is detected as suspicious but not definitive
		}
	}
}

// calculateAverageTime calculates average response time
func calculateAverageTime(times []time.Duration) time.Duration {
	if len(times) == 0 {
		return 0
	}

	var total time.Duration
	for _, t := range times {
		total += t
	}
	return total / time.Duration(len(times))
}

// GetBypassDelay calculates optimal delay to bypass rate limits
func (rld *RateLimitDetector) GetBypassDelay() time.Duration {
	rld.mu.RLock()
	defer rld.mu.RUnlock()

	baseDelay := rld.currentDelay

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

	// Add random variation to avoid pattern detection
	variation := rld.config.BypassSettings.RandomVariation
	if variation > 0 {
		randomFactor := 1.0 + (mathrand.Float64()-0.5)*2*variation
		baseDelay = time.Duration(float64(baseDelay) * randomFactor)
	}

	// Ensure minimum delay
	if baseDelay < rld.config.BypassSettings.MinDelay {
		baseDelay = rld.config.BypassSettings.MinDelay
	}

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
		"total_requests":      rld.totalRequests,
		"limit_detections":    rld.limitDetections,
		"successful_bypasses": rld.successfulBypasses,
		"success_rate":        successRate,
		"consecutive_limits":  rld.consecutiveLimits,
		"current_delay":       rld.currentDelay,
		"adaptive_rate":       rld.adaptiveRate,
		"backoff_level":       rld.backoffLevel,
	}
}

// IntelligentDelayManager provides sophisticated timing control
type IntelligentDelayManager struct {
	config      *DemonConfig
	detector    *RateLimitDetector
	lastRequest time.Time
	mu          sync.Mutex
}

func NewIntelligentDelayManager(config *DemonConfig, detector *RateLimitDetector) *IntelligentDelayManager {
	return &IntelligentDelayManager{
		config:   config,
		detector: detector,
	}
}

// WaitForOptimalTiming waits for the optimal time to send next request
func (idm *IntelligentDelayManager) WaitForOptimalTiming() {
	idm.mu.Lock()
	defer idm.mu.Unlock()

	if idm.config.RateLimitBypass {
		delay := idm.detector.GetBypassDelay()

		// Distributed timing - spread requests across time
		if idm.config.DistributedTiming {
			delay = idm.applyDistributedTiming(delay)
		}

		// Wait since last request
		elapsed := time.Since(idm.lastRequest)
		if elapsed < delay {
			remaining := delay - elapsed
			time.Sleep(remaining)
		}
	}

	idm.lastRequest = time.Now()
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

