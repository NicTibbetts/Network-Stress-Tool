package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ProxyQuality int

const (
	ProxyQualityUnknown ProxyQuality = iota
	ProxyQualityLow
	ProxyQualityMedium
	ProxyQualityHigh
	ProxyQualityElite
)

type ProxyMetrics struct {
	ResponseTime   time.Duration `json:"response_time"`
	SuccessRate    float64       `json:"success_rate"`
	AnonymityLevel ProxyQuality  `json:"anonymity_level"`
	LastTested     time.Time     `json:"last_tested"`
	TotalRequests  int           `json:"total_requests"`
	FailedRequests int           `json:"failed_requests"`
	IsBlacklisted  bool          `json:"is_blacklisted"`
	Country        string        `json:"country"`
	ISP            string        `json:"isp"`
}

type EnhancedProxy struct {
	URL     string       `json:"url"`
	Type    string       `json:"type"` // "http", "https", "socks5"
	Metrics ProxyMetrics `json:"metrics"`
	mu      sync.Mutex
}

func (p *EnhancedProxy) UpdateMetrics(responseTime time.Duration, success bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.Metrics.TotalRequests++
	if !success {
		p.Metrics.FailedRequests++
	}

	p.Metrics.SuccessRate = float64(p.Metrics.TotalRequests-p.Metrics.FailedRequests) / float64(p.Metrics.TotalRequests)
	p.Metrics.ResponseTime = responseTime
	p.Metrics.LastTested = time.Now()
}

type EnhancedProxyManager struct {
	proxies      []*EnhancedProxy
	currentIndex int64
	mu           sync.RWMutex
	logger       *Logger
	config       *DemonConfig
	testEndpoint string
}

func NewEnhancedProxyManager(config *DemonConfig, logger *Logger) *EnhancedProxyManager {
	return &EnhancedProxyManager{
		proxies:      make([]*EnhancedProxy, 0),
		logger:       logger,
		config:       config,
		testEndpoint: "https://httpbin.org/ip",
	}
}

// AddProxy adds a new proxy to the manager
func (pm *EnhancedProxyManager) AddProxy(proxyURL, proxyType string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	proxy := &EnhancedProxy{
		URL:  proxyURL,
		Type: proxyType,
		Metrics: ProxyMetrics{
			AnonymityLevel: ProxyQualityUnknown,
			LastTested:     time.Time{},
		},
	}

	pm.proxies = append(pm.proxies, proxy)
}

// GetBestProxy returns the proxy with the best metrics
func (pm *EnhancedProxyManager) GetBestProxy() *EnhancedProxy {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if len(pm.proxies) == 0 {
		return nil
	}

	var bestProxy *EnhancedProxy
	bestScore := -1.0

	for _, proxy := range pm.proxies {
		if proxy.Metrics.IsBlacklisted {
			continue
		}

		// Calculate proxy score based on multiple factors
		score := pm.calculateProxyScore(proxy)
		if score > bestScore {
			bestScore = score
			bestProxy = proxy
		}
	}

	return bestProxy
}

// GetNextProxy returns the next proxy in rotation
func (pm *EnhancedProxyManager) GetNextProxy() *EnhancedProxy {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if len(pm.proxies) == 0 {
		return nil
	}

	// Filter out blacklisted proxies
	availableProxies := make([]*EnhancedProxy, 0)
	for _, proxy := range pm.proxies {
		if !proxy.Metrics.IsBlacklisted {
			availableProxies = append(availableProxies, proxy)
		}
	}

	if len(availableProxies) == 0 {
		return nil
	}

	index := atomic.AddInt64(&pm.currentIndex, 1) % int64(len(availableProxies))
	return availableProxies[index]
}

// calculateProxyScore calculates a score for proxy selection
func (pm *EnhancedProxyManager) calculateProxyScore(proxy *EnhancedProxy) float64 {
	score := 0.0

	// Success rate (0-40 points)
	score += proxy.Metrics.SuccessRate * 40

	// Response time (0-30 points, inverted - faster is better)
	if proxy.Metrics.ResponseTime > 0 {
		responseScore := math.Max(0, 30-(float64(proxy.Metrics.ResponseTime.Milliseconds())/1000)*10)
		score += responseScore
	}

	// Anonymity level (0-20 points)
	score += float64(proxy.Metrics.AnonymityLevel) * 5

	// Recency (0-10 points)
	timeSinceTest := time.Since(proxy.Metrics.LastTested)
	if timeSinceTest < time.Hour {
		score += 10
	} else if timeSinceTest < time.Hour*24 {
		score += 5
	}

	return score
}

// TestProxy tests a proxy for connectivity and anonymity
func (pm *EnhancedProxyManager) TestProxy(proxy *EnhancedProxy) bool {
	start := time.Now()
	success := false

	defer func() {
		duration := time.Since(start)
		proxy.UpdateMetrics(duration, success)

		if pm.logger != nil {
			if success {
				pm.logger.Debug(fmt.Sprintf("Proxy test passed: %s (%.2fs)", proxy.URL, duration.Seconds()))
			} else {
				pm.logger.Warning(fmt.Sprintf("Proxy test failed: %s (%.2fs)", proxy.URL, duration.Seconds()))
			}
		}
	}()

	// Create proxy transport
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		return false
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialContext: (&net.Dialer{
			Timeout: time.Duration(pm.config.ProxyTestTimeout) * time.Second,
		}).DialContext,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(pm.config.ProxyTestTimeout) * time.Second,
	}

	// Test connectivity
	resp, err := client.Get(pm.testEndpoint)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return false
	}

	// Test anonymity by checking returned IP
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false
	}

	proxyIP, ok := result["origin"].(string)
	if !ok {
		return false
	}

	// Check if the proxy is actually masking our IP
	realIP := pm.getRealIP()
	if realIP != "" && proxyIP == realIP {
		proxy.Metrics.AnonymityLevel = ProxyQualityLow
		return false
	}

	// Determine anonymity level based on headers
	proxy.Metrics.AnonymityLevel = pm.determineAnonymityLevel(resp.Header)

	success = true
	return true
}

// determineAnonymityLevel analyzes response headers to determine proxy anonymity level
func (pm *EnhancedProxyManager) determineAnonymityLevel(headers http.Header) ProxyQuality {
	// Check for headers that reveal proxy usage
	suspiciousHeaders := []string{
		"X-Forwarded-For",
		"X-Real-IP",
		"Via",
		"X-Proxy-ID",
		"Forwarded",
	}

	suspiciousCount := 0
	for _, header := range suspiciousHeaders {
		if headers.Get(header) != "" {
			suspiciousCount++
		}
	}

	// Classify based on header analysis
	if suspiciousCount == 0 {
		return ProxyQualityElite
	} else if suspiciousCount <= 1 {
		return ProxyQualityHigh
	} else if suspiciousCount <= 2 {
		return ProxyQualityMedium
	} else {
		return ProxyQualityLow
	}
}

// getRealIP gets the real IP address without proxy
func (pm *EnhancedProxyManager) getRealIP() string {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(pm.testEndpoint)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return ""
	}

	if ip, ok := result["origin"].(string); ok {
		return ip
	}
	return ""
}

// LoadProxiesFromFile loads proxies from a file
func (pm *EnhancedProxyManager) LoadProxiesFromFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open proxy file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Determine proxy type based on URL scheme
		proxyType := "http"
		if strings.HasPrefix(line, "socks") {
			proxyType = "socks5"
		} else if !strings.HasPrefix(line, "http") {
			line = "http://" + line
		}

		pm.AddProxy(line, proxyType)
		count++
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading proxy file: %v", err)
	}

	if pm.logger != nil {
		pm.logger.Info(fmt.Sprintf("Loaded %d proxies from %s", count, filename))
	}

	return nil
}

// TestAllProxies tests all proxies concurrently
func (pm *EnhancedProxyManager) TestAllProxies() {
	pm.mu.RLock()
	proxies := make([]*EnhancedProxy, len(pm.proxies))
	copy(proxies, pm.proxies)
	pm.mu.RUnlock()

	if pm.logger != nil {
		pm.logger.Info(fmt.Sprintf("Testing %d proxies for connectivity and anonymity...", len(proxies)))
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 50) // Limit concurrent tests

	for _, proxy := range proxies {
		wg.Add(1)
		go func(p *EnhancedProxy) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			pm.TestProxy(p)
		}(proxy)
	}

	wg.Wait()

	// Count working proxies
	working := 0
	elite := 0
	for _, proxy := range proxies {
		if !proxy.Metrics.IsBlacklisted && proxy.Metrics.SuccessRate > 0 {
			working++
			if proxy.Metrics.AnonymityLevel == ProxyQualityElite {
				elite++
			}
		}
	}

	if pm.logger != nil {
		pm.logger.Info(fmt.Sprintf("Proxy testing complete: %d working (%d elite) out of %d total", working, elite, len(proxies)))
	}
}

// GetProxyStats returns statistics about loaded proxies
func (pm *EnhancedProxyManager) GetProxyStats() map[string]interface{} {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	stats := map[string]interface{}{
		"total":       len(pm.proxies),
		"working":     0,
		"blacklisted": 0,
		"elite":       0,
		"high":        0,
		"medium":      0,
		"low":         0,
		"unknown":     0,
	}

	for _, proxy := range pm.proxies {
		if proxy.Metrics.IsBlacklisted {
			stats["blacklisted"] = stats["blacklisted"].(int) + 1
		} else if proxy.Metrics.SuccessRate > 0 {
			stats["working"] = stats["working"].(int) + 1
		}

		switch proxy.Metrics.AnonymityLevel {
		case ProxyQualityElite:
			stats["elite"] = stats["elite"].(int) + 1
		case ProxyQualityHigh:
			stats["high"] = stats["high"].(int) + 1
		case ProxyQualityMedium:
			stats["medium"] = stats["medium"].(int) + 1
		case ProxyQualityLow:
			stats["low"] = stats["low"].(int) + 1
		default:
			stats["unknown"] = stats["unknown"].(int) + 1
		}
	}

	return stats
}

// GetProxyCount returns the number of proxies in the manager
func (pm *EnhancedProxyManager) GetProxyCount() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return len(pm.proxies)
}

// GetAllProxies returns all proxies in the manager
func (pm *EnhancedProxyManager) GetAllProxies() []*EnhancedProxy {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// Return a copy to avoid race conditions
	proxies := make([]*EnhancedProxy, len(pm.proxies))
	copy(proxies, pm.proxies)
	return proxies
}

// rate limit bypass system
