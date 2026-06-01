package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ProxySource struct {
	URL    string
	Parser func(string) []string
}

// sourceHealthStats tracks per-source scrape results so we can warn when a source
// silently rots, i.e. keeps returning HTTP 200 but yields zero proxies run after run.
// this catches the failure mode where a site restructures or starts blocking us without
// any obvious error signal.
type sourceHealthStats struct {
	mu              sync.Mutex
	consecutiveZero int // how many scrapes in a row returned 0 proxies
	totalScrapes    int
	totalProxies    int // lifetime proxy count from this source across all scrapes
}

// warnAfterConsecutiveZeros is how many consecutive empty scrapes before we flag a source
const warnAfterConsecutiveZeros = 3

// GeoNodeResponse represents the response from GeoNode API
type GeoNodeResponse struct {
	Data []struct {
		ID             string   `json:"_id"`
		IP             string   `json:"ip"`
		Port           string   `json:"port"`
		AnonymityLevel string   `json:"anonymityLevel"`
		Protocols      []string `json:"protocols"`
		LastChecked    int      `json:"lastChecked"`
		ResponseTime   int      `json:"responseTime"`
		Speed          int      `json:"speed"`
		Country        string   `json:"country"`
		Google         bool     `json:"google"`
	} `json:"data"`
}

// ProxyScraper manages automatic proxy collection
type ProxyScraper struct {
	client   *http.Client
	sources  []ProxySource
	health   map[string]*sourceHealthStats
	healthMu sync.RWMutex
}

// ProxyCacheEntry holds one cached proxy entry. target url is intentionally not
// stored, keeping it out of the file removes the most obvious forensic artifact
// linking the cache to a specific destination.
type ProxyCacheEntry struct {
	URL          string    `json:"url"`
	LastVerified time.Time `json:"last_verified"`
}

type ProxyCache struct {
	UpdatedAt time.Time         `json:"updated_at"`
	Entries   []ProxyCacheEntry `json:"entries"`
}

const proxyCacheFile = "proxy_cache.json"

// saveProxyCache writes the validated pool to disk so the next run can skip
// the scrape + test cycle entirely when the cache is still fresh. the target url
// is intentionally not stored, keeping it out of the file removes the most obvious
// forensic artifact linking the cache to a specific destination.
func saveProxyCache(proxies []string) {
	entries := make([]ProxyCacheEntry, 0, len(proxies))
	for _, u := range proxies {
		entries = append(entries, ProxyCacheEntry{
			URL:          u,
			LastVerified: time.Now(),
		})
	}
	data, err := json.Marshal(ProxyCache{UpdatedAt: time.Now(), Entries: entries})
	if err != nil {
		return
	}
	os.WriteFile(proxyCacheFile, data, 0600) //nolint:errcheck
}

// loadProxyCache returns cached proxies that are still within maxAge.
// stale entries are skipped; freshness is the only criterion.
func loadProxyCache(maxAge time.Duration) []string {
	data, err := os.ReadFile(proxyCacheFile)
	if err != nil {
		return nil
	}
	var cache ProxyCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil
	}
	cutoff := time.Now().Add(-maxAge)
	var out []string
	for _, e := range cache.Entries {
		if e.LastVerified.After(cutoff) {
			out = append(out, e.URL)
		}
	}
	return out
}

// NewProxyScraper creates a new proxy scraper
func NewProxyScraper() *ProxyScraper {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	sources := []ProxySource{
		// Tier 0: Premium APIs (high-quality, recently verified)
		{URL: "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&filterUpTime=80&protocols=http%2Chttps&anonymityLevel=elite", Parser: parseGeoNodeAPI},
		{URL: "https://proxylist.geonode.com/api/proxy-list?limit=500&page=2&sort_by=lastChecked&sort_type=desc&filterUpTime=80&protocols=http%2Chttps&anonymityLevel=anonymous", Parser: parseGeoNodeAPI},
		{URL: "https://proxylist.geonode.com/api/proxy-list?limit=500&page=3&sort_by=lastChecked&sort_type=desc&filterUpTime=70&protocols=http%2Chttps&anonymityLevel=elite", Parser: parseGeoNodeAPI},

		// Tier 1: Higher quality sources (better success rate)
		{URL: "http://spys.one/en/https-ssl-proxy/", Parser: parseSpysOne},
		{URL: "http://spys.one/en/anonymous-proxy-list/", Parser: parseSpysOne},
		{URL: "https://api.proxyscrape.com/v2/?request=get&protocol=http&timeout=5000&country=all&ssl=all&anonymity=elite", Parser: parseLineByLine},
		{URL: "https://api.proxyscrape.com/v2/?request=get&protocol=http&timeout=5000&country=all&ssl=all&anonymity=anonymous", Parser: parseLineByLine},
		{URL: "https://raw.githubusercontent.com/fate0/proxylist/master/proxy.list", Parser: parseJSONProxies},
		{URL: "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies_anonymous/http.txt", Parser: parseLineByLine},
		{URL: "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies_elite/http.txt", Parser: parseLineByLine},

		// Tier 2: HTTP sources that aren't on every CDN/WAF prebuilt blocklist.
		// TheSpeedX/monosans/mmpx12 are the first repos any firewall vendor scrapes,
		// so we swap them out for less-indexed alternatives that still get updated.
		{URL: "https://www.proxy-list.download/api/v1/get?type=http&anon=elite", Parser: parseLineByLine},
		{URL: "https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt", Parser: parseLineByLine},
		{URL: "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/http.txt", Parser: parseLineByLine},
		{URL: "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/http_proxies.txt", Parser: parseLineByLine},

		// Tier 3: SOCKS5 sources. SOCKS5 operates at the transport layer so it doesn't
		// inject X-Forwarded-For headers and is much harder to fingerprint than HTTP proxies.
		// parseSocks5 keeps the socks5:// scheme intact, don't collapse these to http://.
		{URL: "https://api.proxyscrape.com/v2/?request=get&protocol=socks5&timeout=5000&country=all", Parser: parseSocks5},
		{URL: "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt", Parser: parseSocks5},
		{URL: "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt", Parser: parseSocks5},
		{URL: "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt", Parser: parseSocks5},
		{URL: "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks5.txt", Parser: parseSocks5},
	}

	// // Additional high-quality sources
	// 	{URL: "https://raw.githubusercontent.com/fate0/proxylist/master/proxy.list", Parser: parseJSONProxies},
	// 	{URL: "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt", Parser: parseLineByLine},
	// 	{URL: "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/http.txt", Parser: parseLineByLine},
	// 	{URL: "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies_anonymous/http.txt", Parser: parseLineByLine},
	// 	{URL: "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies_elite/http.txt", Parser: parseLineByLine},

	// 	// API-based proxy sources
	// 	{URL: "https://api.proxyscrape.com/v2/?request=get&protocol=http&timeout=5000&country=all&ssl=all&anonymity=elite", Parser: parseLineByLine},
	// 	{URL: "https://api.proxyscrape.com/v2/?request=get&protocol=http&timeout=5000&country=all&ssl=all&anonymity=anonymous", Parser: parseLineByLine},
	// 	{URL: "https://proxyspace.pro/http.txt", Parser: parseLineByLine},
	// 	{URL: "https://raw.githubusercontent.com/almroot/proxylist/master/list.txt", Parser: parseLineByLine},
	// 	{URL: "https://raw.githubusercontent.com/proxy4parsing/proxy-list/main/http.txt", Parser: parseLineByLine},

	health := make(map[string]*sourceHealthStats, len(sources))
	for _, s := range sources {
		health[s.URL] = &sourceHealthStats{}
	}

	return &ProxyScraper{
		client:  client,
		sources: sources,
		health:  health,
	}
}

// parseLineByLine parses proxy list where each line is IP:PORT
func parseLineByLine(content string) []string {
	lines := strings.Split(content, "\n")
	var proxies []string

	// Regex to match IP:PORT format
	ipPortRegex := regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Find IP:PORT in the line
		matches := ipPortRegex.FindStringSubmatch(line)
		if len(matches) >= 3 {
			ip := matches[1]
			port := matches[2]

			// Validate IP and port
			if isValidIP(ip) && isValidPort(port) {
				proxies = append(proxies, fmt.Sprintf("http://%s:%s", ip, port))
			}
		}
	}

	return proxies
}

// parseJSONProxies parses JSON-based proxy lists
func parseJSONProxies(content string) []string {
	var proxies []string
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Try to parse as JSON
		var proxyData map[string]interface{}
		if err := json.Unmarshal([]byte(line), &proxyData); err == nil {
			// Extract IP and port from JSON
			if host, hasHost := proxyData["host"].(string); hasHost {
				if port, hasPort := proxyData["port"].(float64); hasPort {
					proxyURL := fmt.Sprintf("http://%s:%.0f", host, port)
					proxies = append(proxies, proxyURL)
				}
			}
		} else {
			// Fallback to line-by-line parsing
			lineProxies := parseLineByLine(line)
			proxies = append(proxies, lineProxies...)
		}
	}

	return proxies
}

// parseSocks5 parses SOCKS5 proxy lists where each line is IP:PORT and keeps them as socks5:// URLs.
// we want to keep them as socks5 because the whole point is that socks5 proxies are harder to
// fingerprint, collapsing them down to http:// throws that advantage away completely.
func parseSocks5(content string) []string {
	lines := strings.Split(content, "\n")
	var proxies []string

	ipPortRegex := regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		matches := ipPortRegex.FindStringSubmatch(line)
		if len(matches) >= 3 {
			ip := matches[1]
			port := matches[2]

			if isValidIP(ip) && isValidPort(port) {
				proxies = append(proxies, fmt.Sprintf("socks5://%s:%s", ip, port))
			}
		}
	}

	return proxies
}

// parseGeoNodeAPI parses the high-quality GeoNode API response
func parseGeoNodeAPI(content string) []string {
	var response GeoNodeResponse
	var proxies []string

	err := json.Unmarshal([]byte(content), &response)
	if err != nil {
		// If JSON parsing fails, return empty slice
		return proxies
	}

	for _, proxy := range response.Data {
		if !((proxy.AnonymityLevel == "elite" || proxy.AnonymityLevel == "anonymous") &&
			proxy.ResponseTime < 5000 &&
			proxy.LastChecked > 0) {
			continue
		}

		if !isValidIP(proxy.IP) || !isValidPort(proxy.Port) {
			continue
		}

		// prefer socks5 when available, it doesn't inject forwarding headers and is
		// harder to fingerprint at the application layer than HTTP CONNECT proxies.
		supportsSocks5 := false
		supportsHTTP := false
		for _, protocol := range proxy.Protocols {
			switch protocol {
			case "socks5":
				supportsSocks5 = true
			case "http", "https":
				supportsHTTP = true
			}
		}

		if supportsSocks5 {
			proxies = append(proxies, fmt.Sprintf("socks5://%s:%s", proxy.IP, proxy.Port))
		} else if supportsHTTP {
			proxies = append(proxies, fmt.Sprintf("http://%s:%s", proxy.IP, proxy.Port))
		}
	}

	return proxies
}

// isValidIP checks if IP address is valid
func isValidIP(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}

	for _, part := range parts {
		if num, err := strconv.Atoi(part); err != nil || num < 0 || num > 255 {
			return false
		}
	}

	// Skip localhost and private ranges for anonymity
	if strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "172.") {
		return false
	}

	return true
}

// isValidPort checks if port is valid
func isValidPort(port string) bool {
	if num, err := strconv.Atoi(port); err != nil || num < 1 || num > 65535 {
		return false
	}
	return true
}

// parseSpysOne scrapes proxies from spys.one format
func parseSpysOne(content string) []string {
	var proxies []string

	// Spys.one uses a table format with encoded data
	// Look for proxy patterns in the HTML
	re := regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{2,5})`)
	matches := re.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) >= 3 {
			proxy := fmt.Sprintf("%s:%s", match[1], match[2])
			// Basic IP validation
			if isValidIP(match[1]) && isValidPort(match[2]) {
				proxies = append(proxies, proxy)
			}
		}
	}

	fmt.Printf("[spys.one] parsed %d proxies\n", len(proxies))
	return proxies
}

// ScrapeProxies fetches proxies from all sources
func (ps *ProxyScraper) ScrapeProxies() []string {
	var allProxies []string
	var wg sync.WaitGroup
	var mu sync.Mutex

	fmt.Printf("scraping proxies from %d sources...\n", len(ps.sources))

	for i, source := range ps.sources {
		wg.Add(1)
		go func(idx int, src ProxySource) {
			defer wg.Done()

			fmt.Printf("[%d/%d] fetching: %s\n", idx+1, len(ps.sources), src.URL)

			resp, err := ps.client.Get(src.URL)
			if err != nil {
				fmt.Printf("[err] [%d/%d] failed: %v\n", idx+1, len(ps.sources), err)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != 200 {
				fmt.Printf("[err] [%d/%d] http %d\n", idx+1, len(ps.sources), resp.StatusCode)
				return
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf("[err] [%d/%d] read error: %v\n", idx+1, len(ps.sources), err)
				return
			}

			proxies := src.Parser(string(body))

			// update health stats for this source so repeated zero-yield runs get flagged.
			// a source that keeps responding 200 but returning nothing has silently rotted.
			ps.healthMu.RLock()
			stats := ps.health[src.URL]
			ps.healthMu.RUnlock()
			if stats != nil {
				stats.mu.Lock()
				stats.totalScrapes++
				if len(proxies) == 0 {
					stats.consecutiveZero++
					if stats.consecutiveZero >= warnAfterConsecutiveZeros {
						fmt.Printf("[!] source returning 0 proxies for %d consecutive scrapes — may be dead or restructured: %s\n",
							stats.consecutiveZero, src.URL)
					}
				} else {
					stats.consecutiveZero = 0
					stats.totalProxies += len(proxies)
				}
				stats.mu.Unlock()
			}

			mu.Lock()
			allProxies = append(allProxies, proxies...)
			mu.Unlock()

			fmt.Printf("[ok] [%d/%d] found %d proxies\n", idx+1, len(ps.sources), len(proxies))
		}(i, source)
	}

	wg.Wait()

	// Remove duplicates
	uniqueProxies := removeDuplicates(allProxies)
	fmt.Printf("total unique proxies found: %d\n", len(uniqueProxies))

	return uniqueProxies
}

// removeDuplicates removes duplicate proxy entries
func removeDuplicates(proxies []string) []string {
	seen := make(map[string]bool)
	var unique []string

	for _, proxy := range proxies {
		if !seen[proxy] {
			seen[proxy] = true
			unique = append(unique, proxy)
		}
	}

	return unique
}

// TestProxy checks if a proxy is working
func (ps *ProxyScraper) TestProxy(proxyURL string) bool {
	proxyParsed, err := url.Parse(proxyURL)
	if err != nil {
		return false
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

	// Test with a simple HTTP request
	testURLs := []string{
		"http://httpbin.org/ip",
		"http://icanhazip.com",
		"http://ipinfo.io/ip",
	}

	for _, testURL := range testURLs {
		resp, err := client.Get(testURL)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 {
			return true
		}
	}

	return false
}

