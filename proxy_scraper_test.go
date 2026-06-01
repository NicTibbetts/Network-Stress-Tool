package main

import (
	"fmt"
	"strings"
	"testing"
)

// proxy scraper tests cover the pure parsing and validation functions.
// none of these make network calls, they transform text strings into
// validated proxy URL lists, so they're safe and fast to run in CI.

// ---- isValidIP ----

func TestIsValidIP_Valid(t *testing.T) {
	valid := []string{
		"8.8.8.8",
		"1.2.3.4",
		"203.0.113.1",
		"198.51.100.42",
		"255.255.255.0",
	}
	for _, ip := range valid {
		if !isValidIP(ip) {
			t.Errorf("isValidIP(%q) = false, want true", ip)
		}
	}
}

func TestIsValidIP_RejectsPrivateRanges(t *testing.T) {
	private := []string{
		"127.0.0.1",
		"10.0.0.1",
		"192.168.1.1",
		"172.16.0.1",
	}
	for _, ip := range private {
		if isValidIP(ip) {
			t.Errorf("isValidIP(%q) = true, want false (private range)", ip)
		}
	}
}

func TestIsValidIP_RejectsInvalid(t *testing.T) {
	invalid := []string{
		"",
		"not.an.ip",
		"256.1.1.1",
		"1.2.3",
		"1.2.3.4.5",
		"1.2.3.-1",
		"abc",
	}
	for _, ip := range invalid {
		if isValidIP(ip) {
			t.Errorf("isValidIP(%q) = true, want false", ip)
		}
	}
}

// ---- isValidPort ----

func TestIsValidPort_Valid(t *testing.T) {
	valid := []string{"1", "80", "443", "8080", "65535"}
	for _, p := range valid {
		if !isValidPort(p) {
			t.Errorf("isValidPort(%q) = false, want true", p)
		}
	}
}

func TestIsValidPort_Invalid(t *testing.T) {
	invalid := []string{"0", "65536", "-1", "abc", "", "99999"}
	for _, p := range invalid {
		if isValidPort(p) {
			t.Errorf("isValidPort(%q) = true, want false", p)
		}
	}
}

// ---- parseLineByLine ----

func TestParseLineByLine_BasicProxies(t *testing.T) {
	content := "8.8.8.8:3128\n8.8.4.4:8080\n"
	got := parseLineByLine(content)
	if len(got) != 2 {
		t.Fatalf("parseLineByLine: got %d proxies, want 2 — output: %v", len(got), got)
	}
	for _, p := range got {
		if !strings.HasPrefix(p, "http://") {
			t.Errorf("proxy %q should have http:// prefix", p)
		}
	}
}

func TestParseLineByLine_SkipsComments(t *testing.T) {
	content := "# comment\n8.8.8.8:3128\n# another comment\n"
	got := parseLineByLine(content)
	if len(got) != 1 {
		t.Errorf("parseLineByLine: got %d proxies, want 1 (comments should be skipped)", len(got))
	}
}

func TestParseLineByLine_SkipsPrivateIPs(t *testing.T) {
	content := "127.0.0.1:8080\n10.0.0.1:3128\n8.8.8.8:3128\n"
	got := parseLineByLine(content)
	if len(got) != 1 {
		t.Errorf("parseLineByLine: got %d proxies, want 1 (private IPs should be filtered)", len(got))
	}
}

func TestParseLineByLine_SkipsEmptyLines(t *testing.T) {
	content := "\n\n8.8.8.8:3128\n\n"
	got := parseLineByLine(content)
	if len(got) != 1 {
		t.Errorf("parseLineByLine: got %d proxies, want 1", len(got))
	}
}

func TestParseLineByLine_SkipsInvalidPort(t *testing.T) {
	content := "8.8.8.8:99999\n8.8.8.8:8080\n"
	got := parseLineByLine(content)
	if len(got) != 1 {
		t.Errorf("parseLineByLine: got %d proxies with invalid port, want 1", len(got))
	}
}

// ---- parseSocks5 ----

func TestParseSocks5_UsesSocks5Scheme(t *testing.T) {
	content := "8.8.8.8:1080\n8.8.4.4:1080\n"
	got := parseSocks5(content)
	if len(got) != 2 {
		t.Fatalf("parseSocks5: got %d proxies, want 2", len(got))
	}
	for _, p := range got {
		if !strings.HasPrefix(p, "socks5://") {
			t.Errorf("parseSocks5 proxy %q should have socks5:// prefix", p)
		}
	}
}

func TestParseSocks5_SkipsPrivateIPs(t *testing.T) {
	content := "192.168.1.1:1080\n8.8.8.8:1080\n"
	got := parseSocks5(content)
	if len(got) != 1 {
		t.Errorf("parseSocks5: got %d proxies, want 1 (private IPs filtered)", len(got))
	}
}

// ---- parseJSONProxies ----

func TestParseJSONProxies_ValidJSON(t *testing.T) {
	// one JSON object per line with host/port fields
	line := `{"host":"8.8.8.8","port":3128}`
	got := parseJSONProxies(line)
	if len(got) != 1 {
		t.Fatalf("parseJSONProxies: got %d proxies, want 1", len(got))
	}
	if !strings.Contains(got[0], "8.8.8.8") {
		t.Errorf("proxy %q should contain IP", got[0])
	}
}

func TestParseJSONProxies_FallsBackToLineByLine(t *testing.T) {
	// non-JSON input should fall back to plain IP:PORT parsing
	content := "8.8.8.8:3128"
	got := parseJSONProxies(content)
	if len(got) != 1 {
		t.Errorf("parseJSONProxies fallback: got %d proxies, want 1", len(got))
	}
}

// ---- parseGeoNodeAPI ----

func TestParseGeoNodeAPI_ValidResponse(t *testing.T) {
	// build a minimal GeoNode JSON payload with one elite proxy
	payload := `{
		"data": [
			{
				"_id": "abc",
				"ip": "8.8.8.8",
				"port": "3128",
				"anonymityLevel": "elite",
				"protocols": ["http"],
				"lastChecked": 1000,
				"responseTime": 500,
				"speed": 1,
				"country": "US",
				"google": false
			}
		]
	}`
	got := parseGeoNodeAPI(payload)
	if len(got) != 1 {
		t.Fatalf("parseGeoNodeAPI: got %d proxies, want 1 — %v", len(got), got)
	}
	if !strings.Contains(got[0], "8.8.8.8") {
		t.Errorf("proxy %q should contain IP", got[0])
	}
}

func TestParseGeoNodeAPI_FiltersByAnonymity(t *testing.T) {
	// transparent proxy should be filtered out
	payload := `{
		"data": [
			{
				"ip": "8.8.8.8",
				"port": "3128",
				"anonymityLevel": "transparent",
				"protocols": ["http"],
				"lastChecked": 1000,
				"responseTime": 500
			}
		]
	}`
	got := parseGeoNodeAPI(payload)
	if len(got) != 0 {
		t.Errorf("parseGeoNodeAPI: got %d proxies for transparent level, want 0", len(got))
	}
}

func TestParseGeoNodeAPI_PrefersSocks5(t *testing.T) {
	// when a proxy supports both socks5 and http, we prefer socks5
	payload := `{
		"data": [
			{
				"ip": "8.8.8.8",
				"port": "1080",
				"anonymityLevel": "elite",
				"protocols": ["http","socks5"],
				"lastChecked": 1000,
				"responseTime": 500
			}
		]
	}`
	got := parseGeoNodeAPI(payload)
	if len(got) == 0 {
		t.Fatal("parseGeoNodeAPI: expected a proxy, got none")
	}
	if !strings.HasPrefix(got[0], "socks5://") {
		t.Errorf("expected socks5:// prefix, got %q", got[0])
	}
}

func TestParseGeoNodeAPI_InvalidJSON(t *testing.T) {
	got := parseGeoNodeAPI("not json at all")
	if len(got) != 0 {
		t.Errorf("parseGeoNodeAPI with invalid JSON: got %d proxies, want 0", len(got))
	}
}

// ---- removeDuplicates ----

func TestRemoveDuplicates_Deduplicates(t *testing.T) {
	in := []string{
		"http://8.8.8.8:3128",
		"http://8.8.8.8:3128",
		"http://8.8.4.4:3128",
	}
	got := removeDuplicates(in)
	if len(got) != 2 {
		t.Errorf("removeDuplicates: got %d, want 2", len(got))
	}
}

func TestRemoveDuplicates_Empty(t *testing.T) {
	// the implementation returns nil for an empty input, that's idiomatic Go
	// for a slice-building function that never appends. len(nil) == 0 is fine.
	got := removeDuplicates([]string{})
	if len(got) != 0 {
		t.Errorf("removeDuplicates([]): got %d elements, want 0", len(got))
	}
}

func TestRemoveDuplicates_NoDuplicates(t *testing.T) {
	in := []string{"http://1.1.1.1:80", "http://2.2.2.2:80"}
	got := removeDuplicates(in)
	if len(got) != 2 {
		t.Errorf("removeDuplicates (no dupes): got %d, want 2", len(got))
	}
}

// import guard
var _ = fmt.Sprintf
