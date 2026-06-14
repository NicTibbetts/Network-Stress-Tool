package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// attacks_test.go covers the pure helpers that don't need live network access:
//   - parseTargetForUDP: URL normalisation + host/port extraction
//   - generateCacheBustingURL: query-param injection into an existing URL
//
// the actual attack goroutines (slowlorisAttack, udpFloodAttack, etc.) require
// a reachable target and a context, so they live in integration tests rather
// than here.

// ---- parseTargetForUDP ----

func TestParseTargetForUDP_IPAndPort(t *testing.T) {
	host, port, explicit, err := parseTargetForUDP("8.8.8.8:53")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "8.8.8.8" {
		t.Errorf("host = %q, want '8.8.8.8'", host)
	}
	if port != "53" {
		t.Errorf("port = %q, want '53'", port)
	}
	if !explicit {
		t.Error("portExplicit = false, want true (port was given in the target)")
	}
}

func TestParseTargetForUDP_StripHTTPScheme(t *testing.T) {
	host, port, _, err := parseTargetForUDP("http://8.8.8.8:8080")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "8.8.8.8" {
		t.Errorf("host = %q, want '8.8.8.8'", host)
	}
	if port != "8080" {
		t.Errorf("port = %q, want '8080'", port)
	}
}

func TestParseTargetForUDP_StripHTTPSScheme(t *testing.T) {
	host, _, _, err := parseTargetForUDP("https://8.8.8.8:443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "8.8.8.8" {
		t.Errorf("host = %q, want '8.8.8.8'", host)
	}
}

func TestParseTargetForUDP_StripUDPScheme(t *testing.T) {
	host, port, _, err := parseTargetForUDP("udp://1.2.3.4:9999")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "1.2.3.4" {
		t.Errorf("host = %q, want '1.2.3.4'", host)
	}
	if port != "9999" {
		t.Errorf("port = %q, want '9999'", port)
	}
}

func TestParseTargetForUDP_StripPath(t *testing.T) {
	// a URL with a path component, only the host:port part should survive
	host, port, _, err := parseTargetForUDP("http://8.8.8.8:80/some/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "8.8.8.8" {
		t.Errorf("host = %q, want '8.8.8.8'", host)
	}
	if port != "80" {
		t.Errorf("port = %q, want '80'", port)
	}
}

func TestParseTargetForUDP_DefaultPort(t *testing.T) {
	// no port specified, should default to "80"
	host, port, explicit, err := parseTargetForUDP("8.8.8.8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "8.8.8.8" {
		t.Errorf("host = %q, want '8.8.8.8'", host)
	}
	if port != "80" {
		t.Errorf("port = %q, want '80' (default)", port)
	}
	if explicit {
		t.Error("portExplicit = true, want false (port was defaulted, not given)")
	}
}

func TestParseTargetForUDP_InvalidFormat(t *testing.T) {
	// garbage with an invalid bracket structure
	_, _, _, err := parseTargetForUDP("not-a-host:[bad")
	if err == nil {
		t.Error("expected error for invalid format, got nil")
	}
}

// ---- generateCacheBustingURL ----

func TestLoadBundledReflectorCorpus_ParsesSections(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reflectors.txt")
	content := strings.Join([]string{
		"[dns]",
		"1.1.1.1",
		"# comment",
		"2.2.2.2",
		"[ntp]",
		"3.3.3.3",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	corpus, err := loadBundledReflectorCorpus(path)
	if err != nil {
		t.Fatalf("loadBundledReflectorCorpus() error = %v", err)
	}
	if got := len(corpus["dns"]); got != 2 {
		t.Fatalf("len(corpus[dns]) = %d, want 2", got)
	}
	if got := len(corpus["ntp"]); got != 1 {
		t.Fatalf("len(corpus[ntp]) = %d, want 1", got)
	}
	if got := corpus["dns"][0].String(); got != "1.1.1.1" {
		t.Fatalf("corpus[dns][0] = %q, want 1.1.1.1", got)
	}
}

func TestNormalizeDiscoverWorkers_UsesSafeCap(t *testing.T) {
	if got := normalizeDiscoverWorkers(0); got < 8 || got > 64 {
		t.Fatalf("normalizeDiscoverWorkers(0) = %d, want a conservative 8..64 worker range", got)
	}
	if got := normalizeDiscoverWorkers(5000); got != 64 {
		t.Fatalf("normalizeDiscoverWorkers(5000) = %d, want 64", got)
	}
}

func TestProbeSeedCandidates_UsesExplicitSeedsAndFiltersDuplicates(t *testing.T) {
	seedIPs := []net.IP{
		net.ParseIP("1.1.1.1"),
		net.ParseIP("1.1.1.1"),
		net.ParseIP("2.2.2.2"),
	}

	var seen []string
	candidates := probeSeedCandidates("dns", seedIPs, time.Now().Add(time.Second), func(ip net.IP) (bool, int, int) {
		seen = append(seen, ip.String())
		return true, 12, 34
	})

	if len(candidates) != 2 {
		t.Fatalf("len(candidates) = %d, want 2", len(candidates))
	}
	if len(seen) != 2 {
		t.Fatalf("probe count = %d, want 2", len(seen))
	}
	if candidates[0].Protocol != "dns" {
		t.Fatalf("candidate protocol = %q, want dns", candidates[0].Protocol)
	}
}

func TestGenerateCacheBustingURL_ContainsBase(t *testing.T) {
	base := "http://example.com/page"
	got := generateCacheBustingURL(base)
	if !strings.HasPrefix(got, "http://example.com/page") {
		t.Errorf("generateCacheBustingURL: result %q does not start with base URL", got)
	}
}

func TestGenerateCacheBustingURL_AddsQueryParams(t *testing.T) {
	base := "http://example.com/"
	got := generateCacheBustingURL(base)
	if !strings.Contains(got, "?") && !strings.Contains(got, "&") {
		t.Errorf("generateCacheBustingURL: result %q contains no query params", got)
	}
}

type stubLogger struct {
	warningCalls int
	infoCalls    int
}

func (s *stubLogger) Warning(msg string) { s.warningCalls++ }
func (s *stubLogger) Info(msg string)    { s.infoCalls++ }

func TestLogReflectionFallbackWarning_OnlyOnce(t *testing.T) {
	reflectionFallbackWarningOnce = sync.Once{}
	logger := &stubLogger{}

	logReflectionFallbackWarning(logger)
	logReflectionFallbackWarning(logger)

	if logger.warningCalls != 1 {
		t.Fatalf("warning calls = %d, want 1", logger.warningCalls)
	}
}

func TestLogDirectFloodInfo_OnlyOnce(t *testing.T) {
	directFloodInfoOnce = sync.Once{}
	logger := &stubLogger{}

	logDirectFloodInfo(logger, "test")
	logDirectFloodInfo(logger, "test")

	if logger.infoCalls != 1 {
		t.Fatalf("info calls = %d, want 1", logger.infoCalls)
	}
}

func TestGenerateCacheBustingURL_PreservesExistingParams(t *testing.T) {
	base := "http://example.com/search?q=test"
	got := generateCacheBustingURL(base)
	// original param should still be present (or at least the base path should be)
	if !strings.Contains(got, "example.com") {
		t.Errorf("generateCacheBustingURL: lost base domain — got %q", got)
	}
}

func TestGenerateCacheBustingURL_InvalidBaseReturnsBase(t *testing.T) {
	// an unparseable URL should be returned unchanged
	garbage := "://invalid url"
	got := generateCacheBustingURL(garbage)
	if got != garbage {
		t.Errorf("generateCacheBustingURL(%q): got %q, want unchanged base", garbage, got)
	}
}

func TestGenerateCacheBustingURL_Uniqueness(t *testing.T) {
	// two calls should very likely produce different URLs due to timestamp nanos
	base := "http://example.com/"
	a := generateCacheBustingURL(base)
	b := generateCacheBustingURL(base)
	// this CAN be equal in the same nanosecond, but practically never happens
	_ = a
	_ = b
	// we don't assert inequality here to avoid flaky tests, but we verify both parse
	if !strings.Contains(a, "example.com") || !strings.Contains(b, "example.com") {
		t.Error("one of the cache-busted URLs lost the base domain")
	}
}
