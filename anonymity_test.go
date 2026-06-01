package main

import (
	"net"
	"net/http"
	"testing"
)

// TestAddAnonymizationHeaders verifies the cleaned-up header spoofing: every IP header
// it sets must carry the SAME public IP (consistent story for a backend that cross-
// checks), must never be a private/loopback address (an instant bot tell), and the
// CDN-set headers must never appear. Run many times since the secondary headers and
// the IP are randomized per request.
func TestAddAnonymizationHeaders(t *testing.T) {
	ipHeaders := append([]string{"X-Forwarded-For", "X-Real-IP"}, secondaryIPHeaders...)

	// headers that must NEVER be set — CDN-populated values that flag as a bot inbound.
	bannedHeaders := []string{"CF-Connecting-IP", "True-Client-IP", "CF-Ray", "CF-Visitor"}

	for i := 0; i < 200; i++ {
		req, _ := http.NewRequest("GET", "https://example.com/", nil)
		addAnonymizationHeaders(req)

		// XFF and X-Real-IP are always set.
		xff := req.Header.Get("X-Forwarded-For")
		if xff == "" || req.Header.Get("X-Real-IP") == "" {
			t.Fatalf("X-Forwarded-For/X-Real-IP must always be set")
		}

		// every IP header that's present must equal the same IP, and be public.
		for _, h := range ipHeaders {
			v := req.Header.Get(h)
			if v == "" {
				continue
			}
			if v != xff {
				t.Fatalf("%s = %q, inconsistent with X-Forwarded-For %q", h, v, xff)
			}
			ip := net.ParseIP(v)
			if ip == nil {
				t.Fatalf("%s = %q is not a valid IP", h, v)
			}
			if ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
				t.Fatalf("%s = %q is a private/loopback IP (instant bot tell)", h, v)
			}
		}

		for _, h := range bannedHeaders {
			if req.Header.Get(h) != "" {
				t.Fatalf("banned header %s was set (%q) — it's a CDN bot fingerprint", h, req.Header.Get(h))
			}
		}
	}
}
