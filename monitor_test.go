package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// monitor_test.go covers controlReachable, the primitive that tells "the target is
// down" apart from "our own uplink is saturated." it's the core of the false-positive
// fix, so it's worth pinning deterministically (no live network / third parties:
// dead hosts are closed localhost ports, the live host is an httptest server).

func TestControlReachable_AllUnreachable(t *testing.T) {
	saved := controlHosts
	defer func() { controlHosts = saved }()
	// closed localhost ports -> connection refused fast -> every probe fails, which is
	// exactly the signal we read as "our own link, not the target."
	controlHosts = []string{"http://127.0.0.1:1", "http://127.0.0.1:2"}

	client := &http.Client{Timeout: 2 * time.Second}
	if controlReachable(context.Background(), client) {
		t.Error("controlReachable = true with all hosts unreachable — congestion would never be detected, reviving the false 'target DOWN'")
	}
}

func TestControlReachable_OneReachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	saved := controlHosts
	defer func() { controlHosts = saved }()
	// one dead, one alive: ANY reachable reference host means our link is fine, so
	// a target failure is the target's fault, controlReachable must return true.
	controlHosts = []string{"http://127.0.0.1:1", srv.URL}

	client := &http.Client{Timeout: 2 * time.Second}
	if !controlReachable(context.Background(), client) {
		t.Error("controlReachable = false despite a reachable host — genuine target-down would be misread as local congestion")
	}
}

// probeTarget: a server that answers (even 4xx) is "up"; only transport errors and
// 5xx count as down. 403/429 (the target blocking us) is not an outage.
func TestProbeTarget_StatusHandling(t *testing.T) {
	cases := []struct {
		code int
		up   bool
	}{
		{200, true}, {403, true}, {429, true}, {500, false}, {503, false},
	}
	client := &http.Client{Timeout: 2 * time.Second}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(c.code)
		}))
		got := probeTarget(context.Background(), client, srv.URL)
		srv.Close()
		if got != c.up {
			t.Errorf("probeTarget(status %d) = %v, want %v", c.code, got, c.up)
		}
	}
}
