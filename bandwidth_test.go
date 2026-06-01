package main

import (
	"context"
	"testing"
)

func TestParseBandwidth(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"0", 0},
		{"40mbit", 5_000_000},   // 40e6 bits / 8
		{"40Mbps", 5_000_000},   // case-insensitive alias
		{"1gbit", 125_000_000},  // 1e9 bits / 8
		{"500kbit", 62_500},     // 500e3 bits / 8
		{"5MB", 5_000_000},      // bytes
		{"64KB", 64_000},        // bytes
		{"2GB", 2_000_000_000},  // bytes
		{"1000000", 1_000_000},  // bare number = bytes/sec
		{"8bit", 1},             // 8 bits = 1 byte
		{"  10mbit ", 1_250_000}, // trimmed
	}
	for _, c := range cases {
		got, err := parseBandwidth(c.in)
		if err != nil {
			t.Errorf("parseBandwidth(%q) unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseBandwidth(%q) = %d, want %d", c.in, got, c.want)
		}
	}

	for _, bad := range []string{"abc", "40xyz", "mbit", "1.2.3mbit"} {
		if _, err := parseBandwidth(bad); err == nil {
			t.Errorf("parseBandwidth(%q) = nil error, want an error", bad)
		}
	}
}

func TestBandwidthPacer(t *testing.T) {
	defer setBandwidthLimit(0) // don't leak state into other tests

	setBandwidthLimit(0)
	if bwLimiter != nil {
		t.Error("setBandwidthLimit(0) should leave the pacer disabled (nil)")
	}
	if !paceEgress(context.Background(), 5000) {
		t.Error("paceEgress should be a no-op (true) when uncapped")
	}

	setBandwidthLimit(1_000_000)
	if bwLimiter == nil {
		t.Error("setBandwidthLimit(1e6) should install a limiter")
	}
	// the burst is sized to allow a small immediate send without blocking the test.
	if !paceEgress(context.Background(), 1400) {
		t.Error("paceEgress(1400) should succeed within the burst budget")
	}

	// paceEgress must forward a WaitN failure as false rather than block/panic
	// (here the request exceeds the burst bucket, which WaitN rejects outright).
	if paceEgress(context.Background(), 10_000_000) {
		t.Error("paceEgress should return false when the request can't be satisfied")
	}
}
