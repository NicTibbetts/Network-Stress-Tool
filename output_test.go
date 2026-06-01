package main

import (
	"strings"
	"testing"
)

// formatBytes and formatNumber are pure formatters, no I/O, no globals.
// the goal is to nail every unit boundary (KB vs MB, comma placement) so a
// future refactor can't silently break human-readable output.

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		in   uint64
		want string
	}{
		{0, "0 B"},
		{1, "1 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1024 * 1024, "1.0 MB"},
		{1024 * 1024 * 1024, "1.0 GB"},
		{1536 * 1024 * 1024, "1.5 GB"},
	}

	for _, tt := range tests {
		got := formatBytes(tt.in)
		if got != tt.want {
			t.Errorf("formatBytes(%d) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestFormatNumber(t *testing.T) {
	tests := []struct {
		in   uint64
		want string
	}{
		{0, "0"},
		{100, "100"},
		{999, "999"},
		{1000, "1,000"},
		{10000, "10,000"},
		{1000000, "1,000,000"},
		{1234567, "1,234,567"},
	}

	for _, tt := range tests {
		got := formatNumber(tt.in)
		if got != tt.want {
			t.Errorf("formatNumber(%d) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		s      string
		length int
		want   string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello world", 8, "hello..."},
		{"hi", 1, "h"},
		{"hi", 2, "hi"},
		{"abcdef", 3, "..."},
		{"abcdef", 4, "a..."},
	}

	for _, tt := range tests {
		got := truncateString(tt.s, tt.length)
		if got != tt.want {
			t.Errorf("truncateString(%q, %d) = %q, want %q", tt.s, tt.length, got, tt.want)
		}
	}
}

// style helpers wrap text in ANSI codes, test that the intended prefix and
// the original text both survive the wrapping, not the exact escape codes.

func TestStyleHelpers(t *testing.T) {
	tests := []struct {
		name    string
		fn      func(string) string
		input   string
		wantSub string // substring that must appear in output
	}{
		{"StyleSuccess", StyleSuccess, "done", "[ok] done"},
		{"StyleError", StyleError, "fail", "[err] fail"},
		{"StyleWarning", StyleWarning, "warn", "[!] warn"},
		{"StyleInfo", StyleInfo, "note", "[i] note"},
	}

	for _, tt := range tests {
		got := tt.fn(tt.input)
		if !strings.Contains(got, tt.wantSub) {
			t.Errorf("%s(%q): output %q does not contain %q", tt.name, tt.input, got, tt.wantSub)
		}
	}
}

func TestColorCode(t *testing.T) {
	// color codes must be valid ANSI escape sequences
	got := ColorCode(ColorRed)
	if !strings.HasPrefix(got, "\x1b[") {
		t.Errorf("ColorCode(ColorRed) = %q, want ANSI escape prefix", got)
	}
	if !strings.HasSuffix(got, "m") {
		t.Errorf("ColorCode(ColorRed) = %q, want trailing 'm'", got)
	}

	// reset must be distinct from red
	red := ColorCode(ColorRed)
	reset := ColorCode(ColorReset)
	if red == reset {
		t.Error("ColorCode(ColorRed) should differ from ColorCode(ColorReset)")
	}
}

// TestComposeFrame_FitDecision verifies the live frame includes the tall skull banner
// only when it fits the terminal, otherwise it drops to a one-line title so a short
// terminal doesn't scroll-creep and pile frames on top of each other (the garbled
// "stats left / skull right" mess).
func TestComposeFrame_FitDecision(t *testing.T) {
	banner := "L1\nL2\nL3\nL4\nL5\n" // 6 lines (5 newlines + 1)
	stats := "S1\nS2\nS3\n"         // 3 lines

	// rows == 0 -> unknown (piped); always include the banner.
	if got := composeFrame(banner, stats, 0); !strings.Contains(got, "L1") {
		t.Error("rows=0 should include the banner (unknown size -> render everything)")
	}

	// plenty of room -> banner included.
	if got := composeFrame(banner, stats, 40); !strings.Contains(got, "L3") {
		t.Error("tall terminal should include the banner")
	}

	// too short for banner+stats+margin -> banner dropped, NO fallback title (the
	// stats block's own "LIVE DASHBOARD" header is enough; a title here just
	// duplicated the banner's last line).
	got := composeFrame(banner, stats, 7)
	if strings.Contains(got, "L1") {
		t.Error("short terminal must DROP the skull banner to avoid scroll-creep")
	}
	if !strings.Contains(got, "S2") {
		t.Error("stats must always be present regardless of fit")
	}
}

// TestComposeFrame_InPlaceControlCodes verifies every frame homes the cursor, erases
// each line to its end, and clears below, the codes that make it repaint in place
// instead of flickering with a full-screen clear.
func TestComposeFrame_InPlaceControlCodes(t *testing.T) {
	got := composeFrame("BANNER\n", "S1\nS2\n", 0)
	if !strings.HasPrefix(got, "\033[H") {
		t.Error("frame must start by homing the cursor (\\033[H), not clearing the screen")
	}
	if !strings.Contains(got, "\033[K") {
		t.Error("each line must be erased to end-of-line (\\033[K) to wipe stale tails")
	}
	if !strings.HasSuffix(got, "\033[J") {
		t.Error("frame must end by erasing everything below it (\\033[J)")
	}
	if strings.Contains(got, "\033[2J") {
		t.Error("frame must NOT use a full-screen clear (\\033[2J) — that's the flicker source")
	}
}
