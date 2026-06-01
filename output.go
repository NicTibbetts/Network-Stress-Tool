package main

import (
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/term"
)

// ansi color attribute type, used by all style helpers
type ColorAttribute int

const (
	ColorBlack ColorAttribute = iota + 90
	ColorRed
	ColorGreen
	ColorYellow
	ColorBlue
	ColorMagenta
	ColorCyan
	ColorWhite
	ColorReset = 0
)

// color escape helpers, one function per color so call sites are readable
func ColorCode(color ColorAttribute) string { return fmt.Sprintf("\x1b[%dm", color) }
func BlackColor() string                    { return ColorCode(ColorBlack) }
func RedColor() string                      { return ColorCode(ColorRed) }
func GreenColor() string                    { return ColorCode(ColorGreen) }
func YellowColor() string                   { return ColorCode(ColorYellow) }
func BlueColor() string                     { return ColorCode(ColorBlue) }
func MagentaColor() string                  { return ColorCode(ColorMagenta) }
func CyanColor() string                     { return ColorCode(ColorCyan) }
func WhiteColor() string                    { return ColorCode(ColorWhite) }
func ResetColor() string                    { return ColorCode(ColorReset) }

// styled text helpers, used in log output and the dashboard
func StyleText(text string, color ColorAttribute) string {
	return ColorCode(color) + text + ResetColor()
}

func StyleSuccess(text string) string { return StyleText("[ok] "+text, ColorGreen) }
func StyleError(text string) string   { return StyleText("[err] "+text, ColorRed) }
func StyleWarning(text string) string { return StyleText("[!] "+text, ColorYellow) }
func StyleInfo(text string) string    { return StyleText("[i] "+text, ColorBlue) }
func StyleHeader(text string) string  { return StyleText(text, ColorCyan) }

// logger wraps leveled output with timestamps and colors
// var (
// 	lastStatsHeight int  = 0
// 	isQuietMode     bool = false
// )

// clearScreen clears the terminal screen
func clearScreen() {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	} else {
		fmt.Print("\033[2J\033[H")
	}
}

// formatBytes formats byte count in human readable format
func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// formatNumber formats numbers with commas
func formatNumber(n uint64) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}

	var result []string
	for i := len(s); i > 0; i -= 3 {
		start := i - 3
		if start < 0 {
			start = 0
		}
		result = append([]string{s[start:i]}, result...)
	}
	return strings.Join(result, ",")
}

// headerString returns the sexy art header (the demon skull banner).
func headerString() string {
	const demonicBehavior string = `


					⠀⠀⠀⠀⢀⡴⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡀⠀⠀⠀
					⠀⠀⠀⠀⡌⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠀⠤⠤⠄⠠⠀⠀⠀⠀⠠⠤⠄⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⠱⠀⠀⠀
					⠀⠀⠀⣘⠀⠆⠀⠀⠀⠀⠀⠀⠀⢀⠠⠐⠂⠉⠀⠀⠀⠀⠀⡔⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠐⠠⢄⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⢣⠀⠀
					⠀⠀⠀⠿⠀⠂⠀⠀⠀⠀⢀⠄⠊⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠑⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠂⠄⡀⠀⠀⠀⠀⠀⠁⡆⡄⠀
					⠀⠀⠸⡆⠀⡇⠀⠀⡠⠂⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠢⡀⠀⠀⢸⠀⢡⢃⠀
					⠀⠀⡀⡇⠀⢃⢀⠌⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⡅⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠢⡀⠙⠀⢸⠸⠀
					⠀⠀⡃⡇⠀⠸⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡼⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠇⠀⣸⢸⠀
					⠀⠀⡇⣇⠀⠀⢆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡌⠀⠀⠘⠢⡀⢀⡠⠤⢄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠁⠀⣿⠐⠀
					⠀⠀⡇⢻⡀⠀⠈⢆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣜⠁⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠲⠀⠀⠀⠀⠀⠀⠀⠀⣰⠁⠀⢰⡿⢰⠀
					⠀⠀⡃⢸⣧⠀⠀⡌⠳⡀⠀⠀⠀⠀⣀⡀⢀⡆⠈⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠄⡠⢄⢀⡼⢁⠀⢀⣾⡇⡌⠀
					⠀⢀⢳⠀⣿⣆⠀⠸⣆⠙⢷⠲⣤⣋⠀⠈⠍⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠄⢒⣩⠴⡶⠋⢠⡇⠀⣼⣿⠀⣇⠀
					⠀⠎⣿⡆⠸⣿⣷⣴⣿⣷⣌⡀⠀⠀⠀⠀⠘⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡨⠆⠀⠀⠀⠀⢀⣴⣿⣷⣾⣿⡇⢠⣿⡄
					⢀⠰⠿⣷⠀⢻⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠉⢢⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⡤⠊⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⣿⡟⠀⣾⡿⡀
					⠸⠀⠀⠈⢣⠈⢿⣿⣿⠟⠁⠀⢀⠀⠀⠀⠀⠀⠀⠑⠒⢏⠀⠀⠀⠀⠀⠀⠀⠀⢀⠤⠙⠀⠀⠀⠀⠀⠀⡀⠈⢿⣿⣿⡿⠁⡜⠁⠀⠁
					⠀⠀⠀⢀⠀⠁⠘⠛⠁⠀⣀⣠⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠑⢄⣀⣀⢰⠀⠒⠂⠃⠀⠀⠀⠀⠀⠀⠀⢰⣿⠀⠀⠛⠿⠧⠀⠀⠀⠀⠀
					⠀⠀⠀⡌⠀⠀⠀⠀⠀⠀⠙⢿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡿⠷⠒⠀⠀⠀⠀⠀⡆⠀⡀
					⠀⢡⠀⠸⡆⠀⠀⠀⠀⠀⠀⠀⠈⠛⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠔⠁⠀⠀⠀⠀⠀⠀⠀⣰⠁⠀⠀
					⠀⠈⡄⠀⢹⡄⠀⢠⢶⣿⣶⣤⡀⠀⠀⠀⠀⠠⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠗⠂⠀⠀⠀⢀⣠⣴⣶⣦⠀⠀⢰⡏⠀⠄⠀
					⠀⠀⠙⠈⢻⣧⠀⠈⠘⣿⣿⠓⠛⣒⡀⠀⠀⠀⠈⠑⠄⡀⠀⠀⠀⠀⠀⠀⠀⢀⡠⠊⠀⠀⠀⠀⢀⡐⠛⠻⣿⣿⠉⠃⠀⣿⡖⢨⠀⠀
					⠀⠀⠀⠇⠀⡟⠀⠀⠀⢿⣿⡀⠀⠿⣿⠗⢤⡀⠀⠀⠀⠈⢆⠀⠀⠀⠀⠀⣰⠋⠀⠀⠀⢀⡄⢴⣿⡿⠀⢀⣿⡟⠀⠀⠀⣿⠁⡎⠀⠀
					⠀⠀⠀⠰⣰⠃⠀⠀⢰⠘⣿⣷⣀⠀⠉⠀⢘⣷⣶⡄⠀⠀⠘⣦⣀⣀⣀⣴⠋⠀⠀⢠⣴⣜⠇⠈⠉⠁⢀⣼⣿⠃⡄⠀⠀⢻⡀⠁⠀⠀
					⠀⠀⢀⠜⠁⠀⠀⠀⠿⢆⡈⠛⠿⢿⣶⣿⣿⣿⣿⣿⡄⠀⠀⠈⢻⣿⡿⠁⠀⠀⢠⣿⣿⣿⣿⣶⣶⣾⡿⠟⠁⣰⠇⠀⠀⠀⠙⣄⠀⠀
					⠀⠀⡊⠀⠀⠀⠀⠀⠀⠀⠙⠒⠒⠒⠀⠀⠀⠀⠠⢉⣉⣂⡀⠀⠀⣻⠀⠀⢀⠐⢋⠁⠀⠀⠀⠀⠀⠠⠄⠒⠊⠁⠀⠀⠀⠀⠀⠈⡆⠀
					⠀⠀⠣⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⢻⡞⠁⣶⠚⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠇⠀
					⠀⠀⠀⠈⠐⠂⢄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢣⢀⡌⠀⠀⠀⠀⠀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠄⠒⠁⠀⠀
					⠀⠀⠀⠀⠀⠀⠀⢰⡋⠘⢻⡍⠉⡗⢤⠴⠞⢶⣤⡀⠀⠀⠀⢠⣿⣿⣿⡄⠀⠀⠀⢸⠃⡶⠶⣤⡤⠖⠛⢲⠢⠒⢶⠉⠀⠀⠀⠀⠀⠀
					⠀⠀⠀⠀⠀⠀⠀⠈⢃⠀⢺⠇⠀⡇⢀⠀⠀⠈⡝⠀⠀⠀⢠⣿⣟⠀⣿⣿⡀⠀⠀⠀⠂⠀⠀⢀⠀⣧⠀⢿⠆⠀⡘⠀⠀⠀⠀⠀⠀⠀⠀
					⠀⠀⠀⠀⠀⠀⠀⠀⠈⠆⠀⠃⢰⠇⠉⢀⠆⠰⢠⠁⠀⠀⠘⠿⣏⢀⢿⠿⠃⠀⠀⠀⡀⠀⢀⠀⡆⢿⠀⠈⠀⡘⠀⠀⠀⠀⠀⠀⠀⠀
					⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⢸ ⡀⠹⢠⡆⣼⠀⠀⣤⠀⠀⢻⠠⠁⠀⠀⡄⠀⠰⡇⢣⡨⠁⢂⣼⠀⠀⢠⠃⠀⠀⠀⠀⠀⠀⠀⠀
					⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡆⠀⢸  ⡀⠀⠈⡇⠀⢰⣇⠀⠃⠀⣤⠀⢠⠀⣱⠂⠀⡏⠹⠀⢀ ⠀⠀⡎⠀⠀⠀⠀⠀⠀⠀⠀⠀
					⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠗⠀⠈   ⡀⠀⠁⠀⠸⠁⠸⡖⠐⡿⠀⢾⠀⢹⠀⠀⠀⠀  ⠙⠁⠀⠀⢨⠄⠀⠀⠀⠀⠀⠀⠀⠀
					⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠀⠀⠀⠘      ⠀⢰⠀⠀⠀⠀⠃⠀⠘⢠⠀⠀    ⠙⠁⠀⠀⢨⠄⠀⠀⠀⠀⠀⠀⠀⠀
					⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠢⡀⠀⠀⢀⡔                   ⣀⠄⠀⠀⢀⠎⠀⠀⠀⠀⠀⠀⠀⠀⠀
					⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠢⢀⠀⢅⡔                  ⣄⠉⠀⡠⠔⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
					⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠂⡀⠗⢴⠺              ⢳⡄⠃⡠⠊⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
					⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠢⡘⠀⢦⠈        ⠀⡆⠘⢠⠌⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
					⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⣄⠈⠘⡇⢠⣇⠀⡀⠀⣦⠀⠞⠘⢀⡔⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
					⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⡆⠀⠀⠀⠆⠈⡇⠀⠇⠀⠁⠀⠎⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
					⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠄⠀⠀⠀⠀⡄⠀⠀⠀⠀⡜⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
							     ⠈ ⠂⠤⠤⠤⠒ ⠁
																			
                            		             HTTP Stress Testing Tool v3.0
`
	return demonicBehavior
}

// printHeader prints the art header to stdout (used for the static intro/report screens).
func printHeader() { fmt.Print(headerString()) }

// printSeparator prints a centered section title. no box-drawing rule characters
// (the old heavy horizontal walls), just a centered label with breathing room.
func printSeparator(title string) {
	width := 120
	padding := (width - len(title)) / 2
	if padding < 0 {
		padding = 0
	}
	fmt.Printf("\n%*s%s\n\n", padding, "", title)
}

// computeImpact turns the attack traffic's own observed behaviour into a 0-100
// impact score. it is the single source of truth for the dashboard's
// "Effectiveness" / "Impact Level", kept pure and testable on purpose: the old
// inline version scored raw volume (30 points just for sending >=1000 requests)
// plus a stale health-probe value, which is exactly how a run that buried the
// target in 25-second timeouts at 0% success came out as "low / target up".
//
//   - responding==0 && successful>0 -> a control-confirmed kill (we reached it,
//     then it went dark while Google/Cloudflare stayed up). full marks.
//   - otherwise the score is driven by latencyDegr (how badly the target is
//     crawling, from the round-trip histogram), scaled by a sample-size confidence
//     ramp so a handful of slow requests can't spike it.
//
// note that volume is deliberately NOT a term: sending a million requests a target
// absorbs at 50ms is not impact, and one that pins it at 25s is, regardless of count.
func computeImpact(attempts, successful, responding uint64, latencyDegr float64) float64 {
	if responding == 0 && successful > 0 {
		return 100
	}
	conf := math.Min(float64(attempts)/500.0, 1.0)
	return math.Min(100*latencyDegr*conf, 100.0)
}

// renderFrame draws ONE in-place dashboard frame as a single buffered write: cursor
// home (no \033[2J full-clear, which is what flickers), each line erased to its end
// (\033[K, so a shorter line can't leave stale tail characters), and the screen
// cleared below the frame (\033[J). building the whole frame, banner + stats, in
// one strings.Builder and writing it once is exactly how a smooth TUI (or the donut
// renderer) repaints without flicker or half-drawn frames. the previous code did a
// full clear, re-emitted the giant banner, and fired ~25 separate Printf calls every
// tick, so the terminal showed blank/partial frames and any concurrent log line
// shoved it around.
func renderFrame(targetURL string, attackType uint8) {
	var stats strings.Builder
	writeStatsTable(&stats, targetURL, attackType)
	statsStr := strings.TrimRight(stats.String(), "\n")

	// only include the tall skull banner if the WHOLE frame comfortably fits the
	// terminal. otherwise it's taller than the window, so each repaint scrolls and
	// the frames pile up on top of each other, that's the garbled "stats on the
	// left, skull bleeding down the right" mess. when it won't fit we drop to a
	// one-line title so the live panel stays put and repaints cleanly in place. the
	// full skull still shows on the static intro and the final report.
	_, rows := terminalSize()
	frame := composeFrame(headerString(), statsStr, rows)
	io.WriteString(os.Stdout, frame)
}

// composeFrame builds the bytes for one in-place repaint: cursor-home, the body with
// each line erased to its end, then erase-below. the body is the skull banner + stats
// when the whole thing fits in `rows`, or a one-line title + stats when it doesn't
// (rows == 0 means "unknown", e.g. piped output, include the banner). kept pure so
// the fit decision is unit-testable without a real terminal.
func composeFrame(banner, statsStr string, rows int) string {
	statsStr = strings.TrimRight(statsStr, "\n")
	bannerLines := strings.Count(banner, "\n") + 1
	statsLines := strings.Count(statsStr, "\n") + 1

	var body string
	if rows == 0 || bannerLines+statsLines+1 <= rows {
		body = banner + statsStr
	} else {
		// banner won't fit, drop it entirely. no fallback title line: the stats
		// block already opens with a centered "LIVE DASHBOARD" header, and repeating
		// the tool name here just duplicated the banner's last line.
		body = statsStr
	}

	var out strings.Builder
	out.WriteString("\033[H") // home the cursor, overwrite in place, don't clear
	for _, line := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
		out.WriteString(line)
		out.WriteString("\033[K\n") // wipe any leftover tail from a longer previous frame
	}
	out.WriteString("\033[J") // erase everything below the frame
	return out.String()
}

// terminalSize returns the terminal's column/row count, or (0,0) if it can't be
// determined (e.g. output is piped to a file). callers treat 0 as "unknown" and
// fall back to rendering everything.
func terminalSize() (cols, rows int) {
	if c, r, err := term.GetSize(int(os.Stdout.Fd())); err == nil && r > 0 {
		return c, r
	}
	return 0, 0
}

// hideCursor / showCursor bracket the animation so the blinking caret doesn't jump
// around the redraw region. showCursor MUST run on every exit path or the user is
// left with an invisible cursor at their shell prompt.
func hideCursor() { fmt.Print("\033[?25l") }
func showCursor() { fmt.Print("\033[?25h") }

// writeStatsTable renders the live dashboard into w. it writes to an io.Writer (not
// straight to stdout) so renderFrame can buffer the entire frame and flush it in a
// single write, see renderFrame for why that matters.
func writeStatsTable(w io.Writer, targetURL string, attackType uint8) {
	// Get current stats
	successful := atomic.LoadUint64(&successfulHits)
	failed := failedRequests.Load()
	bytesSent := atomic.LoadUint64(&totalBytesSent)
	responding := atomic.LoadUint64(&targetResponding)
	responseTime := atomic.LoadUint64(&lastResponseTime)
	healthChecks := atomic.LoadUint64(&healthCheckCount)
	okChecks := atomic.LoadUint64(&targetOKChecks)
	congChecks := atomic.LoadUint64(&congestionChecks)
	congestion := atomic.LoadUint64(&localCongestion)
	slowloris := atomic.LoadUint64(&slowlorisActive)

	// total requests/packets attempted across all workers, the honest denominator
	// for both success rate and the volume metric. NOT totalConnections, which counts
	// dispatched jobs: one job can fan out to 100 HTTP/2 streams or hundreds of UDP
	// packets, so mixing that per-job count with the per-request success/failure
	// counters produced nonsense like a 470587% success rate.
	attempts := successful + failed
	var successRate float64 = 0
	if attempts > 0 {
		successRate = float64(successful) / float64(attempts) * 100
	}

	// uptime = target availability among checks we could actually measure. checks
	// lost to local congestion are excluded, they're our saturated uplink's fault,
	// not the target's, so they count as neither up nor down.
	var uptime float64 = 100
	if measurable := healthChecks - congChecks; measurable > 0 {
		uptime = float64(okChecks) / float64(measurable) * 100
	}

	// latencyDegr (0-1) is the heart of the honest impact metric: how badly the
	// target is crawling under our load, measured from the attack traffic's OWN
	// round-trip times rather than a separate probe or a raw volume count. timeouts
	// are recorded at full duration so they land in the slow tail; a fast 403/429
	// (target cheaply rejecting us, not impact) stays in the low buckets and is
	// excluded. severe (>5s) responses are double-counted so a flood that pins the
	// target at multi-second latency reads as strong impact even before full
	// timeouts. see metrics.go shareSlowerThan.
	lat := demonStats.aggregateSnapshot()
	slowShare := lat.shareSlowerThan(1000)   // fraction of round-trips over 1s
	severeShare := lat.shareSlowerThan(5000) // fraction over 5s (timing out / near-dead)
	latencyDegr := math.Min(slowShare+severeShare, 1.0)

	status := "[up]    "
	statusColor := ""
	switch {
	case responding == 0:
		// health monitor confirmed a hard down: target unreachable while known-good
		// control hosts stayed up. the strongest, least-ambiguous signal, show it first.
		status = "[down]  "
		statusColor = "\033[31m"
	case congestion == 1:
		// our own uplink is saturated, so we can't independently attribute the
		// degradation to the target vs our link. say what's actually happening
		// (uplink maxed) instead of the old cryptic "[your link]". magenta to stand
		// apart from a real red "down". the impact line + caveat below carry the detail.
		status = "[uplink maxed]"
		statusColor = "\033[35m"
	case latencyDegr >= 0.5:
		// the target is crawling under our traffic, over half our round-trips are
		// slow, and control hosts are fine, so this is the target, not our link.
		status = "[degraded]"
		statusColor = "\033[33m"
	case uptime < 80:
		status = "[slow]  "
		statusColor = "\033[33m"
	default:
		statusColor = "\033[32m"
	}

	attackTypes := []string{
		"Volume Attack", "Slowloris", "HTTP/2 Flood", "Cache Busting",
		"API Fuzzing", "WAF Bypass", "Protocol Exploits", "Bandwidth Saturation",
		"Connection Exhaustion", "Resource Exhaustion", "UDP Flood",
		
	}

	currentAttack := "Unknown"
	if int(attackType) < len(attackTypes) {
		currentAttack = attackTypes[attackType]
	}
	// in tag-team mode the single attackType label is misleading, show the
	// whole pool so the header matches the per-type breakdown printed below.
	if len(hybridAttackTypes) > 1 {
		parts := make([]string, 0, len(hybridAttackTypes))
		for _, t := range hybridAttackTypes {
			parts = append(parts, fmt.Sprintf("%d", t))
		}
		currentAttack = "Tag-team " + strings.Join(parts, ",")
	}

	// Print main stats table
	fmt.Fprintf(w, "                                                          LIVE DASHBOARD                                                \n")
	fmt.Fprintf(w, "%s", truncateString(targetURL, 85))
	fmt.Fprintf(w, " Attack: %-20s │ Status: %s%-20s\033[0m │ Uptime: %6.1f%%              \n",
		currentAttack, statusColor, status, uptime)

	// Performance metrics
	fmt.Fprintf(w, " PERFORMANCE METRICS                                                                                              \n")
	fmt.Fprintf(w, " Total Requests:    %12s │ Successful: %12s │ Failed: %12s │ Success Rate: %6.1f%% \n",
		formatNumber(attempts), formatNumber(successful), formatNumber(failed), successRate)
	fmt.Fprintf(w, " Data Transmitted:  %12s │ Response Time: %8dms │ Health Checks: %8s                     \n",
		formatBytes(bytesSent), responseTime, formatNumber(healthChecks))

	// when the attack saturates our OWN uplink, the health monitor (which shares it)
	// can't reach the target OR known-good control hosts. that does NOT mean "no
	// impact", our traffic may still be hammering the target, it means we can't
	// independently attribute the degradation to the target vs our own link. say
	// exactly that, and point at the two ways to disambiguate.
	if congestion == 1 {
		fmt.Fprintf(w, " [!] YOUR UPLINK IS SATURATED — even Google/Cloudflare are unreachable from here, so the degradation above may be partly local, not the target (%s checks inconclusive)\n",
			formatNumber(congChecks))
		fmt.Fprintf(w, "     to measure the target cleanly: cap output with -bandwidth <your-uplink> (e.g. -bandwidth 40mbit) or spread load across machines (fleet.sh)\n")
	}

	// latency section. for a single-type run we show one aggregate LATENCY row.
	// in tag-team mode (more than one type in hybridAttackTypes) that single row
	// would only reflect hybridAttackTypes[0], hiding the other types entirely,
	// so we print one row per type instead. the per-type histograms are already
	// collected in demonStats by every worker (worker.go records by actual type),
	// this just surfaces data that was being thrown away on the display side.
	if len(hybridAttackTypes) > 1 {
		fmt.Fprintf(w, "  PER-TYPE LATENCY (tag-team)\n")
		for _, t := range hybridAttackTypes {
			snap := demonStats.snapshot(t)
			if snap.requests == 0 {
				continue // type hasn't produced a recordable round-trip yet
			}
			label := "?"
			if int(t) < len(attackTypes) {
				label = attackTypes[t]
			}
			fmt.Fprintf(w, "  [%d] %-22s reqs:%-11s err:%-10s avg:%4.0fms  p95:%5dms  max:%6dms\n",
				t, label, formatNumber(snap.requests), formatNumber(snap.errors),
				snap.avgLatencyMs, snap.percentileMs(0.95), snap.maxLatencyMs)
		}
	} else {
		// latency histogram row, only shown once we have at least one sample so
		// the row doesn't appear as all-zeros during the first second of a run.
		latSnap := demonStats.snapshot(attackType)
		if latSnap.requests > 0 {
			p50 := latSnap.percentileMs(0.50)
			p95 := latSnap.percentileMs(0.95)
			p99 := latSnap.percentileMs(0.99)
			fmt.Fprintf(w, " LATENCY              avg: %6.0fms │ p50: %5dms │ p95: %5dms │ p99: %5dms │ max: %5dms \n",
				latSnap.avgLatencyMs, p50, p95, p99, latSnap.maxLatencyMs)
		}
	}

	// Overall Attack Effectiveness, grounded in what the attack traffic actually
	// measured, NOT in raw volume. the previous model handed out 30 points just for
	// sending >=1000 requests and read responsiveness off a stale health probe, so a
	// run that buried the target in 25-second timeouts (0% success) still scored
	// "low / target up". impact is now driven by latencyDegr (computed above from the
	// round-trip histogram), which already separates real saturation (slow timeouts)
	// from a target cheaply rejecting us (fast 4xx, not impact).
	overallEffectiveness := computeImpact(attempts, successful, responding, latencyDegr)

	// Status determination based on effectiveness. labels describe what's happening
	// to the target ("severe/high" = it's buckling), green->red tracks the operator's
	// view of a stress test (high impact is the goal, so it's green).
	var effectivenessColor, effectivenessStatus string
	if overallEffectiveness >= 75 {
		effectivenessColor = "\033[32m"
		effectivenessStatus = "severe"
	} else if overallEffectiveness >= 50 {
		effectivenessColor = "\033[32m"
		effectivenessStatus = "high"
	} else if overallEffectiveness >= 30 {
		effectivenessColor = "\033[33m"
		effectivenessStatus = "moderate"
	} else if overallEffectiveness >= 15 {
		effectivenessColor = "\033[35m"
		effectivenessStatus = "low"
	} else {
		effectivenessColor = "\033[31m"
		effectivenessStatus = "minimal"
	}

	fmt.Fprintf(w, " EFFECTIVENESS                                                                                                   \n")

	// Target health, must stay consistent with the impact line above and the
	// congestion banner. the old code reported a flat "[up]" off a held probe value
	// even while the dashboard screamed 0% success / 25s latency. now it reflects
	// what we actually observe: confirmed down > degraded (target crawling) >
	// unknown (we can't see it, uplink maxed) > slow > up.
	var targetHealth string
	switch {
	case responding == 0:
		targetHealth = "[down]     "
	case latencyDegr >= 0.5:
		targetHealth = "[degraded] "
	case congestion == 1:
		targetHealth = "[unknown]  "
	case lat.avgLatencyMs > 2000:
		targetHealth = "[slow]     "
	default:
		targetHealth = "[up]       "
	}

	fmt.Fprintf(w, " Status: %s%-15s\033[0m │ Effectiveness: %6.1f%% │ Target Health: %s │ Impact Level: %s%-12s\033[0m \n",
		effectivenessColor, effectivenessStatus, overallEffectiveness,
		targetHealth, effectivenessColor, effectivenessStatus)

	// Rate limiting detection status
	if rateLimitDetector != nil {
		stats := rateLimitDetector.GetStatistics()
		var detections, bypasses int

		if val, ok := stats["limit_detections"]; ok && val != nil {
			switch v := val.(type) {
			case float64:
				detections = int(v)
			case uint64:
				detections = int(v)
			case int:
				detections = v
			}
		}
		if val, ok := stats["successful_bypasses"]; ok && val != nil {
			switch v := val.(type) {
			case float64:
				bypasses = int(v)
			case uint64:
				bypasses = int(v)
			case int:
				bypasses = v
			}
		}

		var rlStatus string
		var rlColor string

		if detections == 0 {
			rlStatus = "NOT DETECTED"
			rlColor = "\033[32m" // Green
		} else if bypasses > detections/2 {
			rlStatus = "DETECTED - BYPASSING"
			rlColor = "\033[33m" // Yellow
		} else {
			rlStatus = "DETECTED - SITE WINNING"
			rlColor = "\033[31m" // Red
		}

		fmt.Fprintf(w, " RATE LIMITING                                                                                                   \n")
		fmt.Fprintf(w, " Status: %s%-25s\033[0m │ Detections: %8d │ Bypasses: %8d │ Bypass Rate: %6.1f%% \n",
			rlColor, rlStatus, detections, bypasses, float64(bypasses)/math.Max(float64(detections), 1)*100)
	}

	// connection-hold attacks (types 1/6/8) don't complete requests, so they never
	// appear in the per-request latency table, this gauge is how they're made
	// visible, in both single and tag-team mode. it shows the live held-connection
	// count per type, plus any hold dispatches skipped because the held-connection
	// cap (maxHeldConnections) was hit.
	protoHold := atomic.LoadUint64(&protocolExploitActive)
	connHold := atomic.LoadUint64(&connExhaustActive)
	heldSkipped := atomic.LoadUint64(&heldConnSkipped)
	if slowloris+protoHold+connHold > 0 || heldSkipped > 0 {
		fmt.Fprintf(w, "  HELD CONNECTIONS    slowloris:%-8s slow-POST:%-8s conn-exhaust:%-8s capped:%s\n",
			formatNumber(slowloris), formatNumber(protoHold), formatNumber(connHold), formatNumber(heldSkipped))
	}

	// compression bomb (type 7) landing signal, shown whenever any bomb has been
	// sent (single-type or as part of a tag-team pool). "landing rate" is the share
	// of bombs the target accepted into its pipeline rather than rejecting on
	// size/format at the edge. a low rate means the bomb is being dropped before it
	// can cost the server anything, exactly the "uncertain impact" the README warns
	// about, now visible instead of guessed at.
	bombAcc := atomic.LoadUint64(&compressionAccepted)
	bombRej := atomic.LoadUint64(&compressionRejected)
	if bombAcc+bombRej > 0 {
		landRate := float64(bombAcc) / float64(bombAcc+bombRej) * 100
		fmt.Fprintf(w, "  COMPRESSION BOMB    accepted:%-11s rejected:%-11s landing rate:%5.1f%%\n",
			formatNumber(bombAcc), formatNumber(bombRej), landRate)
	}

	// resource exhaustion (type 9) burn signal, share of responses slow enough to
	// suggest the payload made the server do real work rather than being parsed
	// cheaply or rejected. a high burn rate (or high p95 in the per-type table) is
	// the closest we get to confirming type 9 is landing on this target.
	burnDone := atomic.LoadUint64(&resourceCompleted)
	if burnDone > 0 {
		burn := atomic.LoadUint64(&resourceBurnHits)
		burnRate := float64(burn) / float64(burnDone) * 100
		fmt.Fprintf(w, "  RESOURCE BURN       slow(>%dms):%-9s of %-11s responses  burn rate:%5.1f%%\n",
			resourceBurnThresholdMs, formatNumber(burn), formatNumber(burnDone), burnRate)
	}

	// Real-time activity indicator
	spinner := []string{"-", "\\", "|", "/"}
	currentTime := time.Now().Unix()
	spinnerChar := spinner[currentTime%int64(len(spinner))]

	// Get latest request details for live activity display
	requestTrackingMux.RLock()
	latestURL := lastRequestURL
	latestReqSize := lastRequestSize
	latestRespSize := lastResponseSize
	latestRespCode := lastResponseCode
	latestProto := lastRequestProto
	requestTrackingMux.RUnlock()

	fmt.Fprintf(w, " %s LIVE ACTIVITY - %s                                                                               \n",
		spinnerChar, time.Now().Format("15:04:05"))

	// Show rate limiting diagnostics if workers are blocked
	waitingWorkers := atomic.LoadUint64(&workersWaitingOnRate)
	if waitingWorkers > 0 {
		fmt.Fprintf(w, " [!] rate limiter bottleneck: %d workers waiting for rate limiter permission                               \n", waitingWorkers)
	}

	// Show latest request in-place instead of spamming console
	if latestURL != "" {
		truncatedURL := truncateString(latestURL, 70)
		fmt.Fprintf(w, " Latest: [%s] %s -> %d bytes, Status: %d, Response: %d bytes              \n",
			latestProto, truncatedURL, latestReqSize, latestRespCode, latestRespSize)
	} else {
		fmt.Fprintf(w, " Latest: Waiting for first request...                                                                        \n")
	}
}

// truncateString truncates a string to specified length with ellipsis
func truncateString(s string, length int) string {
	if len(s) <= length {
		return s
	}
	if length < 3 {
		return s[:length]
	}
	return s[:length-3] + "..."
}

// printEffectivenessReport summarises health check results after the run
func printEffectivenessReport() {
	healthChecks := atomic.LoadUint64(&healthCheckCount)
	okChecks := atomic.LoadUint64(&targetOKChecks)
	congChecks := atomic.LoadUint64(&congestionChecks)
	responding := atomic.LoadUint64(&targetResponding)
	successful := atomic.LoadUint64(&successfulHits)
	failed := failedRequests.Load()
	genuineFails := healthChecks - okChecks - congChecks // target failed while control hosts stayed up

	if healthChecks == 0 {
		return
	}

	// what the attack traffic ITSELF observed, the most direct evidence of impact,
	// independent of the health probe. timeouts land in the slow tail, fast 4xx
	// (target cheaply rejecting us) don't, so a high latencyDegr means real
	// saturation. this is the signal the old report ignored, which is how a run that
	// buried the target in 25s timeouts came out as "couldn't measure / target up".
	lat := demonStats.aggregateSnapshot()
	attempts := successful + failed
	var failRate float64
	if attempts > 0 {
		failRate = float64(failed) / float64(attempts) * 100
	}
	latencyDegr := math.Min(lat.shareSlowerThan(1000)+lat.shareSlowerThan(5000), 1.0)
	severeShare := lat.shareSlowerThan(5000)
	degraded := attempts >= 200 && latencyDegr >= 0.4 // enough samples AND a real slowdown
	mostlyMeasurable := congChecks*2 < healthChecks   // controls were up for most of the run

	fmt.Printf("                                                      EFFECTIVENESS REPORT                                              \n")

	switch {
	case responding == 0 && successful > 0:
		// confirmed kill: we reached the target earlier, control hosts are still up,
		// and now the target won't answer. unambiguous and attributable.
		downTime := time.Now().Unix() - int64(atomic.LoadUint64(&targetDownTime))
		fmt.Printf(" target: DOWN — unreachable while Google/Cloudflare stayed up (a genuine, attributable target failure)\n")
		fmt.Printf(" down for %ds; your traffic saw %.1f%% failures at avg %.0fms latency before it dropped\n",
			downTime, failRate, lat.avgLatencyMs)
	case degraded && mostlyMeasurable:
		// heavy degradation AND we could measure for most of the run -> the target is
		// crawling under our load and it's attributable to the target, not our link.
		fmt.Printf(" target: DEGRADED — buckling under load, attributable to the target (control hosts stayed reachable)\n")
		fmt.Printf(" your traffic saw %.1f%% failures, avg %.0fms latency, %.0f%% of round-trips over 5s\n",
			failRate, lat.avgLatencyMs, severeShare*100)
	case degraded:
		// heavy degradation AND our uplink was saturated a lot of the run. the impact
		// is real and the target is taking load, congestion only blurs HOW MUCH is the
		// target vs our own link, it does not mean the target was untouched. word it
		// that way so we don't undersell a hit we genuinely landed.
		fmt.Printf(" target: DEGRADED — your traffic saw %.1f%% failures at avg %.0fms latency; the target is under heavy load and was effectively unreachable from this machine\n",
			failRate, lat.avgLatencyMs)
		fmt.Printf(" NOTE: your uplink was also saturated (%d/%d checks inconclusive), so the tool can't measure how much of the slowdown is the target vs your own link — both are real, the split is just unknown\n",
			congChecks, healthChecks)
		fmt.Printf("       to quantify the target's share, cap -bandwidth to your uplink (so your link stops being a bottleneck) or spread load with fleet.sh\n")
	case congChecks > 0 && okChecks == 0 && genuineFails == 0:
		// uplink saturated the whole run AND the traffic showed no clear degradation,
		// we genuinely never got a reading. don't claim up OR down.
		fmt.Printf(" target: UNKNOWN — your uplink was saturated for the whole run; target health could not be measured\n")
		fmt.Printf(" (a local bottleneck, not necessarily the target going down — cap -bandwidth to measure cleanly)\n")
	case responding == 0:
		// control hosts up, target unreachable, but we never had a confirmed hit, more
		// likely the target blackholed our IP than that we took it down.
		downTime := time.Now().Unix() - int64(atomic.LoadUint64(&targetDownTime))
		fmt.Printf(" target: UNREACHABLE — control hosts stayed up but we never landed a clean hit (likely an IP block, not a takedown)\n")
		fmt.Printf(" unreachable for %ds\n", downTime)
	default:
		uptime := 100.0
		if measurable := healthChecks - congChecks; measurable > 0 {
			uptime = float64(okChecks) / float64(measurable) * 100
		}
		// don't print "UP" while uptime is low or latency is elevated, that's the
		// self-contradiction ("target: UP (0.0% uptime)") this whole pass is about.
		if uptime >= 80 && latencyDegr < 0.2 && failRate < 50 {
			fmt.Printf(" target: UP — stable, absorbing your load (%.1f%% uptime over measurable checks)\n", uptime)
		} else {
			fmt.Printf(" target: UNDER LOAD — %.1f%% uptime over measurable checks, avg %.0fms latency, %.1f%% request failures\n",
				uptime, lat.avgLatencyMs, failRate)
		}
	}

	fmt.Printf(" Health Checks: %d performed — %d target-up, %d target-down, %d inconclusive (local congestion)\n",
		healthChecks, okChecks, genuineFails, congChecks)
}

// printPerTypeSummary prints an exact, end-of-run reconciliation of the per-type
// counters. unlike the live dashboard, which samples eventually-consistent atomics
// while thousands of goroutines are still writing, this runs after every worker has
// stopped, so the tally is final and stable rather than approximate. it prints
// nothing if no type recorded a completed round-trip (e.g. a pure connection-hold
// run, where types 1/6/8 never finish a request to record).
func printPerTypeSummary() {
	attackTypes := []string{
		"Volume Attack", "Slowloris", "HTTP/2 Flood", "Cache Busting",
		"API Fuzzing", "WAF Bypass", "Protocol Exploits", "Bandwidth Saturation",
		"Connection Exhaustion", "Resource Exhaustion", "UDP Flood",
		
	}

	var active []uint8
	for t := uint8(0); int(t) < numAttackTypes; t++ {
		if demonStats.snapshot(t).requests > 0 {
			active = append(active, t)
		}
	}
	if len(active) == 0 {
		return
	}

	// no box-drawing rule characters, just a labelled block with blank-line spacing.
	fmt.Printf("\n  PER-TYPE SUMMARY (final, exact)\n\n")
	for _, t := range active {
		s := demonStats.snapshot(t)
		var errRate float64
		if s.requests > 0 {
			errRate = float64(s.errors) / float64(s.requests) * 100
		}
		label := "?"
		if int(t) < len(attackTypes) {
			label = attackTypes[t]
		}
		fmt.Printf("  [%d] %-21s reqs:%-11s err:%-9s(%4.1f%%) avg:%4.0fms p95:%5dms max:%6dms\n",
			t, label, formatNumber(s.requests), formatNumber(s.errors), errRate,
			s.avgLatencyMs, s.percentileMs(0.95), s.maxLatencyMs)
	}
	fmt.Printf("\n")
}

// quietLog logs messages only when not in quiet mode, or for important messages
// func quietLog(format string, args ...interface{}) {
// 	if !isQuietMode {
// 		fmt.Printf(format, args...)
// 	}
// }
