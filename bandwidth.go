package main

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// bwLimiter paces total UDP egress to a byte/sec budget. it exists because a single
// machine cannot send more than its uplink: blasting past line rate just queues and
// drops at our OWN egress (self congestion), kills our health checks, and delivers
// nothing extra to the target. pacing to ~line rate is the difference between
// maximum *effective* output and DoS-ing yourself.
//
// the pointer is installed once at startup before any worker runs, so the plain
// read in paceEgress is race-free. its RATE, however, is adjusted live by
// adaptiveCongestionControl (via the limiter's own internal locking): it's backed
// off when the uplink saturates and ramped back as congestion clears. nil means
// uncapped (paceEgress becomes a no-op).
var bwLimiter *rate.Limiter

// defaultUDPEgressBytesPerSec is the conservative UDP egress cap applied when
// -bandwidth isn't set. UDP is never run truly uncapped, because overshooting your
// own uplink only self-congests; raise -bandwidth to use more of your pipe.
const defaultUDPEgressBytesPerSec = 2 * 1024 * 1024

// setBandwidthLimit installs a byte/sec egress pacer (<=0 disables it). burst is
// kept to ~100ms of budget so pacing stays smooth without stalling, and is always
// at least one max-size packet so WaitN can never exceed the bucket.
func setBandwidthLimit(bytesPerSec int) {
	if bytesPerSec <= 0 {
		bwLimiter = nil
		return
	}
	burst := bytesPerSec / 10
	if burst < 64*1024 {
		burst = 64 * 1024
	}
	bwLimiter = rate.NewLimiter(rate.Limit(bytesPerSec), burst)
}

// paceEgress blocks until n bytes of egress budget are available. it's a no-op when
// uncapped. returns false if ctx is cancelled while waiting, so a sender can bail on
// shutdown instead of finishing a full burst.
func paceEgress(ctx context.Context, n int) bool {
	lim := bwLimiter
	if lim == nil {
		return true
	}
	return lim.WaitN(ctx, n) == nil
}

// parseBandwidth converts a human-readable rate into bytes/sec. accepts bit-rate
// suffixes (bit/kbit/mbit/gbit, and the *bps aliases) and byte suffixes
// (b/kb/mb/gb); a bare number is bytes/sec. "" or "0" means uncapped.
func parseBandwidth(s string) (int, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || s == "0" {
		return 0, nil
	}
	type unit struct {
		suffix string
		mult   float64
		bits   bool
	}
	// most specific suffixes first so "mbit" wins over "m" / "b"
	units := []unit{
		{"gbit", 1e9, true}, {"gbps", 1e9, true},
		{"mbit", 1e6, true}, {"mbps", 1e6, true},
		{"kbit", 1e3, true}, {"kbps", 1e3, true},
		{"gb", 1e9, false}, {"mb", 1e6, false}, {"kb", 1e3, false},
		{"g", 1e9, false}, {"m", 1e6, false}, {"k", 1e3, false},
		{"bit", 1, true},
		{"b", 1, false},
	}
	for _, u := range units {
		if strings.HasSuffix(s, u.suffix) {
			num := strings.TrimSpace(strings.TrimSuffix(s, u.suffix))
			val, err := strconv.ParseFloat(num, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid bandwidth %q: %v", s, err)
			}
			bps := val * u.mult
			if u.bits {
				bps /= 8 // bit rate -> byte rate
			}
			return int(bps), nil
		}
	}
	val, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid bandwidth %q (use forms like 40mbit, 5MB, 500kbit, or a plain bytes/sec number)", s)
	}
	return val, nil
}

// adaptiveCongestionControl auto-throttles the send rate when the health monitor
// reports LOCAL congestion (our own uplink saturated, see monitor.go). classic
// AIMD on a single shared fraction: multiplicative-decrease the moment we're
// self-congesting, additive-increase back toward full once it clears. the fraction
// is applied to BOTH the HTTP request limiter and the UDP egress limiter, so
// whichever one the running attack actually uses gets backed off (the idle one is
// adjusted too but isn't sending, so it has no effect). this keeps a run from
// strangling itself even when -bandwidth isn't set, because overshooting our own
// uplink was never helping the attack anyway, it only hurt this machine.
//
// udpLimiter may be nil (then only the HTTP limiter is managed). httpBaseRate is in
// requests/sec, udpBaseRate in bytes/sec; the fraction scales each against its own
// base so the two different units stay correct.
func adaptiveCongestionControl(ctx context.Context, httpLimiter *rate.Limiter, httpBaseRate float64, udpLimiter *rate.Limiter, udpBaseRate float64, logger *Logger) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	const (
		minFrac = 0.05 // never throttle below 5% of the configured rate
		step    = 0.10 // ramp back up 10% of full per second
	)
	frac := 1.0
	throttled := false

	apply := func() {
		if httpLimiter != nil {
			httpLimiter.SetLimit(rate.Limit(math.Max(1, httpBaseRate*frac)))
		}
		if udpLimiter != nil {
			udpLimiter.SetLimit(rate.Limit(math.Max(1, udpBaseRate*frac)))
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			switch {
			case atomic.LoadUint64(&localCongestion) == 1:
				if frac > minFrac {
					frac = math.Max(minFrac, frac*0.5)
					apply()
					if !throttled {
						logger.Warning(fmt.Sprintf("local uplink saturated — auto-throttling send rate to %.0f%% of configured to relieve self-congestion", frac*100))
						throttled = true
					}
				}
			case frac < 1.0:
				frac = math.Min(1.0, frac+step)
				apply()
				if frac >= 1.0 && throttled {
					logger.Info("congestion cleared — send rate restored to configured value")
					throttled = false
				}
			}
		}
	}
}
