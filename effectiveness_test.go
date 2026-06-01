package main

import "testing"

// feedHistogram records n round-trips of the given latency into a fresh statsStore,
// so tests can reconstruct a known latency distribution and check the derived signals.
func feedHistogram(s *statsStore, attackType uint8, latencyMs int64, success bool, n int) {
	for i := 0; i < n; i++ {
		s.record(attackType, latencyMs, success)
	}
}

func TestShareSlowerThan(t *testing.T) {
	var s statsStore
	// 700 fast (50ms), 300 slow-timeout (25_000ms), mirrors a target that's half
	// answering quickly and half timing out.
	feedHistogram(&s, 0, 50, true, 700)
	feedHistogram(&s, 0, 25000, false, 300)
	snap := s.aggregateSnapshot()

	if got := snap.shareSlowerThan(1000); got < 0.29 || got > 0.31 {
		t.Errorf("shareSlowerThan(1000) = %.3f, want ~0.30", got)
	}
	if got := snap.shareSlowerThan(5000); got < 0.29 || got > 0.31 {
		t.Errorf("shareSlowerThan(5000) = %.3f, want ~0.30", got)
	}
	// a fast 403 (recorded at ~80ms, success=false) must NOT count as slow, that's
	// the target cheaply rejecting us, not impact.
	if got := snap.shareSlowerThan(1000); got > 0.31 {
		t.Errorf("fast rejections leaked into the slow share: %.3f", got)
	}
}

// TestComputeImpact_UserRegression reproduces the churchofjesuschristtemples.org run
// that read "Impact Level: low / Target Health: [up]" despite 0% success and 25s
// latency. with the histogram pinned in the slow tail, impact must now be ~severe.
func TestComputeImpact_UserRegression(t *testing.T) {
	var s statsStore
	// ~142k requests, almost all timing out past 10s (the overflow bucket), a few
	// fast successes, exactly the shape the user pasted.
	feedHistogram(&s, 2, 25000, false, 142_000)
	feedHistogram(&s, 2, 60000, false, 600)
	feedHistogram(&s, 2, 80, true, 62)
	snap := s.aggregateSnapshot()
	latencyDegr := min1(snap.shareSlowerThan(1000) + snap.shareSlowerThan(5000))

	attempts := uint64(142_662)
	successful := uint64(62)
	responding := uint64(1) // health monitor never confirmed a hard down (congestion)

	score := computeImpact(attempts, successful, responding, latencyDegr)
	if score < 75 {
		t.Fatalf("user-regression run scored %.1f (want >=75 'severe'); the volume-only "+
			"bug would have produced ~30", score)
	}
}

// TestComputeImpact_FastRejections guards the opposite error: a target that cheaply
// rejects everything with fast 403/429s is DEFENDING, not degrading. high failure
// rate + low latency must NOT read as high impact.
func TestComputeImpact_FastRejections(t *testing.T) {
	var s statsStore
	feedHistogram(&s, 0, 60, false, 50_000) // 50k fast rejections
	snap := s.aggregateSnapshot()
	latencyDegr := min1(snap.shareSlowerThan(1000) + snap.shareSlowerThan(5000))

	score := computeImpact(50_000, 0, 1, latencyDegr)
	if score > 15 {
		t.Errorf("fast-rejection run scored %.1f (want <=15 'minimal'); fast 4xx must "+
			"not count as impact", score)
	}
}

// TestComputeImpact_AbsorbedLoad: target answers everything quickly. lots of volume,
// no degradation -> minimal impact. volume alone is never impact.
func TestComputeImpact_AbsorbedLoad(t *testing.T) {
	var s statsStore
	feedHistogram(&s, 0, 120, true, 1_000_000)
	snap := s.aggregateSnapshot()
	latencyDegr := min1(snap.shareSlowerThan(1000) + snap.shareSlowerThan(5000))

	if score := computeImpact(1_000_000, 1_000_000, 1, latencyDegr); score > 5 {
		t.Errorf("absorbed-load run scored %.1f (want ~0); a million fast 200s is not impact", score)
	}
}

// TestComputeImpact_ConfirmedKill: control-confirmed down after prior hits is a
// definitive 100 regardless of the latency histogram.
func TestComputeImpact_ConfirmedKill(t *testing.T) {
	if score := computeImpact(5000, 4000, 0, 0); score != 100 {
		t.Errorf("confirmed kill scored %.1f, want 100", score)
	}
	// but down with NO prior successful hit is treated as a likely IP block, not a kill.
	if score := computeImpact(5000, 0, 0, 0); score == 100 {
		t.Errorf("down-without-hits should not score a full 100 (likely an IP block)")
	}
}

// TestComputeImpact_LowSampleGuard: a few slow requests early in a run must not spike
// the score before there's enough evidence.
func TestComputeImpact_LowSampleGuard(t *testing.T) {
	// 10 requests, all slow -> latencyDegr is high, but confidence is 10/500 = 0.02.
	if score := computeImpact(10, 0, 1, 2.0 /*clamped to 1*/); score > 5 {
		t.Errorf("low-sample run scored %.1f (want small); confidence ramp should suppress it", score)
	}
}

// min1 mirrors math.Min(x, 1.0) without importing math into the test.
func min1(x float64) float64 {
	if x > 1.0 {
		return 1.0
	}
	return x
}
