package main

import "sync/atomic"

// latency bucket upper bounds in milliseconds. these mirror the whitgateway
// data plane boundaries (converted from seconds) so runs from both tools
// stay directly comparable.
var latencyBuckets = []int64{5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000}

const numAttackTypes = 11

// perTypeMetrics holds live counters for one attack type.
// every field is a separate atomic so the thousands of worker goroutines
// writing here never block each other. the dashboard reads at 1Hz and can
// tolerate values that were updated at slightly different instants, the
// jitter is sub-millisecond and invisible to a human watching the screen.
type perTypeMetrics struct {
	requests     atomic.Uint64
	errors       atomic.Uint64
	latencySumMs atomic.Int64
	latencyMaxMs atomic.Int64
	// buckets[i] counts requests with latency <= latencyBuckets[i].
	// buckets[11] is the overflow slot for anything above 10 000ms.
	buckets [12]atomic.Uint64
}

// perTypeSnapshot is a read-only copy built for one dashboard refresh cycle.
type perTypeSnapshot struct {
	requests     uint64
	errors       uint64
	avgLatencyMs float64
	maxLatencyMs int64
	buckets      [12]uint64
}

// demonStats is the singleton holding per-attack-type latency histograms.
// it sits alongside the existing atomic globals (totalConnections, etc.) rather
// than replacing them, those live paths stay untouched, and statsStore adds
// the latency dimension that raw counters cannot express.
var demonStats statsStore

type statsStore struct {
	byType [numAttackTypes]perTypeMetrics
}

// record is called after every completed HTTP round trip.
// latencyMs is the full request/response time in milliseconds. success is
// false for anything that didn't produce a usable response, connection
// errors, 4xx, body-read failures, and 429s all count as errors here.
func (s *statsStore) record(attackType uint8, latencyMs int64, success bool) {
	if int(attackType) >= numAttackTypes {
		return
	}
	m := &s.byType[attackType]
	m.requests.Add(1)
	if !success {
		m.errors.Add(1)
	}
	if latencyMs < 0 {
		latencyMs = 0
	}
	m.latencySumMs.Add(latencyMs)
	// CAS loop to track the maximum. contention is rare because only the
	// tail of the latency distribution wins, the loop almost always exits
	// in one iteration.
	for {
		cur := m.latencyMaxMs.Load()
		if latencyMs <= cur {
			break
		}
		if m.latencyMaxMs.CompareAndSwap(cur, latencyMs) {
			break
		}
	}
	// linear scan over 11 entries to place the sample in the right bucket
	for i, bound := range latencyBuckets {
		if latencyMs <= bound {
			m.buckets[i].Add(1)
			return
		}
	}
	m.buckets[len(latencyBuckets)].Add(1) // overflow: >10 000ms
}

// snapshot returns a coherent read of one attack type's metrics.
// all fields are read as a group in one function call, which keeps the
// dashboard from mixing values from two different moments even though
// individual reads are still not transactionally atomic.
func (s *statsStore) snapshot(attackType uint8) perTypeSnapshot {
	if int(attackType) >= numAttackTypes {
		return perTypeSnapshot{}
	}
	m := &s.byType[attackType]
	reqs := m.requests.Load()
	sumMs := m.latencySumMs.Load()
	var avg float64
	if reqs > 0 {
		avg = float64(sumMs) / float64(reqs)
	}
	snap := perTypeSnapshot{
		requests:     reqs,
		errors:       m.errors.Load(),
		avgLatencyMs: avg,
		maxLatencyMs: m.latencyMaxMs.Load(),
	}
	for i := range snap.buckets {
		snap.buckets[i] = m.buckets[i].Load()
	}
	return snap
}

// aggregateSnapshot merges every attack type's metrics into one snapshot. the
// dashboard's impact score reads the attack traffic's OWN latency/error behaviour
// (the most direct measurement of whether the target is crawling under our load),
// and that signal has to span all active types, a tag-team run spreads its
// round-trips across several. summing the per-type atomics here is cheap (11×
// a few loads) and runs once per 1Hz refresh.
func (s *statsStore) aggregateSnapshot() perTypeSnapshot {
	var reqs, errs uint64
	var sumMs, maxMs int64
	var buckets [12]uint64
	for t := 0; t < numAttackTypes; t++ {
		m := &s.byType[t]
		reqs += m.requests.Load()
		errs += m.errors.Load()
		sumMs += m.latencySumMs.Load()
		if mx := m.latencyMaxMs.Load(); mx > maxMs {
			maxMs = mx
		}
		for i := range buckets {
			buckets[i] += m.buckets[i].Load()
		}
	}
	var avg float64
	if reqs > 0 {
		avg = float64(sumMs) / float64(reqs)
	}
	snap := perTypeSnapshot{requests: reqs, errors: errs, avgLatencyMs: avg, maxLatencyMs: maxMs}
	snap.buckets = buckets
	return snap
}

// shareSlowerThan returns the fraction (0-1) of recorded round-trips whose
// latency exceeded thresholdMs. it's the core saturation signal: timeouts are
// recorded at their full duration so they land in the slow tail, while a fast
// 403/429 (the target cheaply rejecting us, NOT impact) stays in the low
// buckets and is correctly excluded. a bucket counts as "slow" when its entire
// range is above the threshold, i.e. its upper bound exceeds thresholdMs; the
// overflow bucket (index == len(latencyBuckets)) is always slow.
func (snap perTypeSnapshot) shareSlowerThan(thresholdMs int64) float64 {
	var total, slow uint64
	for i, c := range snap.buckets {
		total += c
		if i >= len(latencyBuckets) || latencyBuckets[i] > thresholdMs {
			slow += c
		}
	}
	if total == 0 {
		return 0
	}
	return float64(slow) / float64(total)
}

// percentileMs returns the bucket-upper-bound latency at the requested
// percentile (0.0-1.0). we report the upper boundary of the containing bucket,
// which is the conventional conservative overestimate when you don't store
// individual sample values. returns 0 if no requests have been recorded yet.
func (snap perTypeSnapshot) percentileMs(pct float64) int64 {
	var total uint64
	for _, c := range snap.buckets {
		total += c
	}
	if total == 0 {
		return 0
	}
	threshold := uint64(float64(total) * pct)
	var cumulative uint64
	for i, count := range snap.buckets {
		cumulative += count
		if cumulative > threshold {
			if i < len(latencyBuckets) {
				return latencyBuckets[i]
			}
			// overflow bucket: report 2× the last defined boundary
			return latencyBuckets[len(latencyBuckets)-1] * 2
		}
	}
	return latencyBuckets[len(latencyBuckets)-1]
}
