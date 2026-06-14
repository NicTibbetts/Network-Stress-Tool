package main

import (
	"net"
	"testing"
	"time"
)

func TestScoreReflectorCandidateRewardsMeasuredAmplification(t *testing.T) {
	good := reflectorCandidate{Protocol: "dns", ResponseBytes: 600, SuccessCount: 10, FailureCount: 1}
	weak := reflectorCandidate{Protocol: "dns", ResponseBytes: 80, SuccessCount: 3, FailureCount: 1}

	if scoreReflectorCandidate(good) <= scoreReflectorCandidate(weak) {
		t.Fatalf("expected larger replies and reliability to win")
	}
}

func TestSelectReflectorCandidatePrefersHealthyInventory(t *testing.T) {
	candidates := []reflectorCandidate{
		{IP: net.ParseIP("203.0.113.1"), Protocol: "dns", SuccessCount: 0, FailureCount: 5, ResponseBytes: 0, Dead: true},
		{IP: net.ParseIP("203.0.113.2"), Protocol: "dns", SuccessCount: 8, FailureCount: 1, ResponseBytes: 700},
	}

	picked := selectReflectorCandidate(candidates)
	if picked.IP.String() != "203.0.113.2" {
		t.Fatalf("expected the healthy reflector to be selected, got %s", picked.IP)
	}
}

func TestRecordReflectorObservationKeepsMeasuredBytes(t *testing.T) {
	reflectorManager.Reset()

	ip := net.ParseIP("203.0.113.10")
	recordReflectorObservation(ip, "dns", true, 64, 700, "", true)
	recordReflectorObservation(ip, "dns", true, 64, 0, "", false)

	entry := getReflectorTelemetry(ip, "dns")
	if entry.ResponseBytes != 700 {
		t.Fatalf("expected measured bytes to be preserved, got %d", entry.ResponseBytes)
	}
}

func TestRecordReflectorObservationDoesNotTreatLocalSendFailureAsDead(t *testing.T) {
	reflectorManager.Reset()

	ip := net.ParseIP("203.0.113.11")
	recordReflectorObservation(ip, "dns", false, 64, 0, "sendto: no route", false)

	entry := getReflectorTelemetry(ip, "dns")
	if entry.Dead {
		t.Fatal("expected local send failures to stay non-dead for health scoring")
	}
}

func TestReflectorManagerPrunesExpiredCandidates(t *testing.T) {
	mgr := NewReflectorManager()
	mgr.ttl = time.Minute

	stale := net.ParseIP("203.0.113.20")
	mgr.byKey[reflectorKey("dns", stale)] = &reflectorCandidate{
		IP:       stale,
		Protocol: "dns",
		LastSeen: time.Now().Add(-2 * time.Minute),
	}

	pruned := mgr.PruneExpired(time.Now())
	if pruned != 1 {
		t.Fatalf("expected 1 expired candidate to be pruned, got %d", pruned)
	}
	if _, ok := mgr.byKey[reflectorKey("dns", stale)]; ok {
		t.Fatal("expected expired candidate to be removed from inventory")
	}
}

func TestReflectorManagerSummaryCountsMeasuredInventory(t *testing.T) {
	mgr := NewReflectorManager()

	measured := net.ParseIP("203.0.113.30")
	mgr.byKey[reflectorKey("dns", measured)] = &reflectorCandidate{
		IP:                measured,
		Protocol:          "dns",
		LastSeen:          time.Now(),
		RequestBytes:      64,
		ResponseBytes:     700,
		ProbeSuccesses:    1,
		SuccessCount:      1,
		LastResponseBytes: 700,
	}

	verified, reqBytes, respBytes := mgr.Summary("dns")
	if verified != 1 {
		t.Fatalf("expected 1 verified reflector, got %d", verified)
	}
	if reqBytes != 64 || respBytes != 700 {
		t.Fatalf("expected summary bytes 64/700, got %d/%d", reqBytes, respBytes)
	}
}

func TestReflectorProtocolNameRecognizesExtraAmplificationPorts(t *testing.T) {
	if got := reflectorProtocolName(17); got != "qotd" {
		t.Fatalf("expected qotd for port 17, got %q", got)
	}
	if got := reflectorProtocolName(19); got != "chargen" {
		t.Fatalf("expected chargen for port 19, got %q", got)
	}
}

func TestDefaultReflectorResponseBytesUsesExtraProtocolBudgets(t *testing.T) {
	if got := defaultReflectorResponseBytes("qotd"); got < 512 {
		t.Fatalf("expected qotd to keep a larger default response budget, got %d", got)
	}
	if got := defaultReflectorResponseBytes("chargen"); got < 512 {
		t.Fatalf("expected chargen to keep a larger default response budget, got %d", got)
	}
}

func TestRecordTargetCollectorEvidenceUpdatesMeasuredReflectors(t *testing.T) {
	reflectorManager.Reset()

	dnsIP := net.ParseIP("203.0.113.40")
	ntpIP := net.ParseIP("203.0.113.41")
	reflectorManager.Record(reflectorObservation{Source: ObsProbeReply, IP: dnsIP, Protocol: "dns", ResponseBytes: 512, At: time.Now()})
	reflectorManager.Record(reflectorObservation{Source: ObsProbeReply, IP: ntpIP, Protocol: "ntp", ResponseBytes: 1024, At: time.Now()})

	recordTargetCollectorEvidence(7, 2048)

	if got := getReflectorTelemetry(dnsIP, "dns").TargetPackets; got != 7 {
		t.Fatalf("expected dns target packets to be recorded, got %d", got)
	}
	if got := getReflectorTelemetry(ntpIP, "ntp").TargetBytes; got != 2048 {
		t.Fatalf("expected ntp target bytes to be recorded, got %d", got)
	}
}

func TestReflectorManagerVerifiedCandidatesOnlyReturnsMeasuredInventory(t *testing.T) {
	mgr := NewReflectorManager()
	localOnly := net.ParseIP("203.0.113.21")
	measured := net.ParseIP("203.0.113.22")

	mgr.byKey[reflectorKey("dns", localOnly)] = &reflectorCandidate{
		IP:                    localOnly,
		Protocol:              "dns",
		LastSeen:              time.Now(),
		LocalSendSuccessCount: 1,
	}
	mgr.byKey[reflectorKey("dns", measured)] = &reflectorCandidate{
		IP:             measured,
		Protocol:       "dns",
		LastSeen:       time.Now(),
		ProbeSuccesses: 1,
		SuccessCount:   1,
		ResponseBytes:  700,
	}

	verified := mgr.VerifiedCandidates("dns")
	if len(verified) != 1 || verified[0].IP.String() != measured.String() {
		t.Fatalf("expected only measured reflectors to be returned, got %+v", verified)
	}
}
