package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type DemonConfig struct {
	// Attack Configuration
	AttackType        int           `json:"attack_type"`
	// AttackTypes is the tag-team pool. when non-empty (and -attack is not passed
	// on the command line) workers randomly pick from this list each job, the same
	// way `-attack 2,7` works on the CLI. AttackType stays as the primary/first type
	// for backward compatibility with anything that reads a single value.
	AttackTypes       []int         `json:"attack_types,omitempty"`
	ConcurrentWorkers int           `json:"concurrent_workers"`
	RequestRate       int           `json:"request_rate"`
	AttackDuration    time.Duration `json:"attack_duration"`

	// Proxy Configuration
	ProxyRotation    bool   `json:"proxy_rotation"`
	ProxyFile        string `json:"proxy_file"`
	ProxyTestTimeout int    `json:"proxy_test_timeout"`
	ProxyRetries     int    `json:"proxy_retries"`

	// Proxy acquisition tuning (also exposed as flags; 0 = use built-in default)
	ProxyTargetCount       int `json:"proxy_target_count"`        // stop acquiring once this many good proxies are verified
	ProxyAcquireTimeoutSec int `json:"proxy_acquire_timeout_sec"` // hard time budget for acquisition, in seconds
	ProxyRefreshIntervalSec int `json:"proxy_refresh_interval_sec"` // how often the background refresh tops up the worker pool

	// Security Configuration
	AnonymityRequired   bool   `json:"anonymity_required"`
	AnonymityLevel      string `json:"anonymity_level"` // "basic", "high", "extreme"
	UserAgentRotation   bool   `json:"user_agent_rotation"`
	HeaderRandomization bool   `json:"header_randomization"`

	// Performance Configuration
	KeepAlive        bool          `json:"keep_alive"`
	KeepAliveAbuse   bool          `json:"keep_alive_abuse"`
	HTTP2            bool          `json:"http2"`
	CompressionLevel int           `json:"compression_level"`
	TimeoutSettings  TimeoutConfig `json:"timeout_settings"`

	// Attack tuning knobs (also exposed as flags; 0 = use built-in default)
	HTTP2Connections   int `json:"http2_connections"`    // type 2, independent h2 connections to fan streams across
	BombSizeMB         int `json:"bomb_size_mb"`         // type 7, decompressed size of the gzip bomb, in MB
	MaxHeldConnections int `json:"max_held_connections"` // types 1/6/8, cap on simultaneously held connections
	MaxUDPFloods       int `json:"max_udp_floods"`       // type 10, cap on concurrent UDP flood invocations (OS-thread safety backstop)
	UDPPacketsPerSec   int `json:"udp_packets_per_sec"`  // type 10 direct flood, aggregate packet-rate cap (0 = built-in 100k default)

	// UDPDirect forces type 10 to use the direct, non-spoofed flood against the
	// target only (this is also the default mode). Kept as an explicit force-direct
	// that overrides UDPReflection if both are set.
	UDPDirect bool `json:"udp_direct"`

	// UDPReflection selects the reflection/amplification ATTACK MODE for type 10
	// (raw sockets, spoofed source IP, third-party amplifiers). Off by default: the
	// default type-10 mode is the direct, non-spoofed flood against your own target.
	UDPReflection bool `json:"udp_reflection"`

	// Bandwidth / congestion control, keep a flood from saturating your OWN uplink
	Bandwidth         string `json:"bandwidth"`          // cap UDP egress (e.g. "40mbit", "5MB", "500kbit"); "" = uncapped
	AdaptiveBandwidth bool   `json:"adaptive_bandwidth"` // auto-throttle the send rate when local uplink congestion is detected

	// Logging Configuration
	LogLevel      LogLevel `json:"log_level"`
	LogFile       string   `json:"log_file"`
	VerboseOutput bool     `json:"verbose_output"`

	// Advanced Features
	CacheBusting       bool `json:"cache_busting"`
	WAFEvasion         bool `json:"waf_evasion"`
	BehaviorMimicry    bool `json:"behavior_mimicry"`
	TLSFingerprinting  bool `json:"tls_fingerprinting"`

	// Rate Limit Bypass Configuration
	RateLimitBypass     bool         `json:"rate_limit_bypass"`
	DistributedTiming   bool         `json:"distributed_timing"`
	IntelligentThrottle bool         `json:"intelligent_throttle"`
	AdaptiveRateControl bool         `json:"adaptive_rate_control"`
	BypassSettings      BypassConfig `json:"bypass_settings"`

	// Safety Features
	MaxConcurrency int  `json:"max_concurrency"`
	MaxRate        int  `json:"max_rate"`
	SafetyLimits   bool `json:"safety_limits"`
}

type TimeoutConfig struct {
	Connection time.Duration `json:"connection"`
	Request    time.Duration `json:"request"`
	Response   time.Duration `json:"response"`
	KeepAlive  time.Duration `json:"keep_alive"`
}

type BypassConfig struct {
	// Intelligent Throttling
	MinDelay          time.Duration `json:"min_delay"`           // Minimum delay between requests
	MaxDelay          time.Duration `json:"max_delay"`           // Maximum delay between requests
	AdaptiveDelayStep time.Duration `json:"adaptive_delay_step"` // How much to adjust delay

	// Distributed Timing Patterns
	BurstSize       int           `json:"burst_size"`       // Requests per burst
	BurstInterval   time.Duration `json:"burst_interval"`   // Time between bursts
	RandomVariation float64       `json:"random_variation"` // % variation in timing (0.0-1.0)

	// Rate Limit Detection
	StatusCodeTriggers []int         `json:"status_code_triggers"` // Status codes that indicate rate limiting
	HeaderTriggers     []string      `json:"header_triggers"`      // Headers that indicate rate limiting
	ResponseTimeThresh time.Duration `json:"response_time_thresh"` // Response time threshold for detection

	// Bypass Strategies
	BackoffMultiplier  float64       `json:"backoff_multiplier"`    // How much to back off when detected
	RecoveryTime       time.Duration `json:"recovery_time"`         // Time to wait before recovery attempt
	ProxyRotateOnLimit bool          `json:"proxy_rotate_on_limit"` // Rotate proxy when rate limited
	IPRotateOnLimit    bool          `json:"ip_rotate_on_limit"`    // Change IP when rate limited
}

func DefaultConfig() *DemonConfig {
	return &DemonConfig{
		AttackType:        0,
		ConcurrentWorkers: 100,
		RequestRate:       1000,
		AttackDuration:    0, // 0 = run until Ctrl+C unless -duration/-infinite is given

		ProxyRotation:           false,
		ProxyTestTimeout:        5,
		ProxyRetries:            3,
		ProxyTargetCount:        50,
		ProxyAcquireTimeoutSec:  45,
		ProxyRefreshIntervalSec: 300,

		AnonymityRequired:   false,
		AnonymityLevel:      "high",
		UserAgentRotation:   true,
		HeaderRandomization: true,

		KeepAlive:          true,
		HTTP2:              true,
		CompressionLevel:   6,
		HTTP2Connections:   4,
		BombSizeMB:         64,
		MaxHeldConnections: 50000,
		MaxUDPFloods:       maxConcurrentUDPFloods,
		UDPPacketsPerSec:   0,     // 0 = built-in 100k pps default for the direct flood
		UDPDirect:          false, // direct is the default mode; this only force-pins it
		UDPReflection:      false, // reflection/amplification is opt-in via -udp-reflection
		Bandwidth:          "", // uncapped by default; set to your uplink to avoid self-congestion
		AdaptiveBandwidth:  true,
		TimeoutSettings: TimeoutConfig{
			Connection: 10 * time.Second,
			Request:    30 * time.Second,
			Response:   30 * time.Second,
			KeepAlive:  60 * time.Second,
		},

		LogLevel:      LogLevelInfo,
		LogFile:       "demon.log",
		VerboseOutput: false,

		CacheBusting:    true,
		WAFEvasion:      false,
		BehaviorMimicry: false,

		RateLimitBypass:     false,
		DistributedTiming:   false,
		IntelligentThrottle: false,
		AdaptiveRateControl: false,
		BypassSettings: BypassConfig{
			MinDelay:           100 * time.Millisecond,
			MaxDelay:           2 * time.Second,
			AdaptiveDelayStep:  50 * time.Millisecond,
			BurstSize:          5,
			BurstInterval:      10 * time.Second,
			RandomVariation:    0.3,
			StatusCodeTriggers: []int{429, 503, 520, 521, 522, 523, 524},
			HeaderTriggers:     []string{"X-RateLimit-Remaining", "Retry-After", "X-Rate-Limited"},
			ResponseTimeThresh: 5 * time.Second,
			BackoffMultiplier:  2.0,
			RecoveryTime:       30 * time.Second,
			ProxyRotateOnLimit: true,
			IPRotateOnLimit:    true,
		},

		MaxConcurrency: 1000,
		MaxRate:        10000,
		SafetyLimits:   true,
	}
}

func LoadConfig(configFile string) (*DemonConfig, error) {
	config := DefaultConfig()

	if configFile == "" {
		return config, nil
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		return config, fmt.Errorf("failed to read config file: %v", err)
	}

	if err := json.Unmarshal(data, config); err != nil {
		return config, fmt.Errorf("failed to parse config file: %v", err)
	}

	return config, nil
}

func (c *DemonConfig) SaveConfig(configFile string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	return os.WriteFile(configFile, data, 0644)
}

