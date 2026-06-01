package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

// this file is the answer to the single biggest silent killer: the TLS
// fingerprint. go's stdlib crypto/tls emits a ClientHello whose cipher list,
// extension order, and curve preferences are unmistakably "go client". every
// serious WAF (cloudflare, akamai, aws) hashes that handshake into a JA3/JA4
// fingerprint and blocks it at the TLS layer, before our request is ever seen
// by the application. the stats then show failures with no http status to
// explain them, which is exactly the kind of invisible wall that makes a tool
// look powerful in a lab and useless in the real world.
//
// uTLS fixes this by letting us emit a ClientHello that is byte-for-byte a real
// chrome or firefox handshake. the server's fingerprinter sees chrome, not go,
// and the connection survives long enough for the request to actually land.

// browserProfile pairs a TLS ClientHello identity with the User-Agent that the
// same browser would send. the pairing matters: a chrome JA3 with a firefox
// User-Agent is itself a bot tell, because no real chrome ever sends a firefox
// UA. keeping them consistent is what makes the disguise hold up.
type browserProfile struct {
	helloID   utls.ClientHelloID
	userAgent string
}

// the profiles we rotate through. these are current-ish chrome/firefox builds
// that uTLS ships parrots for. we deliberately keep the UA string in lockstep
// with the helloID so the handshake and the header agree on who we claim to be.
var browserProfiles = []browserProfile{
	{
		helloID:   utls.HelloChrome_133,
		userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
	},
	{
		helloID:   utls.HelloChrome_131,
		userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	},
	{
		helloID:   utls.HelloChrome_120,
		userAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	},
	{
		helloID:   utls.HelloFirefox_120,
		userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
	},
	{
		helloID:   utls.HelloFirefox_120,
		userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
	},
}

// randomBrowserProfile picks one of the paired profiles. callers use the
// returned UA for the request header so the header story matches the handshake.
func randomBrowserProfile() browserProfile {
	return browserProfiles[mathrand.Intn(len(browserProfiles))]
}

// uTLSRoundTripper is an http.RoundTripper that dials every connection through
// uTLS so the TLS handshake mimics a real browser. it speaks both http/1.1 and
// http/2: after the uTLS handshake we look at the negotiated ALPN and hand the
// connection to the matching protocol. that detail matters because a browser
// that advertises h2 in its ClientHello but then speaks http/1.1 is another
// detectable inconsistency.
//
// connections are cached per host so we are not paying a fresh handshake on
// every request, which would both be slow and look nothing like a browser
// reusing keep-alive connections.
type uTLSRoundTripper struct {
	profile     browserProfile
	proxyURL    *url.URL
	dialTimeout time.Duration

	mu sync.Mutex
	// per host cached transports. the h2 transport wraps a single uTLS conn,
	// the h1 transport keeps its own small pool, so we key both by host.
	conns map[string]http.RoundTripper
}

// newUTLSRoundTripper builds a round tripper for one browser profile, optionally
// routing through a proxy. pass nil proxyURL for a direct connection.
func newUTLSRoundTripper(profile browserProfile, proxyURL *url.URL) *uTLSRoundTripper {
	return &uTLSRoundTripper{
		profile:     profile,
		proxyURL:    proxyURL,
		dialTimeout: 15 * time.Second,
		conns:       make(map[string]http.RoundTripper),
	}
}

// RoundTrip dispatches the request over a browser-mimicking TLS connection.
func (rt *uTLSRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// pin the User-Agent to the one paired with our handshake. the attack
	// functions upstream pick a UA from the generic pool, which can disagree
	// with our actual ClientHello and reintroduce the very inconsistency we
	// are trying to erase. stamping it here keeps the handshake and the header
	// telling the same story no matter what the caller set.
	req.Header.Set("User-Agent", rt.profile.userAgent)

	// only https benefits from TLS mimicry. plain http has no handshake to
	// disguise, so we fall back to a normal transport for those.
	if req.URL.Scheme != "https" {
		return rt.plainTransport().RoundTrip(req)
	}

	host := req.URL.Host
	rt.mu.Lock()
	cached, ok := rt.conns[host]
	rt.mu.Unlock()
	if ok {
		resp, err := cached.RoundTrip(req)
		if err == nil {
			return resp, nil
		}
		// the cached connection went bad (server closed it, proxy dropped it).
		// drop it and fall through to build a fresh one rather than failing.
		rt.mu.Lock()
		delete(rt.conns, host)
		rt.mu.Unlock()
	}

	transport, err := rt.buildTransport(req.Context(), req.URL)
	if err != nil {
		return nil, err
	}

	rt.mu.Lock()
	rt.conns[host] = transport
	rt.mu.Unlock()

	return transport.RoundTrip(req)
}

// plainTransport is the http (non-TLS) fallback. it still honors the proxy.
func (rt *uTLSRoundTripper) plainTransport() http.RoundTripper {
	t := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
	}
	if rt.proxyURL != nil {
		t.Proxy = http.ProxyURL(rt.proxyURL)
	}
	return t
}

// buildTransport performs the uTLS handshake and returns a RoundTripper bound to
// the resulting connection, picking http/2 or http/1.1 based on negotiated ALPN.
func (rt *uTLSRoundTripper) buildTransport(ctx context.Context, u *url.URL) (http.RoundTripper, error) {
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(u.Hostname(), "443")
	}

	rawConn, err := rt.dialRaw(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	uConf := &utls.Config{
		ServerName: u.Hostname(),
		// we are a stress tool pointed at a target the operator chose, so we
		// skip cert verification the same way the rest of the tool does. this
		// does not weaken the fingerprint, only the trust check on the response.
		InsecureSkipVerify: true,
		// advertise both protocols exactly like a browser does. the server's
		// ALPN choice then tells us which to actually speak.
		NextProtos: []string{"h2", "http/1.1"},
	}

	uConn := utls.UClient(rawConn, uConf, rt.profile.helloID)
	if err := uConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("utls handshake: %w", err)
	}

	switch uConn.ConnectionState().NegotiatedProtocol {
	case "h2":
		return rt.h2Transport(uConn)
	default:
		return rt.h1Transport(uConn), nil
	}
}

// dialRaw opens the underlying TCP connection, going through the configured
// proxy when one is set. SOCKS5 and http CONNECT proxies are both handled so we
// can sit behind whatever residential/datacenter proxy list the operator feeds.
func (rt *uTLSRoundTripper) dialRaw(ctx context.Context, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: rt.dialTimeout}

	if rt.proxyURL == nil {
		return dialer.DialContext(ctx, "tcp", addr)
	}

	switch rt.proxyURL.Scheme {
	case "socks5", "socks5h":
		return rt.dialViaSOCKS5(ctx, addr)
	default:
		// treat everything else (http/https proxy) as an http CONNECT tunnel.
		return rt.dialViaConnect(ctx, addr)
	}
}

// h2Transport wraps an already-handshaked uTLS conn in an http2.Transport. we
// hand http2 the live connection rather than letting it dial, so the browser
// ClientHello we just sent is the one h2 rides on.
//
// the SETTINGS frame is where layer-2 fingerprinting lives. go's http2 defaults
// send HEADER_TABLE_SIZE=4096 and no MAX_HEADER_LIST_SIZE, both of which differ
// from chrome in an immediately detectable way. we set chrome's actual values
// here so the SETTINGS frame is consistent with the ClientHello we already sent.
//
// what this does NOT fix: SETTINGS_INITIAL_WINDOW_SIZE (chrome sends 6291456,
// go's http2 transport does not expose this field) and the connection-level
// WINDOW_UPDATE frame (chrome sends 15663105, also not configurable here).
// those gaps require replacing x/net/http2 with bogdanfinn/tls-client, which
// handles the complete h2 fingerprint alongside the TLS fingerprint.
func (rt *uTLSRoundTripper) h2Transport(conn net.Conn) (http.RoundTripper, error) {
	tr := &http2.Transport{
		// we already validated (or chose to skip) TLS above. this config is
		// only consulted if h2 ever needs to dial again, which it will not for
		// a connection we hand it directly.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		AllowHTTP:       false,
		// chrome sends SETTINGS_HEADER_TABLE_SIZE = 65536. go's default is 4096.
		// akamai's h2 fingerprinter (sometimes called peet) checks this value.
		MaxDecoderHeaderTableSize: 65536,
		// chrome sends SETTINGS_MAX_HEADER_LIST_SIZE = 262144. go does not send
		// this setting at all (which the library treats as "unlimited"), so the
		// absence is itself a signal. sending chrome's value closes that gap.
		MaxHeaderListSize: 262144,
	}
	h2Conn, err := tr.NewClientConn(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("h2 client conn: %w", err)
	}
	return &singleH2Conn{conn: h2Conn}, nil
}

// h1Transport speaks http/1.1 over the handshaked conn. we use a fresh
// http.Transport whose DialTLSContext just returns the connection we already
// built, so the first request reuses our browser handshake.
func (rt *uTLSRoundTripper) h1Transport(conn net.Conn) http.RoundTripper {
	used := false
	var mu sync.Mutex
	return &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			mu.Lock()
			defer mu.Unlock()
			if !used {
				used = true
				return conn, nil
			}
			// http.Transport wants another connection for the same host. build
			// a fresh browser handshake rather than letting it dial with stdlib.
			return rt.freshTLSConn(ctx, addr)
		},
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
}

// freshTLSConn performs another browser handshake for the same host, used when
// the http/1.1 transport asks for a second connection.
func (rt *uTLSRoundTripper) freshTLSConn(ctx context.Context, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	rawConn, err := rt.dialRaw(ctx, addr)
	if err != nil {
		return nil, err
	}
	uConn := utls.UClient(rawConn, &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	}, rt.profile.helloID)
	if err := uConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}
	return uConn, nil
}

// singleH2Conn adapts an *http2.ClientConn to the RoundTripper interface so it
// slots into our per-host cache alongside the http/1.1 transports.
type singleH2Conn struct {
	conn *http2.ClientConn
}

func (s *singleH2Conn) RoundTrip(req *http.Request) (*http.Response, error) {
	return s.conn.RoundTrip(req)
}

// dialViaSOCKS5 tunnels the raw TCP connection through a SOCKS5 proxy. this is
// the proxy type that matters for evasion: residential and mobile SOCKS5 exits
// give us source IPs that are not on the datacenter blocklists every CDN
// shares. the uTLS handshake then happens end to end over that tunnel, so the
// target sees a browser fingerprint arriving from a residential IP.
func (rt *uTLSRoundTripper) dialViaSOCKS5(ctx context.Context, addr string) (net.Conn, error) {
	var auth *proxy.Auth
	if rt.proxyURL.User != nil {
		pass, _ := rt.proxyURL.User.Password()
		auth = &proxy.Auth{User: rt.proxyURL.User.Username(), Password: pass}
	}
	d, err := proxy.SOCKS5("tcp", rt.proxyURL.Host, auth, &net.Dialer{Timeout: rt.dialTimeout})
	if err != nil {
		return nil, fmt.Errorf("socks5 dialer: %w", err)
	}
	// prefer the context-aware path when the dialer supports it so a cancelled
	// request actually aborts the connect instead of hanging on a dead proxy.
	if ctxDialer, ok := d.(proxy.ContextDialer); ok {
		return ctxDialer.DialContext(ctx, "tcp", addr)
	}
	return d.Dial("tcp", addr)
}

// dialViaConnect opens an http CONNECT tunnel through an http/https proxy. we
// write the CONNECT request by hand and read the proxy's response before
// handing the raw conn back for the uTLS handshake to ride on top of.
func (rt *uTLSRoundTripper) dialViaConnect(ctx context.Context, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: rt.dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", rt.proxyURL.Host)
	if err != nil {
		return nil, fmt.Errorf("dial proxy %s: %w", rt.proxyURL.Host, err)
	}

	connectReq := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}
	if rt.proxyURL.User != nil {
		pass, _ := rt.proxyURL.User.Password()
		connectReq.SetBasicAuth(rt.proxyURL.User.Username(), pass)
		// proxy auth rides in Proxy-Authorization, not Authorization.
		connectReq.Header.Set("Proxy-Authorization", connectReq.Header.Get("Authorization"))
		connectReq.Header.Del("Authorization")
	}

	if err := connectReq.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write CONNECT: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, connectReq)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read CONNECT response: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT refused: %s", resp.Status)
	}
	return conn, nil
}
