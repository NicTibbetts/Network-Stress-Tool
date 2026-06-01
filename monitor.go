package main

import (
	"context"
	"crypto/tls"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// controlHosts are highly-available reference endpoints used to tell two very
// different failures apart: "the target is down" vs "our own uplink is saturated."
// the health monitor runs on the SAME machine and link as the attack, so when a
// flood maxes out our uplink (UDP floods especially), a plain HEAD to the target
// times out, which naively looks identical to the target being down. by also
// probing these anycast hosts on a failure, we can disambiguate: if even Google /
// Cloudflare are unreachable, the problem is on our side, and we must NOT report the
// target as down. they're chosen for reliability and fast HEAD responses.
var controlHosts = []string{
	"https://www.google.com",
	"https://1.1.1.1",
	"https://www.cloudflare.com",
}

func healthMonitor(ctx context.Context, target string) {
	// client for the target probe.
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	// separate, shorter timeout client for control probes, these only fire when the
	// target probe has already failed, so we keep them snappy to bound the loop.
	controlClient := &http.Client{
		Timeout: 4 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			start := time.Now()
			ok := probeTarget(ctx, client, target)
			duration := time.Since(start)
			atomic.AddUint64(&healthCheckCount, 1)

			if ok {
				// target answered, definitively up. clear all failure state.
				atomic.AddUint64(&targetOKChecks, 1)
				atomic.StoreUint64(&targetResponding, 1)
				atomic.StoreUint64(&consecutiveFailures, 0)
				atomic.StoreUint64(&localCongestion, 0)
				atomic.StoreUint64(&lastResponseTime, uint64(duration.Milliseconds()))
				continue
			}

			// target probe failed (timeout, connection error, or 5xx). is it the
			// target, or is it us? ask the control hosts.
			if !controlReachable(ctx, controlClient) {
				// even a rock solid reference host is unreachable -> our own uplink is
				// saturated (or down). we genuinely cannot measure the target right
				// now, so we hold the current target state and do NOT count this
				// toward the down trigger. flag local congestion for the dashboard.
				atomic.AddUint64(&congestionChecks, 1)
				atomic.StoreUint64(&localCongestion, 1)
				continue
			}

			// control hosts answer but the target doesn't -> this is a real target
			// failure. require 3 consecutive before declaring down (a single miss is
			// often the server rate-limiting/blocking our IP, not an outage).
			atomic.StoreUint64(&localCongestion, 0)
			cf := atomic.AddUint64(&consecutiveFailures, 1)
			if cf >= 3 && atomic.LoadUint64(&targetResponding) == 1 {
				atomic.StoreUint64(&targetResponding, 0)
				atomic.StoreUint64(&targetDownTime, uint64(time.Now().Unix()))
			}
			// no fmt.Printf here, writing to stdout races the dashboard redraw
		}
	}
}

// probeTarget sends a HEAD to target and reports whether it counts as "up": a usable
// response, i.e. not a transport error/timeout and not a 5xx. 4xx (403/429/etc.)
// counts as up, the server answered, it's just refusing us, which is not an outage.
func probeTarget(ctx context.Context, client *http.Client, target string) bool {
	req, err := http.NewRequestWithContext(ctx, "HEAD", target, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; HealthCheck/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode < 500
}

// controlReachable returns true if ANY control host answers. probes run concurrently
// and we return on the first success so one slow or blocked host can't gate the
// result. every host failing means the problem is our own link, not the target.
func controlReachable(ctx context.Context, client *http.Client) bool {
	cctx, cancel := context.WithCancel(ctx)
	defer cancel() // cancels the still in flight probes once we have an answer

	results := make(chan bool, len(controlHosts))
	var wg sync.WaitGroup
	for _, host := range controlHosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			req, err := http.NewRequestWithContext(cctx, "HEAD", h, nil)
			if err != nil {
				results <- false
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; HealthCheck/1.0)")
			resp, err := client.Do(req)
			if err != nil {
				results <- false
				return
			}
			resp.Body.Close()
			results <- resp.StatusCode < 500
		}(host)
	}
	go func() { wg.Wait(); close(results) }()

	for ok := range results {
		if ok {
			return true // a reference host answered -> our link is fine
		}
	}
	return false // nobody answered -> local congestion / our link is down
}
