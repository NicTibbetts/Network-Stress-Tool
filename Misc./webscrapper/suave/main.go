package main

import (
    "fmt"
    "log"
    "net/http"
    "net/url"
    "os"
    "strings"
    "sync"
    "time"

    "github.com/PuerkitoBio/goquery"
)

// Custom HTTP client with timeout
var client = &http.Client{Timeout: 10 * time.Second}
var counter int = 0
var counterMutex sync.Mutex
// Worker pool size
const MaxWorkers = 10

func main() {
    baseURL := "https:/"
    file, err := os.Create("pure_knowledge.txt")
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close()

    mdFile, err := os.Create("pure_knowledge.md")
    if err != nil {
        log.Fatal(err)
    }
    defer mdFile.Close()

    res, err := fetch(baseURL)
    if err != nil {
        log.Fatal(err)
    }
    defer res.Body.Close()

    doc, err := goquery.NewDocumentFromReader(res.Body)
    if err != nil {
        log.Fatal(err)
    }

    var wg sync.WaitGroup
    urls := make(chan string, MaxWorkers)

    // Create worker pool
    for i := 0; i < MaxWorkers; i++ {
        go worker(&wg, urls, file, mdFile)
    }

	doc.Find("ul li a").Each(func(index int, link *goquery.Selection) {
        linkURL, exists := link.Attr("href")
        if !exists {
            return
        }
		

		 // Debugging: Print the link URL
        fmt.Printf("Found link: %s\n", linkURL)
        // Resolve the URL to an absolute URL
        resolvedURL, err := url.Parse(linkURL)
        if err != nil {
            log.Printf("Failed to parse URL: %s", linkURL)
            return
        }
        resolvedURL = res.Request.URL.ResolveReference(resolvedURL)

        // Check if the URL is under the base URL
        if strings.HasPrefix(resolvedURL.String(), baseURL) {
            wg.Add(1)
            urls <- resolvedURL.String()
        }
    })

	close(urls)
    wg.Wait()

    fmt.Printf("Total pages scraped: %d\n", counter)
    fmt.Println("Web scraping and text saving completed successfully.")
}

func worker(wg *sync.WaitGroup, urls <-chan string, file *os.File, mdFile *os.File) {
    for url := range urls {
        processURL(url, file, mdFile)
        wg.Done()
    }
}



func processURL(url string, file *os.File, mdFile *os.File) {
	res, err := fetch(url)
	if err != nil {
		log.Printf("Failed to fetch URL: %s", url)
		return
	}
	defer res.Body.Close()

	linkedDoc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		log.Printf("Failed to parse linked HTML: %s", url)
		return
	}

	var linkedText strings.Builder
	var mdText strings.Builder

	linkedDoc.Find("article").Each(func(i int, s *goquery.Selection) {
		s.Find("script").Remove()

		s.Contents().Each(func(i int, content *goquery.Selection) {
			nodeName := goquery.NodeName(content)
			text := strings.TrimSpace(content.Text()) // Trim spaces from the text

			switch nodeName {
			case "h1":
				linkedText.WriteString(text + "\n\n") // Add as is to .txt
				mdText.WriteString("# " + text + "\n\n") // Format as Markdown H1
			case "h2":
				linkedText.WriteString(text + "\n\n") // Add as is to .txt
				mdText.WriteString("## " + text + "\n\n") // Format as Markdown H2
			case "br":
				linkedText.WriteString("\n")
				mdText.WriteString("\n")
			default:
				if text != "" {
					linkedText.WriteString(text + "\n")
					mdText.WriteString(text + "\n")
				}
			}
		})
	})

	var mutex sync.Mutex
	mutex.Lock()
	_, err = file.WriteString(linkedText.String() + "\n")
	_, err = mdFile.WriteString(mdText.String() + "\n")
	mutex.Unlock()

	if err != nil {
		log.Printf("Failed to write to files for URL: %s", url)
		return
	}

	counterMutex.Lock()
    counter++
    counterMutex.Unlock()

}

func fetch(url string) (*http.Response, error) {
    return client.Get(url)
}
