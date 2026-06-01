package main

import (
    "bufio"
    "fmt"
    "log"
    "net/http"
    "os"
    "strings"
	"time"

    "github.com/PuerkitoBio/goquery"
)

var client = &http.Client{Timeout: 10 * time.Second}

func main() {
    url := "https://spys.one/en/free-proxy-list/"
    filePath := "ip_addresses.csv"
    file, err := os.Create(filePath)
    if err != nil {
        log.Fatal("Error creating file:", err)
    }
    defer file.Close()

    writer := bufio.NewWriter(file)
    defer writer.Flush()

    res, err := fetch(url)
    if err != nil {
        log.Fatal("Error fetching URL:", err)
    }
    defer res.Body.Close()

    doc, err := goquery.NewDocumentFromReader(res.Body)
    if err != nil {
        log.Fatal("Error parsing HTML:", err)
    }

    // Enhanced extraction logic to skip the header
    doc.Find("tr.spy1x, tr.spy1xx").Each(func(index int, item *goquery.Selection) {
        fullText := item.Find("td").First().Text()
        ipEndIndex := strings.Index(fullText, "document.write")
        if ipEndIndex == -1 {
            ipEndIndex = len(fullText) // Use the full text if no script is found
        }
        ip := strings.TrimSpace(fullText[:ipEndIndex])

        // Skip the header based on its exact content
        if ip != "" && ip != "Proxy address:port" {
            _, err := writer.WriteString(ip + "\n")
            if err != nil {
                log.Fatal("Error writing IP to file:", err)
            }
        }
    })

    if err := writer.Flush(); err != nil {
        log.Fatal("Error flushing writer:", err)
    }

    fmt.Println("IP addresses extraction completed successfully. Output file:", filePath)
}

func fetch(url string) (*http.Response, error) {
    req, err := http.NewRequest("GET", url, nil)
    req.Header.Set("User-Agent", "Mozilla/5.0")
    if err != nil {
        return nil, err
    }
    return client.Do(req)
}
