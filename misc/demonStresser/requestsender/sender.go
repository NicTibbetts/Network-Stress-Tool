package requestsender

import (
    "net/http"
    "net/url"
    "errors"
)

func SendRequestThroughProxy(requestURL, proxyURL string) (*http.Response, error) {
    if proxyURL == "" {
        return nil, errors.New("no proxy URL provided")
    }

    proxy, err := url.Parse(proxyURL)
    if err != nil {
        return nil, err
    }

    transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
    client := &http.Client{Transport: transport}

    request, err := http.NewRequest("GET", requestURL, nil) // Customize as needed
    if err != nil {
        return nil, err
    }

    return client.Do(request)
}
