package proxymanager

import (
	"net/http"
	_"net/url"
	"sync"
	"time"
)

type Proxy struct {
	Address string
	Type    string // "HTTP", "HTTPS", or "SOCKS"
}

type Manager struct {
	Proxies   []Proxy
	current   int
	lock      sync.Mutex
	client    *http.Client
	testURL   string
	validator func(*Proxy) bool
}

func NewManager(testURL string, validator func(*Proxy) bool) *Manager {
	return &Manager{
		testURL:   testURL,
		validator: validator,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (pm *Manager) LoadProxies(proxies []Proxy) {
	pm.lock.Lock()
	defer pm.lock.Unlock()
	pm.Proxies = proxies
	pm.current = 0
}

func (pm *Manager) RotateProxy() *Proxy {
	pm.lock.Lock()
	defer pm.lock.Unlock()
	if len(pm.Proxies) == 0 {
		return nil
	}
	proxy := pm.Proxies[pm.current]
	pm.current = (pm.current + 1) % len(pm.Proxies)
	return &proxy
}

func (pm *Manager) ValidateProxies() {
	var wg sync.WaitGroup
	for i, proxy := range pm.Proxies {
		wg.Add(1)
		go func(index int, p Proxy) {
			defer wg.Done()
			if !pm.validator(&p) {
				pm.removeProxy(index)
			}
		}(i, proxy)
	}
	wg.Wait()
}

func (pm *Manager) removeProxy(index int) {
	pm.lock.Lock()
	defer pm.lock.Unlock()
	pm.Proxies = append(pm.Proxies[:index], pm.Proxies[index+1:]...)
	if pm.current >= index {
		pm.current--
	}
}

func defaultValidator(proxy *Proxy) bool {
	// Implement validation logic, e.g., making a test HTTP request via the proxy
	return true
}
