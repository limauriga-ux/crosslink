package gui

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"time"
)

func (s *Service) RunConnectivityTests(req TestRequest) TestReport {
	timeout := time.Duration(req.TimeoutMillis) * time.Millisecond
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	targets := req.Items
	if len(targets) == 0 {
		targets = defaultTestTargets()
	}
	client := req.HTTPClient
	if client == nil {
		// Ignore HTTP_PROXY/HTTPS_PROXY. An active system TUN may still capture
		// this normal application path, which is the behavior being measured.
		client = &http.Client{Timeout: timeout, Transport: &http.Transport{Proxy: nil}}
	} else {
		copyClient := *client
		copyClient.Timeout = timeout
		client = &copyClient
	}

	// Run all tests concurrently; collect in original order.
	results := make([]TestResult, len(targets))
	var wg sync.WaitGroup
	for i, target := range targets {
		wg.Add(1)
		go func(idx int, t TestTarget) {
			defer wg.Done()
			results[idx] = runHTTPTest(client, timeout, t)
		}(i, target)
	}
	wg.Wait()
	return TestReport{OK: true, Results: results}
}

// RunSingleTest runs one connectivity test, repeated `samples` times.
// Used by the frontend to trigger individual tests in parallel and show
// results as they arrive. An empty proxyAddr uses the normal system path;
// a non-empty mixed_addr explicitly uses the sing-box HTTP proxy.
//
// Single-shot timings jitter wildly (TCP/TLS handshake, CDN steering),
// so the frontend asks for several samples: the reported duration is the
// mean over successful probes, Reachable means at least one success, and
// Samples/Successes let the UI show "3/3" instead of hiding flakiness.
func (s *Service) RunSingleTest(target TestTarget, proxyAddr string, samples int) TestResult {
	if samples <= 0 {
		samples = 3
	}
	timeout := 6 * time.Second
	transport := &http.Transport{Proxy: nil}
	if proxyAddr != "" {
		proxyURL := &url.URL{Scheme: "http", Host: proxyAddr}
		transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	}
	client := &http.Client{Timeout: timeout, Transport: transport}

	var totalMillis int64
	var successes int
	var last TestResult
	for i := 0; i < samples; i++ {
		last = runHTTPTest(client, timeout, target)
		if last.Reachable {
			successes++
			totalMillis += last.DurationMillis
		}
	}
	last.Samples = samples
	last.Successes = successes
	last.Reachable = successes > 0
	if successes > 0 {
		last.DurationMillis = totalMillis / int64(successes)
		last.Error = ""
	}
	return last
}

// browserUA is sent on every connectivity probe. Default Go UA
// (`Go-http-client/1.1`) trips anti-bot on some big CN sites — e.g.
// qq.com's CDN returns 501 to it. Any commonly-recognised UA dodges
// that without changing the test's network-layer signal.
const browserUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

func runHTTPTest(client *http.Client, timeout time.Duration, target TestTarget) TestResult {
	start := time.Now()
	result := TestResult{
		Name: target.Name,
		URL:  target.URL,
	}
	if target.URL == "" {
		result.Error = "empty URL"
		return result
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	req.Header.Set("User-Agent", browserUA)
	// Do not follow redirects. Bing sets a regional cookie via 302 → `?cc=cn`;
	// http.Client has no jar so the cookie is dropped and Bing keeps appending
	// `cc=cn` until Go bails out at 10 redirects with a polluted URL in the
	// error. For a connectivity probe a 3xx already proves reachability, so
	// stop at the first response. Shallow-copy so we don't mutate the caller's
	// client (concurrent goroutines / tests).
	probe := *client
	probe.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := probe.Do(req)
	result.DurationMillis = time.Since(start).Milliseconds()
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()
	result.HTTPStatus = resp.StatusCode
	result.Reachable = isReachableStatus(resp.StatusCode)
	return result
}

// isReachableStatus treats any HTTP response as proof the network path
// works. 4xx/5xx mean we reached the server and it answered — that is
// the question a connectivity test answers. The frontend can colour-
// code further if it cares about specific status families.
func isReachableStatus(code int) bool {
	return code >= 100 && code < 600
}

func defaultTestTargets() []TestTarget {
	return []TestTarget{
		{Name: "Baidu", URL: "https://www.baidu.com"},
		{Name: "Bing", URL: "https://www.bing.com"},
		{Name: "QQ", URL: "https://www.qq.com"},
		{Name: "Google", URL: "https://www.google.com/generate_204"},
		{Name: "GitHub", URL: "https://github.com"},
		{Name: "YouTube", URL: "https://www.youtube.com/generate_204"},
		{Name: "X", URL: "https://x.com"},
	}
}
