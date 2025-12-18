package js

import (
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/felinux0x/VoidScope/pkg/web"
)

// Regex patterns for secrets
var (
	AWSKey     = regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`)
	GoogleAPI  = regexp.MustCompile(`(?i)AIza[0-9A-Za-z\\-_]{35}`)
	Slack      = regexp.MustCompile(`xox[baprs]-([0-9a-zA-Z]{10,48})`)
	GenericAPI = regexp.MustCompile(`(?i)(api_key|access_token|secret)[\s=:"']+([0-9a-zA-Z\-_]{16,64})`)
)

type Result struct {
	Type  string
	Value string
	URL   string
}

type Scanner struct {
	Prober *web.Prober
}

func NewScanner(prober *web.Prober) *Scanner {
	return &Scanner{Prober: prober}
}

func (s *Scanner) Scan(html string, baseURL string) []Result {
	var results []Result

	// 1. Extract JS links
	scriptRegex := regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
	matches := scriptRegex.FindAllStringSubmatch(html, -1)

	var jsURLs []string
	for _, m := range matches {
		if len(m) > 1 {
			jsURL := m[1]
			if !strings.HasPrefix(jsURL, "http") {
				// Handle relative
				if strings.HasPrefix(jsURL, "//") {
					jsURL = "https:" + jsURL
				} else if strings.HasPrefix(jsURL, "/") {
					jsURL = baseURL + jsURL
				} else {
					jsURL = baseURL + "/" + jsURL
				}
			}
			jsURLs = append(jsURLs, jsURL)
		}
	}

	// 2. Scan each JS file
	var wg sync.WaitGroup
	resultChan := make(chan Result, len(jsURLs)*5) // buffer
	sem := make(chan struct{}, 5)

	for _, url := range jsURLs {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if s.Prober.Stealth != nil {
				s.Prober.Stealth.Wait()
			}

			req, err := http.NewRequest("GET", target, nil)
			if err != nil {
				return
			}

			res, err := s.Prober.Client.Do(req)
			if err != nil {
				return
			}
			defer res.Body.Close()

			body, _ := io.ReadAll(res.Body)
			content := string(body)

			// Check Patterns
			if match := AWSKey.FindString(content); match != "" {
				resultChan <- Result{Type: "AWS Key", Value: match, URL: target}
			}
			if match := GoogleAPI.FindString(content); match != "" {
				resultChan <- Result{Type: "Google API", Value: match, URL: target}
			}
			if match := Slack.FindString(content); match != "" {
				resultChan <- Result{Type: "Slack Token", Value: match, URL: target}
			}
		}(url)
	}

	wg.Wait()
	close(resultChan)

	for r := range resultChan {
		results = append(results, r)
	}

	return results
}
