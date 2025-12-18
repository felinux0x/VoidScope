package web

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/felinux0x/VoidScope/internal/utils"
	"github.com/felinux0x/VoidScope/pkg/stealth"
	"github.com/felinux0x/VoidScope/pkg/waf"
)

type Result struct {
	URL        string
	StatusCode int
	Title      string
	ContentLen int64
	Tech       []string
	WAF        string
}

type Prober struct {
	Client  *http.Client
	Stealth *stealth.Engine
}

// NewProber configuration
func NewProber(proxy string, stealthEngine *stealth.Engine) (*Prober, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	if err := stealth.ConfigureProxy(proxy, transport); err != nil {
		return nil, err
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &Prober{Client: client, Stealth: stealthEngine}, nil
}

func (p *Prober) Probe(host string, port int) *Result {
	// ENFORCE S.T.E.A.L.T.H
	if p.Stealth != nil {
		p.Stealth.Wait()
	}

	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}

	url := fmt.Sprintf("%s://%s:%d", scheme, host, port)
	if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
		url = fmt.Sprintf("%s://%s", scheme, host)
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", utils.RandomUserAgent())

	resp, err := p.Client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := string(bodyBytes)

	title := extractTitle(bodyStr)
	tech := detectTech(resp.Header, bodyStr)
	wafDetected := waf.Detect(resp.Header, bodyStr)

	return &Result{
		URL:        url,
		StatusCode: resp.StatusCode,
		Title:      title,
		ContentLen: resp.ContentLength,
		Tech:       tech,
		WAF:        wafDetected,
	}
}

var titleRegex = regexp.MustCompile(`(?i)<title>(.*?)</title>`)

func extractTitle(body string) string {
	matches := titleRegex.FindStringSubmatch(body)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

func detectTech(headers http.Header, body string) []string {
	var techs []string

	if server := headers.Get("Server"); server != "" {
		techs = append(techs, server)
	}
	if powered := headers.Get("X-Powered-By"); powered != "" {
		techs = append(techs, powered)
	}

	if strings.Contains(body, "wp-content") {
		techs = append(techs, "WordPress")
	}
	if strings.Contains(body, "Drupal") {
		techs = append(techs, "Drupal")
	}

	return techs
}
