package subdomains

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/felinux0x/VoidScope/internal/utils"
)

type HackerTargetSource struct{}

func (s *HackerTargetSource) Name() string {
	return "hackertarget"
}

func (s *HackerTargetSource) Run(ctx context.Context, domain string, results chan<- Result) {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		results <- Result{Source: s.Name(), Error: err}
		return
	}
	req.Header.Set("User-Agent", utils.RandomUserAgent())

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		results <- Result{Source: s.Name(), Error: err}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		results <- Result{Source: s.Name(), Error: fmt.Errorf("unexpected status code: %d", resp.StatusCode)}
		return
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ",")
		if len(parts) >= 1 {
			// HackerTarget returns "subdomain,ip"
			// Example: www.example.com,93.184.216.34
			results <- Result{Source: s.Name(), Value: parts[0]}
		}
	}
}
