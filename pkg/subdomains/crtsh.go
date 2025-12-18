package subdomains

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type CrtShSource struct{}

type crtShEntry struct {
	NameValue string `json:"name_value"`
}

func (s *CrtShSource) Name() string {
	return "crt.sh"
}

func (s *CrtShSource) Run(ctx context.Context, domain string, results chan<- Result) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		results <- Result{Source: s.Name(), Error: err}
		return
	}

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

	var entries []crtShEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		results <- Result{Source: s.Name(), Error: err}
		return
	}

	for _, entry := range entries {
		results <- Result{Source: s.Name(), Value: entry.NameValue}
	}
}
