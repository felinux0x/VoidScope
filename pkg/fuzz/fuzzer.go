package fuzz

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/felinux0x/VoidScope/pkg/web"
)

var CommonSensitiveFiles = []string{
	".env",
	".git/HEAD",
	".ds_store",
	"wp-config.php.bak",
	"backup.zip",
	"web.config",
	"server-status",
	"api/.env",
	"admin/",
}

type Result struct {
	Target string
	Path   string
	Status int
}

type Fuzzer struct {
	Prober *web.Prober
}

func NewFuzzer(prober *web.Prober) *Fuzzer {
	return &Fuzzer{Prober: prober}
}

func (f *Fuzzer) Scan(url string) []Result {
	var results []Result
	baseURL := strings.TrimRight(url, "/")

	// We can run these in parallel, but limit concurrency per host to avoid instant ban
	var wg sync.WaitGroup
	resultChan := make(chan Result, len(CommonSensitiveFiles))

	for _, path := range CommonSensitiveFiles {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			targetURL := fmt.Sprintf("%s/%s", baseURL, p)

			// Re-use prober logic but stripped down? Prober expects host/port.
			// Let's just use the client directly to allow path fuzzing
			req, err := http.NewRequest("GET", targetURL, nil)
			if err != nil {
				return
			}

			// Use existing client config (proxy, stealth etc is embedded in Client if Prober set it up right?
			// Actually Prober has Stealth engine outside. We need to respect it.
			if f.Prober.Stealth != nil {
				f.Prober.Stealth.Wait()
			}

			res, err := f.Prober.Client.Do(req)
			if err != nil {
				return
			}
			defer res.Body.Close()

			// Filter interesting results
			if res.StatusCode == 200 || res.StatusCode == 403 {
				resultChan <- Result{Target: baseURL, Path: p, Status: res.StatusCode}
			}
		}(path)
	}

	wg.Wait()
	close(resultChan)

	for r := range resultChan {
		results = append(results, r)
	}
	return results
}
