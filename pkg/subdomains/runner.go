package subdomains

import (
	"context"
	"strings"
	"sync"
)

type Runner struct {
	Sources []Source
}

func NewRunner() *Runner {
	return &Runner{
		Sources: []Source{
			&CrtShSource{},
			&HackerTargetSource{},
		},
	}
}

func (r *Runner) Run(ctx context.Context, domain string) <-chan string {
	results := make(chan Result)
	uniqueSubdomains := make(chan string)

	// Start sources
	var wg sync.WaitGroup
	for _, source := range r.Sources {
		wg.Add(1)
		go func(s Source) {
			defer wg.Done()
			s.Run(ctx, domain, results)
		}(source)
	}

	// Close results channel when all sources are done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Deduplication and processing
	go func() {
		defer close(uniqueSubdomains)
		seen := make(map[string]bool)
		for res := range results {
			if res.Error != nil {
				// Log error? For now, skip
				continue
			}

			// Basic cleanup
			cleanVal := strings.TrimSpace(res.Value)
			// Handle wildcards *.example.com -> example.com
			cleanVal = strings.TrimPrefix(cleanVal, "*.")

			if cleanVal == "" {
				continue
			}

			if !seen[cleanVal] {
				seen[cleanVal] = true
				uniqueSubdomains <- cleanVal
			}
		}
	}()

	return uniqueSubdomains
}
