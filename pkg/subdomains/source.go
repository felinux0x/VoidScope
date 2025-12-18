package subdomains

import "context"

// Result represents a found subdomain
type Result struct {
	Type   string
	Source string
	Value  string
	Error  error
}

// Source is an interface that all subdomain discovery sources must implement
type Source interface {
	Run(ctx context.Context, domain string, results chan<- Result)
	Name() string
}
