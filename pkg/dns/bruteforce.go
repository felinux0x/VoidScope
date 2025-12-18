package dns

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/felinux0x/VoidScope/pkg/stealth"
)

// Mini Top-List for embedded use
var TopSubdomains = []string{
	"www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp", "secure",
	"vpn", "m", "shop", "ftp", "mail2", "test", "portal", "ns", "ww1", "host",
	"support", "dev", "web", "bbs", "ww42", "mx", "email", "cloud", "1", "mail1",
	"2", "forum", "owa", "www2", "gw", "admin", "store", "mx1", "cdn", "api",
	"exchange", "app", "gov", "2web", "vps", "zimbra", "backup", "service", "intranet",
	"staging", "jenkins", "gitlab", "db", "prod", "ops", "monitor", "dashboard",
}

type Bruteforcer struct {
	Stealth *stealth.Engine
}

func NewBruteforcer(engine *stealth.Engine) *Bruteforcer {
	return &Bruteforcer{Stealth: engine}
}

func (b *Bruteforcer) Run(ctx context.Context, domain string) chan string {
	results := make(chan string)

	go func() {
		defer close(results)

		var wg sync.WaitGroup
		// Throttle DNS requests
		sem := make(chan struct{}, 20)

		for _, sub := range TopSubdomains {
			wg.Add(1)
			go func(s string) {
				defer wg.Done()

				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-sem }()

				if b.Stealth != nil {
					b.Stealth.Wait()
				}

				hostname := fmt.Sprintf("%s.%s", s, domain)

				// Use system resolver (looks like normal traffic)
				ips, err := net.LookupHost(hostname)
				if err == nil && len(ips) > 0 {
					results <- hostname
				}
			}(sub)
		}

		wg.Wait()
	}()

	return results
}
