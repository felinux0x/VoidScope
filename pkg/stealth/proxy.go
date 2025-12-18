package stealth

import (
	"fmt"
	"net/http"
	"net/url"
)

// ConfigureProxy returns a Transport configured with the proxy
func ConfigureProxy(proxyAddr string, transport *http.Transport) error {
	if proxyAddr == "" {
		return nil
	}

	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		return fmt.Errorf("invalid proxy URL: %v", err)
	}

	transport.Proxy = http.ProxyURL(proxyURL)
	return nil
}
