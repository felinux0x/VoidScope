package waf

import (
	"net/http"
	"strings"
)

// Detect analyzes headers and body to find WAF traces
func Detect(headers http.Header, body string) string {
	// 1. Check Headers
	if server := headers.Get("Server"); server != "" {
		if strings.Contains(strings.ToLower(server), "cloudflare") {
			return "Cloudflare"
		}
		if strings.Contains(strings.ToLower(server), "akamai") {
			return "Akamai"
		}
		if strings.Contains(strings.ToLower(server), "imperva") {
			return "Imperva"
		}
	}

	// Cloudflare Headers
	if headers.Get("cf-ray") != "" {
		return "Cloudflare"
	}

	// AWS WAF
	if headers.Get("x-amzn-requestid") != "" && strings.Contains(body, "Request blocked") {
		return "AWS WAF"
	}

	// 2. Check Body Content (Block pages)
	if strings.Contains(body, "Cloudflare Ray ID") {
		return "Cloudflare"
	}
	if strings.Contains(body, "The request was rejected") && strings.Contains(body, "support ID") {
		return "F5 BIG-IP"
	}

	return ""
}
