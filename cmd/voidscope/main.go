package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/felinux0x/VoidScope/internal/utils"
	"github.com/felinux0x/VoidScope/pkg/config"
	"github.com/felinux0x/VoidScope/pkg/dns"
	"github.com/felinux0x/VoidScope/pkg/fuzz"
	"github.com/felinux0x/VoidScope/pkg/js"
	"github.com/felinux0x/VoidScope/pkg/ports"
	"github.com/felinux0x/VoidScope/pkg/report"
	"github.com/felinux0x/VoidScope/pkg/stealth"
	"github.com/felinux0x/VoidScope/pkg/subdomains"
	"github.com/felinux0x/VoidScope/pkg/web"
)

type Output struct {
	Timestamp  string   `json:"timestamp"`
	Type       string   `json:"type"`
	Target     string   `json:"target"`
	Port       int      `json:"port,omitempty"`
	Banner     string   `json:"banner,omitempty"`
	URL        string   `json:"url,omitempty"`
	StatusCode int      `json:"status_code,omitempty"`
	Title      string   `json:"title,omitempty"`
	Tech       []string `json:"tech,omitempty"`
	WAF        string   `json:"waf,omitempty"`
	Fuzz       []string `json:"fuzz,omitempty"`
	Secrets    []string `json:"secrets,omitempty"`
}

func main() {
	// 0. Args & Config
	var configPath string
	flag.StringVar(&configPath, "config", "", "Path to config.json")
	var targetFlag string
	var concurrency int
	var silent bool
	var portsFlag string
	var proxyFlag string
	var jsonFlag bool
	var jitterMin int
	var jitterMax int
	var rateLimit int
	var reportPath string
	var fuzzFlag bool
	var activeDNS bool
	var jsScan bool

	flag.StringVar(&targetFlag, "target", "", "Target domain")
	flag.IntVar(&concurrency, "c", 0, "Concurrency")
	flag.BoolVar(&silent, "silent", false, "Silent mode")
	flag.StringVar(&portsFlag, "ports", "", "Ports")
	flag.StringVar(&proxyFlag, "proxy", "", "Proxy URL")
	flag.BoolVar(&jsonFlag, "json", false, "JSONL")
	flag.IntVar(&jitterMin, "jitter-min", 0, "Min Jitter")
	flag.IntVar(&jitterMax, "jitter-max", 0, "Max Jitter")
	flag.IntVar(&rateLimit, "rate", 0, "Rate")
	flag.StringVar(&reportPath, "report", "", "HTML Report")
	flag.BoolVar(&fuzzFlag, "fuzz", false, "Enable Fuzzing")
	flag.BoolVar(&activeDNS, "active-dns", false, "Enable Active DNS Bruteforce")
	flag.BoolVar(&jsScan, "js", false, "Enable JS Secret Scan")

	flag.Parse()

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Overrides
	if targetFlag != "" {
		cfg.Target = targetFlag
	}
	if concurrency > 0 {
		cfg.Concurrency = concurrency
	}
	if silent {
		cfg.Silent = true
	}
	if portsFlag != "" {
		cfg.Ports = portsFlag
	}
	if proxyFlag != "" {
		cfg.Proxy = proxyFlag
	}
	if jsonFlag {
		cfg.JSON = true
	}
	if jitterMin > 0 {
		cfg.JitterMin = jitterMin
	}
	if jitterMax > 0 {
		cfg.JitterMax = jitterMax
	}
	if rateLimit > 0 {
		cfg.RateLimit = rateLimit
	}
	if cfg.JSON {
		cfg.Silent = true
	}

	if !cfg.Silent {
		utils.PrintBanner()
		utils.Log(utils.Info, "Configuration loaded.")
		if activeDNS {
			utils.Log(utils.Warning, "Active DNS: ENABLED 🧱")
		}
		if jsScan {
			utils.Log(utils.Warning, "JS Secret Scan: ENABLED 📜")
		}
	}

	// Handle graceful shutdown so we don't lose data on Ctrl+C
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		if !cfg.JSON {
			utils.Log(utils.Warning, "Shutting down...")
		}
		cancel()
	}()

	// Feed targets (either flag or stdin)
	targets := make(chan string)
	go func() {
		defer close(targets)
		if cfg.Target != "" {
			targets <- cfg.Target
		}
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				t := strings.TrimSpace(scanner.Text())
				if t != "" {
					select {
					case targets <- t:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()

	// Init all the scanners
	subRunner := subdomains.NewRunner()
	portScanner := ports.NewScanner()
	stealthEngine := stealth.NewEngine(cfg.JitterMin, cfg.JitterMax, cfg.RateLimit)

	prober, err := web.NewProber(cfg.Proxy, stealthEngine)
	if err != nil {
		os.Exit(1)
	}

	fuzzer := fuzz.NewFuzzer(prober)
	dnsBrute := dns.NewBruteforcer(stealthEngine)
	jsScanner := js.NewScanner(prober)

	var rootTargets []string
	for t := range targets {
		rootTargets = append(rootTargets, t)
	}
	if len(rootTargets) == 0 {
		os.Exit(1)
	}

	var reportResults []report.WebResult
	var reportMu sync.Mutex

	// 1. Enumerate Subdomains
	if !cfg.Silent {
		utils.Log(utils.Info, "Starting Subdomain Discovery...")
	}
	distinctHosts := make(map[string]bool)
	for _, t := range rootTargets {
		distinctHosts[t] = true
	}

	subCtx, subCancel := context.WithTimeout(ctx, 15*time.Minute)
	defer subCancel()

	for _, t := range rootTargets {
		if ctx.Err() != nil {
			break
		}
		if strings.Contains(t, ".") {
			// Passive sources (crt.sh etc)
			subResults := subRunner.Run(subCtx, t)
			for sub := range subResults {
				distinctHosts[sub] = true
				if !cfg.JSON && !cfg.Silent {
					utils.Log(utils.Info, "[SUB] Found: %s", sub)
				}
				if cfg.JSON {
					emitJSON("subdomain", sub, 0, "", nil, nil, nil)
				}
			}

			// Active Bruteforce if flag is set
			if activeDNS {
				if !cfg.Silent {
					utils.Log(utils.Info, "[DNS] Bruteforcing %s...", t)
				}
				activeResults := dnsBrute.Run(subCtx, t)
				for sub := range activeResults {
					if !distinctHosts[sub] {
						distinctHosts[sub] = true
						if !cfg.JSON && !cfg.Silent {
							utils.Log(utils.Success, "[DNS] Active Found: %s", sub)
						}
						if cfg.JSON {
							emitJSON("subdomain", sub, 0, "", nil, nil, nil)
						}
					}
				}
			}
		}
	}

	// 2. Scan Ports
	if ctx.Err() == nil {
		hostList := make([]string, 0, len(distinctHosts))
		for h := range distinctHosts {
			hostList = append(hostList, h)
		}
		if !cfg.Silent {
			utils.Log(utils.Info, "Starting Port Scan on %d hosts...", len(hostList))
		}

		type hostPort struct {
			Host string
			Port int
		}
		openPortResults := make(chan hostPort, len(hostList)*10)
		var scanWg sync.WaitGroup
		sem := make(chan struct{}, 10)

		scanWg.Add(len(hostList))
		for _, h := range hostList {
			go func(host string) {
				defer scanWg.Done()
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-sem }()
				if ctx.Err() != nil {
					return
				}

				results := portScanner.Scan(host, cfg.Concurrency)
				for _, res := range results {
					bannerStr := ""
					if res.Banner != "" {
						bannerStr = fmt.Sprintf(" [%s]", res.Banner)
					}

					if !cfg.JSON && !cfg.Silent {
						utils.Log(utils.Info, "[PORT] %s:%d open%s", host, res.Port, bannerStr)
					}
					if cfg.JSON {
						emitJSON("port", host, res.Port, res.Banner, nil, nil, nil)
					}
					openPortResults <- hostPort{Host: host, Port: res.Port}
				}
			}(h)
		}
		go func() { scanWg.Wait(); close(openPortResults) }()

		// 3. Web Probing & Exploitation
		if ctx.Err() == nil {
			if !cfg.Silent {
				utils.Log(utils.Info, "Starting HTTP Probing...")
			}

			var probeWg sync.WaitGroup
			probeSem := make(chan struct{}, cfg.Concurrency)

			for hp := range openPortResults {
				if ctx.Err() != nil {
					break
				}
				probeWg.Add(1)
				go func(target hostPort) {
					defer probeWg.Done()
					select {
					case probeSem <- struct{}{}:
					case <-ctx.Done():
						return
					}
					defer func() { <-probeSem }()
					if ctx.Err() != nil {
						return
					}

					res := prober.Probe(target.Host, target.Port)
					if res != nil {
						var fuzzPaths []string
						var secretsFound []string

						// Fuzzing
						if fuzzFlag {
							findings := fuzzer.Scan(res.URL)
							for _, f := range findings {
								fuzzPaths = append(fuzzPaths, fmt.Sprintf("%s (%d)", f.Path, f.Status))
								if !cfg.Silent {
									utils.Log(utils.Warning, "[FUZZ] %s/%s [%d]", f.Target, f.Path, f.Status)
								}
							}
						}

						// JS Scanning
						if jsScan {
							// We need to fetch the HTML content first. Prober result doesn't have body.
							// We can quickly re-fetch or modify Prober. For now re-fetch with Client (stealth applied)
							req, _ := http.NewRequest("GET", res.URL, nil)
							if resp, err := prober.Client.Do(req); err == nil {
								body, _ := io.ReadAll(resp.Body)
								resp.Body.Close()
								jsRes := jsScanner.Scan(string(body), res.URL)
								for _, secret := range jsRes {
									secretsFound = append(secretsFound, fmt.Sprintf("%s: %s", secret.Type, secret.Value))
									if !cfg.Silent {
										utils.Log(utils.Error, "[JS] %s found in %s", secret.Type, secret.URL)
									}
								}
							}
						}

						if cfg.JSON {
							emitJSON("web", target.Host, target.Port, "", res, fuzzPaths, secretsFound)
						} else {
							techStr := ""
							if len(res.Tech) > 0 {
								techStr = fmt.Sprintf(" [%s]", strings.Join(res.Tech, ", "))
							}
							wafStr := ""
							if res.WAF != "" {
								wafStr = fmt.Sprintf(" [WAF: %s]", res.WAF)
							}
							utils.Log(utils.Success, "%s [%d] - %s%s%s", res.URL, res.StatusCode, res.Title, techStr, wafStr)
						}

						if reportPath != "" {
							// Convert to Report struct (simplified)
							// Ideally report handles all this data. For now we just add basics.
							reportMu.Lock()
							reportResults = append(reportResults, report.WebResult{
								URL: res.URL, StatusCode: res.StatusCode, Title: res.Title, Tech: res.Tech, WAF: res.WAF,
							})
							reportMu.Unlock()
						}
					}
				}(hp)
			}
			probeWg.Wait()
		}
	}

	if !cfg.Silent {
		utils.Log(utils.Info, "Scan completed.")
	}
	if reportPath != "" && len(reportResults) > 0 {
		report.Generate(reportPath, reportResults)
	}
}

func emitJSON(typ string, target string, port int, banner string, webRes *web.Result, fuzz []string, secrets []string) {
	out := Output{
		Timestamp: time.Now().Format(time.RFC3339),
		Type:      typ,
		Target:    target,
		Port:      port,
		Banner:    banner,
		Fuzz:      fuzz,
		Secrets:   secrets,
	}
	if webRes != nil {
		out.URL = webRes.URL
		out.StatusCode = webRes.StatusCode
		out.Title = webRes.Title
		out.Tech = webRes.Tech
		out.WAF = webRes.WAF
	}
	bytes, _ := json.Marshal(out)
	utils.WriteJSONL(string(bytes))
}
