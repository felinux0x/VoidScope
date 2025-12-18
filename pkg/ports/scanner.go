package ports

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type PortResult struct {
	Port   int
	Banner string
}

type Scanner struct {
	Ports []int
}

func NewScanner() *Scanner {
	// Top 100 common ports
	return &Scanner{
		Ports: []int{
			20, 21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 443, 445, 465, 587,
			993, 995, 1080, 1194, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8008,
			8080, 8443, 8888, 9000, 27017,
		},
	}
}

func (s *Scanner) Scan(host string, concurrency int) []PortResult {
	if concurrency <= 0 {
		concurrency = 25
	}

	portsChan := make(chan int, len(s.Ports))
	resultsChan := make(chan PortResult)
	var wg sync.WaitGroup

	// Spin up workers
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portsChan {
				if s.checkPort(host, port) {
					banner := s.grabBanner(host, port)
					resultsChan <- PortResult{Port: port, Banner: banner}
				}
			}
		}()
	}

	// Dispatch ports
	go func() {
		for _, p := range s.Ports {
			portsChan <- p
		}
		close(portsChan)
	}()

	// Cleanup
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Gather results
	var openPorts []PortResult
	for p := range resultsChan {
		openPorts = append(openPorts, p)
	}

	// Sort by port number
	for i := 0; i < len(openPorts); i++ {
		for j := i + 1; j < len(openPorts); j++ {
			if openPorts[i].Port > openPorts[j].Port {
				openPorts[i], openPorts[j] = openPorts[j], openPorts[i]
			}
		}
	}

	return openPorts
}

func (s *Scanner) checkPort(host string, port int) bool {
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", address, 1*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (s *Scanner) grabBanner(host string, port int) string {
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil || n == 0 {
		return ""
	}

	// Clean up banner
	output := string(buffer[:n])
	lines := strings.Split(output, "\n")
	if len(lines) > 0 {
		return strings.TrimSpace(strings.Trim(lines[0], "\r"))
	}
	return ""
}
