package utils

import (
	"fmt"
	"os"
	"sync"
)

// ANSI Color Codes
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorGray   = "\033[90m"
)

type LogLevel int

const (
	Info LogLevel = iota
	Warning
	Error
	Success
	Debug
)

// Thread-safe output
var mu sync.Mutex

func PrintBanner() {
	banner := `
%s██╗   ██╗ ██████╗ ██╗██████╗ ███████╗ ██████╗ ██████╗ ██████╗ ███████╗
██║   ██║██╔═══██╗██║██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
██║   ██║██║   ██║██║██║  ██║███████╗██║     ██║   ██║██████╔╝█████╗  
╚██╗ ██╔╝██║   ██║██║██║  ██║╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝  
 ╚████╔╝ ╚██████╔╝██║██████╔╝███████║╚██████╗╚██████╔╝██║     ███████╗
  ╚═══╝   ╚═════╝ ╚═╝╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝%s
                                            v2.2.0-ELITE
    `
	fmt.Fprintf(os.Stderr, banner, ColorPurple, ColorReset)
	fmt.Fprintln(os.Stderr, ColorGray+"    :: Advanced Reconnaissance Operations :: VoidScope"+ColorReset)
	fmt.Fprintln(os.Stderr, "")
}

func Log(level LogLevel, format string, args ...interface{}) {
	mu.Lock()
	defer mu.Unlock()

	msg := fmt.Sprintf(format, args...)
	switch level {
	case Info:
		fmt.Fprintf(os.Stderr, "%s[INF]%s %s\n", ColorBlue, ColorReset, msg)
	case Warning:
		fmt.Fprintf(os.Stderr, "%s[WRN]%s %s\n", ColorYellow, ColorReset, msg)
	case Error:
		fmt.Fprintf(os.Stderr, "%s[ERR]%s %s\n", ColorRed, ColorReset, msg)
	case Success:
		fmt.Printf("%s[+]%s %s\n", ColorGreen, ColorReset, msg)
	case Debug:
		fmt.Fprintf(os.Stderr, "%s[DBG]%s %s\n", ColorGray, ColorReset, msg)
	}
}

// WriteJSONL writes a raw JSON line to stdout (bypassing log format)
func WriteJSONL(jsonStr string) {
	mu.Lock()
	defer mu.Unlock()
	fmt.Println(jsonStr)
}
