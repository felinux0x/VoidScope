package stealth

import (
	"math/rand"
	"time"
)

type Engine struct {
	JitterMinMs int
	JitterMaxMs int
	Ticker      *time.Ticker
}

func NewEngine(jitterMin, jitterMax, rateLimit int) *Engine {
	e := &Engine{
		JitterMinMs: jitterMin,
		JitterMaxMs: jitterMax,
	}

	if rateLimit > 0 {
		// Simple ticker based rate limiter
		e.Ticker = time.NewTicker(time.Second / time.Duration(rateLimit))
	}

	return e
}

func (e *Engine) Wait() {
	// 1. Rate Limit
	if e.Ticker != nil {
		<-e.Ticker.C
	}

	// 2. Jitter
	if e.JitterMaxMs > 0 {
		rand.Seed(time.Now().UnixNano())
		delta := e.JitterMaxMs - e.JitterMinMs
		if delta <= 0 {
			delta = 1
		}

		delay := e.JitterMinMs + rand.Intn(delta)
		time.Sleep(time.Duration(delay) * time.Millisecond)
	}
}
