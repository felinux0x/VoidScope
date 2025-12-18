package config

import (
	"encoding/json"
	"os"
)

type Config struct {
	Target      string `json:"target"`
	Concurrency int    `json:"concurrency"`
	Ports       string `json:"ports"`
	Proxy       string `json:"proxy"`
	JSON        bool   `json:"json"`
	Silent      bool   `json:"silent"`

	// Stealth
	JitterMin int `json:"jitter_min_ms"` // Minimum delay in ms
	JitterMax int `json:"jitter_max_ms"` // Maximum delay in ms
	RateLimit int `json:"rate_limit"`    // Requests per second
}

func Default() *Config {
	return &Config{
		Concurrency: 25,
		Ports:       "top100",
		JitterMin:   0,
		JitterMax:   0,
		RateLimit:   0, // Unlimited
	}
}

func Load(path string) (*Config, error) {
	if path == "" {
		return Default(), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := Default()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}
