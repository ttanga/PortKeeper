package portkeeper

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddr        string       `yaml:"listen_addr"`
	DefaultTTL        string       `yaml:"default_ttl"`
	StateFile         string       `yaml:"state_file"`
	RateLimitRequests int          `yaml:"rate_limit_requests"`
	RateLimitWindow   string       `yaml:"rate_limit_window"`
	Access            []AccessRule `yaml:"access"`
}

type AccessRule struct {
	GUID string `yaml:"guid"`
	Port uint16 `yaml:"port"`
}

func LoadConfig(path string) (Config, time.Duration, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, 0, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, 0, fmt.Errorf("parse config: %w", err)
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8787"
	}
	if cfg.DefaultTTL == "" {
		cfg.DefaultTTL = "24h"
	}
	if cfg.StateFile == "" {
		cfg.StateFile = "/var/lib/portkeeper/state.json"
	}
	if cfg.RateLimitRequests == 0 {
		cfg.RateLimitRequests = 10
	}
	if cfg.RateLimitWindow == "" {
		cfg.RateLimitWindow = "1m"
	}

	ttl, err := time.ParseDuration(cfg.DefaultTTL)
	if err != nil || ttl <= 0 {
		return Config{}, 0, fmt.Errorf("default_ttl must be a positive Go duration")
	}
	rateLimitWindow, err := time.ParseDuration(cfg.RateLimitWindow)
	if err != nil || rateLimitWindow <= 0 {
		return Config{}, 0, fmt.Errorf("rate_limit_window must be a positive Go duration")
	}
	if cfg.RateLimitRequests < 1 {
		return Config{}, 0, fmt.Errorf("rate_limit_requests must be at least 1")
	}
	if len(cfg.Access) == 0 {
		return Config{}, 0, fmt.Errorf("access must contain at least one GUID/port mapping")
	}

	seenGUID := make(map[string]struct{}, len(cfg.Access))
	for i, rule := range cfg.Access {
		if rule.GUID == "" {
			return Config{}, 0, fmt.Errorf("access[%d].guid is empty", i)
		}
		if rule.Port == 0 {
			return Config{}, 0, fmt.Errorf("access[%d].port must be between 1 and 65535", i)
		}
		if _, ok := seenGUID[rule.GUID]; ok {
			return Config{}, 0, fmt.Errorf("duplicate GUID in access[%d]", i)
		}
		seenGUID[rule.GUID] = struct{}{}
	}
	return cfg, ttl, nil
}
