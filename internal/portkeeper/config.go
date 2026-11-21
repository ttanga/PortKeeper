package portkeeper

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddr        string       `yaml:"listen_addr" json:"listen_addr"`
	PublicBaseURL     string       `yaml:"public_base_url" json:"public_base_url"`
	DefaultTTL        string       `yaml:"default_ttl" json:"default_ttl"`
	StateFile         string       `yaml:"state_file" json:"state_file"`
	RateLimitRequests int          `yaml:"rate_limit_requests" json:"rate_limit_requests"`
	RateLimitWindow   string       `yaml:"rate_limit_window" json:"rate_limit_window"`
	Access            []AccessRule `yaml:"access" json:"access"`
	Admin             AdminConfig  `yaml:"admin" json:"admin"`
}

type AdminConfig struct {
	Enabled     bool   `yaml:"enabled" json:"enabled"`
	ListenAddr  string `yaml:"listen_addr" json:"listen_addr"`
	HTTPS       bool   `yaml:"https" json:"https"`
	TLSCertFile string `yaml:"tls_cert_file" json:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file" json:"tls_key_file"`
}

type AccessRule struct {
	ServiceName string `yaml:"service_name,omitempty" json:"service_name,omitempty"`
	Path string `yaml:"path,omitempty" json:"path,omitempty"`
	GUID string `yaml:"guid" json:"guid"`
	Port uint16 `yaml:"port" json:"port"`
	AllowedNetworks []string `yaml:"allowed_networks,omitempty" json:"allowed_networks,omitempty"`
}

func LoadConfig(path string) (Config, time.Duration, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, 0, fmt.Errorf("read config: %w", err)
	}
	return ParseConfig(data)
}

func ParseConfig(data []byte) (Config, time.Duration, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, 0, fmt.Errorf("parse config: %w", err)
	}
	return ValidateConfig(cfg)
}

func ValidateConfig(cfg Config) (Config, time.Duration, error) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8787"
	}
	cfg.PublicBaseURL = strings.TrimRight(strings.TrimSpace(cfg.PublicBaseURL), "/")
	if cfg.PublicBaseURL != "" {
		parsed, parseErr := url.Parse(cfg.PublicBaseURL)
		if parseErr != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
			return Config{}, 0, fmt.Errorf("public_base_url must be an absolute http(s) URL with host and optional port, without path, query or fragment")
		}
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
	if cfg.Admin.ListenAddr == "" {
		cfg.Admin.ListenAddr = "0.0.0.0:8083"
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
		cfg.Access[i].ServiceName = strings.TrimSpace(rule.ServiceName)
		if rule.Path == "" { cfg.Access[i].Path = "/" } else {
			if !strings.HasPrefix(rule.Path, "/") || strings.HasPrefix(rule.Path, "//") || strings.ContainsAny(rule.Path, "?#\\") || strings.ContainsAny(rule.Path, "\r\n\t") { return Config{}, 0, fmt.Errorf("access[%d].path must be a relative URL path starting with /, without query or fragment", i) }
			cfg.Access[i].Path = rule.Path
		}
		if len([]rune(cfg.Access[i].ServiceName)) > 120 { return Config{}, 0, fmt.Errorf("access[%d].service_name must contain at most 120 characters", i) }
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
		seenNetworks := make(map[string]struct{}, len(rule.AllowedNetworks))
		for j, cidr := range rule.AllowedNetworks {
			ip, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
			if err != nil || ip == nil || network == nil {
				return Config{}, 0, fmt.Errorf("access[%d].allowed_networks[%d] must be a valid IPv4 or IPv6 CIDR", i, j)
			}
			canonical := network.String()
			if _, exists := seenNetworks[canonical]; exists {
				return Config{}, 0, fmt.Errorf("access[%d].allowed_networks contains duplicate %s", i, canonical)
			}
			seenNetworks[canonical] = struct{}{}
			cfg.Access[i].AllowedNetworks[j] = canonical
		}
	}
	if cfg.Admin.Enabled {
		if _, _, err := net.SplitHostPort(cfg.Admin.ListenAddr); err != nil {
			return Config{}, 0, fmt.Errorf("admin.listen_addr must be a valid host:port address")
		}
		_, apiPort, apiErr := net.SplitHostPort(cfg.ListenAddr)
		_, adminPort, adminErr := net.SplitHostPort(cfg.Admin.ListenAddr)
		if apiErr == nil && adminErr == nil && apiPort == adminPort {
			return Config{}, 0, fmt.Errorf("admin.listen_addr must use a different port from listen_addr")
		}
	}
	if cfg.Admin.Enabled && cfg.Admin.HTTPS && (cfg.Admin.TLSCertFile == "" || cfg.Admin.TLSKeyFile == "") {
		return Config{}, 0, fmt.Errorf("admin HTTPS requires tls_cert_file and tls_key_file")
	}
	return cfg, ttl, nil
}
