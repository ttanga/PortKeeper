package portkeeper

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Server struct {
	guidPorts map[string]uint16
	ttl       time.Duration
	firewall  Firewall
	store     StateStore
	limiter   *RateLimiter
	mu        sync.Mutex
	entries   map[string]AccessState
}

type AccessResponse struct {
	Status    string `json:"status"`
	IP        string `json:"ip"`
	Port      uint16 `json:"port"`
	ExpiresIn int64  `json:"expires_in"`
}

func NewServer(cfg Config, ttl time.Duration, fw Firewall, store StateStore, entries []AccessState) *Server {
	guidPorts := make(map[string]uint16, len(cfg.Access))
	for _, rule := range cfg.Access {
		guidPorts[rule.GUID] = rule.Port
	}
	rateLimitWindow, err := time.ParseDuration(cfg.RateLimitWindow)
	if err != nil || rateLimitWindow <= 0 {
		rateLimitWindow = time.Minute
	}
	rateLimitRequests := cfg.RateLimitRequests
	if rateLimitRequests <= 0 {
		rateLimitRequests = 10
	}
	state := make(map[string]AccessState, len(entries))
	for _, entry := range entries {
		state[stateKey(entry.Port, entry.IP)] = entry
	}
	return &Server{
		guidPorts: guidPorts,
		ttl:       ttl,
		firewall:  fw,
		store:     store,
		limiter:   NewRateLimiter(rateLimitRequests, rateLimitWindow),
		entries:   state,
	}
}

func stateKey(port uint16, ip string) string {
	return fmt.Sprintf("%d|%s", port, ip)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip, err := requestIP(r)
	if err != nil {
		http.Error(w, "invalid remote address", http.StatusBadRequest)
		return
	}
	if allowed, retryAfter := s.limiter.Allow(ip.String(), time.Now()); !allowed {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfterSeconds(retryAfter)))
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	guid := strings.Trim(r.URL.Path, "/")
	if guid == "" || strings.Contains(guid, "/") {
		http.NotFound(w, r)
		return
	}
	port, ok := s.guidPorts[guid]
	if !ok {
		http.NotFound(w, r)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	expiresAt := time.Now().Add(s.ttl)
	if err := s.firewall.Refresh(port, ip, s.ttl); err != nil {
		http.Error(w, "failed to update access", http.StatusInternalServerError)
		return
	}
	entry := AccessState{Port: port, IP: ip.String(), ExpiresAt: expiresAt}
	s.entries[stateKey(port, ip.String())] = entry
	if err := s.saveLocked(); err != nil {
		http.Error(w, "failed to save access state", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(AccessResponse{Status: "ok", IP: ip.String(), Port: port, ExpiresIn: int64(s.ttl.Seconds())})
}

func requestIP(r *http.Request) (net.IP, error) {
	if forwarded := strings.TrimSpace(r.Header.Get("X-Real-IP")); forwarded != "" {
		if ip := net.ParseIP(forwarded); ip != nil {
			return ip, nil
		}
	}
	return remoteIP(r.RemoteAddr)
}

func remoteIP(remoteAddr string) (net.IP, error) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, errors.New("remote address is not an IP")
	}
	return ip, nil
}

func (s *Server) saveLocked() error {
	entries := make([]AccessState, 0, len(s.entries))
	for key, entry := range s.entries {
		if entry.ExpiresAt.After(time.Now()) {
			entries = append(entries, entry)
		} else {
			delete(s.entries, key)
		}
	}
	return s.store.Save(entries)
}
