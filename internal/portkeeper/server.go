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

func (s *Server) ApplyConfig(cfg Config, ttl time.Duration) error {
	rateWindow, err := time.ParseDuration(cfg.RateLimitWindow)
	if err != nil || rateWindow <= 0 {
		rateWindow = time.Minute
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	oldPortsSet := make(map[uint16]struct{}, len(s.guidPorts))
	for _, port := range s.guidPorts {
		oldPortsSet[port] = struct{}{}
	}
	newPortsSet := make(map[uint16]struct{}, len(cfg.Access))
	newGUIDPorts := make(map[string]uint16, len(cfg.Access))
	for _, rule := range cfg.Access {
		newGUIDPorts[rule.GUID] = rule.Port
		newPortsSet[rule.Port] = struct{}{}
	}
	unionPorts := make(map[uint16]struct{}, len(oldPortsSet)+len(newPortsSet))
	oldPorts := make([]uint16, 0, len(oldPortsSet))
	newPorts := make([]uint16, 0, len(newPortsSet))
	for port := range oldPortsSet {
		oldPorts = append(oldPorts, port)
		unionPorts[port] = struct{}{}
	}
	for port := range newPortsSet {
		newPorts = append(newPorts, port)
		unionPorts[port] = struct{}{}
	}
	union := make([]uint16, 0, len(unionPorts))
	for port := range unionPorts {
		union = append(union, port)
	}

	oldEntries := make([]AccessState, 0, len(s.entries))
	for _, entry := range s.entries {
		if entry.ExpiresAt.After(time.Now()) {
			oldEntries = append(oldEntries, entry)
		}
	}
	restoreOldFirewall := func() {
		_ = s.firewall.Ensure(oldPorts)
		for _, port := range union {
			_ = s.firewall.FlushPort(port)
		}
		for _, entry := range oldEntries {
			ip := net.ParseIP(entry.IP)
			if ip != nil && entry.ExpiresAt.After(time.Now()) {
				_ = s.firewall.Refresh(entry.Port, ip, time.Until(entry.ExpiresAt))
			}
		}
		_ = s.store.Save(oldEntries)
	}

	if err := s.firewall.Ensure(newPorts); err != nil {
		restoreOldFirewall()
		return fmt.Errorf("rebuild firewall chains: %w", err)
	}
	for _, port := range union {
		if err := s.firewall.FlushPort(port); err != nil {
			restoreOldFirewall()
			return fmt.Errorf("clear old firewall set for port %d: %w", port, err)
		}
	}

	nextEntries := make(map[string]AccessState)
	persisted := make([]AccessState, 0, len(oldEntries))
	for _, entry := range oldEntries {
		if _, keep := newPortsSet[entry.Port]; !keep {
			continue
		}
		ip := net.ParseIP(entry.IP)
		if ip == nil {
			continue
		}
		if err := s.firewall.Refresh(entry.Port, ip, time.Until(entry.ExpiresAt)); err != nil {
			restoreOldFirewall()
			return fmt.Errorf("restore active access for port %d: %w", entry.Port, err)
		}
		nextEntries[stateKey(entry.Port, entry.IP)] = entry
		persisted = append(persisted, entry)
	}
	if err := s.store.Save(persisted); err != nil {
		restoreOldFirewall()
		return fmt.Errorf("save filtered access state: %w", err)
	}

	s.guidPorts = newGUIDPorts
	s.ttl = ttl
	s.limiter = NewRateLimiter(cfg.RateLimitRequests, rateWindow)
	s.entries = nextEntries
	return nil
}

// GrantAccess adds the requesting IP to the allowlist for a configured port.
func (s *Server) GrantAccess(port uint16, ip net.IP) (time.Time, error) {
	if ip == nil {
		return time.Time{}, errors.New("invalid client IP")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	configured := false
	for _, configuredPort := range s.guidPorts {
		if configuredPort == port { configured = true; break }
	}
	if !configured { return time.Time{}, errors.New("port is not configured") }

	key := stateKey(port, ip.String())
	previous, hadPrevious := s.entries[key]
	expiresAt := time.Now().Add(s.ttl)
	if err := s.firewall.Refresh(port, ip, s.ttl); err != nil {
		return time.Time{}, fmt.Errorf("update firewall allowlist: %w", err)
	}
	s.entries[key] = AccessState{Port: port, IP: ip.String(), ExpiresAt: expiresAt}
	if err := s.saveLocked(); err != nil {
		if hadPrevious {
			s.entries[key] = previous
			if previous.ExpiresAt.After(time.Now()) { _ = s.firewall.Refresh(port, ip, time.Until(previous.ExpiresAt)) }
		} else {
			delete(s.entries, key)
			_ = s.firewall.run("ipset", "del", setName(port, ip), ip.String())
		}
		return time.Time{}, fmt.Errorf("save access state: %w", err)
	}
	return expiresAt, nil
}

func stateKey(port uint16, ip string) string {
	return fmt.Sprintf("%d|%s", port, ip)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ip, err := requestIP(r)
	if err != nil {
		http.Error(w, "invalid remote address", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if allowed, retryAfter := s.limiter.Allow(ip.String(), time.Now()); !allowed {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfterSeconds(retryAfter)))
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
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
