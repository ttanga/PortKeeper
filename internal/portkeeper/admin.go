package portkeeper

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	webadmin "github.com/ttanga/PortKeeper/web/admin"
	"gopkg.in/yaml.v3"
)

const (
	adminCredentialsPath = "/var/lib/portkeeper/admin.json"
	adminCookieName      = "portkeeper_admin"
	passwordIterations   = 310000
	sessionLifetime      = 12 * time.Hour
)

type adminCredentials struct {
	Username      string `json:"username"`
	Salt          string `json:"salt"`
	PasswordHash  string `json:"password_hash"`
	SessionSecret string `json:"session_secret"`
}

type adminController struct {
	configPath string
	service    *Server
	mu         sync.Mutex
}

type adminSessions struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

func (s *adminSessions) add(token string, expires time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for key, expiry := range s.entries {
		if !expiry.After(now) {
			delete(s.entries, key)
		}
	}
	s.entries[token] = expires
}

func (s *adminSessions) valid(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	expires, ok := s.entries[token]
	if !ok {
		return false
	}
	if !expires.After(time.Now()) {
		delete(s.entries, token)
		return false
	}
	return true
}

func (s *adminSessions) revoke(token string) {
	s.mu.Lock()
	delete(s.entries, token)
	s.mu.Unlock()
}

func CreateAdminCredentials(username, password string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("admin username is required")
	}
	if len(password) < 12 {
		return errors.New("admin password must contain at least 12 characters")
	}
	salt := make([]byte, 16)
	secret := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("generate password salt: %w", err)
	}
	if _, err := rand.Read(secret); err != nil {
		return fmt.Errorf("generate session secret: %w", err)
	}
	creds := adminCredentials{
		Username: username,
		Salt: hex.EncodeToString(salt),
		PasswordHash: hex.EncodeToString(derivePassword([]byte(password), salt, passwordIterations)),
		SessionSecret: base64.RawURLEncoding.EncodeToString(secret),
	}
	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(adminCredentialsPath), 0750); err != nil {
		return err
	}
	tmp := adminCredentialsPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0640); err != nil {
		return err
	}
	if err := os.Rename(tmp, adminCredentialsPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(adminCredentialsPath, 0640); err != nil {
		return err
	}
	group, err := user.LookupGroup("portkeeper")
	if err != nil {
		return fmt.Errorf("lookup portkeeper group: %w", err)
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return fmt.Errorf("parse portkeeper group id: %w", err)
	}
	if err := os.Chown(adminCredentialsPath, 0, gid); err != nil {
		return fmt.Errorf("set admin credentials ownership: %w", err)
	}
	return nil
}

func derivePassword(password, salt []byte, iterations int) []byte {
	var block [4]byte
	block[3] = 1
	mac := hmac.New(sha256.New, password)
	_, _ = mac.Write(salt)
	_, _ = mac.Write(block[:])
	u := mac.Sum(nil)
	out := append([]byte(nil), u...)
	for i := 1; i < iterations; i++ {
		mac.Reset()
		_, _ = mac.Write(u)
		u = mac.Sum(nil)
		for j := range out {
			out[j] ^= u[j]
		}
	}
	return out
}

func NewAdminHandler(configPath string, service *Server) (http.Handler, error) {
	data, err := os.ReadFile(adminCredentialsPath)
	if err != nil {
		return nil, fmt.Errorf("read admin credentials (%s): %w; create an administrator with -admin-create", adminCredentialsPath, err)
	}
	var creds adminCredentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("parse admin credentials: %w", err)
	}
	if creds.Username == "" || creds.Salt == "" || creds.PasswordHash == "" || creds.SessionSecret == "" {
		return nil, errors.New("admin credentials file is incomplete")
	}
	salt, err := hex.DecodeString(creds.Salt)
	if err != nil {
		return nil, errors.New("invalid admin password salt")
	}
	hash, err := hex.DecodeString(creds.PasswordHash)
	if err != nil {
		return nil, errors.New("invalid admin password hash")
	}
	secret, err := base64.RawURLEncoding.DecodeString(creds.SessionSecret)
	if err != nil || len(secret) < 32 {
		return nil, errors.New("invalid admin session secret")
	}

	controller := &adminController{configPath: configPath, service: service}
	sessions := &adminSessions{entries: make(map[string]time.Time)}
	loginLimiter := NewRateLimiter(5, time.Minute)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !validBrowserMutation(r) {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ip, err := remoteIP(r.RemoteAddr)
		if err == nil {
			if allowed, retry := loginLimiter.Allow(ip.String(), time.Now()); !allowed {
				w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(retry)))
				http.Error(w, "too many login attempts", http.StatusTooManyRequests)
				return
			}
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		var input struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		candidate := derivePassword([]byte(input.Password), salt, passwordIterations)
		if subtle.ConstantTimeCompare(candidate, hash) != 1 || subtle.ConstantTimeCompare([]byte(input.Username), []byte(creds.Username)) != 1 {
			http.Error(w, "invalid username or password", http.StatusUnauthorized)
			return
		}
		token, expires := createSession(creds.Username, secret)
		sessions.add(token, expires)
		http.SetCookie(w, &http.Cookie{Name: adminCookieName, Value: token, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, Expires: expires, MaxAge: int(sessionLifetime.Seconds())})
		writeAdminJSON(w, http.StatusOK, map[string]bool{"authenticated": true})
	})
	mux.HandleFunc("/api/session", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !authenticated(r, creds.Username, secret, sessions) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		writeAdminJSON(w, http.StatusOK, map[string]bool{"authenticated": true})
	})
	mux.HandleFunc("/api/logout", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !validBrowserMutation(r) {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if cookie, err := r.Cookie(adminCookieName); err == nil {
			sessions.revoke(cookie.Value)
		}
		http.SetCookie(w, &http.Cookie{Name: adminCookieName, Value: "", Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: time.Unix(1, 0)})
		writeAdminJSON(w, http.StatusOK, map[string]bool{"authenticated": false})
	})
	mux.Handle("/api/config", controller.authorize(creds.Username, secret, sessions, http.HandlerFunc(controller.configHandler)))
	mux.Handle("/api/firewall/apply", controller.authorize(creds.Username, secret, sessions, http.HandlerFunc(controller.applyFirewallHandler)))
	mux.Handle("/api/access/current-ip", controller.authorize(creds.Username, secret, sessions, http.HandlerFunc(controller.grantCurrentIPHandler)))

	staticFS, err := webadmin.SubFS()
	if err != nil {
		return nil, err
	}
	static := http.FileServer(http.FS(staticFS))
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path != "/" {
			if f, err := staticFS.Open(strings.TrimPrefix(filepath.Clean(r.URL.Path), "/")); err == nil {
				_ = f.Close()
				static.ServeHTTP(w, r)
				return
			}
		}
		http.ServeFileFS(w, r, staticFS, "index.html")
	}))
	return securityHeaders(mux), nil
}

func (c *adminController) authorize(username string, secret []byte, sessions *adminSessions, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authenticated(r, username, secret, sessions) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (c *adminController) configHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg, _, err := LoadConfig(c.configPath)
		if err != nil {
			http.Error(w, "failed to read configuration", http.StatusInternalServerError)
			return
		}
		writeAdminJSON(w, http.StatusOK, cfg)
	case http.MethodPut:
		if !validBrowserMutation(r) {
			http.Error(w, "invalid request origin", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		var next Config
		if err := json.NewDecoder(r.Body).Decode(&next); err != nil {
			http.Error(w, "invalid configuration", http.StatusBadRequest)
			return
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		current, _, err := LoadConfig(c.configPath)
		if err != nil {
			http.Error(w, "failed to read current configuration", http.StatusInternalServerError)
			return
		}
		// Listener, state storage and admin transport are host-level settings.
		next.ListenAddr = current.ListenAddr
		next.StateFile = current.StateFile
		next.Admin.Enabled = current.Admin.Enabled
		next.Admin.ListenAddr = current.Admin.ListenAddr
		next, ttl, err := ValidateConfig(next)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		restartRequired := next.Admin.HTTPS != current.Admin.HTTPS ||
			next.Admin.TLSCertFile != current.Admin.TLSCertFile ||
			next.Admin.TLSKeyFile != current.Admin.TLSKeyFile
		if next.Admin.Enabled && next.Admin.HTTPS {
			if _, err := tls.LoadX509KeyPair(next.Admin.TLSCertFile, next.Admin.TLSKeyFile); err != nil {
				http.Error(w, "invalid or unreadable TLS certificate/key: "+err.Error(), http.StatusBadRequest)
				return
			}
		}
		oldData, err := os.ReadFile(c.configPath)
		if err != nil {
			http.Error(w, "failed to read configuration file", http.StatusInternalServerError)
			return
		}
		if err := c.backupConfig(oldData); err != nil {
			http.Error(w, "failed to back up current configuration", http.StatusInternalServerError)
			return
		}
		encoded, err := yaml.Marshal(next)
		if err == nil {
			err = os.WriteFile(c.configPath, encoded, 0640)
		}
		if err != nil {
			http.Error(w, "failed to save configuration; check config.yaml ownership and mode 0660", http.StatusInternalServerError)
			return
		}
		if err := c.service.ApplyConfig(next, ttl); err != nil {
			_ = os.WriteFile(c.configPath, oldData, 0640)
			http.Error(w, "configuration apply failed; previous config restored: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeAdminJSON(w, http.StatusOK, map[string]any{"saved": true, "restart_required": restartRequired, "config": next})
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (c *adminController) backupConfig(data []byte) error {
	cfg, _, err := LoadConfig(c.configPath)
	if err != nil {
		return err
	}
	dir := filepath.Join(filepath.Dir(cfg.StateFile), "config-backups")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	name := "config-" + time.Now().UTC().Format("20060102T150405.000000000Z") + ".yaml"
	return os.WriteFile(filepath.Join(dir, name), data, 0600)
}

func (c *adminController) applyFirewallHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !validBrowserMutation(r) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	cfg, ttl, err := LoadConfig(c.configPath)
	if err != nil {
		http.Error(w, "failed to read configuration", http.StatusInternalServerError)
		return
	}
	ports := make([]uint16, 0, len(cfg.Access))
	for _, rule := range cfg.Access {
		ports = append(ports, rule.Port)
	}
	if err := c.service.ApplyConfig(cfg, ttl); err != nil {
		http.Error(w, "failed to apply firewall rules: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{"applied": true, "ports": ports, "mode": "temporary-ip-allowlist"})
}

func (c *adminController) grantCurrentIPHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !validBrowserMutation(r) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	var input struct { Port uint16 `json:"port"` }
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.Port == 0 {
		http.Error(w, "invalid port", http.StatusBadRequest)
		return
	}
	// Trust only the TCP peer address, never client-supplied forwarding headers.
	ip, err := remoteIP(r.RemoteAddr)
	if err != nil {
		http.Error(w, "unable to determine client IP", http.StatusBadRequest)
		return
	}
	expiresAt, err := c.service.GrantAccess(input.Port, ip)
	if err != nil {
		if strings.Contains(err.Error(), "not configured") {
			http.Error(w, "port is not configured", http.StatusBadRequest)
			return
		}
		http.Error(w, "failed to grant access: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{
		"granted": true, "ip": ip.String(), "port": input.Port,
		"expires_at": expiresAt.UTC().Format(time.RFC3339),
		"expires_in": int64(time.Until(expiresAt).Seconds()),
	})
}

func validBrowserMutation(r *http.Request) bool {
	if r.Header.Get("X-PortKeeper-Request") != "1" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" || !strings.EqualFold(parsed.Host, r.Host) {
		return false
	}
	if r.TLS != nil && parsed.Scheme != "https" {
		return false
	}
	if r.TLS == nil && parsed.Scheme != "http" {
		return false
	}
	return true
}

func createSession(username string, secret []byte) (string, time.Time) {
	expires := time.Now().Add(sessionLifetime).UTC()
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	payload := username + "|" + strconv.FormatInt(expires.Unix(), 10) + "|" + base64.RawURLEncoding.EncodeToString(nonce)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(payload))
	token := base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return token, expires
}

func authenticated(r *http.Request, username string, secret []byte, sessions *adminSessions) bool {
	cookie, err := r.Cookie(adminCookieName)
	if err != nil {
		return false
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return false
	}
	fields := strings.Split(string(payload), "|")
	if len(fields) != 3 || fields[0] != username {
		return false
	}
	expires, err := strconv.ParseInt(fields[1], 10, 64)
	return err == nil && time.Now().Unix() < expires && sessions.valid(cookie.Value)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func writeAdminJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
