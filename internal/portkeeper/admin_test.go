package portkeeper

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionAuthentication(t *testing.T) {
	secret := []byte("01234567890123456789012345678901")
	token, expires := createSession("admin", secret)
	if !expires.After(time.Now()) {
		t.Fatal("session expiration must be in the future")
	}
	req := httptest.NewRequest("GET", "http://localhost:8083/api/session", nil)
	req.AddCookie(&http.Cookie{Name: adminCookieName, Value: token})
	if !authenticated(req, "admin", secret) {
		t.Fatal("valid session was rejected")
	}
	if authenticated(req, "admin", []byte("different secret")) {
		t.Fatal("session signed with a different secret was accepted")
	}
}

func TestValidBrowserMutationRequiresSameOrigin(t *testing.T) {
	req := httptest.NewRequest("POST", "http://localhost:8083/api/login", nil)
	req.Header.Set("X-PortKeeper-Request", "1")
	req.Header.Set("Origin", "http://localhost:8083")
	if !validBrowserMutation(req) {
		t.Fatal("same-origin browser request was rejected")
	}
	req.Header.Set("Origin", "https://attacker.example")
	if validBrowserMutation(req) {
		t.Fatal("cross-origin browser request was accepted")
	}
	req.Header.Del("Origin")
	if validBrowserMutation(req) {
		t.Fatal("request without Origin was accepted")
	}
}
