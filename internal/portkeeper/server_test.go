package portkeeper

import (
	"net"
	"net/http"
	"testing"
	"time"
)

func TestRemoteIP(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"192.0.2.10:12345", "192.0.2.10"},
		{"[2001:db8::1]:12345", "2001:db8::1"},
	}
	for _, tc := range cases {
		got, err := remoteIP(tc.input)
		if err != nil {
			t.Fatalf("remoteIP(%q): %v", tc.input, err)
		}
		if got.String() != tc.want {
			t.Errorf("remoteIP(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestRemoteIPRejectsInvalidAddress(t *testing.T) {
	if _, err := remoteIP("not-an-address"); err == nil {
		t.Fatal("expected error")
	}
}

func TestSetName(t *testing.T) {
	if got := setName(8080, net.ParseIP("192.0.2.1")); got != "pk_8080_v4" {
		t.Fatalf("unexpected IPv4 set name: %s", got)
	}
	if got := setName(8080, net.ParseIP("2001:db8::1")); got != "pk_8080_v6" {
		t.Fatalf("unexpected IPv6 set name: %s", got)
	}
}

func TestRequestIPUsesXRealIP(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "/guid", nil)
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("X-Real-IP", "198.51.100.25")
	got, err := requestIP(r)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "198.51.100.25" {
		t.Fatalf("requestIP() = %q", got)
	}
}

func TestRateLimiterPerIPAndWindowExpiry(t *testing.T) {
	limiter := NewRateLimiter(2, time.Minute)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	if allowed, _ := limiter.Allow("192.0.2.1", now); !allowed {
		t.Fatal("first request should be allowed")
	}
	if allowed, _ := limiter.Allow("192.0.2.1", now.Add(time.Second)); !allowed {
		t.Fatal("second request should be allowed")
	}
	if allowed, retry := limiter.Allow("192.0.2.1", now.Add(2*time.Second)); allowed || retry != 58*time.Second {
		t.Fatalf("third request = allowed %v, retry %v; want false, 58s", allowed, retry)
	}
	if allowed, _ := limiter.Allow("192.0.2.2", now.Add(2*time.Second)); !allowed {
		t.Fatal("a different IP should have its own limit")
	}
	if allowed, _ := limiter.Allow("192.0.2.1", now.Add(61*time.Second)); !allowed {
		t.Fatal("request should be allowed after the oldest request expires")
	}
}

func TestRetryAfterSecondsRoundsUp(t *testing.T) {
	if got := retryAfterSeconds(1500 * time.Millisecond); got != 2 {
		t.Fatalf("retryAfterSeconds() = %d, want 2", got)
	}
}
