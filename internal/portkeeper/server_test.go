package portkeeper

import (
	"net"
	"net/http"
	"testing"
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
