package middleware

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLoginRateLimitReset(t *testing.T) {
	l := NewLoginRateLimit()
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for i := 0; i < 10; i++ {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		r.RemoteAddr = "198.51.100.1:1"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 204 {
			t.Fatalf("attempt %d = %d", i, w.Code)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = "198.51.100.1:1"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 429 {
		t.Fatalf("11th = %d", w.Code)
	}
	l.Reset("198.51.100.1:1")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("after reset = %d", w.Code)
	}
}

// mustCIDR — парсинг CIDR в тестах.
func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	return ipNet
}

// TestRealClientIP — XFF читается только от доверенного пира и до
// доверенной границы (аудит 2026-08-27): чужой XFF (spoofing) и
// недоверенный пир не двигают корзину с RemoteAddr.
func TestRealClientIP(t *testing.T) {
	trusted := []*net.IPNet{mustCIDR(t, "10.0.0.0/8"), mustCIDR(t, "127.0.0.0/8")}
	cases := []struct {
		name    string
		remote  string
		xff     string
		trusted []*net.IPNet
		want    string
	}{
		{"no trusted, xff ignored", "198.51.100.7:5", "203.0.113.9", nil, "198.51.100.7"},
		{"trusted proxy, client in xff", "10.0.0.1:5", "203.0.113.9", trusted, "203.0.113.9"},
		{"chain to first untrusted", "10.0.0.1:5", "203.0.113.9, 10.0.0.2", trusted, "203.0.113.9"},
		{"all trusted, leftmost wins", "10.0.0.1:5", "10.1.0.1, 10.0.0.2", trusted, "10.1.0.1"},
		{"untrusted peer xff spoof", "198.51.100.7:5", "1.2.3.4", trusted, "198.51.100.7"},
		{"garbage xff falls back", "10.0.0.1:5", "not-an-ip", trusted, "10.0.0.1"},
		{"ipv6 remote", "[2001:db8::1]:5", "", nil, "2001:db8::1"},
		{"ipv6 in xff", "[2001:db8::ff]:5", "2001:db8::9", []*net.IPNet{mustCIDR(t, "2001:db8::/64")}, "2001:db8::9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RealClientIP(tc.remote, tc.xff, tc.trusted); got != tc.want {
				t.Fatalf("RealClientIP(%q, %q) = %q, хочу %q", tc.remote, tc.xff, got, tc.want)
			}
		})
	}
}

// TestLoginRateLimitXFFBucket — корзина по клиенту из XFF (доверенный
// пир): разные RemoteAddr прокси с одним клиентом делят лимит.
func TestLoginRateLimitXFFBucket(t *testing.T) {
	l := NewLoginRateLimit(mustCIDR(t, "10.0.0.0/8"))
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	do := func(remote, xff string) int {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	for i := 0; i < 10; i++ {
		if code := do("10.0.0."+string(rune('0'+i))+":9", "203.0.113.50"); code != 204 {
			t.Fatalf("попытка %d через разные прокси = %d", i, code)
		}
	}
	if code := do("10.0.0.99:9", "203.0.113.50"); code != 429 {
		t.Fatalf("11-я попытка того же клиента = %d, хочу 429", code)
	}
	// другой клиент — своя корзина
	if code := do("10.0.0.99:9", "203.0.113.51"); code != 204 {
		t.Fatalf("другой клиент = %d, хочу 204", code)
	}
}

// TestLoginRateLimitXFFIgnoredWithoutTrust — без trusted_proxies
// подделанный XFF не выводит из-под лимита (все попытки с одного
// RemoteAddr остаются в одной корзине).
func TestLoginRateLimitXFFIgnoredWithoutTrust(t *testing.T) {
	l := NewLoginRateLimit()
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for i := 0; i < 10; i++ {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		r.RemoteAddr = "10.0.0.1:9"
		r.Header.Set("X-Forwarded-For", "203.0.113."+string(rune('0'+i%10)))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 204 {
			t.Fatalf("попытка %d = %d", i, w.Code)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = "10.0.0.1:9"
	r.Header.Set("X-Forwarded-For", "203.0.113.99")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 429 {
		t.Fatalf("спуфинг XFF обошёл лимит: %d", w.Code)
	}
}

// TestLoginRateLimitMapCap — карта корзин ограничена (ротация IPv6 не
// растит её бесконечно): после >maxTrackedIPs уникальных адресов размер
// не превышает потолок.
func TestLoginRateLimitMapCap(t *testing.T) {
	l := NewLoginRateLimit()
	for i := 0; i < maxTrackedIPs+150; i++ {
		l.Allow("2001:db8::" + itoaHex(i) + ":1")
	}
	l.mu.Lock()
	size := len(l.hits)
	l.mu.Unlock()
	if size > maxTrackedIPs {
		t.Fatalf("корзин %d > потолка %d", size, maxTrackedIPs)
	}
}

// itoaHex — компактная hex-запись числа для IPv6-суффиксов.
func itoaHex(n int) string {
	const digits = "0123456789abcdef"
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = digits[n%16]
		n /= 16
	}
	return string(b[i:])
}
