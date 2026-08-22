package middleware

import (
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
