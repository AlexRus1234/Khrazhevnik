package middleware

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

// LoginRateLimit limits each source IP to ten attempts per rolling minute.
type LoginRateLimit struct {
	mu   sync.Mutex
	hits map[string][]time.Time
	now  func() time.Time
}

func NewLoginRateLimit() *LoginRateLimit {
	return &LoginRateLimit{hits: make(map[string][]time.Time), now: time.Now}
}

func (l *LoginRateLimit) Allow(ip string) bool {
	ip = clientIP(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := l.now().Add(-time.Minute)
	old := l.hits[ip]
	i := 0
	for i < len(old) && !old[i].After(cutoff) {
		i++
	}
	old = old[i:]
	if len(old) >= 10 {
		l.hits[ip] = old
		return false
	}
	l.hits[ip] = append(old, l.now())
	return true
}
func (l *LoginRateLimit) Reset(ip string) { l.mu.Lock(); delete(l.hits, clientIP(ip)); l.mu.Unlock() }
func (l *LoginRateLimit) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r.RemoteAddr)
		if !l.Allow(ip) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func clientIP(remote string) string {
	if i := strings.LastIndexByte(remote, ':'); i >= 0 {
		return remote[:i]
	}
	return remote
}
