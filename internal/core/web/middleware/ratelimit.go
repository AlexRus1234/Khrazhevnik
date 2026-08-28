// Хражевник — кеш-прокси и зеркало linux-репозиториев
// Copyright (C) 2026 AlexRus1234
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package middleware

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// maxAttemptsPerMinute — окно на IP (как в v0).
const maxAttemptsPerMinute = 10

// maxTrackedIPs — потолок карты корзин: без него ротация IPv6-префиксов
// (каждый новый /128 — новый ключ) растит карту бесконечно (аудит
// 2026-08-27). При переполнении выкидываются протухшие корзины, затем —
// самая давно виденная.
const maxTrackedIPs = 10000

// LoginRateLimit limits each source IP to ten attempts per rolling minute.
type LoginRateLimit struct {
	mu      sync.Mutex
	hits    map[string][]time.Time
	now     func() time.Time
	trusted []*net.IPNet
}

// NewLoginRateLimit принимает опциональные CIDR'ы доверенных reverse-
// прокси: пусто — ключ корзины это RemoteAddr (статус-кво, XFF
// игнорируется как подделываемый); заполнено — адрес клиента берётся из
// X-Forwarded-For до доверенной границы (иначе все клиенты за прокси
// делят одну корзину 10/мин — глобальный lockout логина).
func NewLoginRateLimit(trustedProxies ...*net.IPNet) *LoginRateLimit {
	return &LoginRateLimit{hits: make(map[string][]time.Time), now: time.Now, trusted: trustedProxies}
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
	if len(old) >= maxAttemptsPerMinute {
		l.hits[ip] = old
		return false
	}
	l.hits[ip] = append(old, l.now())
	l.evictLocked()
	return true
}

func (l *LoginRateLimit) Reset(ip string) { l.mu.Lock(); delete(l.hits, clientIP(ip)); l.mu.Unlock() }

// ResetRequest сбрасывает корзину по адресу запроса (учитывает
// trusted proxies — тот же ключ, каким считал Middleware).
func (l *LoginRateLimit) ResetRequest(r *http.Request) {
	l.mu.Lock()
	delete(l.hits, l.key(r))
	l.mu.Unlock()
}

func (l *LoginRateLimit) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.Allow(l.key(r)) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// key — адрес клиента запроса (XFF-aware при настроенных прокси).
func (l *LoginRateLimit) key(r *http.Request) string {
	return RealClientIP(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), l.trusted)
}

// evictLocked держит карту в пределах maxTrackedIPs. Вызывается после
// вставки: сначала выкидываем корзины, чьё окно целиком протухло, затем
// (если всё ещё полно) — самую давно виденную. O(n) на переполнении,
// но не чаще одной вставки — амортизированно дёшево.
func (l *LoginRateLimit) evictLocked() {
	if len(l.hits) < maxTrackedIPs {
		return
	}
	cutoff := l.now().Add(-time.Minute)
	for ip, ts := range l.hits {
		if len(ts) == 0 || !ts[len(ts)-1].After(cutoff) {
			delete(l.hits, ip)
		}
	}
	for len(l.hits) >= maxTrackedIPs {
		oldestIP := ""
		var oldest time.Time
		for ip, ts := range l.hits {
			if last := ts[len(ts)-1]; oldestIP == "" || last.Before(oldest) {
				oldestIP, oldest = ip, last
			}
		}
		delete(l.hits, oldestIP)
	}
}

// RealClientIP выбирает адрес клиента для rate-limit корзины: без
// доверенных прокси — хост RemoteAddr; с настроенным списком —
// X-Forwarded-For проходится справа налево до первой недоверенной
// позиции (схема nginx/CDN: правый конец списка писал ближайший прокси).
// Подделываемый клиентом XFF от недоверенного пира не читается.
func RealClientIP(remoteAddr, xff string, trusted []*net.IPNet) string {
	remote := clientIP(remoteAddr)
	if len(trusted) == 0 || xff == "" || remote == "" {
		return remote
	}
	if !ipInList(remote, trusted) {
		// непосредственный пир не доверен — его XFF spoofing
		return remote
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(parts[i]))
		if ip == nil {
			return remote
		}
		if !ipInList(ip.String(), trusted) {
			return ip.String()
		}
	}
	// весь список — доверенные прокси; источник — крайний слева
	if first := net.ParseIP(strings.TrimSpace(parts[0])); first != nil {
		return first.String()
	}
	return remote
}

// ipInList — адрес (без порта) в списке CIDR.
func ipInList(ip string, trusted []*net.IPNet) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range trusted {
		if cidr.Contains(parsed) {
			return true
		}
	}
	return false
}

func clientIP(remote string) string {
	if host, _, err := net.SplitHostPort(remote); err == nil {
		return host
	}
	return remote
}
