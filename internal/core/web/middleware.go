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

package web

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"khrazhevnik/internal/core/metrics"
)

// RequestIDHeader — заголовок сквозного идентификатора запроса.
const RequestIDHeader = "X-Request-Id"

// requestIDKey — типизированный ключ контекста.
type requestIDKey struct{}

// RequestID гарантирует сквозной X-Request-Id: валидный входящий
// сохраняется, иначе генерируется новый (16 байт hex). Идентификатор
// кладётся в контекст и в заголовок ответа.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := sanitizeRequestID(r.Header.Get(RequestIDHeader))
		if id == "" {
			id = newRequestID()
		}
		w.Header().Set(RequestIDHeader, id)
		ctx := context.WithValue(r.Context(), requestIDKey{}, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequestIDFromContext достаёт идентификатор запроса ("" — нет).
func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// sanitizeRequestID пропускает только компактные печатные значения
// (8..64 символа из [0-9A-Za-z-]): чужие заголовки не льём в логи
// как есть.
func sanitizeRequestID(id string) string {
	if len(id) < 8 || len(id) > 64 {
		return ""
	}
	for i := range len(id) {
		c := id[i]
		isAlnum := c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		if !isAlnum && c != '-' {
			return ""
		}
	}
	return id
}

// newRequestID — 16 случайных байт hex; при исчерпании энтропии —
// метка времени base36 (тоже валидна по формату).
func newRequestID() string {
	var b [16]byte
	if _, err := crand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(b[:])
}

// statusRecorder запоминает статус ответа для лога.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

// WriteHeader фиксирует статус до делегирования.
func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Unwrap открывает http.ResponseController доступ к нижележащему
// writer (аудит 2026-08-30): без него SetWriteDeadline/
// SetReadDeadline stall-хендлеров молча возвращали errNotSupported
// на всём публичном роутере — пер-write защита от slow-reader не
// работала в прод-цепочке, только в тестах с сырым writer.
func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

// LogRequests — построчный лог запросов (slog): метод, путь, статус,
// длительность, request_id. Статусы 5xx поднимаются до error.
func LogRequests(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			defer func() {
				level := slog.LevelInfo
				if rec.status >= http.StatusInternalServerError {
					level = slog.LevelError
				}
				log.Log(r.Context(), level, "http",
					"method", r.Method,
					"path", r.URL.Path,
					"status", rec.status,
					"duration_ms", time.Since(start).Milliseconds(),
					"request_id", RequestIDFromContext(r.Context()),
					"remote", r.RemoteAddr,
				)
			}()
			next.ServeHTTP(rec, r)
		})
	}
}

// ObserveMetrics наполняет гистограмму khrazhevnik_request_duration_seconds
// {method,status} (аудит 2026-08-30: до сих пор Observe звался только из
// тестов, гистограмма была вечно пустой). Статус пишет тот же тип
// statusRecorder, что и лог запросов — третьей обёртки не плодим; elapsed —
// от старта middleware (web-доставка, time.Now здесь разрешён). nil-Handler
// (метрики выключены/деградация) — no-op без обёртки. Ставится НАРУЖУ
// Recoverer: паника хендлера = 500 от Recoverer — тоже наблюдение.
func ObserveMetrics(h *metrics.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if h == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			defer func() {
				h.ObserveRequestLatency(r.Method, strconv.Itoa(rec.status), time.Since(start).Seconds())
			}()
			next.ServeHTTP(rec, r)
		})
	}
}

// spaContentSecurityPolicy — CSP админской поверхности: SPA грузит
// только собственные бандлы (script 'self'), стили Vue используют
// inline-атрибуты ('unsafe-inline' в style-src — данных, не скриптов),
// картинки — data:-иконки. connect-src 'self' закрывает API-вызовы.
const spaContentSecurityPolicy = "default-src 'self'; script-src 'self'; " +
	"style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
	"connect-src 'self'; font-src 'self'; object-src 'none'; " +
	"base-uri 'self'; frame-ancestors 'none'"

// SecurityHeaders — базовые заголовки админ-поверхности (API + /ui,
// аудит 2026-08-27): nosniff гасит content-type sniffing, DENY —
// фрейминг админки, CSP — инъекции сторонних ресурсов в SPA.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", spaContentSecurityPolicy)
		next.ServeHTTP(w, r)
	})
}

// NoSniff — X-Content-Type-Options: nosniff на всех ответах публичного
// порта :29202 (аудит 2026-08-30): жёсткий Content-Type repo-объектов
// не даёт браузеру переинтерпретировать тело, но nosniff закрывает и
// прокси-ветку, где upstream-тип передаётся byte-exact, и healthz.
func NoSniff(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}
