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
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"khrazhevnik/internal/core/metrics"
	"khrazhevnik/internal/core/port"
)

// RequestIDHeader — заголовок сквозного идентификатора запроса.
const RequestIDHeader = "X-Request-Id"

// requestIDKey — типизированный ключ контекста.
type requestIDKey struct{}

// RequestID гарантирует сквозной X-Request-Id: валидный входящий
// сохраняется, иначе генерируется новый (16 байт hex). Идентификатор
// кладётся в контекст и в заголовок ответа. rand — порт случайности
// (инжект из Deps: подмена в тестах даёт детерминированные ID); nil —
// системная реализация.
func RequestID(rand port.Rand) func(http.Handler) http.Handler {
	if rand == nil {
		rand = systemWebRand{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := sanitizeRequestID(r.Header.Get(RequestIDHeader))
			if id == "" {
				id = newRequestID(rand)
			}
			w.Header().Set(RequestIDHeader, id)
			ctx := context.WithValue(r.Context(), requestIDKey{}, id)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
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

// newRequestID — 16 случайных байт hex через port.Rand: UUID4 без
// дефисов — те же 32 hex-символа из 16 байт (случайность — через порт,
// инжект в тестах). При отказе источника — метка времени base36 (тоже
// валидна по формату).
func newRequestID(rand port.Rand) string {
	u, err := rand.UUID4()
	if err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return strings.ReplaceAll(u, "-", "")
}

// systemWebRand — port.Rand поверх crypto/rand: web-случайность
// (request-id, task ID) без явного Rand (тесты подменяют) получает
// системную реализацию, не дёргая wire. Реализационное использование
// crypto/rand, как systemWebClock поверх time.Now.
type systemWebRand struct{}

// UUID4 генерирует канонический UUID v4 (8-4-4-4-12, lowercase).
func (systemWebRand) UUID4() (string, error) {
	var b [16]byte
	if _, err := crand.Read(b[:]); err != nil {
		return "", fmt.Errorf("web: чтение crypto/rand: %w", err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

// Int64 возвращает неотрицательное число в [0, max) из 8 байт
// crypto/rand (контракт порта; сам web Int64 не использует).
func (systemWebRand) Int64(max int64) int64 {
	if max <= 0 {
		return 0
	}
	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		return 0
	}
	n := int64(b[0])<<56 | int64(b[1])<<48 | int64(b[2])<<40 | int64(b[3])<<32 |
		int64(b[4])<<24 | int64(b[5])<<16 | int64(b[6])<<8 | int64(b[7])
	if n < 0 {
		n = -n
	}
	return n % max
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

// methodLabel — allowlist значений лейбла method: net/http принимает
// любой RFC-7230 token, а chi гоняет Use-стек до method-роутинга, поэтому
// каждый уникальный токен вида «X-FROB/1a2b» создал бы вечного ребёнка
// HistogramVec — кардинальность лейбла росла бы без границ (медленный
// memory-DoS на :29202). Всё вне фиксированного списка — "other":
// кардинальность ограничена константой независимо от трафика.
func methodLabel(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodOptions,
		http.MethodConnect, http.MethodTrace:
		return method
	default:
		return "other"
	}
}

// ObserveMetrics наполняет гистограмму khrazhevnik_request_duration_seconds
// {method,status} (аудит 2026-08-30: до сих пор Observe звался только из
// тестов, гистограмма была вечно пустой). Метод проходит allowlist
// methodLabel (лейбл-кардинальность), статус — strconv, оба набора
// ограничены. Статус пишет тот же тип statusRecorder, что и лог запросов —
// третьей обёртки не плодим; elapsed — от старта middleware (web-доставка,
// time.Now здесь разрешён). nil-Handler (метрики выключены/деградация) —
// no-op без обёртки. Ставится НАРУЖУ Recoverer: паника хендлера = 500 от
// Recoverer — тоже наблюдение.
func ObserveMetrics(h *metrics.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if h == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			defer func() {
				h.ObserveRequestLatency(methodLabel(r.Method), strconv.Itoa(rec.status), time.Since(start).Seconds())
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
// порта :29202 (аудит 2026-08-30). Сам по себе nosniff от честно
// объявленного text/html НЕ защищает — потому тип задаётся allowlist'ом
// в самих хендлерах (repoContentType, proxyContentType — сессия 78);
// nosniff — второй слой: запрещает переинтерпретацию объявленного типа
// и страхует пути без явного типа (healthz и будущие роуты).
func NoSniff(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}
