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
