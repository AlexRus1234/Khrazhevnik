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
	"log/slog"
	"net/http"
	"strings"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
	authmw "khrazhevnik/internal/core/web/middleware"
)

// auditDetailKey — типизированный ключ контекста для произвольной
// детали аудита, которую хендлер хочет добавить к автоматической записи.
type auditDetailKey struct{}

// auditActionKey — то же для action: хендлер знает, что именно
// происходит (user.create vs user.delete), middleware знает только
// метод и путь.
type auditActionKey struct{}

// WithAuditDetail кладёт в контекст detail, который audit middleware
// добавит к автоматической записи. Возвращает новый context.
func WithAuditDetail(ctx context.Context, detail string) context.Context {
	if detail == "" {
		return ctx
	}
	return context.WithValue(ctx, auditDetailKey{}, detail)
}

// WithAuditAction кладёт в контекст action (например, «remote.create»),
// переопределяя выводимый из метода+пути. Возвращает новый context.
func WithAuditAction(ctx context.Context, action string) context.Context {
	if action == "" {
		return ctx
	}
	return context.WithValue(ctx, auditActionKey{}, action)
}

// AuditMiddleware автоматическая запись аудита для всех не-GET /api/v1
// запросов: actor из auth-контекста (user или «anonymous»), action —
// из контекста (если хендлер положил) или выводится из метода+пути,
// object — путь запроса, result — по коду ответа (2xx → ok, иначе error),
// detail — из контекста, если хендлер положил. Запись идёт после
// завершения хендлера, не ломает основной поток.
//
// GET пропускается без аудита: чтение не мутация. /api/v1/auth/login
// аудитируется отдельно в хендлере (actor ещё неизвестен до входа).
func AuditMiddleware(log port.AuditLog, clock port.Clock) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// GET /healthz и /api/v1/auth/login не пишем здесь.
			if r.Method == http.MethodGet {
				next.ServeHTTP(w, r)
				return
			}
			rec := &auditRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			recordAudit(log, clock, r, rec.status)
		})
	}
}

// auditRecorder запоминает статус для аудита; наследует statusRecorder
// нельзя (поля приватные), поэтому своё поле.
type auditRecorder struct {
	http.ResponseWriter
	status int
}

// WriteHeader фиксирует статус до делегирования.
func (r *auditRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Unwrap открывает http.ResponseController доступ к нижележащему
// writer (аудит 2026-08-30): upload-цепочка auditRecorder →
// statusRecorder → writer без него рвала read-deadline stallReader'а
// (errNotSupported), и PUT /repos/{id}/objects/* длиннее 30s убивал
// adminReadTimeout — цель сессии 27 не достигалась.
func (r *auditRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

// recordAudit собирает запись из контекста запроса и пишет её в порт.
// Ошибка записи логируется, но не возвращается наверх: аудит не должен
// ломать основной ответ (контракт port.AuditLog).
func recordAudit(log port.AuditLog, clock port.Clock, r *http.Request, status int) {
	if log == nil {
		return
	}
	actor := "anonymous"
	if u, ok := authmw.UserFromContext(r.Context()); ok {
		actor = u.Username
	}
	if t, ok := authmw.TokenFromContext(r.Context()); ok && actor == "anonymous" {
		actor = "token:" + t.Prefix
	}
	action, _ := r.Context().Value(auditActionKey{}).(string)
	if action == "" {
		action = actionFromRequest(r)
	}
	detail, _ := r.Context().Value(auditDetailKey{}).(string)
	result := domain.AuditOK
	if status >= 400 {
		result = domain.AuditError
	}
	entry := domain.AuditEntry{
		At:     clock.Now(),
		Actor:  actor,
		Action: action,
		Object: r.URL.Path,
		Result: result,
		Detail: detail,
	}
	if err := log.Record(r.Context(), entry); err != nil {
		// Не ломаем ответ; пишем в slog, чтобы потеря аудита была видна.
		slog.Default().Warn("аудит: запись не удалась", "err", err, "action", action)
	}
}

// actionFromRequest выводит action из метода и пути, если хендлер не
// положил явное через WithAuditAction: «remote.create» для
// POST /api/v1/remotes, «remote.update» для PATCH /api/v1/remotes/{id},
// и т.д. — достаточно для общей картины; специфичные имена хендлер
// переопределяет сам.
func actionFromRequest(r *http.Request) string {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/")
	// /users/{id}/api-tokens → users.api-tokens; сегменты-числа срезаем.
	segs := strings.Split(path, "/")
	var clean []string
	for _, s := range segs {
		if s == "" {
			continue
		}
		if isNumeric(s) {
			continue
		}
		clean = append(clean, s)
	}
	resource := "api"
	if len(clean) > 0 {
		resource = strings.Join(clean, ".")
	}
	verb := verbForMethod(r.Method)
	return verb + "." + resource
}

// verbForMethod маппит HTTP-метод в глагол действия аудита.
func verbForMethod(method string) string {
	switch method {
	case http.MethodPost:
		return "create"
	case http.MethodPatch, http.MethodPut:
		return "update"
	case http.MethodDelete:
		return "delete"
	default:
		return strings.ToLower(method)
	}
}

// isNumeric сообщает, состоит ли s только из цифр (для отсечения ID).
func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
