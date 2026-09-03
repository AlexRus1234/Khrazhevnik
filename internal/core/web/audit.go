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
	"strconv"
	"strings"
	"time"

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

// auditRecordTimeout — потолок записи аудита WithoutCancel-контекстом:
// он не наследует отмену соединения, но и не должен висеть вечно,
// если каталог тормозит (аудит 2026-08-30).
const auditRecordTimeout = 5 * time.Second

// panicAuditTimeout — сокращённый потолок паник-ветки: запись идёт
// после смерти хендлера и ждать её некому — баланс «не потерять запись
// паники» против «не держать соединение» (клиент ждёт 500 от
// Recoverer'а).
const panicAuditTimeout = time.Second

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

// auditAction — middleware-обёртка: ставит фиксированный action в
// контекст до auth-слоя, так что отклонённые auth'ом запросы всё равно
// аудируются осмысленным action'ом (хендлер при reject не выполняется,
// свой action положить не может). Мутирует request, как auth-
// middleware: наружный audit читает тот же r (аудит 2026-08-30).
func auditAction(action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*r = *r.WithContext(WithAuditAction(r.Context(), action))
			next.ServeHTTP(w, r)
		})
	}
}

// AuditMiddleware автоматическая запись аудита для всех не-GET /api/v1
// запросов: actor из auth-контекста (user, токен, маркер отклонённого
// или «anonymous»), action — из контекста (если хендлер положил) или
// выводится из метода+пути, object — путь запроса, result — HTTP-статус
// ответа (2xx → ok, 401/403/500/... — своим кодом: иначе брутфорс
// токенов и упавшие в панику мутации неразличимы в трейле, аудит
// 2026-08-30), detail — из контекста, если хендлер положил. Запись идёт
// после завершения хендлера, не ломает основной поток; переживает
// панику хендлера (recover до наружного Recoverer'а — это 500, а не
// потерянная запись) и отключение клиента (WithoutCancel).
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
			panicked := true
			defer func() {
				if panicked {
					// Паника хендлера: наружный Recoverer ответит 500; здесь
					// остаётся записать её в аудит, иначе мутация исчезает из
					// трейла — Recoverer разворачивает стек выше нас (аудит
					// 2026-08-30). re-panic прокидывает стек в Recoverer.
					if err := recover(); err != nil {
						rec.status = http.StatusInternalServerError
						recordAudit(log, clock, r, rec.status, panicAuditTimeout)
						panic(err)
					}
				}
			}()
			next.ServeHTTP(rec, r)
			panicked = false
			recordAudit(log, clock, r, rec.status, auditRecordTimeout)
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
//
// WithoutCancel: контекст запроса умирает вместе с соединением, а аудит
// мутации не должен зависеть от живости клиента — оборванный upload
// всё равно обязан оставить запись (аудит 2026-08-30). Таймаут — свой
// короткий (обычный или сокращённый в паник-ветке), не наследует
// дедлайны запроса.
func recordAudit(log port.AuditLog, clock port.Clock, r *http.Request, status int, timeout time.Duration) {
	if log == nil {
		return
	}
	actor := "anonymous"
	rejected := authmw.AuditActorFromContext(r.Context())
	if u, ok := authmw.UserFromContext(r.Context()); ok && u.Username != "" {
		actor = u.Username
	} else if t, ok := authmw.TokenFromContext(r.Context()); ok {
		actor = "token:" + t.Prefix
	}
	if rejected != "" {
		// auth-middleware опознал, но отлупил (нет прав) — личность
		// известна, «anonymous» скрыл бы атаку scoped-токеном. Маркер
		// старше остаточного auth-контекста: reject-ветки затирают
		// user-контекст заглушкой, но при способе «не успели затереть»
		// маркер всё равно надёжнее.
		actor = rejected
	}
	action, _ := r.Context().Value(auditActionKey{}).(string)
	if action == "" {
		action = actionFromRequest(r)
	}
	detail, _ := r.Context().Value(auditDetailKey{}).(string)
	entry := domain.AuditEntry{
		At:     clock.Now(),
		Actor:  actor,
		Action: action,
		Object: r.URL.Path,
		Result: auditResultForStatus(status),
		Detail: detail,
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), timeout)
	defer cancel()
	if err := log.Record(ctx, entry); err != nil {
		// Не ломаем ответ; пишем в slog, чтобы потеря аудита была видна.
		slog.Default().Warn("аудит: запись не удалась", "err", err, "action", action)
	}
}

// auditResultForStatus — result-словарь: успешные мутации остаются
// «ok» (богатый результат уже в detail успешных записей), отклонённые
// и упавшие — HTTP-кодом статуса: «401»/«403»/«500» говорят сами за
// себя и не требуют расшифровки. Неизвестный не-2xx — «error».
func auditResultForStatus(status int) string {
	switch {
	case status < 300:
		return domain.AuditOK
	case status == http.StatusUnauthorized,
		status == http.StatusForbidden,
		status == http.StatusNotFound,
		status == http.StatusConflict,
		status == http.StatusRequestEntityTooLarge,
		status == http.StatusUnprocessableEntity,
		status == http.StatusTooManyRequests,
		status == http.StatusInternalServerError,
		status == http.StatusServiceUnavailable:
		return strconv.Itoa(status)
	default:
		return domain.AuditError
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
