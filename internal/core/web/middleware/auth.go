package middleware

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/engine/auth"
	"khrazhevnik/internal/core/port"
)

// auditActorKey — actor для audit-трейла, когда аутентификация
// опознала, но отклонила личность (403: валидная сессия без прав,
// валидный scoped-токен не туда). Ключ живёт здесь, а не в web/audit:
// middleware не имеет права импортировать web (depguard), а web читает
// его через AuditActorFromContext — уже импортируя middleware (аудит
// 2026-08-30).
type auditActorKey struct{}

// WithAuditActor кладёт опознанного-но-отклонённого actor. Никакого
// самого токена — только username сессии или префикс токена.
func WithAuditActor(ctx context.Context, actor string) context.Context {
	if actor == "" {
		return ctx
	}
	return context.WithValue(ctx, auditActorKey{}, actor)
}

// AuditActorFromContext достаёт отклонённого actor ("" — не клался).
// Для web recordAudit: приоритет ниже живой аутентификации.
func AuditActorFromContext(ctx context.Context) string {
	actor, _ := ctx.Value(auditActorKey{}).(string)
	return actor
}

// authReject — единый отлуп auth-middleware: сбой каталога — 503
// (валидная учётка не должна маскироваться под 401 при сбое БД),
// всё остальное — 401.
func authReject(w http.ResponseWriter, err error) {
	var unavail *domain.UnavailableError
	if errors.As(err, &unavail) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

type userKey struct{}
type tokenKey struct{}
type jtiKey struct{}

// UserFromContext returns the user authenticated by a middleware.
func UserFromContext(ctx context.Context) (domain.User, bool) {
	u, ok := ctx.Value(userKey{}).(domain.User)
	return u, ok
}

// WithUserContext кладёт domain.User в контекст. Экспортировано для
// тестов audit-middleware в package web: тесты имитируют результат
// RequireSession, не поднимая auth.Service. В боевом коде не звать —
// аутентификация только через RequireSession/RequireAPIToken.
func WithUserContext(ctx context.Context, u domain.User) context.Context {
	return context.WithValue(ctx, userKey{}, u)
}

// WithTokenContext — то же для API-токена (тесты audit).
func WithTokenContext(ctx context.Context, t domain.APIToken) context.Context {
	return context.WithValue(ctx, tokenKey{}, t)
}

// TokenFromContext returns the API token authenticated by a middleware.
func TokenFromContext(ctx context.Context) (domain.APIToken, bool) {
	t, ok := ctx.Value(tokenKey{}).(domain.APIToken)
	return t, ok
}

// JTIFromContext returns the session identifier set by RequireSession.
func JTIFromContext(ctx context.Context) string { jti, _ := ctx.Value(jtiKey{}).(string); return jti }

func bearer(r *http.Request) (string, bool) {
	v := r.Header.Get("Authorization")
	p := strings.SplitN(v, " ", 2)
	if len(p) != 2 || !strings.EqualFold(p[0], "Bearer") || p[1] == "" {
		return "", false
	}
	return p[1], true
}

// RequireSession authenticates a JWT session.
func RequireSession(a *auth.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, ok := bearer(r)
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			session, err := a.ValidateSession(r.Context(), raw)
			if err != nil {
				authReject(w, err)
				return
			}
			// Мутируем сам request (а не создаём копию): наружный
			// audit-мiddleware держит этот же r и после ответа читает
			// actor из контекста (аудит 2026-08-30).
			ctx := context.WithValue(r.Context(), userKey{}, session.User)
			ctx = context.WithValue(ctx, jtiKey{}, session.JTI)
			*r = *r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAPIToken authenticates a scoped khz token.
func RequireAPIToken(a *auth.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, ok := bearer(r)
			if !ok || !strings.HasPrefix(raw, "khz_") {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			token, user, err := a.VerifyAPIToken(r.Context(), raw)
			if err != nil {
				authReject(w, err)
				return
			}
			// Мутируем сам request — наружный audit-мiddleware видит
			// token/user после ответа (аудит 2026-08-30).
			ctx := context.WithValue(r.Context(), userKey{}, user)
			ctx = context.WithValue(ctx, tokenKey{}, token)
			*r = *r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAdmin enforces the live role loaded from the database.
// 403 при опознанной не-админ сессии кладёт actor в контекст —
// отклонённая мутация аудируется с личностью, а не «anonymous».
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := UserFromContext(r.Context())
		if !ok || u.Role != domain.RoleAdmin {
			if ok {
				*r = *r.WithContext(WithAuditActor(r.Context(), u.Username))
			}
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireScope checks an API token scope, or the admin role for sessions.
// Отклонённый, но валидный токен аудируется своим префиксом.
//
// Ветка токена первична и решается ТОЛЬКО scopes. RequireAPIToken кладёт
// в контекст и владельца токена (userKey), и сам токен (tokenKey); без
// разделения веток админ-роль владельца авторизовала бы repo-scoped
// токен на всём admin-API. Токен авторизует ровно тем, что в нём
// заявлено, а не правами владельца (least-privilege: утечка CI-токена
// publish-агента не должна стоить инстанса; внешнее ревью 2026-09-04,
// раунд 5). Роль admin значима только для сессий — «for sessions» only.
func RequireScope(scope domain.Scope) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if t, ok := TokenFromContext(r.Context()); ok {
				for _, got := range t.Scopes {
					if got == scope || (scope != domain.ScopeAdmin && got == domain.ScopeAdmin) {
						next.ServeHTTP(w, r)
						return
					}
				}
				*r = *r.WithContext(WithAuditActor(r.Context(), "token:"+t.Prefix))
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			if u, ok := UserFromContext(r.Context()); ok && u.Role == domain.RoleAdmin {
				next.ServeHTTP(w, r)
				return
			}
			http.Error(w, "forbidden", http.StatusForbidden)
		})
	}
}

// RequireAdminOrAPIToken принимает либо JWT-сессию админа, либо
// admin-scoped API-токен. Используется для /metrics: оба вида учёточки
// смотрят в БД при каждом запросе (паранойя), чужие — отлупляются 401.
func RequireAdminOrAPIToken(a *auth.Service) func(http.Handler) http.Handler {
	sessionMw := RequireSession(a)
	tokenMw := RequireAPIToken(a)
	return func(next http.Handler) http.Handler {
		session := sessionMw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(w, r)
			})).ServeHTTP(w, r)
		}))
		token := tokenMw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			RequireScope(domain.ScopeAdmin)(next).ServeHTTP(w, r)
		}))
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, ok := bearer(r)
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if strings.HasPrefix(raw, "khz_") {
				token.ServeHTTP(w, r)
				return
			}
			session.ServeHTTP(w, r)
		})
	}
}

// RequireRepoAccess — auth-цепочка для owner-scoped publish-эндпоинтов
// (/repos/{id}/objects/*, /repos/{id}/reindex). Принимает либо JWT-
// сессию (тогда проверяем роль admin или владение репо), либо scoped
// API-токен (тогда проверяем scope admin или `repo:<id>:write`). ID
// репо берётся из chi URLParam "id" (роут зарегистрирован как
// /repos/{id}/...). 401 — нет/невалидный bearer; 403 — нет прав.
//
// Владельцем считается user.ID == repo.OwnerID. Права repo_perms в
// БД — отдельный гранулярный механизм, в v1 им выдаются scoped-токены
// (Session-пользователь — это всегда админ или владелец, perms через
// токен). Это покрывает RBAC-матрицу сессии 14.
func RequireRepoAccess(a *auth.Service, repos port.RepoStore) func(http.Handler) http.Handler {
	sessionMw := RequireSession(a)
	tokenMw := RequireAPIToken(a)
	return func(next http.Handler) http.Handler {
		session := sessionMw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, ok := UserFromContext(r.Context())
			if !ok {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			if u.Role == domain.RoleAdmin {
				next.ServeHTTP(w, r)
				return
			}
			repoID, ok := repoIDFromURL(r)
			if !ok {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			repo, err := repos.Repo(r.Context(), repoID)
			if err == nil && repo.OwnerID == u.ID {
				next.ServeHTTP(w, r)
				return
			}
			// Валидная сессия без прав на это репо — аудируем личность.
			*r = *r.WithContext(WithAuditActor(r.Context(), u.Username))
			http.Error(w, "forbidden", http.StatusForbidden)
		}))
		token := tokenMw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t, ok := TokenFromContext(r.Context())
			if !ok {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			repoID, ok := repoIDFromURL(r)
			if !ok {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			for _, sc := range t.Scopes {
				if sc == domain.ScopeAdmin || sc.AllowsWrite(repoID) {
					next.ServeHTTP(w, r)
					return
				}
			}
			// Валидный токен не с тем scope — аудируем префикс, не секрет.
			// RequireAPIToken выше уже положил token-user в request-контекст;
			// для наружного audit он выглядел бы actor'ом успеха. Затираем
			// user-контекст значением-заглушкой: реальный actor — маркер.
			ctx := context.WithValue(r.Context(), userKey{}, domain.User{})
			ctx = WithAuditActor(ctx, "token:"+t.Prefix)
			*r = *r.WithContext(ctx)
			http.Error(w, "forbidden", http.StatusForbidden)
		}))
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, ok := bearer(r)
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if strings.HasPrefix(raw, "khz_") {
				token.ServeHTTP(w, r)
				return
			}
			session.ServeHTTP(w, r)
		})
	}
}

// repoIDFromURL достаёт {id} из chi URL и парсит в int64. ok=false
// для отсутствующего/нечислового ID — middleware трактует как 403.
func repoIDFromURL(r *http.Request) (int64, bool) {
	raw := chi.URLParam(r, "id")
	if raw == "" {
		return 0, false
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}
