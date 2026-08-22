package middleware

import (
	"context"
	"net/http"
	"strings"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/engine/auth"
)

type userKey struct{}
type tokenKey struct{}
type jtiKey struct{}

// UserFromContext returns the user authenticated by a middleware.
func UserFromContext(ctx context.Context) (domain.User, bool) {
	u, ok := ctx.Value(userKey{}).(domain.User)
	return u, ok
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
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), userKey{}, session.User)
			ctx = context.WithValue(ctx, jtiKey{}, session.JTI)
			next.ServeHTTP(w, r.WithContext(ctx))
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
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), userKey{}, user)
			ctx = context.WithValue(ctx, tokenKey{}, token)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAdmin enforces the live role loaded from the database.
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := UserFromContext(r.Context())
		if !ok || u.Role != domain.RoleAdmin {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireScope checks an API token scope, or the admin role for sessions.
func RequireScope(scope domain.Scope) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if u, ok := UserFromContext(r.Context()); ok && u.Role == domain.RoleAdmin {
				next.ServeHTTP(w, r)
				return
			}
			t, ok := TokenFromContext(r.Context())
			if !ok {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			for _, got := range t.Scopes {
				if got == scope || (scope != domain.ScopeAdmin && got == domain.ScopeAdmin) {
					next.ServeHTTP(w, r)
					return
				}
			}
			http.Error(w, "forbidden", http.StatusForbidden)
		})
	}
}
