package web

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"khrazhevnik/internal/core/domain"
	authmw "khrazhevnik/internal/core/web/middleware"
)

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if json.NewDecoder(r.Body).Decode(v) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return false
	}
	return true
}

func handleSetup(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Auth == nil {
			http.NotFound(w, r)
			return
		}
		has, err := d.Auth.HasUsers(r.Context())
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "database"})
			return
		}
		if has {
			writeJSON(w, 403, map[string]string{"error": "setup_already_done"})
			return
		}
		if d.SetupToken != "" {
			token := r.Header.Get("X-Setup-Token")
			if subtle.ConstantTimeCompare([]byte(token), []byte(d.SetupToken)) != 1 {
				writeJSON(w, 403, map[string]string{"error": "invalid_setup_token"})
				return
			}
		}
		var in credentials
		if !decode(w, r, &in) {
			return
		}
		u, err := d.Auth.CreateUser(r.Context(), in.Username, in.Password, domain.RoleAdmin)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		u.PasswordHash = ""
		writeJSON(w, 201, u)
	}
}

func handleLogin(d Deps, limiter *authmw.LoginRateLimit) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in credentials
		if !decode(w, r, &in) {
			return
		}
		token, err := d.Auth.Login(r.Context(), in.Username, in.Password)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_credentials"})
			return
		}
		limiter.Reset(r.RemoteAddr)
		writeJSON(w, http.StatusOK, map[string]string{"token": token})
	}
}
func handleLogout(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		d.Auth.RevokeSession(authmw.JTIFromContext(r.Context()))
		writeJSON(w, http.StatusNoContent, nil)
	}
}
func handleUsers(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		us, err := d.Auth.Users(r.Context())
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "database"})
			return
		}
		for i := range us {
			us[i].PasswordHash = ""
		}
		writeJSON(w, 200, us)
	}
}
func handleCreateUser(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			credentials
			Role domain.Role `json:"role"`
		}
		if !decode(w, r, &in) {
			return
		}
		if in.Role == "" {
			in.Role = domain.RoleUser
		}
		u, err := d.Auth.CreateUser(r.Context(), in.Username, in.Password, in.Role)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		u.PasswordHash = ""
		writeJSON(w, http.StatusCreated, u)
	}
}
func handleDeleteUser(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
		if err != nil {
			http.Error(w, "bad id", 400)
			return
		}
		if err = d.Auth.DeleteUser(r.Context(), id); err != nil {
			writeJSON(w, 404, map[string]string{"error": err.Error()})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
func handleCreateToken(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
		u, err := d.Auth.User(r.Context(), id)
		if err != nil {
			http.Error(w, "not found", 404)
			return
		}
		var in struct {
			Name   string         `json:"name"`
			Scopes []domain.Scope `json:"scopes"`
			TTL    time.Duration  `json:"ttl"`
		}
		if !decode(w, r, &in) {
			return
		}
		t, raw, err := d.Auth.IssueAPIToken(r.Context(), u, in.Scopes, in.TTL)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 201, map[string]any{"token": raw, "id": t.ID, "name": t.Name, "scopes": t.Scopes, "expires_at": t.ExpiresAt})
	}
}
func handleListTokens(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
		ts, err := d.Auth.Tokens(r.Context(), id)
		if err != nil {
			http.Error(w, "database", 500)
			return
		}
		writeJSON(w, 200, ts)
	}
}
func handleRevokeToken(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(chi.URLParam(r, "tokenID"), 10, 64)
		if err := d.Auth.RevokeToken(r.Context(), id); err != nil {
			http.Error(w, err.Error(), 404)
			return
		}
		w.WriteHeader(204)
	}
}
