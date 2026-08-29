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

// Auth-only хендлеры: setup первого админа, login, logout. Управление
// users/tokens вынесено в handlers_admin.go (сессия 09): «навести
// порядок — auth-хендлеры только про аутентификацию». Все ошибки идут
// через централизованный writeErr/statusFor (validate.go).

package web

import (
	"crypto/subtle"
	"errors"
	"net/http"

	"khrazhevnik/internal/core/domain"

	authmw "khrazhevnik/internal/core/web/middleware"
)

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// handleSetup — POST /api/v1/setup: первый админ. Атомарность —
// EnsureFirstAdmin (один INSERT ... WHERE NOT EXISTS): параллельные
// вызовы в bootstrap-окне завершает ровно один победитель, остальные —
// 403 setup_already_done (аудит 2026-08-27). Опциональный X-Setup-Token.
func handleSetup(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Auth == nil {
			writeErrCode(w, http.StatusNotFound, "not_found")
			return
		}
		if d.SetupToken != "" {
			token := r.Header.Get("X-Setup-Token")
			if subtle.ConstantTimeCompare([]byte(token), []byte(d.SetupToken)) != 1 {
				writeErrCode(w, http.StatusForbidden, "invalid_setup_token")
				return
			}
		}
		var in credentials
		if !decodeJSON(w, r, &in) {
			return
		}
		u, created, err := d.Auth.EnsureFirstAdmin(r.Context(), in.Username, in.Password)
		if err != nil {
			writeErr(w, err)
			return
		}
		if !created {
			writeErrCode(w, http.StatusForbidden, "setup_already_done")
			return
		}
		*r = *r.WithContext(WithAuditAction(r.Context(), "setup"))
		writeJSON(w, http.StatusCreated, userOut(u))
	}
}

// handleLogin — POST /api/v1/auth/login: проверка учётных данных и
// выдача JWT. Аудит успешных/неуспешных попыток пишется в самом движке
// auth (actor ещё неизвестен до входа).
func handleLogin(d Deps, limiter *authmw.LoginRateLimit) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in credentials
		if !decodeJSON(w, r, &in) {
			return
		}
		token, err := d.Auth.Login(r.Context(), in.Username, in.Password)
		if err != nil {
			var forb *domain.ForbiddenError
			if errors.As(err, &forb) {
				writeErrCode(w, http.StatusUnauthorized, "invalid_credentials")
				return
			}
			// сбой каталога — 503, остальное — 500 через статусFor
			writeErr(w, err)
			return
		}
		limiter.ResetRequest(r)
		writeJSON(w, http.StatusOK, map[string]string{"token": token})
	}
}

// handleLogout — POST /api/v1/auth/logout: персистентный отзыв JWT
// (переживает рестарт, сессия 25). Ошибка вставки — не 204: logout,
// не переживающий рестарт, отчитался бы ложным успехом.
func handleLogout(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := d.Auth.RevokeSession(r.Context(), authmw.JTIFromContext(r.Context())); err != nil {
			writeErr(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
