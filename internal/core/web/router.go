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
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Deps — зависимости HTTP-доставки; растёт вместе с движками
// (аутентификация — сессия 05, кеш — 06, задачи — 09).
type Deps struct {
	Log     *slog.Logger
	Version string
}

// BuildPublicRouter — публичный слушатель (:29202): /healthz и, с
// сессии 06, раздача пакетов экосистем.
func BuildPublicRouter(d Deps) http.Handler {
	r := chi.NewRouter()
	r.Use(RequestID)
	r.Use(LogRequests(d.logger()))
	r.Get("/healthz", handleHealthz)
	return r
}

// BuildAdminRouter — админский слушатель (:30202): /healthz, /api/v1,
// позже /metrics и SPA /ui.
func BuildAdminRouter(d Deps) http.Handler {
	r := chi.NewRouter()
	r.Use(RequestID)
	r.Use(LogRequests(d.logger()))
	r.Get("/healthz", handleHealthz)
	r.Route("/api/v1", func(api chi.Router) {
		api.Get("/", handleAPIRoot(d)) // заглушка до сессии 05
	})
	return r
}

// handleHealthz — liveness-проба без зависимостей: слушатель жив.
func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// handleAPIRoot — корень API: имя сервиса и версия (для проверки
// сборки курлом).
func handleAPIRoot(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"service": "khrazhevnik",
			"api":     "v1",
			"version": d.Version,
		})
	}
}

// writeJSON — единая точка JSON-ответов.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// logger — логгер депсов или slog.Default (nil-безопасность).
func (d Deps) logger() *slog.Logger {
	if d.Log != nil {
		return d.Log
	}
	return slog.Default()
}
