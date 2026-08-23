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
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"khrazhevnik/internal/core/engine/auth"
	"khrazhevnik/internal/core/engine/cache"
	"khrazhevnik/internal/core/port"
	authmw "khrazhevnik/internal/core/web/middleware"
)

// Deps — зависимости HTTP-доставки; растёт вместе с движками
// (аутентификация — сессия 05, кеш — 06, задачи — 09, метрики — 09,
// зеркало — 11).
type Deps struct {
	Log        *slog.Logger
	Version    string
	Auth       *auth.Service
	SetupToken string
	Cache      *cache.Engine
	Ecosystems map[string]port.Ecosystem
	// Срезы каталога для админ-API (сессия 09): remotes CRUD, аудит.
	Remotes port.RemoteStore
	Audit   port.AuditLog
	// TaskRegistry — общая инфраструктура фоновых задач (sync, publish).
	Tasks *TaskRegistry
	// Mirror — движок синхронизации зеркал (сессия 11); nil в
	// деградированном режиме — handleSyncRemote отдаёт 503.
	Mirror MirrorSync
	// MetricsHandler — /metrics (Prometheus); nil, если метрики
	// отключены конфигом.
	MetricsHandler http.Handler
	// Clock — для автоматического аудита и хендлеров, где нужно
	// «сейчас» (создание remote, запуск sync). Тесты подменяют.
	Clock port.Clock
}

// MirrorSync — тонкий срез mirror.Engine, нужный API-хендлеру sync:
// запуск синхронизации remote как фоновой задачи TaskRegistry.
// Движок зеркала живёт в core/engine/mirror; web не импортирует
// engine-пакеты напрямую (depguard), только порт-совместимый срез.
type MirrorSync interface {
	Sync(ctx context.Context, remoteID int64) (taskID string, err error)
}

// BuildPublicRouter — публичный слушатель (:29202): /healthz и, с
// сессии 06, раздача пакетов экосистем.
func BuildPublicRouter(d Deps) http.Handler {
	r := chi.NewRouter()
	r.Use(RequestID)
	r.Use(LogRequests(d.logger()))
	r.Get("/healthz", handleHealthz)
	if d.Cache != nil {
		// wildcard в синтаксисе chi — «/*»; имя из {path...} (gin/echo)
		// chi не понимает. Путь достаётся URLParam(r, "*").
		r.Get("/{eco}/*", handleProxy(d))
	}
	return r
}

// BuildAdminRouter — админский слушатель (:30202): /healthz, /api/v1,
// /metrics (Prometheus, за auth) и позже SPA /ui.
func BuildAdminRouter(d Deps) http.Handler {
	r := chi.NewRouter()
	r.Use(RequestID)
	r.Use(LogRequests(d.logger()))
	r.Get("/healthz", handleHealthz)
	if d.MetricsHandler != nil {
		// /metrics — за RequireSession|RequireAPIToken с admin scope:
		// экспонешиал счётчиков кеша и латенси — внутренняя кухня,
		// публичный анонимный доступ недопустим.
		authChain := func() func(http.Handler) http.Handler {
			if d.Auth == nil {
				// Без auth-сервиса (деградированный режим) — отдаём как
				// есть: в этом режиме и считать нечего, но путь живёт.
				return func(h http.Handler) http.Handler { return h }
			}
			return authmw.RequireAdminOrAPIToken(d.Auth)
		}()
		r.With(authChain).Handle("/metrics", d.MetricsHandler)
	}
	r.Route("/api/v1", func(api chi.Router) {
		api.Get("/", handleAPIRoot(d))
		if d.Auth != nil {
			limiter := authmw.NewLoginRateLimit()
			api.Post("/setup", handleSetup(d))
			api.With(limiter.Middleware).Post("/auth/login", handleLogin(d, limiter))
			api.With(authmw.RequireSession(d.Auth)).Post("/auth/logout", handleLogout(d))

			// adminAuth — auth-цепочка для admin-only роутов: сессия
			// админа или admin-scoped API-токен. /metrics выше использует
			// ту же цепочку.
			adminAuth := authmw.RequireAdminOrAPIToken(d.Auth)
			// auditInner — аудит-мiddleware, ставится ПОСЛЕ auth (внутри
			// цепочки), чтобы видеть actor из auth-контекста. Порядок
			// chi: With(A, B) → A → B → handler; A — внешний.
			auditInner := AuditMiddleware(d.Audit, d.clock())

			// /users и /api-tokens — admin-only (вынесены из handlers_auth
			// для порядка: auth-хендлеры теперь только про аутентификацию).
			api.With(adminAuth, auditInner).Route("/users", func(users chi.Router) {
				users.Get("/", handleUsers(d))
				users.Post("/", handleCreateUser(d))
				users.Delete("/{id}", handleDeleteUser(d))
				users.Post("/{id}/api-tokens", handleCreateToken(d))
				users.Get("/{id}/api-tokens", handleListTokens(d))
				users.Delete("/{id}/api-tokens/{tokenID}", handleRevokeToken(d))
			})

			// /remotes — admin-only CRUD upstream'ов + sync-триггер.
			api.With(adminAuth, auditInner).Route("/remotes", func(remotes chi.Router) {
				remotes.Get("/", handleListRemotes(d))
				remotes.Post("/", handleCreateRemote(d))
				remotes.Patch("/{id}", handleUpdateRemote(d))
				remotes.Delete("/{id}", handleDeleteRemote(d))
				remotes.Post("/{id}/sync", handleSyncRemote(d))
			})

			// /tasks — снимки TaskRegistry; admin-only (операторская
			// панель). GET без audit-middleware (чтение).
			api.With(adminAuth).Route("/tasks", func(tasks chi.Router) {
				tasks.Get("/", handleListTasks(d))
				tasks.Get("/{id}", handleGetTask(d))
			})

			// /cache/stats — статистика кеша; admin-only.
			api.With(adminAuth).Get("/cache/stats", handleCacheStats(d))

			// /audit — keyset-пагинация; admin-only.
			api.With(adminAuth).Get("/audit", handleAuditPage(d))
		}
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

// clock — порт часов депсов или системная реализация (nil-безопасность
// для тестов без временной логики).
func (d Deps) clock() port.Clock {
	if d.Clock != nil {
		return d.Clock
	}
	return systemWebClock{}
}
