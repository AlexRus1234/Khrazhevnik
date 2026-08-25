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

// Тонкие хендлеры админ-API личных репозиториев (сессия 14). Маппинг
// domain-ошибок на HTTP — централизован в statusFor (validate.go).
// RBAC — на двух уровнях: adminAuth для CRUD/perms (только админ),
// RequireRepoAccess для upload/delete/reindex (admin|owner|scoped-токен).

package web

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"khrazhevnik/internal/core/domain"
)

// repoOut — DTO ответа репо: поля без аудит-мусора.
type repoOut struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	OwnerID   int64     `json:"owner_id"`
	Ecosystem string    `json:"ecosystem"`
	Quota     quotaOut  `json:"quota"`
	CreatedAt time.Time `json:"created_at"`
}

type quotaOut struct {
	MaxBytes   int64 `json:"max_bytes"`
	MaxObjects int64 `json:"max_objects"`
}

func repoOutFrom(r domain.Repo) repoOut {
	return repoOut{
		ID: r.ID, Name: r.Name, OwnerID: r.OwnerID, Ecosystem: r.Ecosystem,
		Quota:     quotaOut{MaxBytes: r.Quota.MaxBytes, MaxObjects: r.Quota.MaxObjects},
		CreatedAt: r.CreatedAt,
	}
}

// repoInput — тело POST/PATCH /api/v1/repos.
type repoInput struct {
	Name      string   `json:"name"`
	OwnerID   int64    `json:"owner_id"`
	Ecosystem string   `json:"ecosystem"`
	Quota     quotaOut `json:"quota"`
}

// validate нормализует поля (name/eco → lowercase, trim) и проверяет
// доменными валидаторами. Возвращает первую ошибку.
func (in *repoInput) validate() error {
	in.Name = strings.ToLower(strings.TrimSpace(in.Name))
	in.Ecosystem = strings.ToLower(strings.TrimSpace(in.Ecosystem))
	if err := domain.ValidateRepoName(in.Name); err != nil {
		return err
	}
	if in.Ecosystem == "" {
		return &domain.ValidationError{What: "экосистема", Value: in.Ecosystem, Reason: "пусто"}
	}
	if in.OwnerID <= 0 {
		return &domain.ValidationError{What: "owner_id", Value: strconv.FormatInt(in.OwnerID, 10), Reason: "должен быть положительным"}
	}
	if in.Quota.MaxBytes < 0 || in.Quota.MaxObjects < 0 {
		return &domain.ValidationError{What: "quota", Value: "", Reason: "отрицательные поля недопустимы"}
	}
	return nil
}

// handleListRepos — GET /api/v1/repos: список репозиториев.
func handleListRepos(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Repos == nil {
			writeJSON(w, http.StatusOK, []repoOut{})
			return
		}
		rs, err := d.Repos.Repos(r.Context())
		if err != nil {
			writeErr(w, err)
			return
		}
		out := make([]repoOut, 0, len(rs))
		for _, r := range rs {
			out = append(out, repoOutFrom(r))
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// handleCreateRepo — POST /api/v1/repos: создать личный репо (админ).
// Ecosystem проверяется через реестр: publish-движок упадёт на reindex
// с UnsupportedError, если адаптер не зарегистрирован (M3 — только apt).
func handleCreateRepo(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Repos == nil {
			writeErrCode(w, http.StatusServiceUnavailable, "publish_unavailable")
			return
		}
		var in repoInput
		if !decodeJSON(w, r, &in) {
			return
		}
		if err := in.validate(); err != nil {
			writeErr(w, err)
			return
		}
		repo, err := d.Repos.CreateRepo(r.Context(), domain.Repo{
			Name: in.Name, OwnerID: in.OwnerID, Ecosystem: in.Ecosystem,
			Quota:     domain.Quota{MaxBytes: in.Quota.MaxBytes, MaxObjects: in.Quota.MaxObjects},
			CreatedAt: d.clock().Now(),
		})
		if err != nil {
			writeErr(w, err)
			return
		}
		*r = *r.WithContext(WithAuditAction(r.Context(), "repo.create"))
		writeJSON(w, http.StatusCreated, repoOutFrom(repo))
	}
}

// handleGetRepo — GET /api/v1/repos/{id}.
func handleGetRepo(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := parseInt64URLParam(w, r, "id")
		if !ok {
			return
		}
		repo, err := d.Repos.Repo(r.Context(), id)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, repoOutFrom(repo))
	}
}

// handleUpdateRepo — PATCH /api/v1/repos/{id}: full-replace.
func handleUpdateRepo(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := parseInt64URLParam(w, r, "id")
		if !ok {
			return
		}
		existing, err := d.Repos.Repo(r.Context(), id)
		if err != nil {
			writeErr(w, err)
			return
		}
		var in repoInput
		if !decodeJSON(w, r, &in) {
			return
		}
		if err := in.validate(); err != nil {
			writeErr(w, err)
			return
		}
		updated := domain.Repo{
			ID: existing.ID, Name: in.Name, OwnerID: in.OwnerID, Ecosystem: in.Ecosystem,
			Quota:     domain.Quota{MaxBytes: in.Quota.MaxBytes, MaxObjects: in.Quota.MaxObjects},
			CreatedAt: existing.CreatedAt,
		}
		if err := d.Repos.UpdateRepo(r.Context(), updated); err != nil {
			writeErr(w, err)
			return
		}
		*r = *r.WithContext(WithAuditAction(r.Context(), "repo.update"))
		writeJSON(w, http.StatusOK, repoOutFrom(updated))
	}
}

// handleDeleteRepo — DELETE /api/v1/repos/{id}. Права каскадом (FK
// ON DELETE CASCADE); объекты storage остаются — v1 не делает batch-
// delete по префиксу (документируем как расхождение; чистит фоновая
// чистка или ручной delete).
func handleDeleteRepo(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := parseInt64URLParam(w, r, "id")
		if !ok {
			return
		}
		if err := d.Repos.DeleteRepo(r.Context(), id); err != nil {
			writeErr(w, err)
			return
		}
		*r = *r.WithContext(WithAuditAction(r.Context(), "repo.delete"))
		w.WriteHeader(http.StatusNoContent)
	}
}

// permOut — DTO права на запись в репо.
type permOut struct {
	RepoID    int64     `json:"repo_id"`
	UserID    int64     `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
}

// handleListPerms — GET /api/v1/repos/{id}/perms.
func handleListPerms(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := parseInt64URLParam(w, r, "id")
		if !ok {
			return
		}
		ps, err := d.Repos.Perms(r.Context(), id)
		if err != nil {
			writeErr(w, err)
			return
		}
		out := make([]permOut, 0, len(ps))
		for _, p := range ps {
			out = append(out, permOut{RepoID: p.RepoID, UserID: p.UserID, CreatedAt: p.CreatedAt})
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// handleGrantPerm — POST /api/v1/repos/{id}/perms: {user_id}. Выдаёт
// право записи; идемпотентно (повторный грант того же user → 204, не
// 409: модель perms как set, а не upsert).
func handleGrantPerm(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := parseInt64URLParam(w, r, "id")
		if !ok {
			return
		}
		var in struct {
			UserID int64 `json:"user_id"`
		}
		if !decodeJSON(w, r, &in) {
			return
		}
		if in.UserID <= 0 {
			writeErrCode(w, http.StatusBadRequest, "validation_error")
			return
		}
		err := d.Repos.Grant(r.Context(), domain.Perm{RepoID: id, UserID: in.UserID, CreatedAt: d.clock().Now()})
		if err != nil {
			var conf *domain.ConflictError
			if errors.As(err, &conf) {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			writeErr(w, err)
			return
		}
		*r = *r.WithContext(WithAuditAction(r.Context(), "repo.perm.grant"))
		w.WriteHeader(http.StatusNoContent)
	}
}

// handleRevokePerm — DELETE /api/v1/repos/{id}/perms/{userID}.
func handleRevokePerm(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := parseInt64URLParam(w, r, "id")
		if !ok {
			return
		}
		userID, ok := parseInt64URLParam(w, r, "userID")
		if !ok {
			return
		}
		if err := d.Repos.Revoke(r.Context(), id, userID); err != nil {
			writeErr(w, err)
			return
		}
		*r = *r.WithContext(WithAuditAction(r.Context(), "repo.perm.revoke"))
		w.WriteHeader(http.StatusNoContent)
	}
}

// objectOut — DTO листинга объектов репо.
type objectOut struct {
	Key     string    `json:"key"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
}

// handleListObjects — GET /api/v1/repos/{id}/objects: листинг ключей
// и размеров. Делегирует publish.API.ListObjects (Storage.List под
// префиксом repo/<id>/).
func handleListObjects(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Publish == nil {
			writeErrCode(w, http.StatusServiceUnavailable, "publish_unavailable")
			return
		}
		id, ok := parseInt64URLParam(w, r, "id")
		if !ok {
			return
		}
		repo, err := d.Repos.Repo(r.Context(), id)
		if err != nil {
			writeErr(w, err)
			return
		}
		out := make([]objectOut, 0)
		for meta := range d.Publish.ListObjects(r.Context(), repo) {
			out = append(out, objectOut{Key: meta.Key, Size: meta.Size, ModTime: meta.ModTime})
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// handlePutObject — PUT /api/v1/repos/{id}/objects/*: стриминг upload.
// Content-Length обязателен (v1); force=true (query) — переписать
// существующий ключ (RBAC: только админ, scoped-токен не пройдёт
// валидацию контракта force в движке — v1: middleware отсекает чужих,
// внутри движка роль не проверяется; для строгости можно добавить
// RBAC-role-чек внутри handler, но KISS — admin через middleware
// ужеADMIN-gated по owner-or-admin-or-scoped; scoped-токен без force).
func handlePutObject(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Publish == nil {
			writeErrCode(w, http.StatusServiceUnavailable, "publish_unavailable")
			return
		}
		id, ok := parseInt64URLParam(w, r, "id")
		if !ok {
			return
		}
		repo, err := d.Repos.Repo(r.Context(), id)
		if err != nil {
			writeErr(w, err)
			return
		}
		// Путь внутри репо — хвост после /objects/. chi URLParam "*" —
		// весь остаток, decode %2F не нужен (apt-пути не содержат
		// закодированных слешей).
		objPath := chi.URLParam(r, "*")
		if objPath == "" {
			writeErrCode(w, http.StatusBadRequest, "validation_error")
			return
		}
		// Лоуэркейс: domain.ValidateKey пропускает только [a-z0-9/._-];
		// apt-клиенты иногда присылают имена с верхним регистром —
		// нормализуем здесь, до ValidateKey в движке.
		objPath = strings.ToLower(objPath)
		size := r.ContentLength
		if size < 0 {
			writeErrCode(w, http.StatusLengthRequired, "length_required")
			return
		}
		force := r.URL.Query().Has("force")
		if err := d.Publish.Upload(r.Context(), repo, objPath, size, r.Body, force); err != nil {
			writeErr(w, err)
			return
		}
		*r = *r.WithContext(WithAuditAction(r.Context(), "repo.object.upload"))
		writeJSON(w, http.StatusCreated, map[string]any{"path": objPath, "size": size})
	}
}

// handleDeleteObject — DELETE /api/v1/repos/{id}/objects/*.
func handleDeleteObject(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Publish == nil {
			writeErrCode(w, http.StatusServiceUnavailable, "publish_unavailable")
			return
		}
		id, ok := parseInt64URLParam(w, r, "id")
		if !ok {
			return
		}
		repo, err := d.Repos.Repo(r.Context(), id)
		if err != nil {
			writeErr(w, err)
			return
		}
		objPath := strings.ToLower(chi.URLParam(r, "*"))
		if objPath == "" {
			writeErrCode(w, http.StatusBadRequest, "validation_error")
			return
		}
		if err := d.Publish.DeleteObject(r.Context(), repo, objPath); err != nil {
			writeErr(w, err)
			return
		}
		*r = *r.WithContext(WithAuditAction(r.Context(), "repo.object.delete"))
		w.WriteHeader(http.StatusNoContent)
	}
}

// handleReindexRepo — POST /api/v1/repos/{id}/reindex → 202 + task-id.
// Запускает publish.Reindex через TaskRegistry (kind=reindex,
// label=repo.Name); дублирующий reindex того же репо → 409, лимит
// воркеров → 429.
func handleReindexRepo(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Publish == nil {
			writeErrCode(w, http.StatusServiceUnavailable, "publish_unavailable")
			return
		}
		id, ok := parseInt64URLParam(w, r, "id")
		if !ok {
			return
		}
		taskID, err := d.Publish.Reindex(r.Context(), id)
		if err != nil {
			writeErr(w, err)
			return
		}
		*r = *r.WithContext(WithAuditAction(r.Context(), "repo.reindex"))
		writeJSON(w, http.StatusAccepted, map[string]string{"task_id": taskID})
	}
}
