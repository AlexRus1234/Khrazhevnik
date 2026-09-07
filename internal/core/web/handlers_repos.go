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

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
	authmw "khrazhevnik/internal/core/web/middleware"
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
// доменными валидаторами. Ecosystem сверяется с реестром Deps
// .Ecosystems (те же имена, что у роутера прокси): любая непустая
// строка раньше проходила, и каждый upload обрекался на invalid_key
// (аудит 2026-08-30). Возвращает первую ошибку.
func (in *repoInput) validate(ecosystems map[string]port.Ecosystem) error {
	in.Name = strings.ToLower(strings.TrimSpace(in.Name))
	in.Ecosystem = strings.ToLower(strings.TrimSpace(in.Ecosystem))
	if err := domain.ValidateRepoName(in.Name); err != nil {
		return err
	}
	if in.Ecosystem == "" {
		return &domain.ValidationError{What: "экосистема", Value: in.Ecosystem, Reason: "пусто"}
	}
	if _, ok := ecosystems[in.Ecosystem]; !ok {
		return &domain.ValidationError{What: "экосистема", Value: in.Ecosystem, Reason: "нет такого адаптера (зарегистрированы: apt, rpm-md, pacman, apk, nix; включены — зависит от конфига)"}
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
		if err := in.validate(d.Ecosystems); err != nil {
			writeErr(w, err)
			return
		}
		*r = *r.WithContext(WithAuditAction(r.Context(), "repo.create"))
		repo, err := d.Repos.CreateRepo(r.Context(), domain.Repo{
			Name: in.Name, OwnerID: in.OwnerID, Ecosystem: in.Ecosystem,
			Quota:     domain.Quota{MaxBytes: in.Quota.MaxBytes, MaxObjects: in.Quota.MaxObjects},
			CreatedAt: d.clock().Now(),
		})
		if err != nil {
			writeErr(w, err)
			return
		}
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
		if err := in.validate(d.Ecosystems); err != nil {
			writeErr(w, err)
			return
		}
		// ecosystem — immutable: ключи объектов «repo/<id>/<eco>/…»,
		// смена осиротила бы всё опубликованное (аудит 2026-08-30).
		// PATCH с тем же значением (full-replace присылает все поля) —
		// ок, отличающееся — validation_error.
		if in.Ecosystem != existing.Ecosystem {
			writeErr(w, &domain.ValidationError{What: "ecosystem", Value: in.Ecosystem, Reason: "immutable field: смена осиротит опубликованные объекты"})
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
// delete по префиксу (документируем как расхождение: осиротевшие
// repo/<id>/ накапливаются, выметающей чистки в v1 нет — см. ROADMAP;
// убрать можно только ручным delete).
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
// 409: модель perms как set, а не upsert). До INSERT проверяем пару
// repo/user выборками: FK-нарушение 23503 (несуществующий user_id)
// mapWrite мапит в ConflictError — без проверки это ложный 204
// «успех» (аудит 2026-08-30). Двойная выборка на редкой админ-
// операции — плата за честный 404; вариант с Kind в ConflictError
// отклонён: трогал бы домен и все три драйвера ради одного хендлера.
// Pre-check не закрывает race-окно (юзер удалён между User() и
// Grant()): отличаем unique-дубль от FK по Reason — mapWrite всех
// трёх драйверов (сессия 21) оставляет Reason пустым ТОЛЬКО у
// unique-нарушений, FK/NOT NULL/CHECK получают непустой.
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
		if _, err := d.Repos.Repo(r.Context(), id); err != nil {
			writeErr(w, err)
			return
		}
		if _, err := d.Auth.User(r.Context(), in.UserID); err != nil {
			writeErr(w, err)
			return
		}
		// Action ставится ДО Grant: идемпотентный дубль-204 (пустой
		// Reason) пишется под тем же repo.perm.grant, а не под
		// fallback-именем метода+пути — два имени одной операции
		// ломали однообразие трейла.
		*r = *r.WithContext(WithAuditAction(r.Context(), "repo.perm.grant"))
		err := d.Repos.Grant(r.Context(), domain.Perm{RepoID: id, UserID: in.UserID, CreatedAt: d.clock().Now()})
		if err != nil {
			var conf *domain.ConflictError
			if errors.As(err, &conf) {
				// Пустой Reason — genuine unique-дубль: идемпотентный
				// 204. Непустой (FK и пр.) — юзер/репо исчезли в
				// окне после пред-проверки: 404, как и pre-check-путь,
				// а не ложный «успех» с аудитом ok.
				if conf.Reason == "" {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				// Текст не называет виновного: FK стоит и на user_id,
				// и на repo_id (migrations 0001), хендлер не знает,
				// какая из двух сущностей исчезла (сессия 62). Тело
				// API несёт только not_found-код (i18n на фронте),
				// честный текст — в detail аудита для оператора.
				*r = *r.WithContext(WithAuditDetail(r.Context(), "пользователь или репозиторий исчез во время выдачи права (гонка удаления)"))
				writeErr(w, &domain.NotFoundError{What: "пользователь или репозиторий исчез во время выдачи права (гонка удаления)", Key: strconv.FormatInt(in.UserID, 10)})
				return
			}
			writeErr(w, err)
			return
		}
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
// префиксом repo/<id>/). Ошибка листинга — 5xx (не пустой список:
// клиент не должен путать сбой носителя с «объектов нет»).
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
		for meta, err := range d.Publish.ListObjects(r.Context(), repo) {
			if err != nil {
				writeErr(w, err)
				return
			}
			out = append(out, objectOut{Key: meta.Key, Size: meta.Size, ModTime: meta.ModTime})
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// handlePutObject — PUT /api/v1/repos/{id}/objects/*: стриминг upload.
// Content-Length обязателен (v1); force=true (query) — переписать
// существующий ключ. force — привилегия админ-сессии (аудит
// 2026-08-27): перезапись опубликованных content-addressed объектов
// равна отравлению репо, scoped-токен repo:<id>:write и не-админ-
// владелец получают 403 (RequireRepoAccess остаётся, поверх — роль).
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
		// Путь внутри репо — хвост после /objects/. chi отдаёт wildcard
		// экранированным (RawPath-маршрутизация, chi v5.3.1 mux.go:455):
		// клиент, кодирующий «+» как %2b, иначе ловит 400 на ValidateKey
		// (whitelist режет «%») — декод обязателен (decodedWildcard).
		objPath, err := decodedWildcard(r)
		if err != nil {
			writeErrCode(w, http.StatusBadRequest, "validation_error")
			return
		}
		if objPath == "" {
			writeErrCode(w, http.StatusBadRequest, "validation_error")
			return
		}
		// Лоуэркейс — v1-конвенция «опубликованные ключи lowercase»
		// (docs/func/ru/personal-repos.md): генераторы индексов и
		// клиентские URL рассчитаны на неё. Сессия 19 разрешила
		// верхний регистр в ValidateKey для case-чувствительных
		// путей прокси-кеша — ветку publish сознательно не меняем.
		objPath = strings.ToLower(objPath)
		size := r.ContentLength
		if size < 0 {
			writeErrCode(w, http.StatusLengthRequired, "length_required")
			return
		}
		force := r.URL.Query().Has("force")
		if force && !isAdminSession(r) {
			writeErrCode(w, http.StatusForbidden, "admin_required")
			return
		}
		// stallReader: таймауты админ-сервера (30s) мерятся от начала
		// запроса и рвали бы upload большого пакета на медленном канале
		// (read, сессия 27) и ответ после него (write, сессия 78) —
		// каждый Read тела продлевает оба дедлайна (stream.go). Только
		// этот эндпоинт: остальные тела админ-API идут через decodeJSON
		// и уже под MaxBytesReader 1 MiB (validate.go) — им окно не нужно.
		*r = *r.WithContext(WithAuditAction(r.Context(), "repo.object.upload"))
		if err := d.Publish.Upload(r.Context(), repo, objPath, size, newStallReader(w, r.Body), force); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"path": objPath, "size": size})
	}
}

// isAdminSession — админ-сессия без API-токена: user из auth-контекста
// с ролью admin, пришедший по JWT (не по khz_-токену). Даже admin-
// scoped токен для force не годится: компрометация токена не должна
// давать перезапись опубликованных объектов (аудит 2026-08-27).
func isAdminSession(r *http.Request) bool {
	if _, isToken := authmw.TokenFromContext(r.Context()); isToken {
		return false
	}
	u, ok := authmw.UserFromContext(r.Context())
	return ok && u.Role == domain.RoleAdmin
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
		objPath, err := decodedWildcard(r)
		if err != nil {
			writeErrCode(w, http.StatusBadRequest, "validation_error")
			return
		}
		if objPath == "" {
			writeErrCode(w, http.StatusBadRequest, "validation_error")
			return
		}
		objPath = strings.ToLower(objPath)
		*r = *r.WithContext(WithAuditAction(r.Context(), "repo.object.delete"))
		if err := d.Publish.DeleteObject(r.Context(), repo, objPath); err != nil {
			writeErr(w, err)
			return
		}
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
