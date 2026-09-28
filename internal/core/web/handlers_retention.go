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

// Хендлеры ретеншн-политики личных репозиториев (сессия 172): прогноз,
// применение и пины версий. Политика живёт в самом репо (GET/PATCH
// /repos), здесь — действия по ней.
//
// Прогноз синхронный: сухой остаток считается движком за один обход
// листинга (секунды), 202+task для просмотра был бы избыточен — задачей
// идёт только apply (удаления + reindex). Права: preview/apply — admin
// (политика и чистка — админская настройка репо, как CRUD), пины —
// RequireRepoAccess (пин ставит владелец или scoped-токен репо, не любой
// админ-CRUD: прецедент upload/delete). Аудит: apply/pin/unpin под своими
// именами и ДО мутации (урок сессии 87); preview — чтение, без записи.

package web

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
)

// RetentionCandidate — строка прогноза: версия семейства, прошедшая
// топ-N-фильтр политики. ProtectedBy — первая сработавшая защита
// («access» — свежее обращение, «pin» — пин); пусто — кандидат на
// удаление. Версии, удержанные топ-N, в прогноз не попадают: их считает
// totals.protected_by_min (прогноз показывает то, что политика
// рассматривает, а не весь репозиторий).
type RetentionCandidate struct {
	Key         string    `json:"key"`
	Family      string    `json:"family"`
	Size        int64     `json:"size"`
	ModTime     time.Time `json:"mod_time"`
	LastAccess  time.Time `json:"last_access"`
	ProtectedBy string    `json:"protected_by"`
}

// RetentionTotals — счётчики прохода (Result движка ретеншна в терминах
// web): totals прогноза и итог задачи apply.
type RetentionTotals struct {
	DryRun            bool    `json:"dry_run"`
	DurationSeconds   float64 `json:"duration_seconds"`
	Families          int64   `json:"families"`
	ObjectsScanned    int64   `json:"objects_scanned"`
	Candidates        int64   `json:"candidates"`
	Deleted           int64   `json:"deleted"`
	FailedDeletes     int64   `json:"failed_deletes"`
	BytesFreed        int64   `json:"bytes_freed"`
	ProtectedByMin    int64   `json:"protected_by_min"`
	ProtectedByAccess int64   `json:"protected_by_access"`
	ProtectedByPin    int64   `json:"protected_by_pin"`
}

// RetentionPreview — ответ GET /api/v1/repos/{id}/retention/preview.
type RetentionPreview struct {
	Candidates []RetentionCandidate `json:"candidates"`
	Totals     RetentionTotals      `json:"totals"`
}

// handleRetentionPreview — GET /api/v1/repos/{id}/retention/preview:
// сухой проход (движок, dryRun) и отчёт по кандидатам. Носитель не
// меняется; политика выключена — пустой отчёт, не ошибка.
func handleRetentionPreview(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Retention == nil {
			writeErrCode(w, http.StatusServiceUnavailable, "retention_unavailable")
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
		preview, err := d.Retention.Preview(r.Context(), repo)
		if err != nil {
			writeErr(w, err)
			return
		}
		if preview.Candidates == nil {
			// Пустой прогноз — пустой массив, не null: фронт рисует
			// dim-строку «кандидатов нет» (сессия 173).
			preview.Candidates = []RetentionCandidate{}
		}
		writeJSON(w, http.StatusOK, preview)
	}
}

// handleRetentionApply — POST /api/v1/repos/{id}/retention/apply:
// проход политики с перегенерацией индексов как фоновая задача
// TaskRegistry (kind=retention, label=repo-<id>; прецедент gc|repo-<id>
// сессии 122). Повторный запуск при активной задаче того же репо — 409
// (ErrTaskDuplicate → statusFor), лимит воркеров — 429.
func handleRetentionApply(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Retention == nil || d.Tasks == nil {
			writeErrCode(w, http.StatusServiceUnavailable, "retention_unavailable")
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
		// Action до запуска задачи (урок сессии 87): и 409/429, и запись
		// middleware идут под repo.retention.apply, а не под
		// fallback-именем метода+пути.
		*r = *r.WithContext(WithAuditAction(r.Context(), "repo.retention.apply"))
		taskID, err := d.Tasks.Start("retention", fmt.Sprintf("repo-%d", id), func(ctx context.Context, p Progress) error {
			res, err := d.Retention.ApplyAndReindex(ctx, repo, false)
			if err != nil {
				return err
			}
			p.Log(fmt.Sprintf("проход завершён: кандидатов %d, удалено %d (%s), сбоев удаления %d, защита: топ-N %d, обращение %d, пин %d",
				res.Candidates, res.Deleted, humanBytes(res.BytesFreed), res.FailedDeletes,
				res.ProtectedByMin, res.ProtectedByAccess, res.ProtectedByPin))
			return nil
		})
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"task_id": taskID})
	}
}

// handleListRetentionPins — GET /api/v1/repos/{id}/retention/pins:
// ключи хранилища, закреплённые в репо (полные, как в листинге объектов —
// фронт сверяет их со колонкой key таблицы объектов, сессия 173).
func handleListRetentionPins(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Retention == nil {
			writeErrCode(w, http.StatusServiceUnavailable, "retention_unavailable")
			return
		}
		id, ok := parseInt64URLParam(w, r, "id")
		if !ok {
			return
		}
		if _, err := d.Repos.Repo(r.Context(), id); err != nil {
			writeErr(w, err)
			return
		}
		keys, err := d.Retention.Pins(r.Context(), id)
		if err != nil {
			writeErr(w, err)
			return
		}
		if keys == nil {
			keys = []string{}
		}
		writeJSON(w, http.StatusOK, keys)
	}
}

// handlePutRetentionPin — PUT /api/v1/repos/{id}/retention/pins/*:
// закрепить версию. Объект обязан существовать (Stat → 404): пин
// фантома лишён смысла — он не защищает ничего и живёт до ручной уборки.
// Идемпотентно: повторный пин — 204 (модель PinStore).
func handlePutRetentionPin(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Storage нужен для проверки существования объекта: без него
		// пин неотличим от опечатки в ключе (деградированный режим —
		// тот же 503, что и без движка).
		if d.Retention == nil || d.Storage == nil {
			writeErrCode(w, http.StatusServiceUnavailable, "retention_unavailable")
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
		key, ok := retentionPinKey(w, r, repo)
		if !ok {
			return
		}
		if _, err := d.Storage.Stat(r.Context(), key); err != nil {
			writeErr(w, err)
			return
		}
		*r = *r.WithContext(WithAuditAction(r.Context(), "repo.retention.pin"))
		if err := d.Retention.SetPin(r.Context(), repo.ID, key, true); err != nil {
			writeErr(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// handleDeleteRetentionPin — DELETE /api/v1/repos/{id}/retention/pins/*:
// снять пин. Существование объекта не проверяется (SetPin идемпотентен в
// обе стороны): анпин снятой версии — no-op 204, а не 404 — иначе уборка
// устаревших пинов требовала бы объекта, которого уже нет.
func handleDeleteRetentionPin(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Retention == nil {
			writeErrCode(w, http.StatusServiceUnavailable, "retention_unavailable")
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
		key, ok := retentionPinKey(w, r, repo)
		if !ok {
			return
		}
		*r = *r.WithContext(WithAuditAction(r.Context(), "repo.retention.unpin"))
		if err := d.Retention.SetPin(r.Context(), repo.ID, key, false); err != nil {
			writeErr(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// retentionPinKey — ключ хранилища из wildcard-хвоста запроса: путь
// внутри репо (тот же decodedWildcard, что у upload: chi маршрутизирует по
// RawPath, и «+» приходит экранированным) + префикс репо. Пустой хвост и
// битый escape — 400: пинить нечего.
func retentionPinKey(w http.ResponseWriter, r *http.Request, repo domain.Repo) (string, bool) {
	path, err := decodedWildcard(r)
	if err != nil || path == "" {
		writeErrCode(w, http.StatusBadRequest, "validation_error")
		return "", false
	}
	return port.RepoPrefix(repo) + "/" + path, true
}
