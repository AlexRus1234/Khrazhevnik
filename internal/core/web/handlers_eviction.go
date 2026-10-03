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

// Хендлеры политики авто-очистки кеша pull-through прокси (сессия 202):
// прогноз кандидатов и применение политики по одному remote. Политика
// живёт в самом remote (GET/PATCH /remotes), здесь — действия по ней;
// образец — retention личных репо (сессия 172).
//
// Прогноз синхронный: сухой проход движка по листингу кеша одного remote
// (секунды), 202+task для просмотра был бы избыточен — задачей идёт
// только apply (удаления). Права — admin на обоих: чистка кеша это
// админская настройка источника, как CRUD; owner-scope сюда не доходит
// (в отличие от ретеншна, где пин ставит владелец репо). Аудит: apply под
// своим именем и ДО запуска задачи (урок сессии 87); preview — чтение,
// без записи. Пинов у кеша нет: пин-хранилище repo_pins личных репо кеша
// не касается, поэтому protected_by здесь только "" | "access".

package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"khrazhevnik/internal/core/domain"
)

// EvictionCandidate — строка прогноза: версия семейства, прошедшая
// топ-N-фильтр политики. ProtectedBy — первая сработавшая защита
// («access» — свежее обращение); пусто — кандидат на удаление. Версии,
// удержанные топ-N, в прогноз не попадают: их считает
// totals.protected_by_min (прогноз показывает то, что политика
// рассматривает, а не весь кеш).
type EvictionCandidate struct {
	Key         string    `json:"key"`
	Family      string    `json:"family"`
	Size        int64     `json:"size"`
	ModTime     time.Time `json:"mod_time"`
	LastAccess  time.Time `json:"last_access"`
	ProtectedBy string    `json:"protected_by"`
}

// EvictionTotals — счётчики прохода eviction в терминах web: totals
// прогноза и итог задачи apply. ProtectedByPin отсутствует — пинов у
// кеша нет (движок его не считает).
type EvictionTotals struct {
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
}

// EvictionPreview — ответ GET /api/v1/remotes/{id}/eviction/preview.
type EvictionPreview struct {
	Candidates []EvictionCandidate `json:"candidates"`
	Totals     EvictionTotals      `json:"totals"`
}

// retentionOutFrom переводит доменную политику в DTO: nil — «наследует
// глобальный дефолт [eviction]» (JSON null в теле remote).
func retentionOutFrom(p *domain.Retention) *retentionOut {
	if p == nil {
		return nil
	}
	return &retentionOut{MinVersions: p.MinVersions, MaxAgeDays: p.MaxAgeDays}
}

// retentionFromInput переводит tri-state поле eviction тела remote в
// доменную политику: nil (ключа нет или null) — наследование
// глобального дефолта.
func retentionFromInput(in evictionInput) *domain.Retention {
	if in.Policy == nil {
		return nil
	}
	return &domain.Retention{MinVersions: in.Policy.MinVersions, MaxAgeDays: in.Policy.MaxAgeDays}
}

// handleEvictionPreview — GET /api/v1/remotes/{id}/eviction/preview:
// сухой проход по кешу remote и отчёт по кандидатам. Носитель не
// меняется; политика выключена или remote зеркальный — пустой отчёт, не
// ошибка (proxy-only инвариант держит сам движок). Экосистема без
// резолвера семейств кеш-путей (nix — content-addressed) — 400
// `eviction_unsupported`: политика к ней неприменима не потому, что
// «нечего чистить», а потому что чистить нечего уметь.
func handleEvictionPreview(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Eviction == nil {
			writeErrCode(w, http.StatusServiceUnavailable, "eviction_unavailable")
			return
		}
		id, ok := parseInt64URLParam(w, r, "id")
		if !ok {
			return
		}
		remote, err := d.Remotes.Remote(r.Context(), id)
		if err != nil {
			writeErr(w, err)
			return
		}
		preview, err := d.Eviction.Preview(r.Context(), remote)
		if err != nil {
			var unsup *domain.UnsupportedError
			if errors.As(err, &unsup) {
				// statusFor отдал бы 501 unsupported (сбой сервиса);
				// здесь же клиент просит политику у экосистемы, которая
				// её не поддерживает, — это его ошибка (400).
				writeErrCode(w, http.StatusBadRequest, "eviction_unsupported")
				return
			}
			writeErr(w, err)
			return
		}
		if preview.Candidates == nil {
			// Пустой прогноз — пустой массив, не null: фронт рисует
			// dim-строку «кандидатов нет» (прецедент ретеншна, 173).
			preview.Candidates = []EvictionCandidate{}
		}
		writeJSON(w, http.StatusOK, preview)
	}
}

// handleEvictionApply — POST /api/v1/remotes/{id}/eviction/apply: боевой
// проход политики по кешу remote как фоновая задача TaskRegistry
// (kind=eviction, label=remote-<id>; прецедент retention|repo-<id> и
// gc|repo-<id>). Повторный запуск при активной задаче того же remote —
// 409 (ErrTaskDuplicate → statusFor), лимит воркеров — 429.
func handleEvictionApply(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Eviction == nil || d.Tasks == nil {
			writeErrCode(w, http.StatusServiceUnavailable, "eviction_unavailable")
			return
		}
		id, ok := parseInt64URLParam(w, r, "id")
		if !ok {
			return
		}
		remote, err := d.Remotes.Remote(r.Context(), id)
		if err != nil {
			writeErr(w, err)
			return
		}
		// Action до запуска задачи (урок сессии 87): и 409/429, и запись
		// middleware идут под remote.eviction.apply, а не под
		// fallback-именем метода+пути.
		*r = *r.WithContext(WithAuditAction(r.Context(), "remote.eviction.apply"))
		taskID, err := d.Tasks.Start("eviction", fmt.Sprintf("remote-%d", id), func(ctx context.Context, p Progress) error {
			res, err := d.Eviction.Apply(ctx, remote)
			if err != nil {
				return err
			}
			p.Log(fmt.Sprintf("проход завершён: семейств %d, кандидатов %d, удалено %d (%s), сбоев удаления %d, защита: топ-N %d, обращение %d",
				res.Families, res.Candidates, res.Deleted, humanBytes(res.BytesFreed), res.FailedDeletes,
				res.ProtectedByMin, res.ProtectedByAccess))
			return nil
		})
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"task_id": taskID})
	}
}
