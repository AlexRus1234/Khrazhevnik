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

// sync_jobs-обновления: mirror.Sync пишет состояние и прогресс в
// persistence (port.JobStore) — это единственный персистентный след
// синхронизации (TaskRegistry in-memory, sync_jobs — в БД). Cursor
// сейчас не используется (resume по diff), поле оставлено под будущие
// инкрементальные оптимизации.

package mirror

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"khrazhevnik/internal/core/domain"
)

// startJob находит или создаёт sync_job для remote и переводит в running.
// Создаёт запись с Interval=remote.SyncInterval (для планировщика и
// аудита). LastRunAt = сейчас.
func (e *Engine) startJob(ctx context.Context, remote domain.Remote) (domain.SyncJob, error) {
	existing, err := e.findJobByRemote(ctx, remote.ID)
	switch {
	case err == nil:
		existing.State = domain.StateRunning
		existing.Interval = remote.SyncInterval
		existing.LastRunAt = e.clock.Now()
		existing.UpdatedAt = e.clock.Now()
		if jErr := e.jobs.UpdateJob(ctx, existing); jErr != nil {
			return domain.SyncJob{}, fmt.Errorf("update: %w", jErr)
		}
		return existing, nil
	case isNotFound(err):
		// нет записи — создаём
	default:
		return domain.SyncJob{}, err
	}
	job := domain.SyncJob{
		RemoteID:  remote.ID,
		State:     domain.StateRunning,
		Interval:  remote.SyncInterval,
		LastRunAt: e.clock.Now(),
		UpdatedAt: e.clock.Now(),
	}
	created, err := e.jobs.CreateJob(ctx, job)
	if err != nil {
		return domain.SyncJob{}, fmt.Errorf("create: %w", err)
	}
	return created, nil
}

// succeedJob фиксирует успешное завершение.
func (e *Engine) succeedJob(ctx context.Context, job domain.SyncJob, files int, bytes int64) error {
	job.State = domain.StateSucceeded
	job.Cursor = encodeCursor(files, bytes)
	job.UpdatedAt = e.clock.Now()
	return e.jobs.UpdateJob(ctx, job)
}

// failJob фиксирует завершение с ошибкой; cursor не трогаем (при resume
// по diff он не нужен, но сохраняем старый для аудита).
func (e *Engine) failJob(ctx context.Context, job domain.SyncJob, cause error) error {
	job.State = domain.StateFailed
	job.UpdatedAt = e.clock.Now()
	if cause != nil {
		job.Cursor = "error:" + truncateForCursor(cause.Error())
	}
	return e.jobs.UpdateJob(ctx, job)
}

// touchJob — батч-обновление прогресса (files_done/bytes_done в cursor)
// раз в ProgressInterval. Не меняет state; курсор кодирует прогресс.
func (e *Engine) touchJob(ctx context.Context, remote domain.Remote, files int64, bytes int64) error {
	job, err := e.findJobByRemote(ctx, remote.ID)
	if err != nil {
		return err
	}
	job.Cursor = encodeCursor(int(files), bytes)
	job.UpdatedAt = e.clock.Now()
	return e.jobs.UpdateJob(ctx, job)
}

// findJobByRemote ищет sync_job по remote_id. NotFound, если нет.
func (e *Engine) findJobByRemote(ctx context.Context, remoteID int64) (domain.SyncJob, error) {
	jobs, err := e.jobs.Jobs(ctx)
	if err != nil {
		return domain.SyncJob{}, err
	}
	for _, j := range jobs {
		if j.RemoteID == remoteID {
			return j, nil
		}
	}
	return domain.SyncJob{}, &domain.NotFoundError{What: "sync-задача", Key: strconv.FormatInt(remoteID, 10)}
}

// isNotFound — короткая обёртка errors.As для *NotFoundError.
func isNotFound(err error) bool {
	var nf *domain.NotFoundError
	return errors.As(err, &nf)
}

// encodeCursor кодирует прогресс в непрозрачную строку sync_jobs.cursor.
// Формат «files=<n>;bytes=<m>» — читается оператором через GET /tasks
// (TaskRegistry-снимок) и напрямую из БД при разборе инцидентов.
func encodeCursor(files int, bytes int64) string {
	return fmt.Sprintf("files=%d;bytes=%d", files, bytes)
}

// truncateForCursor укорачивает сообщение ошибки до безопасной длины
// колонки cursor (sqlite TEXT без лимита, но оператору длинный курсор
// не нужен).
func truncateForCursor(s string) string {
	const max = 200
	if len(s) > max {
		return s[:max]
	}
	return s
}
