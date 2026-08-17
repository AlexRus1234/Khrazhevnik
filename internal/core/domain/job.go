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

package domain

import "time"

// SyncState — состояние sync-задачи зеркала.
type SyncState string

// Состояния: задача создаётся pending, воркер переводит в running,
// по итогу — succeeded или failed (с возвратом в pending на retry).
const (
	StatePending   SyncState = "pending"
	StateRunning   SyncState = "running"
	StateSucceeded SyncState = "succeeded"
	StateFailed    SyncState = "failed"
)

// SyncJob — фоновая задача синхронизации зеркала. Cursor — непрозрачный
// для БД токен resume (etag/size последнего объекта): воркер пишет,
// при рестарте продолжает с места обрыва.
type SyncJob struct {
	ID        int64
	RemoteID  int64
	State     SyncState
	Interval  time.Duration // период sync; 0 — только вручную
	LastRunAt time.Time
	Cursor    string
	UpdatedAt time.Time
}
