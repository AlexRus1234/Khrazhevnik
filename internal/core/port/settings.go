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

package port

import (
	"context"
	"time"
)

// UpstreamProxyStore — глобальная настройка прокси исходящих запросов
// (таблица settings, ключ upstream.proxy; сессия 154). Runtime-значение
// из веб-GUI живёт в БД, чтобы переживать рестарт; env HTTP(S)_PROXY —
// фолбэк при пустой настройке (слоем выше). Интерфейс специализированный,
// хотя таблица generic key-value: произвольные настройки через API не
// предполагаются (YAGNI).
type UpstreamProxyStore interface {
	// UpstreamProxy возвращает сохранённый URL прокси; пустая БД —
	// "" без ошибки (настройка ещё не задавалась, не ошибка чтения).
	UpstreamProxy(ctx context.Context) (string, error)
	// SetUpstreamProxy сохраняет URL (upsert); value уже провалидирован
	// слоем выше (domain.ValidateProxyURL), at — момент изменения
	// (port.Clock).
	SetUpstreamProxy(ctx context.Context, value string, at time.Time) error
}
