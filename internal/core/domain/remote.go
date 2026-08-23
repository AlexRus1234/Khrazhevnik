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

// RemoteMode — режим работы с upstream: pull-through кеш или полное
// зеркало с фоновым sync.
type RemoteMode string

// Режимы remote.
const (
	ModeProxy  RemoteMode = "proxy"
	ModeMirror RemoteMode = "mirror"
)

// Remote — настроенный upstream: источник пакетов экосистемы.
// Ключи кеша строятся от ID: cache/<eco>/<remote-id>/...
type Remote struct {
	ID        int64
	Name      string // slug для конфигов и URL
	Ecosystem string // «apt», «rpm-md», ...
	BaseURL   string
	Mode      RemoteMode
	Enabled   bool
	// SyncInterval — период авто-sync для mode=mirror; 0 — только
	// ручной запуск через POST /remotes/{id}/sync. Для mode=proxy
	// игнорируется (планировщик зеркал таких remote не трогает).
	SyncInterval time.Duration
	// Include — фильтр объектов sync: для apt — список дистрибутивов
	// с опциональной компонентой («stable», «stable/main»); для
	// rpm-md — не используется (репо — единое целое по repomd). Пустой
	// срез — sync всего, что Enumerate найдёт по умолчанию.
	Include   []string
	CreatedAt time.Time
}
