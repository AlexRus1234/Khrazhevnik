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

// ObjectMeta — индексная запись mutable-объекта кеша (object_index):
// etag/expires для conditional revalidate. Хранится в БД отдельно от
// байтов объекта; ETag/LastModified — побайтово от upstream.
type ObjectMeta struct {
	// Key — логический ключ (port.Target.StorageKey): под ним запись
	// ищется и по нему считается TTL.
	Key string
	// StorageKey — где лежат байты: версии mutable-объектов пишутся
	// под уникальными ключами, чтобы замена не ломала читателей
	// старой версии. Пустая строка — байты под самим Key (записи до
	// версионирования).
	StorageKey   string
	Size         int64
	ETag         string
	ContentType  string
	LastModified time.Time
	// ExpiresAt — момент, после которого объект считается протухшим;
	// нулевое время = бессрочно (immutable).
	ExpiresAt time.Time
}

// Expired сообщает, протух ли объект на момент at.
func (m ObjectMeta) Expired(at time.Time) bool {
	return !m.ExpiresAt.IsZero() && !m.ExpiresAt.After(at)
}
