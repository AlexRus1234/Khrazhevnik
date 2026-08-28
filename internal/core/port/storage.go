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

// Порт хранилища объектов — единый namespace: cache/..., repo/...,
// tmp/.... Реализации: mod/storage/fs (posix), mod/storage/s3.

package port

import (
	"context"
	"io"
	"iter"
	"time"
)

// Meta — сведения об объекте, известные хранилищу. ETag/ContentType
// хранилище не гарантирует (fs их не знает); версионные данные
// mutable-объектов живут в domain.ObjectMeta (ObjectIndex).
type Meta struct {
	Key         string
	Size        int64
	ETag        string
	ContentType string
	ModTime     time.Time
}

// Object — объект хранилища: метаданные + тело. Body обязан быть
// закрыт вызывающим; каждая выдача — независимый ридер.
type Object struct {
	Meta
	Body io.ReadCloser
}

// Writer — транзакционная запись: объект становится видим только
// после Commit. Abort обязан удалить временные данные. Повторный
// Commit/Abort после завершения — ошибка.
type Writer interface {
	io.Writer
	Commit(ctx context.Context) error
	Abort(ctx context.Context) error
}

// Storage — бэкенд байтовых объектов. Контракт:
//   - ключи проходят domain.ValidateKey (недопустимый ключ —
//     *domain.InvalidKeyError до всякого обращения к носителю);
//   - отсутствующий объект — *domain.NotFoundError (Get/Stat/Delete);
//   - Get возвращает ридер поверх зафиксированных байт; Put на
//     существующий ключ перезаписывает его после Commit;
//   - List отдаёт объекты с префиксом в лексическом порядке ключей;
//     ошибка перечисления — терминальная: один (Meta{}, err) и обход
//     прекращается. Пустая последовательность без ошибки означает
//     «объектов нет», но никогда «не удалось перечислить» — потребители
//     (генераторы индексов, квоты) обязаны fail-closed на err, иначе
//     транзиентный сбой носителя «опустошает» репозиторий.
type Storage interface {
	Get(ctx context.Context, key string) (Object, error)
	Stat(ctx context.Context, key string) (Meta, error)
	Put(ctx context.Context, key string) (Writer, error)
	Delete(ctx context.Context, key string) error
	List(ctx context.Context, prefix string) iter.Seq2[Meta, error]
}
