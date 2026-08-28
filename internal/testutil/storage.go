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

// FakeStorage — двойник port.Storage поверх map: та же семантика
// видимости (объект появляется только после Commit, Abort отбрасывает)
// и те же типизированные ошибки домена, что у боевых реализаций.

package testutil

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"iter"
	"slices"
	"sync"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
)

// fakeObject — зафиксированное содержимое + метаданные.
type fakeObject struct {
	data []byte
	meta port.Meta
}

// FakeStorage — потокобезопасное in-memory хранилище. ModTime
// зафиксированных объектов берётся с clock из конструктора.
type FakeStorage struct {
	mu      sync.Mutex
	clock   port.Clock
	objects map[string]fakeObject
}

// NewFakeStorage создаёт пустое хранилище; clock задаёт ModTime
// коммитов (детерминированность тестов).
func NewFakeStorage(clock port.Clock) *FakeStorage {
	return &FakeStorage{clock: clock, objects: map[string]fakeObject{}}
}

// Get возвращает независимый ридер поверх зафиксированных байт.
func (s *FakeStorage) Get(ctx context.Context, key string) (port.Object, error) {
	if err := validateKey(ctx, key); err != nil {
		return port.Object{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	obj, ok := s.objects[key]
	if !ok {
		return port.Object{}, &domain.NotFoundError{What: "объект", Key: key}
	}
	return port.Object{Meta: obj.meta, Body: io.NopCloser(bytes.NewReader(obj.data))}, nil
}

// Stat возвращает метаданные зафиксированного объекта.
func (s *FakeStorage) Stat(ctx context.Context, key string) (port.Meta, error) {
	if err := validateKey(ctx, key); err != nil {
		return port.Meta{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	obj, ok := s.objects[key]
	if !ok {
		return port.Meta{}, &domain.NotFoundError{What: "объект", Key: key}
	}
	return obj.meta, nil
}

// Put открывает транзакционную запись; видимость — после Commit.
func (s *FakeStorage) Put(ctx context.Context, key string) (port.Writer, error) {
	if err := validateKey(ctx, key); err != nil {
		return nil, err
	}
	return &fakeWriter{s: s, key: key}, nil
}

// Delete удаляет зафиксированный объект; отсутствующий — NotFound.
func (s *FakeStorage) Delete(ctx context.Context, key string) error {
	if err := validateKey(ctx, key); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.objects[key]; !ok {
		return &domain.NotFoundError{What: "объект", Key: key}
	}
	delete(s.objects, key)
	return nil
}

// List отдаёт метаданные объектов с префиксом prefix в лексическом
// порядке ключей (детерминированность тестов). Префикс проверяется
// мягко: чужие символы просто ничего не матчат. Ошибок не даёт
// (in-memory map), но сигнатура — Seq2, как у боевых носителей: err
// приходит от отмены ctx, потребители fail-closed отрабатывают его.
func (s *FakeStorage) List(ctx context.Context, prefix string) iter.Seq2[port.Meta, error] {
	return func(yield func(port.Meta, error) bool) {
		s.mu.Lock()
		keys := make([]string, 0, len(s.objects))
		metas := make(map[string]port.Meta, len(s.objects))
		for k, obj := range s.objects {
			if bytes.HasPrefix([]byte(k), []byte(prefix)) {
				keys = append(keys, k)
				metas[k] = obj.meta
			}
		}
		s.mu.Unlock()
		slices.Sort(keys)
		if ctx.Err() != nil {
			yield(port.Meta{}, ctx.Err())
			return
		}
		for _, k := range keys {
			if !yield(metas[k], nil) {
				return
			}
		}
	}
}

// validateKey — предохранитель: контекст + единая точка path-traversal.
func validateKey(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return domain.ValidateKey(key)
}

// fakeWriter накапливает байты и на Commit фиксирует их в хранилище.
type fakeWriter struct {
	s    *FakeStorage
	key  string
	buf  []byte
	done bool
}

// Write реализует io.Writer.
func (w *fakeWriter) Write(p []byte) (int, error) {
	if w.done {
		return 0, fmt.Errorf("fakestorage: запись после завершения Writer для %q", w.key)
	}
	w.buf = append(w.buf, p...)
	return len(p), nil
}

// Commit фиксирует объект: он становится видимым для Get/Stat/List.
func (w *fakeWriter) Commit(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if w.done {
		return fmt.Errorf("fakestorage: повторный Commit для %q", w.key)
	}
	w.done = true
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	w.s.objects[w.key] = fakeObject{
		data: w.buf,
		meta: port.Meta{Key: w.key, Size: int64(len(w.buf)), ModTime: w.s.clock.Now()},
	}
	return nil
}

// Abort отбрасывает запись: объект остаётся невидимым.
func (w *fakeWriter) Abort(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if w.done {
		return fmt.Errorf("fakestorage: повторный Abort для %q", w.key)
	}
	w.done = true
	w.buf = nil
	return nil
}
