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

package testutil

import (
	"context"
	"errors"
	"io"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
)

// newStorage — хранилище с замороженными часами: детерминированный
// ModTime для всех коммитов.
func newStorage(t *testing.T) (*FakeStorage, time.Time) {
	t.Helper()
	fixed := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	return NewFakeStorage(FixedClock(fixed)), fixed
}

func TestFakeStorageCommitVisible(t *testing.T) {
	s, fixed := newStorage(t)
	ctx := context.Background()

	w, err := s.Put(ctx, "cache/apt/1/pool/a.deb")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("bytes")); err != nil {
		t.Fatal(err)
	}
	// До Commit объекта нет.
	if _, err := s.Stat(ctx, "cache/apt/1/pool/a.deb"); !errors.Is(err, &domain.NotFoundError{}) {
		t.Fatalf("Stat до Commit = %v, хочу NotFound", err)
	}
	if err := w.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	meta, err := s.Stat(ctx, "cache/apt/1/pool/a.deb")
	if err != nil {
		t.Fatal(err)
	}
	if meta.Size != 5 || meta.Key != "cache/apt/1/pool/a.deb" || !meta.ModTime.Equal(fixed) {
		t.Errorf("Meta после Commit = %+v", meta)
	}
	obj, err := s.Get(ctx, "cache/apt/1/pool/a.deb")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(obj.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := obj.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if string(body) != "bytes" {
		t.Errorf("тело = %q, хочу %q", body, "bytes")
	}
}

func TestFakeStorageAbortInvisible(t *testing.T) {
	s, _ := newStorage(t)
	ctx := context.Background()

	w, err := s.Put(ctx, "repo/7/apt/x.deb")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("secret")); err != nil {
		t.Fatal(err)
	}
	if err := w.Abort(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Stat(ctx, "repo/7/apt/x.deb"); !errors.Is(err, &domain.NotFoundError{}) {
		t.Fatalf("Stat после Abort = %v, хочу NotFound", err)
	}
	// После Abort запись завершена: Commit уже не пройдёт.
	if err := w.Commit(ctx); err == nil {
		t.Error("Commit после Abort = nil, хочу ошибку")
	}
}

func TestFakeStorageListPrefix(t *testing.T) {
	s, _ := newStorage(t)
	ctx := context.Background()
	for _, key := range []string{"cache/apt/1/b.deb", "cache/apt/1/a.deb", "repo/7/apt/r.deb"} {
		w, err := s.Put(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}

	var keys []string
	for meta := range s.List(ctx, "cache/") {
		keys = append(keys, meta.Key)
	}
	// Отсортировано и только нужный префикс.
	if !slices.Equal(keys, []string{"cache/apt/1/a.deb", "cache/apt/1/b.deb"}) {
		t.Errorf("List(cache/) = %v", keys)
	}

	all := 0
	for range s.List(ctx, "") {
		all++
	}
	if all != 3 {
		t.Errorf("List(пусто) = %d объектов, хочу 3", all)
	}
	if n := len(slices.Collect(s.List(ctx, "zzz"))); n != 0 {
		t.Errorf("List(zzz) = %d объектов, хочу 0", n)
	}
}

func TestFakeStorageListCanceledContext(t *testing.T) {
	s, _ := newStorage(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	count := 0
	for range s.List(ctx, "") {
		count++
	}
	if count != 0 {
		t.Errorf("List с отменённым контекстом отдал %d объектов", count)
	}
}

func TestFakeStorageDelete(t *testing.T) {
	s, _ := newStorage(t)
	ctx := context.Background()

	if err := s.Delete(ctx, "cache/x"); !errors.Is(err, &domain.NotFoundError{}) {
		t.Fatalf("Delete отсутствующего = %v, хочу NotFound", err)
	}
	w, err := s.Put(ctx, "cache/x")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "cache/x"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Stat(ctx, "cache/x"); !errors.Is(err, &domain.NotFoundError{}) {
		t.Errorf("Stat после Delete = %v, хочу NotFound", err)
	}
}

func TestFakeStorageInvalidKeys(t *testing.T) {
	s, _ := newStorage(t)
	ctx := context.Background()
	bad := "../escape"
	if _, err := s.Get(ctx, bad); !errors.Is(err, &domain.InvalidKeyError{}) {
		t.Errorf("Get(traversal) = %v, хочу InvalidKey", err)
	}
	if _, err := s.Stat(ctx, bad); !errors.Is(err, &domain.InvalidKeyError{}) {
		t.Errorf("Stat(traversal) = %v, хочу InvalidKey", err)
	}
	if _, err := s.Put(ctx, bad); !errors.Is(err, &domain.InvalidKeyError{}) {
		t.Errorf("Put(traversal) = %v, хочу InvalidKey", err)
	}
	if err := s.Delete(ctx, bad); !errors.Is(err, &domain.InvalidKeyError{}) {
		t.Errorf("Delete(traversal) = %v, хочу InvalidKey", err)
	}
	if _, err := s.Get(ctx, "/abs"); !errors.Is(err, &domain.InvalidKeyError{}) {
		t.Errorf("Get(абсолютный) = %v, хочу InvalidKey", err)
	}
}

func TestFakeStorageGetMissing(t *testing.T) {
	s, _ := newStorage(t)
	ctx := context.Background()
	if _, err := s.Get(ctx, "cache/nope"); !errors.Is(err, &domain.NotFoundError{}) {
		t.Fatalf("Get отсутствующего = %v, хочу NotFound", err)
	}
}

func TestFakeStorageListEarlyBreak(t *testing.T) {
	s, _ := newStorage(t)
	ctx := context.Background()
	for _, key := range []string{"cache/a", "cache/b", "cache/c"} {
		w, err := s.Put(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	seen := 0
	for range s.List(ctx, "cache/") {
		seen++
		break // потребитель прервал обход после первого элемента
	}
	if seen != 1 {
		t.Errorf("после раннего break получено %d элементов, хочу 1", seen)
	}
}

func TestFakeStorageWriterMisuse(t *testing.T) {
	s, _ := newStorage(t)
	ctx := context.Background()

	w, err := s.Put(ctx, "cache/a")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("x")); err == nil {
		t.Error("Write после Commit = nil, хочу ошибку")
	}
	if err := w.Commit(ctx); err == nil {
		t.Error("повторный Commit = nil, хочу ошибку")
	}
	if err := w.Abort(ctx); err == nil {
		t.Error("Abort после Commit = nil, хочу ошибку")
	}

	w2, err := s.Put(ctx, "cache/b")
	if err != nil {
		t.Fatal(err)
	}
	if err := w2.Abort(ctx); err != nil {
		t.Fatal(err)
	}
	if err := w2.Abort(ctx); err == nil {
		t.Error("повторный Abort = nil, хочу ошибку")
	}
}

func TestFakeStorageCanceledContext(t *testing.T) {
	s, _ := newStorage(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Get(ctx, "cache/a"); !errors.Is(err, context.Canceled) {
		t.Errorf("Get с отменённым ctx = %v, хочу context.Canceled", err)
	}
	if _, err := s.Put(ctx, "cache/a"); !errors.Is(err, context.Canceled) {
		t.Errorf("Put с отменённым ctx = %v, хочу context.Canceled", err)
	}
	w, err := s.Put(context.Background(), "cache/a")
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if err := w.Commit(canceled); !errors.Is(err, context.Canceled) {
		t.Errorf("Commit с отменённым ctx = %v, хочу context.Canceled", err)
	}
	w2, err := s.Put(context.Background(), "cache/b")
	if err != nil {
		t.Fatal(err)
	}
	if err := w2.Abort(canceled); !errors.Is(err, context.Canceled) {
		t.Errorf("Abort с отменённым ctx = %v, хочу context.Canceled", err)
	}
}

func TestFakeStorageIndependentReaders(t *testing.T) {
	s, _ := newStorage(t)
	ctx := context.Background()
	w, err := s.Put(ctx, "cache/a")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	o1, err := s.Get(ctx, "cache/a")
	if err != nil {
		t.Fatal(err)
	}
	o2, err := s.Get(ctx, "cache/a")
	if err != nil {
		t.Fatal(err)
	}
	first, err := io.ReadAll(o1.Body)
	if err != nil {
		t.Fatal(err)
	}
	second, err := io.ReadAll(o2.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != len(second) {
		t.Errorf("ридеры зависимы: %d против %d байт", len(first), len(second))
	}
}

func TestFakeStorageOverwrite(t *testing.T) {
	s, _ := newStorage(t)
	ctx := context.Background()
	for _, content := range []string{"old", "new"} {
		w, err := s.Put(ctx, "cache/a")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
		if err := w.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	obj, err := s.Get(ctx, "cache/a")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(obj.Body)
	if string(body) != "new" {
		t.Errorf("после перезаписи тело = %q, хочу %q", body, "new")
	}
}

func TestFakeStorageConcurrentWriters(t *testing.T) {
	s, _ := newStorage(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w, err := s.Put(ctx, "cache/"+strconv.Itoa(i))
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := w.Write([]byte{byte(i)}); err != nil {
				t.Error(err)
				return
			}
			if err := w.Commit(ctx); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if n := len(slices.Collect(s.List(ctx, ""))); n != 16 {
		t.Errorf("после гонки объектов %d, хочу 16", n)
	}
}

func TestFakeStorageImplementsStorage(t *testing.T) {
	storage := NewFakeStorage(FixedClock(time.Unix(0, 0)))
	_ = storage // компиляционная проверка — см. port_test.go
}
