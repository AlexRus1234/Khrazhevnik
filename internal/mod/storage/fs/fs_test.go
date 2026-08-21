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

package fs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/testutil"
)

// newTest — хранилище во временном каталоге; FixedRand даёт
// предсказуемые tmp-имена (последовательные записи).
func newTest(t *testing.T) *Storage {
	t.Helper()
	st, err := New(filepath.Join(t.TempDir(), "store"), testutil.FixedRand())
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// put фиксирует объект с содержимым content.
func put(t *testing.T, st *Storage, key, content string) {
	t.Helper()
	w, err := st.Put(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := w.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// keys собирает ключи из List.
func keys(ctx context.Context, st *Storage, prefix string) []string {
	var out []string
	for m := range st.List(ctx, prefix) {
		out = append(out, m.Key)
	}
	return out
}

func TestCommitGetStatListDelete(t *testing.T) {
	ctx := context.Background()
	st := newTest(t)

	put(t, st, "cache/apt/1/pool/main/a/a.deb", "aaa")
	put(t, st, "cache/apt/1/pool/main/b/b.deb", "bbbb")
	put(t, st, "repo/2/apt/x.pkg", "xx")

	obj, err := st.Get(ctx, "cache/apt/1/pool/main/a/a.deb")
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
	if string(body) != "aaa" {
		t.Fatalf("Get = %q", body)
	}

	meta, err := st.Stat(ctx, "cache/apt/1/pool/main/a/a.deb")
	if err != nil || meta.Key != "cache/apt/1/pool/main/a/a.deb" || meta.Size != 3 {
		t.Fatalf("Stat = %+v, %v", meta, err)
	}
	if meta.ModTime.IsZero() {
		t.Fatal("ModTime не заполнен")
	}

	got := keys(ctx, st, "cache/apt/1/")
	if len(got) != 2 || got[0] != "cache/apt/1/pool/main/a/a.deb" || got[1] != "cache/apt/1/pool/main/b/b.deb" {
		t.Fatalf("List = %v", got)
	}
	all := keys(ctx, st, "")
	if len(all) != 3 {
		t.Fatalf("List всех = %v", all)
	}

	if err := st.Delete(ctx, "cache/apt/1/pool/main/a/a.deb"); err != nil {
		t.Fatal(err)
	}
	err = st.Delete(ctx, "cache/apt/1/pool/main/a/a.deb")
	wantNotFound(t, err)
	_, err = st.Get(ctx, "cache/apt/1/pool/main/a/a.deb")
	wantNotFound(t, err)
}

// wantNotFound — общий ассерт.
func wantNotFound(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("ожидалась ошибка")
	}
	var nf *domain.NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("хочу NotFoundError, получено: %v", err)
	}
}

func TestOverwriteByCommit(t *testing.T) {
	ctx := context.Background()
	st := newTest(t)
	put(t, st, "cache/x", "old")
	put(t, st, "cache/x", "new-longer")

	obj, err := st.Get(ctx, "cache/x")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(obj.Body)
	_ = obj.Body.Close()
	if string(body) != "new-longer" {
		t.Fatalf("после перезаписи = %q", body)
	}
	if m, _ := st.Stat(ctx, "cache/x"); m.Size != int64(len("new-longer")) {
		t.Fatalf("Size = %d", m.Size)
	}
}

func TestAbortDiscards(t *testing.T) {
	ctx := context.Background()
	st := newTest(t)

	w, err := st.Put(ctx, "cache/y")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("discard me")); err != nil {
		t.Fatal(err)
	}
	if err := w.Abort(ctx); err != nil {
		t.Fatal(err)
	}

	_, err = st.Get(ctx, "cache/y")
	wantNotFound(t, err)
	if got := keys(ctx, st, ""); len(got) != 0 {
		t.Fatalf("после Abort видны объекты: %v", got)
	}
	// tmp-каталог пуст: временных файлов не осталось
	entries, err := os.ReadDir(filepath.Join(st.root, tmpDir))
	if err != nil || len(entries) != 0 {
		t.Fatalf("tmp после Abort: %v (err %v)", entries, err)
	}
}

func TestWriterStateMachine(t *testing.T) {
	ctx := context.Background()
	st := newTest(t)

	w, _ := st.Put(ctx, "cache/z")
	if err := w.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := w.Commit(ctx); err == nil {
		t.Fatal("повторный Commit не вернул ошибку")
	}
	if err := w.Abort(ctx); err == nil {
		t.Fatal("Abort после Commit не вернул ошибку")
	}
	if _, err := w.Write([]byte("x")); err == nil {
		t.Fatal("Write после Commit не вернул ошибку")
	}

	w2, _ := st.Put(ctx, "cache/z2")
	_ = w2.Abort(ctx)
	if err := w2.Abort(ctx); err == nil {
		t.Fatal("повторный Abort не вернул ошибку")
	}
}

func TestTraversalRejected(t *testing.T) {
	ctx := context.Background()
	st := newTest(t)
	put(t, st, "cache/ok", "v")

	bad := []string{
		"", "/abs", "a/../b", "../escape", "..", "a//b", "a/./b",
		"Back\\slash", "UPPER", "percent%", "пробел x", "nul\x00byte",
	}
	for _, key := range bad {
		var ike *domain.InvalidKeyError
		if _, err := st.Get(ctx, key); !errors.As(err, &ike) {
			t.Fatalf("Get(%q): хочу InvalidKeyError, получено %v", key, err)
		}
		if _, err := st.Stat(ctx, key); !errors.As(err, &ike) {
			t.Fatalf("Stat(%q): хочу InvalidKeyError, получено %v", key, err)
		}
		if _, err := st.Put(ctx, key); !errors.As(err, &ike) {
			t.Fatalf("Put(%q): хочу InvalidKeyError, получено %v", key, err)
		}
		if err := st.Delete(ctx, key); !errors.As(err, &ike) {
			t.Fatalf("Delete(%q): хочу InvalidKeyError, получено %v", key, err)
		}
	}
	// недопустимый префикс не касается диска и не отдаёт ничего
	if got := keys(ctx, st, "../"); got != nil {
		t.Fatalf("List(../) = %v", got)
	}
	if got := keys(ctx, st, "UPPER/"); got != nil {
		t.Fatalf("List(UPPER/) = %v", got)
	}
}

func TestLongKeys(t *testing.T) {
	ctx := context.Background()
	st := newTest(t)

	// валидный длинный ключ: сегменты короткие (лимиты ФС), общая
	// длина — сотни байт
	deep := strings.TrimSuffix(strings.Repeat("k/", 300), "/") + "/leaf.deb"
	if len(deep) <= 1024 {
		put(t, st, deep, "deep")
		obj, err := st.Get(ctx, deep)
		if err != nil {
			t.Fatal(err)
		}
		_ = obj.Body.Close()
	}

	// за пределами maxKeyLen — отказ до обращения к диску
	tooLong := strings.Repeat("a/", 600) + "x"
	var ike *domain.InvalidKeyError
	if _, err := st.Stat(ctx, tooLong); !errors.As(err, &ike) {
		t.Fatalf("Stat(tooLong): %v", err)
	}
}

func TestParallelPutSameKey(t *testing.T) {
	ctx := context.Background()
	// боевой источник случайности: FixedRand раздаёт один UUID по кругу
	// и параллельные писатели столкнутся на O_EXCL
	st, err := New(filepath.Join(t.TempDir(), "store"), cryptoRand{})
	if err != nil {
		t.Fatal(err)
	}

	const writers = 8
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w, err := st.Put(ctx, "cache/race")
			if err != nil {
				errs <- err
				return
			}
			if _, err := w.Write([]byte(fmt.Sprintf("writer-%d", i))); err != nil {
				errs <- err
				return
			}
			if err := w.Commit(ctx); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	obj, err := st.Get(ctx, "cache/race")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(obj.Body)
	_ = obj.Body.Close()
	if len(body) != len("writer-0") {
		t.Fatalf("содержимое после гонки: %q", body)
	}
	// tmp-каталог пуст: все временные файлы переименованы
	entries, err := os.ReadDir(filepath.Join(st.root, tmpDir))
	if err != nil || len(entries) != 0 {
		t.Fatalf("tmp после гонки: %d файлов (err %v)", len(entries), err)
	}
}

func TestGetDirIsNotObject(t *testing.T) {
	ctx := context.Background()
	st := newTest(t)
	put(t, st, "cache/d/inner", "x")

	_, err := st.Get(ctx, "cache/d")
	wantNotFound(t, err)
	_, err = st.Stat(ctx, "cache/d")
	wantNotFound(t, err)
}

func TestCanceledContext(t *testing.T) {
	st := newTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := st.Get(ctx, "cache/x"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Get с отменённым ctx: %v", err)
	}
	if _, err := st.Put(ctx, "cache/x"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Put с отменённым ctx: %v", err)
	}
	put(t, st, "cache/x", "v") // живой контекст
	if got := keys(ctx, st, ""); got != nil {
		t.Fatalf("List с отменённым ctx = %v", got)
	}
}

func TestNewRejectsEmptyRoot(t *testing.T) {
	if _, err := New("", testutil.FixedRand()); err == nil {
		t.Fatal("New с пустым корнем не вернул ошибку")
	}
}

func TestNewUnwritableRoot(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("файл"), 0o644); err != nil {
		t.Fatal(err)
	}
	// MkdirAll под существующим файлом невозможен
	if _, err := New(filepath.Join(blocker, "store"), testutil.FixedRand()); err == nil {
		t.Fatal("New с непроходимым корнем не вернул ошибку")
	}
}

func TestReservedTmpNamespace(t *testing.T) {
	ctx := context.Background()
	st := newTest(t)
	var ike *domain.InvalidKeyError
	for _, key := range []string{"tmp", "tmp/anything", "tmp/x/y.deb"} {
		if _, err := st.Put(ctx, key); !errors.As(err, &ike) {
			t.Fatalf("Put(%q): %v", key, err)
		}
		if _, err := st.Get(ctx, key); !errors.As(err, &ike) {
			t.Fatalf("Get(%q): %v", key, err)
		}
		if err := st.Delete(ctx, key); !errors.As(err, &ike) {
			t.Fatalf("Delete(%q): %v", key, err)
		}
	}
}

func TestPutRandFailure(t *testing.T) {
	root := filepath.Join(t.TempDir(), "store")
	st, err := New(root, testutil.FailingRand(fmt.Errorf("rand сдох")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Put(context.Background(), "cache/x"); err == nil {
		t.Fatal("Put с отказавшим Rand не вернул ошибку")
	}
}

func TestCommitMkdirFailure(t *testing.T) {
	ctx := context.Background()
	st := newTest(t)
	// «cache/x» занят файлом — каталог для «cache/x/y» не создать
	put(t, st, "cache/x", "файл")
	w, err := st.Put(ctx, "cache/x/y")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("z")); err != nil {
		t.Fatal(err)
	}
	err = w.Commit(ctx)
	if err == nil {
		t.Fatal("Commit поверх файла-каталога не вернул ошибку")
	}
	var ike *domain.InvalidKeyError
	if errors.As(err, &ike) {
		t.Fatalf("ошибка Commit не должна быть InvalidKeyError: %v", err)
	}
}

func TestDeleteNonEmptyDirPassesThrough(t *testing.T) {
	ctx := context.Background()
	st := newTest(t)
	put(t, st, "cache/d/inner", "x")
	// «cache/d» — непустой каталог: os.Remove откажет, это не NotFound
	err := st.Delete(ctx, "cache/d")
	if err == nil {
		t.Fatal("Delete непустого каталога не вернул ошибку")
	}
	var nf *domain.NotFoundError
	if errors.As(err, &nf) {
		t.Fatalf("Delete непустого каталога замаскирован под NotFound: %v", err)
	}
}

func TestListAfterRootRemoved(t *testing.T) {
	ctx := context.Background()
	st := newTest(t)
	put(t, st, "cache/x", "v")
	if err := os.RemoveAll(st.root); err != nil {
		t.Fatal(err)
	}
	if got := keys(ctx, st, ""); got != nil {
		t.Fatalf("List без корня = %v", got)
	}
}

// compile-time: Storage реализует весь порт.
var _ port.Storage = (*Storage)(nil)
