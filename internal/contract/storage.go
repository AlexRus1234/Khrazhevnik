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

package contract

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
)

// StorageSuite гоняет контрактный suite port.Storage (commit/abort/
// list/traversal/overwrite/state-machine/отмена ctx/reserved tmp) по
// одному адаптеру. open возвращает свежее хранилище на каждый вызов
// (изоляция под-тестов); для теста параллельной записи адаптер должен
// использовать настоящий источник случайности (уникальные tmp/спул-
// имена) — фиксированный Rand дал бы коллизию имён.
//
// ETag/ContentType НЕ проверяются: fs их не знает (пусто), s3
// заполняет (md5/inferred) — это деталь драйвера, не контракта.
func StorageSuite(t *testing.T, open func(t *testing.T) port.Storage) {
	t.Helper()
	newSt := func(t *testing.T) port.Storage { return open(t) }
	t.Run("commit_get_stat_list_delete", func(t *testing.T) { commitGetStatListDelete(t, newSt(t)) })
	t.Run("overwrite_by_commit", func(t *testing.T) { overwriteByCommit(t, newSt(t)) })
	t.Run("abort_discards", func(t *testing.T) { abortDiscards(t, newSt(t)) })
	t.Run("writer_state_machine", func(t *testing.T) { writerStateMachine(t, newSt(t)) })
	t.Run("traversal_rejected", func(t *testing.T) { traversalRejected(t, newSt(t)) })
	t.Run("long_keys", func(t *testing.T) { longKeys(t, newSt(t)) })
	t.Run("parallel_put_same_key", func(t *testing.T) { parallelPutSameKey(t, newSt(t)) })
	t.Run("parent_key_not_object", func(t *testing.T) { parentKeyNotObject(t, newSt(t)) })
	t.Run("canceled_context", func(t *testing.T) { canceledContext(t, newSt(t)) })
	t.Run("reserved_tmp_namespace", func(t *testing.T) { reservedTmp(t, newSt(t)) })
}

func commitGetStatListDelete(t *testing.T, st port.Storage) {
	ctx := context.Background()
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
	_ = obj.Body.Close()
	if string(body) != "aaa" || obj.Size != 3 {
		t.Fatalf("Get = %q (%d байт)", body, obj.Size)
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
	if all := keys(ctx, st, ""); len(all) != 3 {
		t.Fatalf("List всех = %v", all)
	}
	if err := st.Delete(ctx, "cache/apt/1/pool/main/a/a.deb"); err != nil {
		t.Fatal(err)
	}
	wantNotFound(t, st.Delete(ctx, "cache/apt/1/pool/main/a/a.deb"))
	_, err = st.Get(ctx, "cache/apt/1/pool/main/a/a.deb")
	wantNotFound(t, err)
}

func overwriteByCommit(t *testing.T, st port.Storage) {
	ctx := context.Background()
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

func abortDiscards(t *testing.T, st port.Storage) {
	ctx := context.Background()
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
}

func writerStateMachine(t *testing.T, st port.Storage) {
	ctx := context.Background()
	w, err := st.Put(ctx, "cache/z")
	if err != nil {
		t.Fatal(err)
	}
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
	w2, err := st.Put(ctx, "cache/z2")
	if err != nil {
		t.Fatal(err)
	}
	if err := w2.Abort(ctx); err != nil {
		t.Fatal(err)
	}
	if err := w2.Abort(ctx); err == nil {
		t.Fatal("повторный Abort не вернул ошибку")
	}
}

func traversalRejected(t *testing.T, st port.Storage) {
	ctx := context.Background()
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
	if got := keys(ctx, st, "../"); got != nil {
		t.Fatalf("List(../) = %v", got)
	}
	if got := keys(ctx, st, "UPPER/"); got != nil {
		t.Fatalf("List(UPPER/) = %v", got)
	}
}

func longKeys(t *testing.T, st port.Storage) {
	ctx := context.Background()
	deep := strings.TrimSuffix(strings.Repeat("k/", 300), "/") + "/leaf.deb"
	if len(deep) <= 1024 {
		put(t, st, deep, "deep")
		obj, err := st.Get(ctx, deep)
		if err != nil {
			t.Fatal(err)
		}
		_ = obj.Body.Close()
	}
	tooLong := strings.Repeat("a/", 600) + "x"
	var ike *domain.InvalidKeyError
	if _, err := st.Stat(ctx, tooLong); !errors.As(err, &ike) {
		t.Fatalf("Stat(tooLong): %v", err)
	}
}

func parallelPutSameKey(t *testing.T, st port.Storage) {
	ctx := context.Background()
	const writers = 8
	payload := []byte("payload")
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w, err := st.Put(ctx, "cache/race")
			if err != nil {
				errs <- err
				return
			}
			if _, err := w.Write(payload); err != nil {
				errs <- err
				return
			}
			if err := w.Commit(ctx); err != nil {
				errs <- err
			}
		}()
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
	if !bytes.Equal(body, payload) {
		t.Fatalf("содержимое после гонки: %q", body)
	}
}

func parentKeyNotObject(t *testing.T, st port.Storage) {
	ctx := context.Background()
	put(t, st, "cache/d/inner", "x")
	_, err := st.Get(ctx, "cache/d")
	wantNotFound(t, err)
	_, err = st.Stat(ctx, "cache/d")
	wantNotFound(t, err)
}

func canceledContext(t *testing.T, st port.Storage) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := st.Get(ctx, "cache/x"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Get с отменённым ctx: %v", err)
	}
	if _, err := st.Put(ctx, "cache/x"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Put с отменённым ctx: %v", err)
	}
	if got := keys(ctx, st, ""); got != nil {
		t.Fatalf("List с отменённым ctx = %v", got)
	}
}

func reservedTmp(t *testing.T, st port.Storage) {
	ctx := context.Background()
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

// put фиксирует объект с содержимым content.
func put(t *testing.T, st port.Storage, key, content string) {
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
func keys(ctx context.Context, st port.Storage, prefix string) []string {
	var out []string
	for m := range st.List(ctx, prefix) {
		out = append(out, m.Key)
	}
	return out
}
