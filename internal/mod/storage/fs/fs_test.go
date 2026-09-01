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
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"khrazhevnik/internal/contract"
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

// TestStorageContract — общий контрактный suite port.Storage (сессии 04
// + 17); тот же код в test/integration гоняет s3 через minio. Фабрика
// использует настоящий cryptoRand — тесту параллельной записи нужны
// уникальные tmp-имена (FixedRand дал бы коллизию на O_EXCL).
func TestStorageContract(t *testing.T) {
	contract.StorageSuite(t, func(t *testing.T) port.Storage {
		st, err := New(filepath.Join(t.TempDir(), "store"), cryptoRand{})
		if err != nil {
			t.Fatal(err)
		}
		return st
	})
}

// fs-специфичные кейсы: каталог-корень, недоступный root, сбой Rand,
// Commit поверх файла-каталога, удаление непустого каталога, List без
// корня. Контрактный suite (выше) покрывает commit/abort/list/traversal
// и пр.; здесь — только то, что зависит от posix-файлов.

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

func TestPutRandFailure(t *testing.T) {
	root := filepath.Join(t.TempDir(), "store")
	st, err := New(root, testutil.FailingRand(errors.New("rand сдох")))
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
	putCommit(t, st, "cache/x", "файл")
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
	// Ошибка фиксации после done не должна течь tmp до рестарта:
	// Abort уже заблокирован, чистит сам Commit (сессия 44).
	entries, err := os.ReadDir(filepath.Join(st.root, tmpDir))
	if err != nil || len(entries) != 0 {
		t.Fatalf("tmp после сбоя Commit: %d записей (err %v), хочу 0", len(entries), err)
	}
}

func TestDeleteNonEmptyDirPassesThrough(t *testing.T) {
	ctx := context.Background()
	st := newTest(t)
	putCommit(t, st, "cache/d/inner", "x")
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
	putCommit(t, st, "cache/x", "v")
	if err := os.RemoveAll(st.root); err != nil {
		t.Fatal(err)
	}
	// Пропавший корень — терминальная ошибка листинга, не «пусто»
	// (иначе генераторы записали бы пустые индексы поверх валидных).
	metas, err := collectList(ctx, st, "")
	if err == nil {
		t.Fatal("List без корня не вернул ошибку")
	}
	if len(metas) != 0 {
		t.Fatalf("List без корня отдал метаданные: %v", metas)
	}
}

// TestListUnreadableDir — недоступный подкаталог (chmod 000) даёт
// терминальную ошибку, а не молчаливо-неполный листинг. POSIX-права:
// на Windows chmod — no-op, кейс неприменим.
func TestListUnreadableDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod 000 на Windows — no-op")
	}
	if os.Geteuid() == 0 {
		t.Skip("под root chmod 000 не запрещает доступ")
	}
	ctx := context.Background()
	st := newTest(t)
	putCommit(t, st, "cache/a/visible.deb", "v")
	putCommit(t, st, "cache/b/hidden.deb", "v")
	locked := filepath.Join(st.root, "cache", "b")
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	metas, err := collectList(ctx, st, "cache/")
	if err == nil {
		t.Fatalf("List с недоступным подкаталогом не вернул ошибку: %v", metas)
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("ошибка листинга не Permission-обёртка: %v", err)
	}
}

func TestAbortLeavesTmpEmpty(t *testing.T) {
	ctx := context.Background()
	st := newTest(t)
	w, err := st.Put(ctx, "cache/y")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("discard")); err != nil {
		t.Fatal(err)
	}
	if err := w.Abort(ctx); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(st.root, tmpDir))
	if err != nil || len(entries) != 0 {
		t.Fatalf("tmp после Abort: %v (err %v)", entries, err)
	}
}

func TestAbortTmpAlreadyRemoved(t *testing.T) {
	// На Windows нельзя удалить открытый файл (w.file держит хэндл);
	// Linux позволяет unlink открытого файла — там тест валиден.
	if runtime.GOOS == "windows" {
		t.Skip("удаление открытого файла неприменимо на Windows")
	}
	ctx := context.Background()
	st := newTest(t)
	w, err := st.Put(ctx, "cache/g")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	// tmp-файл удалили внешне (краш/чистка) — Abort не должен падать
	// на os.IsNotExist, а молча завершиться.
	if err := os.Remove(filepath.Join(st.root, tmpDir, "00000000-0000-4000-8000-000000000000")); err != nil {
		t.Fatal(err)
	}
	if err := w.Abort(ctx); err != nil {
		t.Fatalf("Abort без tmp-файла: %v", err)
	}
}

// TestAbortWithCanceledContext — Abort выполняется даже при отменённом
// ctx: иначе недокачка при обрыве клиента утекала бы tmp-файлом и fd
// до подметания на следующем старте (аудит, fs durability).
func TestAbortWithCanceledContext(t *testing.T) {
	ctx := context.Background()
	st := newTest(t)
	w, err := st.Put(ctx, "cache/cancel")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("partial")); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := w.Abort(canceled); err != nil {
		t.Fatalf("Abort с отменённым ctx: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(st.root, tmpDir))
	if err != nil || len(entries) != 0 {
		t.Fatalf("tmp после Abort с отменённым ctx: %d записей (err %v), хочу 0", len(entries), err)
	}
}

// TestAbortCloseErrorStillRemovesTmp — Close-ошибка Abort не должна
// прятать cleanup: tmp удаляется всегда, ошибка возвращается (сессия
// 44).
func TestAbortCloseErrorStillRemovesTmp(t *testing.T) {
	ctx := context.Background()
	st := newTest(t)
	w, err := st.Put(ctx, "cache/closefail")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	// Двойной Close *os.File детерминированно падает ErrFileClosed на
	// обеих платформах — без экзотических FS-состояний.
	if err := w.(*writer).file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Abort(ctx); err == nil {
		t.Fatal("Abort с Close-ошибкой не вернул ошибку")
	}
	entries, err := os.ReadDir(filepath.Join(st.root, tmpDir))
	if err != nil || len(entries) != 0 {
		t.Fatalf("tmp после Abort с Close-ошибкой: %d записей (err %v), хочу 0", len(entries), err)
	}
}

// TestNewSweepsTmp — мусор в tmp/ (осиротевшие недокачки крэша)
// вычищается при старте хранилища: живых writers не бывает.
func TestNewSweepsTmp(t *testing.T) {
	root := filepath.Join(t.TempDir(), "store")
	tmp := filepath.Join(root, tmpDir)
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		t.Fatal(err)
	}
	garbage := filepath.Join(tmp, "orphaned-upload")
	if err := os.WriteFile(garbage, []byte("dead body"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(root, testutil.FixedRand()); err != nil {
		t.Fatalf("New: %v", err)
	}
	entries, err := os.ReadDir(tmp)
	if err != nil || len(entries) != 0 {
		t.Fatalf("tmp после старта: %d записей (err %v), хочу 0", len(entries), err)
	}
}

func TestCryptoRandInt64(t *testing.T) {
	r := cryptoRand{}
	if n := r.Int64(0); n != 0 {
		t.Fatalf("Int64(0) = %d, хочу 0", n)
	}
	if n := r.Int64(-1); n != 0 {
		t.Fatalf("Int64(-1) = %d, хочу 0", n)
	}
	for i := 0; i < 100; i++ {
		n := r.Int64(100)
		if n < 0 || n >= 100 {
			t.Fatalf("Int64(100) = %d вне [0,100)", n)
		}
	}
}

func TestCryptoRandUUID4(t *testing.T) {
	r := cryptoRand{}
	u, err := r.UUID4()
	if err != nil {
		t.Fatal(err)
	}
	if len(u) != 36 {
		t.Fatalf("UUID4 len = %d, хочу 36", len(u))
	}
	// версия 4: 14-й символ (index 14) — '4'
	if u[14] != '4' {
		t.Fatalf("UUID4 версия не 4: %q", u[14])
	}
}

// putCommit фиксирует объект с содержимым content (fs-локальный helper
// контрактного put, но здесь нужен в fs-специфичных кейсах).
func putCommit(t *testing.T, st *Storage, key, content string) {
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

// collectList собирает List-обход: метаданные до первой ошибки и сама
// ошибка (nil, если обход чистый). Заменяет прежний listKeys: контракт
// List — терминальная ошибка отдельным значением.
func collectList(ctx context.Context, st *Storage, prefix string) ([]port.Meta, error) {
	var out []port.Meta
	for m, err := range st.List(ctx, prefix) {
		if err != nil {
			return out, err
		}
		out = append(out, m)
	}
	return out, nil
}

// compile-time: Storage реализует весь порт.
var _ port.Storage = (*Storage)(nil)
