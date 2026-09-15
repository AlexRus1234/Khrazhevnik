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

package storagegc

import (
	"context"
	"errors"
	"iter"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/testutil"
)

// gcEnv — харнесс контрактов sweeper'а: in-memory хранилище с
// управляемым ModTime (та же семантика ошибок домена, что у боевых
// носителей — правило 17), фейковый каталог и ручные часы.
type gcEnv struct {
	clock   *testutil.ManualClock
	storage *testutil.FakeStorage
	index   *testutil.FakeObjectIndex
	repos   *testutil.FakeRepoStore
}

func newGCEnv(t *testing.T) *gcEnv {
	t.Helper()
	clock := testutil.NewManualClock(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
	return &gcEnv{
		clock:   clock,
		storage: testutil.NewFakeStorage(clock),
		index:   testutil.NewFakeObjectIndex(),
		repos:   testutil.NewFakeRepoStore(),
	}
}

// sweep запускает проход на свежем Sweeper'е (state прохода не
// переносится между вызовами).
func (e *gcEnv) sweep(t *testing.T, grace time.Duration, dryRun bool) (Result, error) {
	t.Helper()
	sw := New(e.storage, e.index, e.repos, e.clock, grace)
	return sw.Sweep(context.Background(), dryRun)
}

func putObject(t *testing.T, st port.Storage, key string, data []byte) {
	t.Helper()
	ctx := context.Background()
	w, err := st.Put(ctx, key)
	if err != nil {
		t.Fatalf("Put(%q): %v", key, err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatalf("Write(%q): %v", key, err)
	}
	if err := w.Commit(ctx); err != nil {
		t.Fatalf("Commit(%q): %v", key, err)
	}
}

func hasKey(t *testing.T, st port.Storage, key string) bool {
	t.Helper()
	_, err := st.Stat(context.Background(), key)
	if err == nil {
		return true
	}
	var nf *domain.NotFoundError
	if errors.As(err, &nf) {
		return false
	}
	t.Fatalf("Stat(%q): %v", key, err)
	return false
}

// Версии реального формата: "-v" + 13 base36-знаков (nonce+seq).
const (
	liveKey  = "cache/foo/Release-v0000000000001"
	oldKey   = "cache/foo/Release-v0000000000002"
	strayKey = "cache/stray/thing-v0000000000009"
	immKey   = "cache/imm/file.deb"
)

// TestSweepCacheOrphans — контракт тройного правила: живая версия,
// чужое имя без строки и immutable не тронуты, осиротевшая старая
// версия удалена при grace=0.
func TestSweepCacheOrphans(t *testing.T) {
	env := newGCEnv(t)
	for _, k := range []string{liveKey, oldKey, strayKey, immKey} {
		putObject(t, env.storage, k, []byte("payload"))
	}
	if err := env.index.PutObjectMeta(context.Background(),
		domain.ObjectMeta{Key: "cache/foo/Release", StorageKey: liveKey}); err != nil {
		t.Fatalf("PutObjectMeta: %v", err)
	}
	env.clock.Advance(time.Hour)

	res, err := env.sweep(t, 0, false)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if res.CacheScanned != 4 {
		t.Errorf("CacheScanned = %d, хочу 4", res.CacheScanned)
	}
	if res.CacheOrphans != 1 {
		t.Errorf("CacheOrphans = %d, хочу 1", res.CacheOrphans)
	}
	if res.Deleted != 1 || res.FailedDeletes != 0 {
		t.Errorf("Deleted = %d, FailedDeletes = %d, хочу 1/0", res.Deleted, res.FailedDeletes)
	}
	if res.BytesFreed != int64(len("payload")) {
		t.Errorf("BytesFreed = %d, хочу %d", res.BytesFreed, len("payload"))
	}
	if hasKey(t, env.storage, oldKey) {
		t.Error("старая версия не удалена")
	}
	for _, k := range []string{liveKey, strayKey, immKey} {
		if !hasKey(t, env.storage, k) {
			t.Errorf("объект %q удалён, хотя не должен", k)
		}
	}
}

// TestSweepGraceKeepsFresh — свежий кандидат при grace=24h переживает
// проход: удаляется только старше now−grace.
func TestSweepGraceKeepsFresh(t *testing.T) {
	env := newGCEnv(t)
	putObject(t, env.storage, liveKey, []byte("payload"))
	putObject(t, env.storage, oldKey, []byte("payload"))
	if err := env.index.PutObjectMeta(context.Background(),
		domain.ObjectMeta{Key: "cache/foo/Release", StorageKey: liveKey}); err != nil {
		t.Fatalf("PutObjectMeta: %v", err)
	}
	env.clock.Advance(time.Hour)

	res, err := env.sweep(t, 24*time.Hour, false)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if res.CacheOrphans != 0 || res.Deleted != 0 {
		t.Errorf("CacheOrphans = %d, Deleted = %d, хочу 0/0", res.CacheOrphans, res.Deleted)
	}
	if !hasKey(t, env.storage, oldKey) {
		t.Error("свежий кандидат удалён при grace=24h")
	}
}

// TestSweepRepoOrphans — repo/ живого репо не тронут, отсутствующего
// выметен, нечисловой сегмент пропущен.
func TestSweepRepoOrphans(t *testing.T) {
	env := newGCEnv(t)
	if _, err := env.repos.CreateRepo(context.Background(), domain.Repo{Name: "live"}); err != nil {
		t.Fatalf("CreateRepo: %v", err)
	}
	const (
		liveRepoKey   = "repo/1/pkg/foo.deb"
		orphanRepoKey = "repo/2/bar.deb"
		foreignKey    = "repo/abc/note.txt"
	)
	for _, k := range []string{liveRepoKey, orphanRepoKey, foreignKey} {
		putObject(t, env.storage, k, []byte("payload"))
	}
	env.clock.Advance(time.Hour)

	res, err := env.sweep(t, 0, false)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if res.RepoScanned != 3 || res.RepoOrphans != 1 || res.Deleted != 1 {
		t.Errorf("RepoScanned/RepoOrphans/Deleted = %d/%d/%d, хочу 3/1/1",
			res.RepoScanned, res.RepoOrphans, res.Deleted)
	}
	if !hasKey(t, env.storage, liveRepoKey) {
		t.Error("объект живого репо удалён")
	}
	if hasKey(t, env.storage, orphanRepoKey) {
		t.Error("объект удалённого репо не выметен")
	}
	if !hasKey(t, env.storage, foreignKey) {
		t.Error("объект вне repo/<id>/ удалён")
	}
}

// TestSweepDryRun — счётчики без единого удаления, хук получает итог.
func TestSweepDryRun(t *testing.T) {
	env := newGCEnv(t)
	putObject(t, env.storage, liveKey, []byte("payload"))
	putObject(t, env.storage, oldKey, []byte("payload"))
	if err := env.index.PutObjectMeta(context.Background(),
		domain.ObjectMeta{Key: "cache/foo/Release", StorageKey: liveKey}); err != nil {
		t.Fatalf("PutObjectMeta: %v", err)
	}
	env.clock.Advance(time.Hour)

	sw := New(env.storage, env.index, env.repos, env.clock, 0)
	var hooked Result
	calls := 0
	sw.OnSweep = func(r Result, _ error) { calls++; hooked = r }
	res, err := sw.Sweep(context.Background(), true)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if !res.DryRun || res.CacheOrphans != 1 || res.Deleted != 0 || res.BytesFreed != 0 {
		t.Errorf("dry-run: DryRun=%v CacheOrphans=%d Deleted=%d BytesFreed=%d",
			res.DryRun, res.CacheOrphans, res.Deleted, res.BytesFreed)
	}
	if !hasKey(t, env.storage, oldKey) {
		t.Error("dry-run удалил объект")
	}
	if calls != 1 || hooked.CacheOrphans != res.CacheOrphans {
		t.Errorf("OnSweep: calls=%d, CacheOrphans=%d (хочу 1 и %d)", calls, hooked.CacheOrphans, res.CacheOrphans)
	}
}

// TestSweepRepoPrefix — точечная чистка repo/<id>/ целиком, соседний
// репозиторий не задет.
func TestSweepRepoPrefix(t *testing.T) {
	env := newGCEnv(t)
	for _, k := range []string{"repo/7/a.deb", "repo/7/sub/b.deb", "repo/8/c.deb"} {
		putObject(t, env.storage, k, []byte("payload"))
	}

	sw := New(env.storage, env.index, env.repos, env.clock, 0)
	res, err := sw.SweepRepoPrefix(context.Background(), 7)
	if err != nil {
		t.Fatalf("SweepRepoPrefix: %v", err)
	}
	if res.RepoScanned != 2 || res.Deleted != 2 {
		t.Errorf("RepoScanned = %d, Deleted = %d, хочу 2/2", res.RepoScanned, res.Deleted)
	}
	if hasKey(t, env.storage, "repo/7/a.deb") || hasKey(t, env.storage, "repo/7/sub/b.deb") {
		t.Error("префикс репо выметен не полностью")
	}
	if !hasKey(t, env.storage, "repo/8/c.deb") {
		t.Error("соседний репозиторий задет")
	}
}

// notFoundStorage — Delete-«уже нет» для одного ключа.
type notFoundStorage struct {
	*testutil.FakeStorage
	key string
}

func (s *notFoundStorage) Delete(ctx context.Context, key string) error {
	if key == s.key {
		return &domain.NotFoundError{What: "объект", Key: key}
	}
	return s.FakeStorage.Delete(ctx, key)
}

// TestSweepDeleteNotFoundIsNotFailure — NotFound от Delete («уже нет»)
// не FailedDeletes и не Deleted.
func TestSweepDeleteNotFoundIsNotFailure(t *testing.T) {
	env := newGCEnv(t)
	putObject(t, env.storage, liveKey, []byte("payload"))
	putObject(t, env.storage, oldKey, []byte("payload"))
	if err := env.index.PutObjectMeta(context.Background(),
		domain.ObjectMeta{Key: "cache/foo/Release", StorageKey: liveKey}); err != nil {
		t.Fatalf("PutObjectMeta: %v", err)
	}
	env.clock.Advance(time.Hour)

	sw := New(&notFoundStorage{FakeStorage: env.storage, key: oldKey}, env.index, env.repos, env.clock, 0)
	res, err := sw.Sweep(context.Background(), false)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if res.FailedDeletes != 0 || res.Deleted != 0 {
		t.Errorf("FailedDeletes = %d, Deleted = %d, хочу 0/0", res.FailedDeletes, res.Deleted)
	}
}

// errDeleteStorage — прочий (не NotFound) сбой удаления одного ключа.
type errDeleteStorage struct {
	*testutil.FakeStorage
	key string
}

func (s *errDeleteStorage) Delete(ctx context.Context, key string) error {
	if key == s.key {
		return errors.New("носитель недоступен")
	}
	return s.FakeStorage.Delete(ctx, key)
}

// TestSweepDeleteErrorContinues — прочий сбой удаления копится в
// FailedDeletes, проход не прерывается.
func TestSweepDeleteErrorContinues(t *testing.T) {
	env := newGCEnv(t)
	putObject(t, env.storage, liveKey, []byte("payload"))
	putObject(t, env.storage, oldKey, []byte("payload"))
	if err := env.index.PutObjectMeta(context.Background(),
		domain.ObjectMeta{Key: "cache/foo/Release", StorageKey: liveKey}); err != nil {
		t.Fatalf("PutObjectMeta: %v", err)
	}
	env.clock.Advance(time.Hour)

	sw := New(&errDeleteStorage{FakeStorage: env.storage, key: oldKey}, env.index, env.repos, env.clock, 0)
	res, err := sw.Sweep(context.Background(), false)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if res.FailedDeletes != 1 || res.Deleted != 0 {
		t.Errorf("FailedDeletes = %d, Deleted = %d, хочу 1/0", res.FailedDeletes, res.Deleted)
	}
	if !hasKey(t, env.storage, oldKey) {
		t.Error("сбойное удаление всё же удалило объект")
	}
}

// errRepoStore — терминальный сбой каталога репозиториев.
type errRepoStore struct {
	*testutil.FakeRepoStore
}

func (s *errRepoStore) Repos(context.Context) ([]domain.Repo, error) {
	return nil, errors.New("каталог недоступен")
}

// TestSweepReposErrorFailClosed — сбой каталога репозиториев завершает
// проход ошибкой: все repo/-объекты разом стали бы «осиротевшими».
func TestSweepReposErrorFailClosed(t *testing.T) {
	env := newGCEnv(t)
	sw := New(env.storage, env.index, &errRepoStore{FakeRepoStore: env.repos}, env.clock, 0)
	if _, err := sw.Sweep(context.Background(), false); err == nil {
		t.Fatal("Sweep вернул nil при сбое каталога репозиториев")
	}
}

// TestNewClampsNegativeGrace — отрицательный grace приводится к нулю:
// «cutoff в будущем» удалял бы свежие объекты.
func TestNewClampsNegativeGrace(t *testing.T) {
	env := newGCEnv(t)
	putObject(t, env.storage, liveKey, []byte("payload"))
	putObject(t, env.storage, oldKey, []byte("payload"))
	if err := env.index.PutObjectMeta(context.Background(),
		domain.ObjectMeta{Key: "cache/foo/Release", StorageKey: liveKey}); err != nil {
		t.Fatalf("PutObjectMeta: %v", err)
	}
	// Часы не двигаем: ModTime == now, при grace=0 — не кандидат.
	sw := New(env.storage, env.index, env.repos, env.clock, -time.Hour)
	res, err := sw.Sweep(context.Background(), false)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if res.CacheOrphans != 0 || res.Deleted != 0 {
		t.Errorf("CacheOrphans = %d, Deleted = %d, хочу 0/0", res.CacheOrphans, res.Deleted)
	}
}

// listErrStorage — терминальная ошибка листинга.
type listErrStorage struct {
	*testutil.FakeStorage
	err error
}

func (s *listErrStorage) List(_ context.Context, _ string) iter.Seq2[port.Meta, error] {
	return func(yield func(port.Meta, error) bool) {
		yield(port.Meta{}, s.err)
	}
}

// TestSweepListErrorFailClosed — ошибка листинга не маскируется под
// «объектов нет»: проход завершается ошибкой.
func TestSweepListErrorFailClosed(t *testing.T) {
	env := newGCEnv(t)
	sw := New(&listErrStorage{FakeStorage: env.storage, err: errors.New("носитель недоступен")},
		env.index, env.repos, env.clock, 0)
	if _, err := sw.Sweep(context.Background(), false); err == nil {
		t.Fatal("Sweep вернул nil при ошибке листинга")
	}
}
