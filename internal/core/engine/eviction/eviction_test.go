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

package eviction_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/engine/eviction"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/testutil"
)

// testNow — «сейчас» движка; ModTime объектов отсчитывается от него, чтобы
// возраст в сутках был явным.
var testNow = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

const (
	testStep = time.Hour             // шаг часов хранилища: порядок записи = порядок свежести
	testOld  = -200 * 24 * time.Hour // старт ModTime «давних» версий (> MaxAge 90 суток)
	testNear = -10 * 24 * time.Hour  // старт ModTime «свежих» версий (< MaxAge)
)

// poolAdapter — двойник генератора с резолвером семейств кеш-путей
// (port.CacheFamilyResolver): семейство — каталог файла под pool/, всё вне
// pool/ — не семейство (индексы, подписи, служебные). seen копит пути,
// переданные резолверу, — так тест видит форму входа (upstream-путь).
type poolAdapter struct {
	name string
	seen []string
}

func (a *poolAdapter) Name() string                    { return a.name }
func (a *poolAdapter) ValidateObjectPath(string) error { return nil }
func (a *poolAdapter) GenerateIndexes(context.Context, domain.Repo, port.Storage, port.RepoProgress) error {
	return nil
}
func (a *poolAdapter) CacheObjectFamily(path string) (string, bool) {
	a.seen = append(a.seen, path)
	p := strings.TrimPrefix(path, "/")
	if !strings.HasPrefix(p, "pool/") {
		return "", false
	}
	return p[:strings.LastIndexByte(p, '/')], true
}

// nixAdapter — генератор БЕЗ CacheFamilyResolver (nix: content-addressed,
// старых версий одного пути не бывает).
type nixAdapter struct{ name string }

func (a *nixAdapter) Name() string                    { return a.name }
func (a *nixAdapter) ValidateObjectPath(string) error { return nil }
func (a *nixAdapter) GenerateIndexes(context.Context, domain.Repo, port.Storage, port.RepoProgress) error {
	return nil
}

// greedyAdapter — резолвер, объявляющий семейством любое имя: нужен, чтобы
// собственные фильтры движка (versioned-суффикс, marker .retained) было на
// чём проверить — с честным резолвером эти ключи отсеклись бы им же.
type greedyAdapter struct{ name string }

func (a *greedyAdapter) Name() string                    { return a.name }
func (a *greedyAdapter) ValidateObjectPath(string) error { return nil }
func (a *greedyAdapter) GenerateIndexes(context.Context, domain.Repo, port.Storage, port.RepoProgress) error {
	return nil
}
func (a *greedyAdapter) CacheObjectFamily(string) (string, bool) { return "all", true }

var (
	_ port.RepoAdapter         = (*poolAdapter)(nil)
	_ port.CacheFamilyResolver = (*poolAdapter)(nil)
	_ port.RepoAdapter         = (*nixAdapter)(nil)
	_ port.RepoAdapter         = (*greedyAdapter)(nil)
	_ port.CacheFamilyResolver = (*greedyAdapter)(nil)
)

// failingAccessStore — учёт обращений, который не может ответить: давность
// неизвестна, гадать о ней и удалять «наугад» запрещено (fail-closed).
type failingAccessStore struct{ *testutil.FakeAccessStore }

func (s *failingAccessStore) AccessEntry(context.Context, string, string) (domain.ObjectAccess, error) {
	return domain.ObjectAccess{}, errors.New("каталог: сбой чтения")
}

// fixture — собранный на фейках движок eviction с одним proxy-remote.
type fixture struct {
	engine  *eviction.Engine
	storage *testutil.FakeStorage
	access  *testutil.FakeAccessStore
	remote  domain.Remote
}

// newFixture собирает движок: часы хранилища идут шагом testStep от
// modStart, поэтому ModTime объектов — в порядке их записи (первый самый
// старый). Часы движка заморожены на testNow; policy — политика remote
// (nil — наследовать дефолт, который здесь выключен).
func newFixture(t *testing.T, adapter port.RepoAdapter, policy *domain.Retention, modStart time.Duration) *fixture {
	t.Helper()
	storage := testutil.NewFakeStorage(testutil.SeqClock(testNow.Add(modStart), testStep))
	f := &fixture{
		storage: storage,
		access:  testutil.NewFakeAccessStore(),
		remote: domain.Remote{
			ID: 1, Name: "deb-main", Ecosystem: adapter.Name(),
			Mode: domain.ModeProxy, Enabled: true, Eviction: policy,
		},
	}
	f.engine = eviction.New(storage, f.access,
		map[string]port.RepoAdapter{adapter.Name(): adapter}, testutil.FixedClock(testNow), domain.Retention{})
	return f
}

// put пишет объект кеша remote (следующий тик часов хранилища).
func (f *fixture) put(t *testing.T, path, body string) string {
	t.Helper()
	key := "cache/" + f.remote.Ecosystem + "/1/" + path
	putObj(t, f.storage, key, body)
	return key
}

// putFamily пишет версии семейства htop в порядке убывания свежести:
// первый в списке — самый старый (ModTime растёт с каждым коммитом).
func (f *fixture) putFamily(t *testing.T, names ...string) []string {
	t.Helper()
	keys := make([]string, 0, len(names))
	for i, name := range names {
		// Разные длины тел — разный BytesFreed у кандидатов.
		keys = append(keys, f.put(t, "pool/main/h/htop/"+name, strings.Repeat("x", i+1)))
	}
	return keys
}

// touch фиксирует обращение к версии так, как это делает accesskeeper.
func (f *fixture) touch(t *testing.T, key string, at time.Time) {
	t.Helper()
	err := f.access.MergeAccess(context.Background(), []domain.ObjectAccess{
		{Scope: domain.AccessScopeCache, Key: key, LastAccess: at, Hits: 1},
	})
	if err != nil {
		t.Fatalf("MergeAccess(%s): %v", key, err)
	}
}

// alive — живой набор кеша remote-1 (ключи хранилища).
func (f *fixture) alive(t *testing.T) map[string]bool {
	t.Helper()
	return listKeys(t, f.storage, "cache/"+f.remote.Ecosystem+"/1/")
}

func putObj(t *testing.T, s *testutil.FakeStorage, key, body string) {
	t.Helper()
	w, err := s.Put(context.Background(), key)
	if err != nil {
		t.Fatalf("Put(%s): %v", key, err)
	}
	if _, err := w.Write([]byte(body)); err != nil {
		t.Fatalf("Write(%s): %v", key, err)
	}
	if err := w.Commit(context.Background()); err != nil {
		t.Fatalf("Commit(%s): %v", key, err)
	}
}

func listKeys(t *testing.T, s *testutil.FakeStorage, prefix string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for meta, err := range s.List(context.Background(), prefix) {
		if err != nil {
			t.Fatalf("List(%s): %v", prefix, err)
		}
		out[meta.Key] = true
	}
	return out
}

func requireResult(t *testing.T, got, want eviction.Result) {
	t.Helper()
	if got != want {
		t.Fatalf("Result = %+v, хочу %+v", got, want)
	}
}

func requireAlive(t *testing.T, alive map[string]bool, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if !alive[k] {
			t.Fatalf("объект %s удалён, хочу живым (в хранилище: %v)", k, alive)
		}
	}
}

// TestApplyDisabledPolicy — политика {0,0} (или выключенный дефолт): проход
// ничего не делает и не ошибка (кеш растёт в пределах носителя).
func TestApplyDisabledPolicy(t *testing.T) {
	off := domain.Retention{}
	f := newFixture(t, &poolAdapter{name: "apt"}, &off, testOld)
	f.putFamily(t, "htop_1.0_amd64.deb", "htop_1.1_amd64.deb", "htop_1.2_amd64.deb")

	res, err := f.engine.Apply(context.Background(), f.remote, false)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	requireResult(t, res, eviction.Result{})
	if n := len(f.alive(t)); n != 3 {
		t.Fatalf("проход тронул хранилище: %d объектов", n)
	}
}

// TestApplyMirrorNoop — proxy-only: зеркало не чистится (churn против
// resume-diff sync), даже когда политика включена.
func TestApplyMirrorNoop(t *testing.T) {
	pol := domain.Retention{MinVersions: 2, MaxAgeDays: 90}
	f := newFixture(t, &poolAdapter{name: "apt"}, &pol, testOld)
	f.remote.Mode = domain.ModeMirror
	f.putFamily(t, "htop_1.0_amd64.deb", "htop_1.1_amd64.deb", "htop_1.2_amd64.deb")

	res, err := f.engine.Apply(context.Background(), f.remote, false)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	requireResult(t, res, eviction.Result{})
	if n := len(f.alive(t)); n != 3 {
		t.Fatalf("mirror-remote очищен: %d объектов", n)
	}
}

// TestApplyUnsupportedEcosystem — генератор без CacheFamilyResolver (nix):
// честная UnsupportedError, а не молчаливый no-op (иначе политика «работает
// вхолостую» незаметно).
func TestApplyUnsupportedEcosystem(t *testing.T) {
	pol := domain.Retention{MinVersions: 2, MaxAgeDays: 90}
	f := newFixture(t, &nixAdapter{name: "nix"}, &pol, testOld)
	f.putFamily(t, "nar_1.nar", "nar_2.nar", "nar_3.nar")

	res, err := f.engine.Apply(context.Background(), f.remote, false)
	var unsupported *domain.UnsupportedError
	if !errors.As(err, &unsupported) {
		t.Fatalf("Apply = %v, хочу *domain.UnsupportedError", err)
	}
	requireResult(t, res, eviction.Result{})
	if n := len(f.alive(t)); n != 3 {
		t.Fatalf("проход тронул хранилище: %d объектов", n)
	}
}

// TestApplyMinVersionsArbitration — ядро политики: семейство из 3 версий,
// все старше окна; при {2,90} старейшая вне топ-2 удалена (топ-2 живы), при
// {3,90} топ-N вырос и жив весь семейство. Заодно проверяется форма входа
// резолвера: upstream-путь с ведущим «/» (ключ минус префикс кеша).
func TestApplyMinVersionsArbitration(t *testing.T) {
	t.Run("удаляет_вне_топ-N", func(t *testing.T) {
		pol := domain.Retention{MinVersions: 2, MaxAgeDays: 90}
		adapter := &poolAdapter{name: "apt"}
		f := newFixture(t, adapter, &pol, testOld)
		keys := f.putFamily(t, "htop_1.0_amd64.deb", "htop_1.1_amd64.deb", "htop_1.2_amd64.deb")

		res, err := f.engine.Apply(context.Background(), f.remote, false)
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		requireResult(t, res, eviction.Result{
			Families: 1, ObjectsScanned: 3, Candidates: 1, Deleted: 1,
			BytesFreed: 1, ProtectedByMin: 2, // тело «x» старейшей
		})
		alive := f.alive(t)
		requireAlive(t, alive, keys[1], keys[2])
		if len(alive) != 2 {
			t.Fatalf("в хранилище %d объектов, хочу 2: %v", len(alive), alive)
		}
		if len(adapter.seen) == 0 {
			t.Fatal("резолвер не вызван")
		}
		for _, p := range adapter.seen {
			if !strings.HasPrefix(p, "/pool/") {
				t.Fatalf("резолверу передан %q, хочу upstream-путь с ведущим «/»", p)
			}
		}
	})
	t.Run("топ-N_растёт", func(t *testing.T) {
		pol := domain.Retention{MinVersions: 3, MaxAgeDays: 90}
		f := newFixture(t, &poolAdapter{name: "apt"}, &pol, testOld)
		f.putFamily(t, "htop_1.0_amd64.deb", "htop_1.1_amd64.deb", "htop_1.2_amd64.deb")

		res, err := f.engine.Apply(context.Background(), f.remote, false)
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		requireResult(t, res, eviction.Result{Families: 1, ObjectsScanned: 3, ProtectedByMin: 3})
		if n := len(f.alive(t)); n != 3 {
			t.Fatalf("семейство в пределах топ-N тронуто: %d объектов", n)
		}
	})
}

// TestApplyFreshAccessProtectsOldVersion — обращение (MergeAccess, скоуп
// cache) обновило last_access: версия жива при {2,1}, хотя ModTime старше
// окна. Обращение к СТАРОЙ версии — ровно то, от чего защищает политика.
func TestApplyFreshAccessProtectsOldVersion(t *testing.T) {
	pol := domain.Retention{MinVersions: 2, MaxAgeDays: 1}
	f := newFixture(t, &poolAdapter{name: "apt"}, &pol, testNear)
	keys := f.putFamily(t, "htop_1.0_amd64.deb", "htop_1.1_amd64.deb", "htop_1.2_amd64.deb")
	f.touch(t, keys[0], testNow)

	res, err := f.engine.Apply(context.Background(), f.remote, false)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	requireResult(t, res, eviction.Result{
		Families: 1, ObjectsScanned: 3, ProtectedByMin: 2, ProtectedByAccess: 1,
	})
	if n := len(f.alive(t)); n != 3 {
		t.Fatalf("обращённая версия удалена: %d объектов", n)
	}
}

// TestApplyBootstrapFromModTime — бутстрап last-access: строки object_access
// нет — давность считается от ModTime. Старая дата → кандидат, свежая →
// защищена возрастом.
func TestApplyBootstrapFromModTime(t *testing.T) {
	t.Run("старая_дата_кандидат", func(t *testing.T) {
		pol := domain.Retention{MinVersions: 2, MaxAgeDays: 30}
		f := newFixture(t, &poolAdapter{name: "apt"}, &pol, testOld)
		f.putFamily(t, "htop_1.0_amd64.deb", "htop_1.1_amd64.deb", "htop_1.2_amd64.deb")

		res, err := f.engine.Apply(context.Background(), f.remote, false)
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		requireResult(t, res, eviction.Result{
			Families: 1, ObjectsScanned: 3, Candidates: 1, Deleted: 1,
			BytesFreed: 1, ProtectedByMin: 2,
		})
	})
	t.Run("свежая_дата_защищена", func(t *testing.T) {
		pol := domain.Retention{MinVersions: 2, MaxAgeDays: 90}
		f := newFixture(t, &poolAdapter{name: "apt"}, &pol, testNear)
		f.putFamily(t, "htop_1.0_amd64.deb", "htop_1.1_amd64.deb", "htop_1.2_amd64.deb")

		res, err := f.engine.Apply(context.Background(), f.remote, false)
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		requireResult(t, res, eviction.Result{
			Families: 1, ObjectsScanned: 3, ProtectedByMin: 2, ProtectedByAccess: 1,
		})
	})
}

// TestApplySkipsVersionedAndRetained — versioned-ключи (прошлые версии
// mutable-объектов, их чистит storagegc) и marker .retained не кандидаты
// никогда. Резолвер здесь жадный: без фильтров движка оба ключа попали бы в
// семейство «all» и были бы удалены как старше топ-N.
func TestApplySkipsVersionedAndRetained(t *testing.T) {
	pol := domain.Retention{MinVersions: 2, MaxAgeDays: 30}
	adapter := &greedyAdapter{name: "apt"}
	f := newFixture(t, adapter, &pol, testOld)
	pkgOld := f.put(t, "pool/main/h/htop/htop_1.0_amd64.deb", "x")
	// Форма versionedKey (cache/engine.go): «-v» + base36 nonce + seq.
	versioned := f.put(t, "dists/stable/Packages-v1abcdefghijkl", "mutable")
	retained := f.put(t, "dists/stable/by-hash/.retained", "marker")
	pkgMid := f.put(t, "pool/main/h/htop/htop_2.0_amd64.deb", "xx")
	pkgNew := f.put(t, "pool/main/h/htop/htop_3.0_amd64.deb", "xxx")

	res, err := f.engine.Apply(context.Background(), f.remote, false)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	requireResult(t, res, eviction.Result{
		Families: 1, ObjectsScanned: 5, Candidates: 1, Deleted: 1,
		BytesFreed: 1, ProtectedByMin: 2, // тело «x» старейшего пакета
	})
	alive := f.alive(t)
	requireAlive(t, alive, versioned, retained, pkgMid, pkgNew)
	if alive[pkgOld] {
		t.Fatal("старейший пакет семейства не удалён")
	}
}

// TestApplyScopedToRemoteID — листинг ограничен префиксом remote:
// cache/apt/1/ не подмешивает соседа по номеру cache/apt/12/.
func TestApplyScopedToRemoteID(t *testing.T) {
	pol := domain.Retention{MinVersions: 2, MaxAgeDays: 30}
	f := newFixture(t, &poolAdapter{name: "apt"}, &pol, testOld)
	f.putFamily(t, "htop_1.0_amd64.deb", "htop_1.1_amd64.deb", "htop_1.2_amd64.deb")
	neighbour := []string{
		"cache/apt/12/pool/main/h/htop/htop_1.0_amd64.deb",
		"cache/apt/12/pool/main/h/htop/htop_1.1_amd64.deb",
		"cache/apt/12/pool/main/h/htop/htop_1.2_amd64.deb",
	}
	for i, k := range neighbour {
		putObj(t, f.storage, k, strings.Repeat("у", i+1))
	}

	res, err := f.engine.Apply(context.Background(), f.remote, false)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Deleted != 1 {
		t.Fatalf("Deleted = %d, хочу 1 (только свой remote)", res.Deleted)
	}
	if n := len(listKeys(t, f.storage, "cache/apt/12/")); n != 3 {
		t.Fatalf("сосед по номеру тронут: %d объектов", n)
	}
}

// TestPreviewDryRun — Preview не удаляет, но наполняет отчёт по версиям,
// которые политика рассматривает (вне топ-N): причина защиты либо пусто —
// кандидат. Боевой Apply после Preview удаляет того же кандидата.
func TestPreviewDryRun(t *testing.T) {
	t.Run("кандидат_в_отчёте", func(t *testing.T) {
		pol := domain.Retention{MinVersions: 2, MaxAgeDays: 90}
		f := newFixture(t, &poolAdapter{name: "apt"}, &pol, testOld)
		keys := f.putFamily(t, "htop_1.0_amd64.deb", "htop_1.1_amd64.deb", "htop_1.2_amd64.deb")

		res, reports, err := f.engine.Preview(context.Background(), f.remote)
		if err != nil {
			t.Fatalf("Preview: %v", err)
		}
		requireResult(t, res, eviction.Result{
			DryRun: true, Families: 1, ObjectsScanned: 3, Candidates: 1, ProtectedByMin: 2,
		})
		if len(reports) != 1 {
			t.Fatalf("отчёт о %d версиях, хочу 1: %+v", len(reports), reports)
		}
		r := reports[0]
		if r.Key != keys[0] || r.Family != "pool/main/h/htop" || r.ProtectedBy != "" {
			t.Fatalf("Report = %+v, хочу кандидата %s семейства pool/main/h/htop", r, keys[0])
		}
		if !r.LastAccess.Equal(r.ModTime) {
			t.Fatalf("LastAccess = %v, хочу бутстрап от ModTime %v", r.LastAccess, r.ModTime)
		}
		if n := len(f.alive(t)); n != 3 {
			t.Fatalf("dry-run удалил: %d объектов", n)
		}

		res, err = f.engine.Apply(context.Background(), f.remote, false)
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if res.Deleted != 1 {
			t.Fatalf("Apply.Deleted = %d, хочу 1 (тот же кандидат)", res.Deleted)
		}
	})
	t.Run("свежее_обращение_в_отчёте", func(t *testing.T) {
		pol := domain.Retention{MinVersions: 2, MaxAgeDays: 1}
		f := newFixture(t, &poolAdapter{name: "apt"}, &pol, testNear)
		keys := f.putFamily(t, "htop_1.0_amd64.deb", "htop_1.1_amd64.deb", "htop_1.2_amd64.deb")
		f.touch(t, keys[0], testNow)

		_, reports, err := f.engine.Preview(context.Background(), f.remote)
		if err != nil {
			t.Fatalf("Preview: %v", err)
		}
		if len(reports) != 1 || reports[0].ProtectedBy != "access" || !reports[0].LastAccess.Equal(testNow) {
			t.Fatalf("отчёт = %+v, хочу одну версию, защищённую свежим обращением", reports)
		}
	})
}

// TestApplyAccessStoreFailureFailClosed — состояние обращений прочесть
// нельзя: давность неизвестна, гадать и удалять «наугад» запрещено — проход
// падает и ничего не удаляет.
func TestApplyAccessStoreFailureFailClosed(t *testing.T) {
	pol := domain.Retention{MinVersions: 2, MaxAgeDays: 90}
	adapter := &poolAdapter{name: "apt"}
	storage := testutil.NewFakeStorage(testutil.SeqClock(testNow.Add(testOld), testStep))
	access := &failingAccessStore{FakeAccessStore: testutil.NewFakeAccessStore()}
	engine := eviction.New(storage, access, map[string]port.RepoAdapter{"apt": adapter}, testutil.FixedClock(testNow), domain.Retention{})
	remote := domain.Remote{ID: 1, Ecosystem: "apt", Mode: domain.ModeProxy, Eviction: &pol}
	for i, name := range []string{"htop_1.0_amd64.deb", "htop_1.1_amd64.deb", "htop_1.2_amd64.deb"} {
		putObj(t, storage, "cache/apt/1/pool/main/h/htop/"+name, strings.Repeat("x", i+1))
	}

	res, err := engine.Apply(context.Background(), remote, false)
	if err == nil {
		t.Fatal("Apply = nil, хочу ошибку чтения обращений")
	}
	if res.Deleted != 0 {
		t.Fatalf("fail-closed нарушен: удалено %d", res.Deleted)
	}
	if n := len(listKeys(t, storage, "cache/apt/1/")); n != 3 {
		t.Fatalf("проход тронул хранилище: %d объектов", n)
	}
}

// TestPolicyTriState — Effective-политика: указатель remote главнее дефолта
// конфига, &{0,0} — явное «выключено», отличимое от наследования nil.
func TestPolicyTriState(t *testing.T) {
	def := domain.Retention{MinVersions: 3, MaxAgeDays: 90}
	engine := eviction.New(nil, nil, nil, testutil.FixedClock(testNow), def)
	cases := []struct {
		name string
		ev   *domain.Retention
		want domain.Retention
	}{
		{"наследование_nil", nil, def},
		{"явно_выключено", &domain.Retention{}, domain.Retention{}},
		{"политика_remote", &domain.Retention{MinVersions: 2, MaxAgeDays: 30}, domain.Retention{MinVersions: 2, MaxAgeDays: 30}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := engine.Policy(domain.Remote{Eviction: tc.ev}); got != tc.want {
				t.Fatalf("Policy = %+v, хочу %+v", got, tc.want)
			}
		})
	}
}
