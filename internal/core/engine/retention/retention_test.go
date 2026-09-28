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

package retention_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/engine/retention"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/testutil"
)

// testNow — «сейчас» движка; ModTime объектов отсчитывается от него, чтобы
// возраст в сутках был явным.
var testNow = time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)

const (
	testStep = time.Hour             // шаг часов хранилища: порядок записи = порядок свежести
	testOld  = -200 * 24 * time.Hour // старт ModTime «давних» версий (> MaxAge 90 суток)
	testNear = -10 * 24 * time.Hour  // старт ModTime «свежих» версий (< MaxAge)
)

// familyAdapter — двойник адаптера с резолвером семейств (механика 169):
// семейство — каталог файла под pool/, всё вне pool/ — не семейство
// (индексы, подписи, служебные объекты).
type familyAdapter struct{ name string }

func (a *familyAdapter) Name() string                    { return a.name }
func (a *familyAdapter) ValidateObjectPath(string) error { return nil }
func (a *familyAdapter) GenerateIndexes(context.Context, domain.Repo, port.Storage, port.RepoProgress) error {
	return nil
}
func (a *familyAdapter) ObjectFamily(p string) (string, bool) {
	if !strings.HasPrefix(p, "pool/") {
		return "", false
	}
	dir := p[:strings.LastIndexByte(p, '/')]
	return dir, true
}

// plainAdapter — адаптер без FamilyResolver (nix: content-addressed).
type plainAdapter struct{ name string }

func (a *plainAdapter) Name() string                    { return a.name }
func (a *plainAdapter) ValidateObjectPath(string) error { return nil }
func (a *plainAdapter) GenerateIndexes(context.Context, domain.Repo, port.Storage, port.RepoProgress) error {
	return nil
}

// missingDeleteStorage — носитель, у которого удаление одного ключа отдаёт
// NotFound: гонка «уже нет» (параллельное удаление или хвост прошлого
// сбоя) не должна считаться сбоем прохода.
type missingDeleteStorage struct {
	*testutil.FakeStorage
	missing string
}

// failingDeleteStorage — носитель, у которого удаление одного ключа падает
// сырой ошибкой: она копится в FailedDeletes, проход не прерывается
// (следующий запуск доберёт остаток).
type failingDeleteStorage struct {
	*testutil.FakeStorage
	failing string
}

func (s *failingDeleteStorage) Delete(ctx context.Context, key string) error {
	if key == s.failing {
		return errors.New("носитель: сбой удаления")
	}
	return s.FakeStorage.Delete(ctx, key)
}

// failingAccessStore — учёт обращений, который не может ответить: давность
// неизвестна, гадать о ней и удалять «наугад» запрещено (fail-closed).
type failingAccessStore struct{ *testutil.FakeAccessStore }

func (s *failingAccessStore) AccessEntry(context.Context, string, string) (domain.ObjectAccess, error) {
	return domain.ObjectAccess{}, errors.New("каталог: сбой чтения")
}

func (s *missingDeleteStorage) Delete(ctx context.Context, key string) error {
	if key == s.missing {
		return &domain.NotFoundError{What: "объект", Key: key}
	}
	return s.FakeStorage.Delete(ctx, key)
}

// fixture — собранный на фейках движок ретеншна с одним личным репо.
type fixture struct {
	engine  *retention.Engine
	storage *testutil.FakeStorage
	access  *testutil.FakeAccessStore
	pins    *testutil.FakePinStore
	repo    domain.Repo
}

// newFixture собирает движок: часы хранилища идут шагом testStep от
// modStart, поэтому ModTime объектов — в порядке их записи (первый самый
// старый). Часы движка заморожены на testNow.
func newFixture(t *testing.T, ret domain.Retention, modStart time.Duration, adapter port.RepoAdapter) *fixture {
	t.Helper()
	storage := testutil.NewFakeStorage(testutil.SeqClock(testNow.Add(modStart), testStep))
	f := &fixture{
		storage: storage,
		access:  testutil.NewFakeAccessStore(),
		pins:    testutil.NewFakePinStore(),
		repo:    domain.Repo{ID: 1, Name: "demo", OwnerID: 1, Ecosystem: adapter.Name(), Retention: ret},
	}
	f.engine = retention.New(storage, testutil.NewFakeRepoStore(), f.access,
		map[string]port.RepoAdapter{adapter.Name(): adapter}, f.pins, testutil.FixedClock(testNow))
	return f
}

// put пишет объект репо (следующий тик часов хранилища) и возвращает ключ.
func (f *fixture) put(t *testing.T, path, body string) string {
	t.Helper()
	key := port.RepoPrefix(f.repo) + "/" + path
	w, err := f.storage.Put(context.Background(), key)
	if err != nil {
		t.Fatalf("Put(%s): %v", key, err)
	}
	if _, err := w.Write([]byte(body)); err != nil {
		t.Fatalf("Write(%s): %v", key, err)
	}
	if err := w.Commit(context.Background()); err != nil {
		t.Fatalf("Commit(%s): %v", key, err)
	}
	return key
}

// putFamily пишет объекты семейства htop в порядке убывания свежести:
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
		{Scope: domain.AccessScopeRepo, Key: key, LastAccess: at, Hits: 1},
	})
	if err != nil {
		t.Fatalf("MergeAccess(%s): %v", key, err)
	}
}

// keys репозитория по возрастанию (живой набор хранилища).
func (f *fixture) keys(t *testing.T) []string {
	t.Helper()
	var out []string
	for meta, err := range f.storage.List(context.Background(), port.RepoPrefix(f.repo)+"/") {
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		out = append(out, meta.Key)
	}
	return out
}

// requireSuffixes сверяет живой набор по хвостам ключей.
func requireSuffixes(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("в хранилище %d объектов, хочу %d: %v", len(got), len(want), got)
	}
	for i, w := range want {
		if !strings.HasSuffix(got[i], w) {
			t.Fatalf("объект %d = %s, хочу хвост %s (все: %v)", i, got[i], w, got)
		}
	}
}

// Печать/ошибки типов: хелперы для ассертов результата.

func requireCounts(t *testing.T, res retention.Result, want retention.Result) {
	t.Helper()
	if res != want {
		t.Fatalf("Result = %+v, хочу %+v", res, want)
	}
}

// TestApplyDisabledPolicy — политика выключена (MinVersions=0): проход
// ничего не делает и не ошибка (текущее поведение — репо растёт в
// пределах квоты).
func TestApplyDisabledPolicy(t *testing.T) {
	f := newFixture(t, domain.Retention{}, testOld, &familyAdapter{name: "apt"})
	f.putFamily(t, "htop_1.0_amd64.deb", "htop_1.1_amd64.deb", "htop_1.2_amd64.deb")
	f.put(t, "dists/stable/Release", "release")

	res, err := f.engine.Apply(context.Background(), f.repo, false)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	requireCounts(t, res, retention.Result{DryRun: false})
	requireSuffixes(t, f.keys(t), "dists/stable/Release", "htop_1.0_amd64.deb", "htop_1.1_amd64.deb", "htop_1.2_amd64.deb")
}

// TestApplyUnsupportedEcosystem — адаптер без FamilyResolver (nix):
// честная UnsupportedError, а не молчаливый no-op (иначе политика «работает
// вхолостую» незаметно).
func TestApplyUnsupportedEcosystem(t *testing.T) {
	f := newFixture(t, domain.Retention{MinVersions: 3, MaxAgeDays: 90}, testOld, &plainAdapter{name: "nix"})
	f.putFamily(t, "htop_1.0_amd64.deb", "htop_1.1_amd64.deb", "htop_1.2_amd64.deb", "htop_1.3_amd64.deb")

	res, err := f.engine.Apply(context.Background(), f.repo, false)
	var unsupported *domain.UnsupportedError
	if !errors.As(err, &unsupported) {
		t.Fatalf("Apply = %v, хочу *domain.UnsupportedError", err)
	}
	requireCounts(t, res, retention.Result{})
	if len(f.keys(t)) != 4 {
		t.Fatalf("проход тронул хранилище: %v", f.keys(t))
	}
}

// TestApplyDropsOldestVersions — ядро политики: семейство из 5 версий,
// MinVersions=3, MaxAge=90; две старейшие (вне топ-3 и старше окна) удалены,
// топ-3 живы (ProtectedByMin=3). Индексы вне семейств не считаются
// кандидатами, но входят в ObjectsScanned. Обращений нет ни у одной
// версии — возраст считается от ModTime (бутстрап).
func TestApplyDropsOldestVersions(t *testing.T) {
	f := newFixture(t, domain.Retention{MinVersions: 3, MaxAgeDays: 90}, testOld, &familyAdapter{name: "apt"})
	keys := f.putFamily(t, "htop_1.0_amd64.deb", "htop_1.1_amd64.deb", "htop_1.2_amd64.deb", "htop_1.3_amd64.deb", "htop_1.4_amd64.deb")
	f.put(t, "dists/stable/Release", "release")

	res, err := f.engine.Apply(context.Background(), f.repo, false)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	requireCounts(t, res, retention.Result{
		Families:          1,
		ObjectsScanned:    6,
		Candidates:        2,
		Deleted:           2,
		BytesFreed:        3, // тела «x» и «xx» двух старейших
		ProtectedByMin:    3,
		ProtectedByAccess: 0,
		ProtectedByPin:    0,
	})
	requireSuffixes(t, f.keys(t), "dists/stable/Release", keys[2], keys[3], keys[4])
}

// TestApplyFreshAccessProtectsOldVersion — обращённая версия жива, даже
// не попав в топ-3 (версированный апстрим: клиент тянет старую версию),
// а её соседка без обращений того же возраста удаляется.
func TestApplyFreshAccessProtectsOldVersion(t *testing.T) {
	f := newFixture(t, domain.Retention{MinVersions: 3, MaxAgeDays: 90}, testOld, &familyAdapter{name: "apt"})
	keys := f.putFamily(t, "htop_1.0_amd64.deb", "htop_1.1_amd64.deb", "htop_1.2_amd64.deb", "htop_1.3_amd64.deb", "htop_1.4_amd64.deb")
	f.touch(t, keys[0], testNow.Add(-24*time.Hour)) // самая старая — обращались вчера

	res, err := f.engine.Apply(context.Background(), f.repo, false)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	requireCounts(t, res, retention.Result{
		Families:          1,
		ObjectsScanned:    5,
		Candidates:        1,
		Deleted:           1,
		BytesFreed:        2, // тело «xx» удалённой htop_1.1
		ProtectedByMin:    3,
		ProtectedByAccess: 1,
	})
	requireSuffixes(t, f.keys(t), keys[0], keys[2], keys[3], keys[4])
}

// TestApplyPinProtects — пин держит версию при прочих условиях удаления
// (старая, без обращений, вне топ-N).
func TestApplyPinProtects(t *testing.T) {
	f := newFixture(t, domain.Retention{MinVersions: 3, MaxAgeDays: 90}, testOld, &familyAdapter{name: "apt"})
	keys := f.putFamily(t, "htop_1.0_amd64.deb", "htop_1.1_amd64.deb", "htop_1.2_amd64.deb", "htop_1.3_amd64.deb", "htop_1.4_amd64.deb")
	if err := f.pins.SetPin(context.Background(), f.repo.ID, keys[0], true); err != nil {
		t.Fatalf("SetPin: %v", err)
	}

	res, err := f.engine.Apply(context.Background(), f.repo, false)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	requireCounts(t, res, retention.Result{
		Families:       1,
		ObjectsScanned: 5,
		Candidates:     1,
		Deleted:        1,
		BytesFreed:     2,
		ProtectedByMin: 3,
		ProtectedByPin: 1,
	})
	requireSuffixes(t, f.keys(t), keys[0], keys[2], keys[3], keys[4])
}

// TestApplyDryRun — dry-run считает кандидатов, ничего не удаляя: ревизия
// перед чисткой должна быть честной (счётчики те же, что у боевого прохода).
func TestApplyDryRun(t *testing.T) {
	f := newFixture(t, domain.Retention{MinVersions: 3, MaxAgeDays: 90}, testOld, &familyAdapter{name: "apt"})
	keys := f.putFamily(t, "htop_1.0_amd64.deb", "htop_1.1_amd64.deb", "htop_1.2_amd64.deb", "htop_1.3_amd64.deb", "htop_1.4_amd64.deb")

	res, err := f.engine.Apply(context.Background(), f.repo, true)
	if err != nil {
		t.Fatalf("Apply(dry-run): %v", err)
	}
	requireCounts(t, res, retention.Result{
		DryRun:         true,
		Families:       1,
		ObjectsScanned: 5,
		Candidates:     2,
		ProtectedByMin: 3,
	})
	requireSuffixes(t, f.keys(t), keys[0], keys[1], keys[2], keys[3], keys[4])
}

// TestApplyKeepNOnlyIgnoresAge — MaxAgeDays=0: возраст не смотрится, живёт
// ровно топ-N (те же свежие версии, что в тесте выше, при MaxAge=90
// остались бы «обращёнными» по бутстрапу: ModTime внутри окна).
func TestApplyKeepNOnlyIgnoresAge(t *testing.T) {
	names := []string{"htop_1.0_amd64.deb", "htop_1.1_amd64.deb", "htop_1.2_amd64.deb", "htop_1.3_amd64.deb", "htop_1.4_amd64.deb"}

	f := newFixture(t, domain.Retention{MinVersions: 3}, testNear, &familyAdapter{name: "apt"})
	keys := f.putFamily(t, names...)
	res, err := f.engine.Apply(context.Background(), f.repo, false)
	if err != nil {
		t.Fatalf("Apply(keep-N): %v", err)
	}
	requireCounts(t, res, retention.Result{
		Families:       1,
		ObjectsScanned: 5,
		Candidates:     2,
		Deleted:        2,
		BytesFreed:     3,
		ProtectedByMin: 3,
	})
	requireSuffixes(t, f.keys(t), keys[2], keys[3], keys[4])

	// Тот же набор с MaxAge=90: свежие (внутри окна) версии вне топ-N
	// защищены бутстрапом ModTime — удалений нет.
	g := newFixture(t, domain.Retention{MinVersions: 3, MaxAgeDays: 90}, testNear, &familyAdapter{name: "apt"})
	g.putFamily(t, names...)
	res, err = g.engine.Apply(context.Background(), g.repo, false)
	if err != nil {
		t.Fatalf("Apply(age): %v", err)
	}
	requireCounts(t, res, retention.Result{
		Families:          1,
		ObjectsScanned:    5,
		ProtectedByMin:    3,
		ProtectedByAccess: 2,
	})
	if len(g.keys(t)) != 5 {
		t.Fatalf("окно возраста не защитило свежие версии: %v", g.keys(t))
	}
}

// TestApplyNotFoundDeleteNotFailure — NotFound от носителя («уже нет») не
// сбой: Deleted считает реально удалённые, FailedDeletes остаётся нулём.
func TestApplyNotFoundDeleteNotFailure(t *testing.T) {
	f := newFixture(t, domain.Retention{MinVersions: 3, MaxAgeDays: 90}, testOld, &familyAdapter{name: "apt"})
	keys := f.putFamily(t, "htop_1.0_amd64.deb", "htop_1.1_amd64.deb", "htop_1.2_amd64.deb", "htop_1.3_amd64.deb", "htop_1.4_amd64.deb")
	engine := retention.New(&missingDeleteStorage{FakeStorage: f.storage, missing: keys[0]},
		testutil.NewFakeRepoStore(), f.access, map[string]port.RepoAdapter{"apt": &familyAdapter{name: "apt"}},
		f.pins, testutil.FixedClock(testNow))

	res, err := engine.Apply(context.Background(), f.repo, false)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	requireCounts(t, res, retention.Result{
		Families:       1,
		ObjectsScanned: 5,
		Candidates:     2,
		Deleted:        1,
		FailedDeletes:  0,
		BytesFreed:     2,
		ProtectedByMin: 3,
	})
	requireSuffixes(t, f.keys(t), keys[0], keys[2], keys[3], keys[4])
}

// TestApplyHookAndUnknownEcosystem — хук OnApply получает итог И ошибку
// прохода (метрики 171 вешаются сюда), а отсутствие адаптера экосистемы —
// та же честная UnsupportedError, что и отсутствие резолвера.
func TestApplyHookAndUnknownEcosystem(t *testing.T) {
	f := newFixture(t, domain.Retention{MinVersions: 3, MaxAgeDays: 90}, testOld, &familyAdapter{name: "apt"})
	f.putFamily(t, "htop_1.0_amd64.deb", "htop_1.1_amd64.deb", "htop_1.2_amd64.deb", "htop_1.3_amd64.deb")

	var gotRes retention.Result
	var gotErr error
	calls := 0
	engine := retention.New(f.storage, testutil.NewFakeRepoStore(), f.access, nil, f.pins, testutil.FixedClock(testNow))
	engine.OnApply = func(res retention.Result, err error) {
		calls++
		gotRes, gotErr = res, err
	}
	res, err := engine.Apply(context.Background(), f.repo, false)
	var unsupported *domain.UnsupportedError
	if !errors.As(err, &unsupported) {
		t.Fatalf("Apply без адаптера = %v, хочу *domain.UnsupportedError", err)
	}
	if calls != 1 || gotRes != res || !errors.Is(gotErr, err) {
		t.Fatalf("OnApply: вызовов %d, res %+v, err %v; хочу один вызов с итогом и ошибкой", calls, gotRes, gotErr)
	}
}

// TestApplySmallFamilyAllProtected — версий меньше MinVersions: топ-N
// покрывает семейство целиком, кандидатов нет (политика не «удаляет
// лишнее» из маленьких семейств).
func TestApplySmallFamilyAllProtected(t *testing.T) {
	f := newFixture(t, domain.Retention{MinVersions: 5, MaxAgeDays: 90}, testOld, &familyAdapter{name: "apt"})
	keys := f.putFamily(t, "htop_1.0_amd64.deb", "htop_1.1_amd64.deb")

	res, err := f.engine.Apply(context.Background(), f.repo, false)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	requireCounts(t, res, retention.Result{Families: 1, ObjectsScanned: 2, ProtectedByMin: 2})
	requireSuffixes(t, f.keys(t), keys[0], keys[1])
}

// TestApplyDeleteFailureCounted — сырая ошибка носителя на одном кандидате:
// FailedDeletes растёт, второй кандидат удаляется, проход не прерывается.
func TestApplyDeleteFailureCounted(t *testing.T) {
	f := newFixture(t, domain.Retention{MinVersions: 3, MaxAgeDays: 90}, testOld, &familyAdapter{name: "apt"})
	keys := f.putFamily(t, "htop_1.0_amd64.deb", "htop_1.1_amd64.deb", "htop_1.2_amd64.deb", "htop_1.3_amd64.deb", "htop_1.4_amd64.deb")
	engine := retention.New(&failingDeleteStorage{FakeStorage: f.storage, failing: keys[0]},
		testutil.NewFakeRepoStore(), f.access, map[string]port.RepoAdapter{"apt": &familyAdapter{name: "apt"}},
		f.pins, testutil.FixedClock(testNow))

	res, err := engine.Apply(context.Background(), f.repo, false)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	requireCounts(t, res, retention.Result{
		Families:       1,
		ObjectsScanned: 5,
		Candidates:     2,
		Deleted:        1,
		FailedDeletes:  1,
		BytesFreed:     2,
		ProtectedByMin: 3,
	})
	requireSuffixes(t, f.keys(t), keys[0], keys[2], keys[3], keys[4])
}

// TestApplyAccessErrorFailsClosed — сбой чтения обращений: проход падает
// с ошибкой и НИЧЕГО не удаляет (давность неизвестна — удаление «наугад»
// недопустимо), в отличие от NotFound, который означает бутстрап.
func TestApplyAccessErrorFailsClosed(t *testing.T) {
	f := newFixture(t, domain.Retention{MinVersions: 3, MaxAgeDays: 90}, testOld, &familyAdapter{name: "apt"})
	keys := f.putFamily(t, "htop_1.0_amd64.deb", "htop_1.1_amd64.deb", "htop_1.2_amd64.deb", "htop_1.3_amd64.deb", "htop_1.4_amd64.deb")
	engine := retention.New(f.storage, testutil.NewFakeRepoStore(), &failingAccessStore{f.access},
		map[string]port.RepoAdapter{"apt": &familyAdapter{name: "apt"}}, f.pins, testutil.FixedClock(testNow))

	if _, err := engine.Apply(context.Background(), f.repo, false); err == nil {
		t.Fatal("Apply со сбоем чтения обращений = nil, хочу ошибку (fail-closed)")
	}
	requireSuffixes(t, f.keys(t), keys[0], keys[1], keys[2], keys[3], keys[4])
}
