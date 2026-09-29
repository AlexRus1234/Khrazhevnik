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
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/engine/retention"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/testutil"
)

// countingAdapter — адаптер apt с механикой 169 (семейство = каталог
// файла под pool/) и счётчиком reindex: периодический проход обязан
// перегенерировать индексы только после реальных удалений (лишняя
// генерация — лишний List и подпись).
type countingAdapter struct {
	*familyAdapter
	genCalls atomic.Int64
}

// GenerateIndexes считает вызовы reindex и пишет индексы «в никуда»:
// движок лишь делегирует, форматы — за адаптером.
func (a *countingAdapter) GenerateIndexes(context.Context, domain.Repo, port.Storage, port.RepoProgress) error {
	a.genCalls.Add(1)
	return nil
}

var (
	_ port.RepoAdapter    = (*countingAdapter)(nil)
	_ port.FamilyResolver = (*countingAdapter)(nil)
)

// runnerFixture — движок ретеншна с несколькими репо в каталоге и
// Runner поверх них: у периодического прохода список репо свой
// (Repos), в отличие от fixture движка с одним репо.
type runnerFixture struct {
	t       *testing.T
	engine  *retention.Engine
	storage *testutil.FakeStorage
	repos   *testutil.FakeRepoStore
	apt     *countingAdapter
	runner  *retention.Runner
}

// newRunnerFixture собирает движок с адаптерами apt (счётчик reindex) и
// nix (без резолвера семейств), пустым каталогом репо и Runner'ом на
// interval. Объекты кладутся «давними» (старт часов — testNow+testOld):
// политики тестов считают их кандидатами.
func newRunnerFixture(t *testing.T, interval time.Duration) *runnerFixture {
	t.Helper()
	return newRunnerFixtureAt(t, interval, testOld)
}

// newRunnerFixtureAt — то же с явным стартом часов хранилища: testNear
// даёт «свежие» версии внутри окна возраста (защита бутстрапом), testOld
// — «давние» кандидаты. Часы идут шагом testStep, так что порядок записи
// = порядок свежести; часы движка заморожены на testNow.
func newRunnerFixtureAt(t *testing.T, interval, modStart time.Duration) *runnerFixture {
	t.Helper()
	storage := testutil.NewFakeStorage(testutil.SeqClock(testNow.Add(modStart), testStep))
	apt := &countingAdapter{familyAdapter: &familyAdapter{name: "apt"}}
	repos := testutil.NewFakeRepoStore()
	engine := retention.New(storage, repos, testutil.NewFakeAccessStore(),
		map[string]port.RepoAdapter{"apt": apt, "nix": &plainAdapter{name: "nix"}},
		testutil.NewFakePinStore(), testutil.FixedClock(testNow))
	return &runnerFixture{
		t: t, engine: engine, storage: storage, repos: repos, apt: apt,
		runner: retention.NewRunner(engine, repos, interval),
	}
}

// withRepo заводит репо в каталоге. ID задаётся явно: объекты кладутся
// под его префиксом (адресация ретеншна — по ID), а порядок прохода —
// по возрастанию ID.
func (rf *runnerFixture) withRepo(id int64, name, eco string, retention domain.Retention) domain.Repo {
	rf.t.Helper()
	r, err := rf.repos.CreateRepo(context.Background(), domain.Repo{
		ID: id, Name: name, OwnerID: 1, Ecosystem: eco, Retention: retention,
	})
	if err != nil {
		rf.t.Fatalf("CreateRepo(%s): %v", name, err)
	}
	return r
}

// put кладёт объект репо (следующий тик часов хранилища) и возвращает ключ.
func (rf *runnerFixture) put(repo domain.Repo, path, body string) string {
	rf.t.Helper()
	key := port.RepoPrefix(repo) + "/" + path
	w, err := rf.storage.Put(context.Background(), key)
	if err != nil {
		rf.t.Fatalf("Put(%s): %v", key, err)
	}
	if _, err := w.Write([]byte(body)); err != nil {
		rf.t.Fatalf("Write(%s): %v", key, err)
	}
	if err := w.Commit(context.Background()); err != nil {
		rf.t.Fatalf("Commit(%s): %v", key, err)
	}
	return key
}

// family кладёт версии семейства htop репо в порядке убывания свежести:
// первый в списке — самый старый (ModTime растёт с каждой записью).
func (rf *runnerFixture) family(repo domain.Repo, names ...string) []string {
	rf.t.Helper()
	keys := make([]string, 0, len(names))
	for i, name := range names {
		// Разные длины тел — разный BytesFreed у жертв.
		keys = append(keys, rf.put(repo, "pool/main/h/htop/"+name, string(make([]byte, i+1))))
	}
	return keys
}

// keys — живой набор репо по возрастанию ключей.
func (rf *runnerFixture) keys(repo domain.Repo) []string {
	rf.t.Helper()
	var out []string
	for meta, err := range rf.storage.List(context.Background(), port.RepoPrefix(repo)+"/") {
		if err != nil {
			rf.t.Fatalf("List: %v", err)
		}
		out = append(out, meta.Key)
	}
	return out
}

// pass — запись хука OnPass: имя репо, итог и ошибка прохода.
type pass struct {
	repo string
	res  retention.Result
	err  error
}

// pass — фиксирует каждый проход по репо.
func (rf *runnerFixture) collectPasses() *[]pass {
	passes := &[]pass{}
	rf.runner.OnPass = func(name string, res retention.Result, err error) {
		*passes = append(*passes, pass{repo: name, res: res, err: err})
	}
	return passes
}

// TestRunnerRunOnceEnabledOnly — проход трогает только репо с включённой
// политикой: выключенный не зовёт Apply вовсе; reindex идёт ровно там,
// где были удаления (репо без жертв индексы не перегенерирует).
func TestRunnerRunOnceEnabledOnly(t *testing.T) {
	rf := newRunnerFixture(t, time.Hour)
	enabled := rf.withRepo(7, "enabled", "apt", domain.Retention{MinVersions: 1, MaxAgeDays: 90})
	rf.withRepo(8, "disabled", "apt", domain.Retention{})
	empty := rf.withRepo(9, "empty", "apt", domain.Retention{MinVersions: 3, MaxAgeDays: 90})
	victims := rf.family(enabled, "htop_1.0_amd64.deb", "htop_1.1_amd64.deb", "htop_1.2_amd64.deb")
	passes := rf.collectPasses()

	if err := rf.runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	// Выключенная политика в проход не попадает (репо 8), репо 9 пуст.
	if len(*passes) != 2 {
		t.Fatalf("проходов %d (%+v); хочу 2 — включённые репо 7 и 9", len(*passes), *passes)
	}
	if p := (*passes)[0]; p.repo != "enabled" || p.err != nil || p.res.Deleted != 2 {
		t.Fatalf("первый проход = %+v; хочу enabled без ошибки и 2 удаления", p)
	}
	if p := (*passes)[1]; p.repo != "empty" || p.err != nil || p.res.Deleted != 0 {
		t.Fatalf("второй проход = %+v; хочу empty без ошибки и 0 удалений", p)
	}
	if got := rf.apt.genCalls.Load(); got != 1 {
		t.Errorf("reindex вызван %d раз; хочу 1 (только после удалений)", got)
	}
	got := rf.keys(enabled)
	for _, v := range victims[:2] {
		if slices.Contains(got, v) {
			t.Errorf("жертва %s жива: %v", v, got)
		}
	}
	if !slices.Contains(got, victims[2]) {
		t.Errorf("топ-1 %s удалён: %v", victims[2], got)
	}
	if n := len(rf.keys(empty)); n != 0 {
		t.Errorf("пустой репо перестал быть пустым: %d объектов", n)
	}
}

// TestRunnerRunOnceRepoErrorDoesNotStopOthers — сбой одного репо (nix:
// семейства не резолвятся) не стопает проход: следующий репо почищен,
// ошибка видна в OnPass и в агрегате RunOnce (молча не теряется).
func TestRunnerRunOnceRepoErrorDoesNotStopOthers(t *testing.T) {
	rf := newRunnerFixture(t, time.Hour)
	rf.withRepo(6, "broken", "nix", domain.Retention{MinVersions: 3, MaxAgeDays: 90})
	good := rf.withRepo(7, "good", "apt", domain.Retention{MinVersions: 1, MaxAgeDays: 90})
	victim := rf.family(good, "htop_3.0_amd64.deb", "htop_3.1_amd64.deb")[0]
	passes := rf.collectPasses()

	err := rf.runner.RunOnce(context.Background())
	var unsupported *domain.UnsupportedError
	if !errors.As(err, &unsupported) {
		t.Fatalf("RunOnce = %v; хочу *domain.UnsupportedError сбойного репо", err)
	}
	if len(*passes) != 2 {
		t.Fatalf("проходов %d (%+v); хочу 2 — сбойный и рабочий", len(*passes), *passes)
	}
	if p := (*passes)[0]; p.repo != "broken" || p.err == nil {
		t.Fatalf("проход сбойного репо = %+v; хочу ошибку", p)
	}
	if p := (*passes)[1]; p.repo != "good" || p.err != nil || p.res.Deleted != 1 {
		t.Fatalf("проход рабочего репо = %+v; хочу 1 удаление без ошибки", p)
	}
	if got := rf.apt.genCalls.Load(); got != 1 {
		t.Errorf("reindex вызван %d раз; хочу 1", got)
	}
	if got := rf.keys(good); slices.Contains(got, victim) {
		t.Errorf("жертва %s жива после прохода: %v", victim, got)
	}
}

// TestRunnerRunOnceCancelBetweenRepos — отмена между репо гасит проход
// на границе: следующий репо не тронут, RunOnce возвращает ctx-ошибку
// (удалённое в первом репо остаётся удалённым, остаток подберёт
// следующий проход).
func TestRunnerRunOnceCancelBetweenRepos(t *testing.T) {
	rf := newRunnerFixture(t, time.Hour)
	rf.withRepo(7, "first", "apt", domain.Retention{MinVersions: 1, MaxAgeDays: 90})
	second := rf.withRepo(9, "second", "apt", domain.Retention{MinVersions: 1, MaxAgeDays: 90})
	// Жертва во втором репо: если проход пойдёт дальше границы — исчезнет.
	victim := rf.family(second, "htop_3.0_amd64.deb", "htop_3.1_amd64.deb")[0]

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var names []string
	rf.runner.OnPass = func(name string, _ retention.Result, _ error) {
		names = append(names, name)
		cancel() // отмена сразу после первого репо
	}

	err := rf.runner.RunOnce(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RunOnce = %v; хочу context.Canceled", err)
	}
	if len(names) != 1 || names[0] != "first" {
		t.Fatalf("проходы = %v; хочу только [first]", names)
	}
	if got := rf.keys(second); !slices.Contains(got, victim) {
		t.Errorf("жертва второго репо тронута после отмены: %v", got)
	}
}

// TestApplyAndReindexDryRunNoReindex — dry-run (preview API) ничего не
// удаляет и индексы не перегенерирует: перегенерировать нечего.
func TestApplyAndReindexDryRunNoReindex(t *testing.T) {
	rf := newRunnerFixture(t, time.Hour)
	repo := rf.withRepo(7, "preview", "apt", domain.Retention{MinVersions: 1, MaxAgeDays: 90})
	rf.family(repo, "htop_3.0_amd64.deb", "htop_3.1_amd64.deb")
	before := rf.keys(repo)

	res, err := rf.engine.ApplyAndReindex(context.Background(), repo, true)
	if err != nil {
		t.Fatalf("ApplyAndReindex (dry-run): %v", err)
	}
	if !res.DryRun || res.Candidates != 1 || res.Deleted != 0 {
		t.Fatalf("dry-run = %+v; хочу 1 кандидата без удалений", res)
	}
	if got := rf.apt.genCalls.Load(); got != 0 {
		t.Errorf("dry-run перегенерировал индексы: %d вызовов", got)
	}
	if got := rf.keys(repo); !slices.Equal(got, before) {
		t.Errorf("dry-run тронул хранилище: %v, было %v", got, before)
	}
}

// TestApplyAndReindexNoDeletionsNoReindex — проход без жертв (политика
// включена, но всё защищено: версии внутри окна возраста) индексы не
// перегенерирует.
func TestApplyAndReindexNoDeletionsNoReindex(t *testing.T) {
	rf := newRunnerFixtureAt(t, 0, testNear)
	repo := rf.withRepo(7, "quiet", "apt", domain.Retention{MinVersions: 1, MaxAgeDays: 90})
	// Свежие версии (старт — testNow−10 суток, окно 90): защищены
	// бутстрапом от даты загрузки, кандидатов нет.
	for i, name := range []string{"htop_3.0_amd64.deb", "htop_3.1_amd64.deb"} {
		rf.put(repo, "pool/main/h/htop/"+name, string(make([]byte, i+1)))
	}

	res, err := rf.engine.ApplyAndReindex(context.Background(), repo, false)
	if err != nil {
		t.Fatalf("ApplyAndReindex: %v", err)
	}
	if res.Deleted != 0 {
		t.Fatalf("Result = %+v; хочу 0 удалений", res)
	}
	if got := rf.apt.genCalls.Load(); got != 0 {
		t.Errorf("reindex без удалений: %d вызовов", got)
	}
}

// TestRunnerRunStop — тикер гоняет проход по интервалу, Stop гасит
// горутину и идемпотентен; Run с interval=0 цикл не поднимает (Stop
// тогда no-op, а не паника тикера).
func TestRunnerRunStop(t *testing.T) {
	rf := newRunnerFixture(t, 20*time.Millisecond)
	rf.withRepo(7, "periodic", "apt", domain.Retention{MinVersions: 1, MaxAgeDays: 90})
	passes := make(chan struct{}, 16)
	rf.runner.OnPass = func(string, retention.Result, error) {
		select {
		case passes <- struct{}{}:
		default:
		}
	}
	rf.runner.Run(context.Background())
	deadline := time.Now().Add(5 * time.Second)
	for n := 0; n < 2; {
		select {
		case <-passes:
			n++
		case <-time.After(time.Until(deadline)):
			t.Fatalf("за 5s тикер дал %d проходов, хочу ≥2", n)
		}
	}
	if err := rf.runner.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := rf.runner.Stop(context.Background()); err != nil {
		t.Fatalf("повторный Stop: %v", err)
	}

	// interval=0 — легальное «выключено»: горутины нет, Stop безвреден.
	off := newRunnerFixture(t, 0)
	off.runner.Run(context.Background())
	if err := off.runner.Stop(context.Background()); err != nil {
		t.Fatalf("Stop выключенного прохода: %v", err)
	}
}
