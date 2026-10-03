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
	"strconv"
	"strings"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/engine/eviction"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/testutil"
)

// runnerFixture — движок eviction с несколькими remote в каталоге и Runner
// поверх них: у периодического прохода список remote свой (Remotes), в
// отличие от fixture движка с одним remote.
type runnerFixture struct {
	t       *testing.T
	engine  *eviction.Engine
	storage *testutil.FakeStorage
	remotes *testutil.FakeRemoteStore
	runner  *eviction.Runner
}

// newRunnerFixture собирает движок с адаптерами apt (резолвер семейств) и
// nix (без резолвера), пустым каталогом remote и Runner'ом на interval.
// Объекты кладутся «давними» (старт часов testNow+testOld): политики тестов
// считают их кандидатами. Глобальный дефолт политики выключен — тесты
// задают политику на remote явно.
func newRunnerFixture(t *testing.T, interval time.Duration) *runnerFixture {
	t.Helper()
	storage := testutil.NewFakeStorage(testutil.SeqClock(testNow.Add(testOld), testStep))
	remotes := testutil.NewFakeRemoteStore()
	engine := eviction.New(storage, testutil.NewFakeAccessStore(),
		map[string]port.RepoAdapter{"apt": &poolAdapter{name: "apt"}, "nix": &nixAdapter{name: "nix"}},
		testutil.FixedClock(testNow), domain.Retention{})
	return &runnerFixture{
		t: t, engine: engine, storage: storage, remotes: remotes,
		runner: eviction.NewRunner(engine, remotes, interval),
	}
}

// addRemote заводит remote в каталоге; ненулевой ID назначает хранилище.
func (rf *runnerFixture) addRemote(name, eco string, mode domain.RemoteMode, enabled bool, policy *domain.Retention) domain.Remote {
	rf.t.Helper()
	r, err := rf.remotes.CreateRemote(context.Background(), domain.Remote{
		Name: name, Ecosystem: eco, Mode: mode, Enabled: enabled, Eviction: policy,
	})
	if err != nil {
		rf.t.Fatalf("CreateRemote(%s): %v", name, err)
	}
	return r
}

// family кладёт версии семейства htop кеша remote в порядке убывания
// свежести: первый в списке — самый старый (ModTime растёт с каждой
// записью), он же кандидат при топ-N, меньшем числа версий.
func (rf *runnerFixture) family(remote domain.Remote, names ...string) []string {
	rf.t.Helper()
	keys := make([]string, 0, len(names))
	prefix := "cache/" + remote.Ecosystem + "/" + strconv.FormatInt(remote.ID, 10) + "/pool/main/h/htop/"
	for i, name := range names {
		key := prefix + name
		// Разные длины тел — разный BytesFreed у жертв.
		putObj(rf.t, rf.storage, key, strings.Repeat("x", i+1))
		keys = append(keys, key)
	}
	return keys
}

// TestRunnerRunOnceFiltersRemotes — проход трогает только proxy-remote с
// включённой политикой: зеркало (proxy-only), выключенный remote и remote
// без политики (наследует выключенный дефолт {0,0}) не зовут Apply вовсе.
func TestRunnerRunOnceFiltersRemotes(t *testing.T) {
	rf := newRunnerFixture(t, time.Hour)
	pol := domain.Retention{MinVersions: 2, MaxAgeDays: 90}
	on := rf.addRemote("proxy-on", "apt", domain.ModeProxy, true, &pol)
	mirror := rf.addRemote("mirror-on", "apt", domain.ModeMirror, true, &pol)
	rf.addRemote("proxy-off", "apt", domain.ModeProxy, true, nil)
	rf.addRemote("disabled", "apt", domain.ModeProxy, false, &pol)
	victims := rf.family(on, "htop_1.0_amd64.deb", "htop_1.1_amd64.deb", "htop_1.2_amd64.deb")
	mirrorKeys := rf.family(mirror, "htop_1.0_amd64.deb", "htop_1.1_amd64.deb", "htop_1.2_amd64.deb")
	var passes []string
	rf.runner.OnPass = func(name string, _ eviction.Result, _ error) {
		passes = append(passes, name)
	}

	if err := rf.runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(passes) != 1 || passes[0] != "proxy-on" {
		t.Fatalf("проходы = %v; хочу только [proxy-on] (фильтры mirror/disabled/без-политики)", passes)
	}
	alive := listKeys(t, rf.storage, "cache/apt/"+strconv.FormatInt(on.ID, 10)+"/")
	if alive[victims[0]] {
		t.Errorf("жертва %s жива: %v", victims[0], alive)
	}
	requireAlive(t, alive, victims[1], victims[2])
	if n := len(alive); n != 2 {
		t.Fatalf("в кеше remote %d объектов, хочу 2: %v", n, alive)
	}
	if got := listKeys(t, rf.storage, "cache/apt/"+strconv.FormatInt(mirror.ID, 10)+"/"); len(got) != 3 {
		t.Fatalf("mirror-remote очищен: %v", got)
	}
	mirrorAlive := listKeys(t, rf.storage, "cache/apt/"+strconv.FormatInt(mirror.ID, 10)+"/")
	requireAlive(t, mirrorAlive, mirrorKeys...)
}

// TestRunnerRunOnceRemoteErrorDoesNotStopOthers — сбой одного remote (nix:
// семейства кеш-путей не резолвятся) не стопает проход: следующий remote
// почищен, ошибка видна в OnPass и в агрегате RunOnce (молча не теряется).
func TestRunnerRunOnceRemoteErrorDoesNotStopOthers(t *testing.T) {
	rf := newRunnerFixture(t, time.Hour)
	pol := domain.Retention{MinVersions: 2, MaxAgeDays: 90}
	broken := rf.addRemote("broken", "nix", domain.ModeProxy, true, &pol)
	good := rf.addRemote("good", "apt", domain.ModeProxy, true, &pol)
	rf.family(broken, "nar_1.nar", "nar_2.nar", "nar_3.nar")
	victim := rf.family(good, "htop_1.0_amd64.deb", "htop_1.1_amd64.deb", "htop_1.2_amd64.deb")[0]
	var passes []passRow
	rf.runner.OnPass = func(name string, res eviction.Result, err error) {
		passes = append(passes, passRow{name: name, res: res, err: err})
	}

	err := rf.runner.RunOnce(context.Background())
	var unsupported *domain.UnsupportedError
	if !errors.As(err, &unsupported) {
		t.Fatalf("RunOnce = %v; хочу *domain.UnsupportedError сбойного remote", err)
	}
	if len(passes) != 2 {
		t.Fatalf("проходов %d (%+v); хочу 2 — сбойный и рабочий", len(passes), passes)
	}
	if p := passes[0]; p.name != "broken" || p.err == nil {
		t.Fatalf("проход сбойного remote = %+v; хочу ошибку", p)
	}
	if p := passes[1]; p.name != "good" || p.err != nil || p.res.Deleted != 1 {
		t.Fatalf("проход рабочего remote = %+v; хочу 1 удаление без ошибки", p)
	}
	if got := listKeys(t, rf.storage, "cache/apt/"+strconv.FormatInt(good.ID, 10)+"/"); got[victim] {
		t.Errorf("жертва %s жива после прохода: %v", victim, got)
	}
}

// passRow — запись хука OnPass: имя remote, итог и ошибка прохода.
type passRow struct {
	name string
	res  eviction.Result
	err  error
}

// TestRunnerRunOnceCancelBetweenRemotes — отмена между remote гасит проход
// на границе: следующий remote не тронут, RunOnce возвращает ctx-ошибку
// (удалённое в первом остаётся удалённым, остаток подберёт следующий проход).
func TestRunnerRunOnceCancelBetweenRemotes(t *testing.T) {
	rf := newRunnerFixture(t, time.Hour)
	pol := domain.Retention{MinVersions: 2, MaxAgeDays: 90}
	rf.addRemote("first", "apt", domain.ModeProxy, true, &pol)
	second := rf.addRemote("second", "apt", domain.ModeProxy, true, &pol)
	// Жертва во втором remote: если проход пойдёт дальше границы — исчезнет.
	victim := rf.family(second, "htop_1.0_amd64.deb", "htop_1.1_amd64.deb")[0]

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var names []string
	rf.runner.OnPass = func(name string, _ eviction.Result, _ error) {
		names = append(names, name)
		cancel() // отмена сразу после первого remote
	}

	err := rf.runner.RunOnce(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RunOnce = %v; хочу context.Canceled", err)
	}
	if len(names) != 1 || names[0] != "first" {
		t.Fatalf("проходы = %v; хочу только [first]", names)
	}
	if got := listKeys(t, rf.storage, "cache/apt/"+strconv.FormatInt(second.ID, 10)+"/"); !got[victim] {
		t.Errorf("жертва второго remote тронута после отмены: %v", got)
	}
}

// TestRunnerRunStop — тикер гоняет проход по интервалу, Stop гасит
// горутину и идемпотентен; Run с interval=0 цикл не поднимает (Stop тогда
// no-op, а не паника тикера).
func TestRunnerRunStop(t *testing.T) {
	rf := newRunnerFixture(t, 20*time.Millisecond)
	pol := domain.Retention{MinVersions: 1, MaxAgeDays: 90}
	rf.addRemote("periodic", "apt", domain.ModeProxy, true, &pol)
	passes := make(chan struct{}, 16)
	rf.runner.OnPass = func(string, eviction.Result, error) {
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
