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

package mirror

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	cacheengine "khrazhevnik/internal/core/engine/cache"
	"khrazhevnik/internal/core/metrics"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/testutil"
)

func TestSchedulerStartsRunnersForMirrorRemotes(t *testing.T) {
	clock := testutil.NewManualClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC))
	remotes := testutil.NewFakeRemoteStore()
	// mirror с интервалом — должен попасть в планировщик
	mirror, _ := remotes.CreateRemote(context.Background(), domain.Remote{
		Name: "m", Ecosystem: "apt", BaseURL: "http://x", Mode: domain.ModeMirror,
		Enabled: true, SyncInterval: time.Hour,
	})
	// proxy — не должен
	remotes.CreateRemote(context.Background(), domain.Remote{
		Name: "p", Ecosystem: "apt", BaseURL: "http://x", Mode: domain.ModeProxy,
		Enabled: true, SyncInterval: time.Hour,
	})
	// mirror без интервала — не должен
	remotes.CreateRemote(context.Background(), domain.Remote{
		Name: "mi", Ecosystem: "apt", BaseURL: "http://x", Mode: domain.ModeMirror,
		Enabled: true, SyncInterval: 0,
	})
	// выключенный mirror — не должен
	remotes.CreateRemote(context.Background(), domain.Remote{
		Name: "md", Ecosystem: "apt", BaseURL: "http://x", Mode: domain.ModeMirror,
		Enabled: false, SyncInterval: time.Hour,
	})

	sched := NewScheduler(nil, remotes, testutil.FixedRand("44444444-4444-4444-8444-444444444444"), clock, time.Minute)
	// сверка напрямую (без горутины): детерминированно
	sched.reconcile()
	sched.mu.Lock()
	got := len(sched.runners)
	_, ok := sched.runners[mirror.ID]
	sched.mu.Unlock()
	if got != 1 {
		t.Fatalf("runners = %d, хочу 1 (только mirror+enabled+interval)", got)
	}
	if !ok {
		t.Errorf("runner для mirror не запущен")
	}
	// остановим и убедимся, что wg сошёлся
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := sched.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

// TestSchedulerReconcilePicksUpNewRemote — remote, включённый после
// старта планировщика (admin-CRUD → Notify), начинает синхронизироваться
// без рестарта процесса.
func TestSchedulerReconcilePicksUpNewRemote(t *testing.T) {
	env := newMirrorEnv(t)
	sched := NewScheduler(env.mirror, env.remotes,
		testutil.FixedRand("44444444-4444-4444-8444-444444444444"), env.clock, 0)
	sched.tick = 20 * time.Millisecond
	sched.Start(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	defer func() { _ = sched.Stop(context.Background()) }()

	// на старте интервал нулевой → планировщик remote не берёт;
	// «админ» задаёт интервал и будит reconcile
	remote := env.remote
	remote.SyncInterval = 20 * time.Millisecond
	if err := env.remotes.UpdateRemote(ctx, remote); err != nil {
		t.Fatal(err)
	}
	sched.Notify()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if env.repo.count("/pkg/a.deb") >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := env.repo.count("/pkg/a.deb"); got == 0 {
		t.Fatal("remote, добавленный после старта, не синхронизировался")
	}
}

// failRemoteOnce — обёртка RemoteStore: первый вызов Remote(id) отдаёт
// ошибку БД (инжект транзиентного сбоя), дальше — прозрачно.
type failRemoteOnce struct {
	port.RemoteStore
	mu   sync.Mutex
	fail bool
}

func (s *failRemoteOnce) Remote(ctx context.Context, id int64) (domain.Remote, error) {
	s.mu.Lock()
	if s.fail {
		s.fail = false
		s.mu.Unlock()
		return domain.Remote{}, errors.New("db down (инжект)")
	}
	s.mu.Unlock()
	return s.RemoteStore.Remote(ctx, id)
}

// TestSchedulerRestartsDeadRunner — runner, умерший от транзиентной
// ошибки БД, перезапускается на ближайшем тике reconcile: remote не
// теряется.
func TestSchedulerRestartsDeadRunner(t *testing.T) {
	env := newMirrorEnv(t)
	remote := env.remote
	remote.SyncInterval = 30 * time.Millisecond
	if err := env.remotes.UpdateRemote(context.Background(), remote); err != nil {
		t.Fatal(err)
	}
	fr := &failRemoteOnce{RemoteStore: env.remotes, fail: true}
	sched := NewScheduler(env.mirror, fr,
		testutil.FixedRand("44444444-4444-4444-8444-444444444444"), env.clock, 0)
	sched.tick = 20 * time.Millisecond
	sched.Start(context.Background())
	defer func() { _ = sched.Stop(context.Background()) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if env.repo.count("/pkg/a.deb") >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := env.repo.count("/pkg/a.deb"); got == 0 {
		t.Fatal("умерший runner не перезапущен — sync не состоялся")
	}
	sched.mu.Lock()
	alive := len(sched.runners)
	sched.mu.Unlock()
	if alive == 0 {
		t.Error("runner не жив после перезапуска")
	}
}

// TestSchedulerForgetsRemovedRemoteState — удаление remote забывает и
// backoff-состояние умерших runner'ов: после reconcile карты deaths/
// lastDeath пусты (иначе записи жили вечно по две на каждый удалённый
// ID), а пересозданный remote с тем же ID стартует с чистым backoff,
// не с накопленным.
func TestSchedulerForgetsRemovedRemoteState(t *testing.T) {
	clock := testutil.NewManualClock(time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC))
	remotes := testutil.NewFakeRemoteStore()
	a, err := remotes.CreateRemote(context.Background(), domain.Remote{
		Name: "a", Ecosystem: "apt", BaseURL: "http://x", Mode: domain.ModeMirror,
		Enabled: true, SyncInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := remotes.CreateRemote(context.Background(), domain.Remote{
		Name: "b", Ecosystem: "apt", BaseURL: "http://x", Mode: domain.ModeMirror,
		Enabled: true, SyncInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	sched := NewScheduler(nil, remotes,
		testutil.FixedRand("44444444-4444-4444-8444-444444444444"), clock, 0)
	// сверка напрямую (без горутины): детерминированно
	sched.reconcile()
	// инжект смертей runner'ов: у a — две, у b — одна
	sched.runnerDied(a.ID, errors.New("смерть 1 (инжект)"))
	sched.runnerDied(a.ID, errors.New("смерть 2 (инжект)"))
	sched.runnerDied(b.ID, errors.New("смерть (инжект)"))
	sched.mu.Lock()
	if sched.deaths[a.ID] != 2 || sched.deaths[b.ID] != 1 {
		sched.mu.Unlock()
		t.Fatal("смерти runner'ов не зафиксированы")
	}
	sched.mu.Unlock()

	// удаляем оба remote: reconcile обязан забыть и runner'ов, и
	// backoff-состояние
	for _, id := range []int64{a.ID, b.ID} {
		if err := remotes.DeleteRemote(context.Background(), id); err != nil {
			t.Fatal(err)
		}
	}
	sched.reconcile()
	sched.mu.Lock()
	deaths, last := len(sched.deaths), len(sched.lastDeath)
	sched.mu.Unlock()
	if deaths != 0 || last != 0 {
		t.Fatalf("после reconcile: deaths=%d, lastDeath=%d — хочу пусто", deaths, last)
	}

	// пересоздание remote с тем же ID: чистый backoff — runner
	// стартует на ближайшем reconcile (ручные часы стоят: унаследованный
	// backoff не истёк бы никогда)
	reborn, err := remotes.CreateRemote(context.Background(), domain.Remote{
		ID: a.ID, Name: "a", Ecosystem: "apt", BaseURL: "http://x", Mode: domain.ModeMirror,
		Enabled: true, SyncInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	sched.reconcile()
	sched.mu.Lock()
	_, alive := sched.runners[reborn.ID]
	sched.mu.Unlock()
	if !alive {
		t.Error("пересозданный remote не стартовал — backoff не забыт")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := sched.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

// TestSchedulerStopIdempotent — повторный Stop не паникует и не висит.
func TestSchedulerStopIdempotent(t *testing.T) {
	clock := testutil.NewManualClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC))
	remotes := testutil.NewFakeRemoteStore()
	remotes.CreateRemote(context.Background(), domain.Remote{
		Name: "m", Ecosystem: "apt", BaseURL: "http://x", Mode: domain.ModeMirror,
		Enabled: true, SyncInterval: time.Hour,
	})
	sched := NewScheduler(nil, remotes,
		testutil.FixedRand("44444444-4444-4444-8444-444444444444"), clock, time.Minute)
	sched.Start(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := sched.Stop(ctx); err != nil {
		t.Fatalf("первый Stop: %v", err)
	}
	if err := sched.Stop(ctx); err != nil {
		t.Fatalf("повторный Stop: %v", err)
	}
}

// TestSchedulerStopRemoteInterruptsSync — стоп remote во время идущего
// sync прерывает sync (AfterFunc-связка stopCh с ctx) и дожидается
// горутины: runner'ов в карте нет, значит sync вернулся.
func TestSchedulerStopRemoteInterruptsSync(t *testing.T) {
	release := make(chan struct{})
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".deb") {
			hits.Add(1)
			<-release
		}
		_, _ = w.Write([]byte("x"))
	}))
	defer srv.Close()
	defer close(release)

	clock := testutil.NewManualClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC))
	storage := testutil.NewFakeStorage(clock)
	index := testutil.NewFakeObjectIndex()
	remotes := testutil.NewFakeRemoteStore()
	remote, err := remotes.CreateRemote(context.Background(), domain.Remote{
		Name: "pkg", Ecosystem: "t", BaseURL: srv.URL, Mode: domain.ModeMirror,
		Enabled: true, SyncInterval: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	eco := testutil.FakeEcosystem{
		NameOf: "t", Base: srv.URL, MutableTTL: time.Minute,
		EnumeratePaths: []string{"/a.deb"},
	}
	cache := cacheengine.New(storage, index, srv.Client(), clock,
		cacheengine.Config{StaleIfError: true}, metrics.NewCache())
	mir := New(Config{Workers: 1, RetryMax: 0, ProgressInterval: 10 * time.Millisecond},
		cache, storage, index, remotes, testutil.NewFakeJobStore(), clock,
		map[string]port.Ecosystem{"t": eco})
	sched := NewScheduler(mir, remotes,
		testutil.FixedRand("44444444-4444-4444-8444-444444444444"), clock, 0)
	sched.tick = 20 * time.Millisecond
	sched.Start(context.Background())
	defer func() { _ = sched.Stop(context.Background()) }()

	// ждём, пока sync встанет на блокирующем upstream
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if hits.Load() >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if hits.Load() == 0 {
		t.Fatal("sync не дошёл до upstream")
	}

	// выключаем remote → reconcile стопает runner с идущим sync
	remote.Enabled = false
	if err := remotes.UpdateRemote(context.Background(), remote); err != nil {
		t.Fatal(err)
	}
	sched.Notify()

	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		sched.mu.Lock()
		n := len(sched.runners)
		sched.mu.Unlock()
		if n == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	sched.mu.Lock()
	n := len(sched.runners)
	sched.mu.Unlock()
	if n != 0 {
		t.Fatalf("runners = %d после выключения remote — sync не прерван/не дожат", n)
	}
}

func TestSchedulerNextIntervalWithJitter(t *testing.T) {
	clock := testutil.NewManualClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC))
	remotes := testutil.NewFakeRemoteStore()
	sched := NewScheduler(nil, remotes,
		testutil.FixedRand("44444444-4444-4444-8444-444444444444"),
		clock, 10*time.Minute)
	r := domain.Remote{ID: 1, SyncInterval: time.Hour}
	got := sched.nextInterval(r)
	// база = 1h; jitter = 0..10m; фиксированный rand даёт конкретное
	// число из хвоста UUID. Проверяем диапазон, не конкретное значение.
	if got < time.Hour || got > time.Hour+10*time.Minute {
		t.Errorf("nextInterval = %v, хочу в [1h, 1h10m]", got)
	}
}

func TestSchedulerNextIntervalNoJitter(t *testing.T) {
	clock := testutil.NewManualClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC))
	remotes := testutil.NewFakeRemoteStore()
	sched := NewScheduler(nil, remotes, testutil.FixedRand("44444444-4444-4444-8444-444444444444"), clock, 0)
	r := domain.Remote{ID: 1, SyncInterval: time.Hour}
	if got := sched.nextInterval(r); got != time.Hour {
		t.Errorf("nextInterval без джиттера = %v, хочу 1h", got)
	}
}

func TestShouldRun(t *testing.T) {
	cases := []struct {
		name string
		r    domain.Remote
		want bool
	}{
		{"mirror+enabled+interval", domain.Remote{Mode: domain.ModeMirror, Enabled: true, SyncInterval: time.Hour}, true},
		{"proxy", domain.Remote{Mode: domain.ModeProxy, Enabled: true, SyncInterval: time.Hour}, false},
		{"disabled", domain.Remote{Mode: domain.ModeMirror, Enabled: false, SyncInterval: time.Hour}, false},
		{"no interval", domain.Remote{Mode: domain.ModeMirror, Enabled: true, SyncInterval: 0}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := shouldRun(c.r); got != c.want {
				t.Errorf("shouldRun = %v, хочу %v", got, c.want)
			}
		})
	}
}

// claimRecorder — фейк Claim/Unclaim с подсчётом вызовов (сессия 38).
type claimRecorder struct {
	mu       sync.Mutex
	busy     map[string]bool // имя → занят
	claims   atomic.Int64
	unclaims atomic.Int64
	denied   atomic.Int64
}

func newClaimRecorder() *claimRecorder {
	return &claimRecorder{busy: map[string]bool{}}
}

func (c *claimRecorder) claim(name string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.busy[name] {
		c.denied.Add(1)
		return false
	}
	c.busy[name] = true
	c.claims.Add(1)
	return true
}

func (c *claimRecorder) unclaim(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.busy, name)
	c.unclaims.Add(1)
}

// claimHeld — ручное занятие ключа имитацией ручного sync.
func (c *claimRecorder) claimHeld(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.busy[name] = true
}

// releaseHeld — ручное освобождение ключа «ручного sync» (не считается
// в unclaims тика).
func (c *claimRecorder) releaseHeld(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.busy, name)
}

func (c *claimRecorder) isBusy(name string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.busy[name]
}

// TestSchedulerTickSkipsWhenManualSyncRunning — ключ sync|<name> занят
// (ручной запуск через TaskRegistry): плановый тик не стартует второй
// sync, а молча пропускает — runner жив, debug-сообщение написано.
func TestSchedulerTickSkipsWhenManualSyncRunning(t *testing.T) {
	env := newMirrorEnv(t)
	remote := env.remote
	remote.SyncInterval = time.Hour
	if err := env.remotes.UpdateRemote(context.Background(), remote); err != nil {
		t.Fatal(err)
	}
	cr := newClaimRecorder()
	cr.claimHeld(remote.Name) // ручной sync уже забрал ключ
	sched := NewScheduler(env.mirror, env.remotes,
		testutil.FixedRand("44444444-4444-4444-8444-444444444444"), env.clock, 0)
	sched.ClaimSync = cr.claim
	sched.UnclaimSync = cr.unclaim
	var debugs atomic.Int64
	sched.DebugHook = func(string) { debugs.Add(1) }

	rn := newRunner(sched, remote)
	if !rn.tick() {
		t.Fatal("проигравший тик — skip, не смерть runner'а")
	}
	if got := env.repo.count("/pkg/a.deb"); got != 0 {
		t.Fatalf("tick дёрнул upstream (%d запросов) — дедуп не сработал", got)
	}
	if debugs.Load() == 0 {
		t.Error("пропуск тика не отражён в debug-хуке")
	}
	if cr.claims.Load() != 0 {
		t.Errorf("тик не должен занимать ключ при отказе: claims = %d", cr.claims.Load())
	}
	if cr.denied.Load() != 1 {
		t.Errorf("denied = %d, хочу 1", cr.denied.Load())
	}

	// ручной sync завершён — следующий тик проходит и занимает ключ
	cr.releaseHeld(remote.Name)
	if !rn.tick() {
		t.Fatal("второй тик после освобождения не должен убивать runner")
	}
	if got := env.repo.count("/pkg/a.deb"); got != 1 {
		t.Fatalf("после освобождения sync не состоялся: %d запросов", got)
	}
	// claimHeld не считается в claims: один успешный Claim от второго тика
	if cr.claims.Load() != 1 || cr.unclaims.Load() != 1 {
		t.Errorf("claims=%d unclaims=%d, хочу 1/1", cr.claims.Load(), cr.unclaims.Load())
	}
}

// TestSchedulerTickClaimReleasesAfterSync — ключ занимается на время
// тика и освобождается после: ручной sync, стартовавший между тиками,
// не блокируется навсегда.
func TestSchedulerTickClaimReleasesAfterSync(t *testing.T) {
	env := newMirrorEnv(t)
	remote := env.remote
	remote.SyncInterval = time.Hour
	if err := env.remotes.UpdateRemote(context.Background(), remote); err != nil {
		t.Fatal(err)
	}
	cr := newClaimRecorder()
	sched := NewScheduler(env.mirror, env.remotes,
		testutil.FixedRand("44444444-4444-4444-8444-444444444444"), env.clock, 0)
	sched.ClaimSync = cr.claim
	sched.UnclaimSync = cr.unclaim

	rn := newRunner(sched, remote)
	if !rn.tick() {
		t.Fatal("свободный remote — тик обязан пройти")
	}
	if cr.claims.Load() != 1 {
		t.Errorf("тик не занял ключ: claims = %d", cr.claims.Load())
	}
	if cr.unclaims.Load() != 1 {
		t.Errorf("ключ не освобождён после тика: unclaims = %d", cr.unclaims.Load())
	}
	if cr.isBusy(remote.Name) {
		t.Error("ключ остался занятым после тика")
	}
}

// TestSchedulerTickClaimReleasesOnSyncError — ошибка sync не держит
// ключ: Unclaim идёт defer'ом, следующий тик может попробовать снова.
func TestSchedulerTickClaimReleasesOnSyncError(t *testing.T) {
	env := newMirrorEnv(t)
	remote := env.remote
	remote.SyncInterval = time.Hour
	if err := env.remotes.UpdateRemote(context.Background(), remote); err != nil {
		t.Fatal(err)
	}
	env.repo.setFail("/pkg/a.deb", true)
	env.repo.setFail("/pkg/b.deb", true)
	// negative-кеш 5xx ещё пуст — ошибки пойдут в sync напрямую
	cr := newClaimRecorder()
	sched := NewScheduler(env.mirror, env.remotes,
		testutil.FixedRand("44444444-4444-4444-8444-444444444444"), env.clock, 0)
	sched.ClaimSync = cr.claim
	sched.UnclaimSync = cr.unclaim

	rn := newRunner(sched, remote)
	// тик с падающим upstream не убивает runner (ошибки — в sync_jobs)
	if !rn.tick() {
		t.Fatal("ошибки sync — не смерть runner'а")
	}
	if cr.unclaims.Load() != 1 {
		t.Errorf("ключ не освобождён после неудачного тика: unclaims = %d", cr.unclaims.Load())
	}
	if cr.isBusy(remote.Name) {
		t.Error("ключ остался занятым после неудачного тика")
	}
}

// TestSchedulerClaimSyncNilKeepsOldBehavior — nil-колбэк (деградация
// без реестра): тик выполняется без дедупа, существующие сценарии
// не задеты.
func TestSchedulerClaimSyncNilKeepsOldBehavior(t *testing.T) {
	env := newMirrorEnv(t)
	remote := env.remote
	remote.SyncInterval = time.Hour
	if err := env.remotes.UpdateRemote(context.Background(), remote); err != nil {
		t.Fatal(err)
	}
	sched := NewScheduler(env.mirror, env.remotes,
		testutil.FixedRand("44444444-4444-4444-8444-444444444444"), env.clock, 0)

	rn := newRunner(sched, remote)
	if !rn.tick() {
		t.Fatal("tick без ClaimSync обязан работать как раньше")
	}
	if got := env.repo.count("/pkg/a.deb"); got != 1 {
		t.Fatalf("sync без дедупа не состоялся: %d запросов", got)
	}
}

// TestSchedulerTickVsManualRace — гонка «тик и ручной стартовали
// одновременно»: обе стороны атомарно проверяют-и-занимают один ключ
// — проходит ровно одна. Пара тик+тик: один Claim, не два (второй
// тик — skip). Реальный TaskRegistry в тесте не используется:
// engine→web импорт запрещён (depguard), атомарность фейка —
// мьютексом, как в реестре.
func TestSchedulerTickVsManualRace(t *testing.T) {
	env := newMirrorEnv(t)
	remote := env.remote
	remote.SyncInterval = time.Hour
	if err := env.remotes.UpdateRemote(context.Background(), remote); err != nil {
		t.Fatal(err)
	}
	cr := newClaimRecorder()
	sched := NewScheduler(env.mirror, env.remotes,
		testutil.FixedRand("44444444-4444-4444-8444-444444444444"), env.clock, 0)
	sched.ClaimSync = cr.claim
	sched.UnclaimSync = cr.unclaim

	// два «тика» идут параллельно: в Claim проходит один, второй — skip.
	// Upstream отдаёт тела мгновенно, поэтому шлагбаум не нужен: даже
	// при быстром sync ровно один Claim засчитывается, второй либо
	// отказан, либо занял бы ключ при пустом дедупе.
	const ticks = 2
	var wg sync.WaitGroup
	var tickOK atomic.Int64
	for range ticks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rn := newRunner(sched, remote)
			if rn.tick() {
				tickOK.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := cr.claims.Load(); got != 1 {
		t.Errorf("успешных Claim = %d, хочу ровно 1 (второй тик — skip)", got)
	}
	if cr.denied.Load() != 1 {
		t.Errorf("отказанных Claim = %d, хочу 1", cr.denied.Load())
	}
	if tickOK.Load() != ticks {
		t.Errorf("живых тиков = %d, хочу %d (skip — не смерть)", tickOK.Load(), ticks)
	}
}
