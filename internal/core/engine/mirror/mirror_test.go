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
	"bytes"
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

// recordingProgress — собирает кадры и логи для проверок.
type recordingProgress struct {
	mu      sync.Mutex
	updates []progressFrame
	logs    []string
}

type progressFrame struct {
	phase     string
	current   string
	processed int64
	total     int64
}

func (p *recordingProgress) Update(phase, current string, processed, total int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.updates = append(p.updates, progressFrame{phase, current, processed, total})
}

func (p *recordingProgress) Log(line string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.logs = append(p.logs, line)
}

func (p *recordingProgress) logCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.logs)
}

// miniRepo — httptest-сервер с предзаполненной map файлов и счётчиком
// запросов по путям. deb-контент — байты из map.
type miniRepo struct {
	mu       sync.Mutex
	files    map[string][]byte
	perPath  map[string]*atomic.Int64
	failPath map[string]bool
	server   *httptest.Server
}

func newMiniRepo(files map[string][]byte) *miniRepo {
	r := &miniRepo{
		files:    files,
		perPath:  map[string]*atomic.Int64{},
		failPath: map[string]bool{},
	}
	r.server = httptest.NewServer(r)
	return r
}

func (r *miniRepo) Close() { r.server.Close() }

func (r *miniRepo) URL() string { return r.server.URL }

func (r *miniRepo) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	counter, ok := r.perPath[req.URL.Path]
	if !ok {
		counter = &atomic.Int64{}
		r.perPath[req.URL.Path] = counter
	}
	fail := r.failPath[req.URL.Path]
	body, found := r.files[req.URL.Path]
	r.mu.Unlock()
	counter.Add(1)
	if fail {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if !found {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("ETag", `"`+req.URL.Path+`"`)
	_, _ = w.Write(body)
}

func (r *miniRepo) count(path string) int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.perPath[path]; ok {
		return c.Load()
	}
	return 0
}

func (r *miniRepo) setFail(path string, fail bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failPath[path] = fail
}

// mirrorEnv — собранное окружение зеркала с FakeEcosystem.
type mirrorEnv struct {
	mirror  *Engine
	cache   *cacheengine.Engine
	storage *testutil.FakeStorage
	jobs    *testutil.FakeJobStore
	remotes *testutil.FakeRemoteStore
	eco     port.Ecosystem
	clock   *testutil.ManualClock
	repo    *miniRepo
	remote  domain.Remote
}

// newMirrorEnv собирает зеркало над FakeEcosystem с двумя пакетами.
// enumerate отдаёт пути /t/testrepo/pkg/a.deb и /t/testrepo/pkg/b.deb;
// upstream отдаёт их тела. Это тестирует движок зеркала (worker pool,
// retry, resume), а не apt-парсер — он покрыт в mod/ecosystem/apt.
func newMirrorEnv(t *testing.T) *mirrorEnv {
	t.Helper()
	// remote.Name = "pkg" так, чтобы после FakeEcosystem.Resolve
	// upstream-путь = "/pkg/a.deb" (Classify матчит /pkg/* → immutable).
	// mirror.Sync соберёт ecoPath = "/t/pkg" + "/a.deb" = "/t/pkg/a.deb",
	// Resolve даст rest = "pkg/a.deb", upstreamPath = "/pkg/a.deb".
	// UpstreamURL = base + "/pkg/a.deb" → серверный Path = "/pkg/a.deb".
	files := map[string][]byte{
		"/pkg/a.deb": []byte("deb-bytes-a"),
		"/pkg/b.deb": []byte("deb-bytes-b"),
	}
	repo := newMiniRepo(files)
	t.Cleanup(repo.Close)
	clock := testutil.NewManualClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC))
	storage := testutil.NewFakeStorage(clock)
	index := testutil.NewFakeObjectIndex()
	m := metrics.NewCache()
	remotes := testutil.NewFakeRemoteStore()
	remote, err := remotes.CreateRemote(context.Background(), domain.Remote{
		Name: "pkg", Ecosystem: "t", BaseURL: repo.URL(),
		Mode: domain.ModeMirror, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	eco := testutil.FakeEcosystem{
		NameOf: "t", Base: repo.URL(), MutableTTL: time.Minute,
		// EnumeratePaths — upstream-пути (после Resolve они станут
		// "/pkg/a.deb" и "/pkg/b.deb", без remote-name: mirror.Sync
		// сам добавит "pkg" в ecoPath, Resolve уберёт его в rest).
		EnumeratePaths: []string{"/a.deb", "/b.deb"},
	}
	cache := cacheengine.New(storage, index, repo.server.Client(), clock,
		cacheengine.Config{StaleIfError: true, NegativeTTL404: 5 * time.Minute, NegativeTTL5xx: 30 * time.Second}, m)
	jobs := testutil.NewFakeJobStore()
	mir := New(Config{Workers: 2, RetryMax: 2, ProgressInterval: 10 * time.Millisecond}, cache, storage, index, remotes, jobs, clock,
		map[string]port.Ecosystem{"t": eco})
	return &mirrorEnv{
		mirror: mir, cache: cache, storage: storage, jobs: jobs, remotes: remotes,
		eco: eco, clock: clock, repo: repo, remote: remote,
	}
}

func TestSyncFullThenEmptyDiff(t *testing.T) {
	env := newMirrorEnv(t)
	p := &recordingProgress{}

	// первый sync: 2 пакета скачиваются
	if err := env.mirror.Sync(context.Background(), env.remote, p); err != nil {
		t.Fatalf("первый Sync: %v\nлоги:\n%s", err, strings.Join(p.logs, "\n"))
	}
	// оба deb в хранилище (FakeEcosystem.Resolve: StorageKey =
	// cache/t/<rest-lower>, rest = "pkg/a.deb" → cache/t/pkg/a.deb)
	for _, key := range []string{
		"cache/t/pkg/a.deb",
		"cache/t/pkg/b.deb",
	} {
		if _, err := env.storage.Stat(context.Background(), key); err != nil {
			t.Errorf("объект %q отсутствует после sync: %v", key, err)
		}
	}
	if got := env.repo.count("/pkg/a.deb"); got != 1 {
		t.Errorf("upstream a.deb получил %d запросов, хочу 1", got)
	}

	// второй sync: diff пуст, 0 скачиваний
	p2 := &recordingProgress{}
	if err := env.mirror.Sync(context.Background(), env.remote, p2); err != nil {
		t.Fatalf("второй Sync: %v", err)
	}
	if got := env.repo.count("/pkg/a.deb"); got != 1 {
		t.Errorf("повторный sync дёрнул upstream: %d, хочу 1 (diff пуст)", got)
	}
	// sync_jobs помечен succeeded
	job, err := env.jobs.Job(context.Background(), jobIDForRemote(env, env.remote.ID))
	if err != nil {
		t.Fatalf("Job: %v", err)
	}
	if job.State != domain.StateSucceeded {
		t.Errorf("sync_jobs.state = %q, хочу succeeded", job.State)
	}
}

func TestSyncResumeAfterPartialFailure(t *testing.T) {
	env := newMirrorEnv(t)
	// первый deb падает 500 — sync падает на ошибке, второй не скачан
	env.repo.setFail("/pkg/a.deb", true)
	p := &recordingProgress{}
	err := env.mirror.Sync(context.Background(), env.remote, p)
	if err == nil {
		t.Fatal("sync с падающим upstream должен вернуть ошибку")
	}
	// чиним upstream и пересинкаем — хвост дочитается. Часы сдвигаем
	// мимо NegativeTTL5xx (30с), иначе cache отдаёт negative-кеш 500
	// без похода upstream — это корректное поведение прокси, не баг sync.
	env.repo.setFail("/pkg/a.deb", false)
	env.clock.Advance(31 * time.Second)
	p2 := &recordingProgress{}
	if err := env.mirror.Sync(context.Background(), env.remote, p2); err != nil {
		t.Fatalf("повторный Sync после починки: %v", err)
	}
	// теперь оба в хранилище
	key1 := "cache/t/pkg/a.deb"
	if _, err := env.storage.Stat(context.Background(), key1); err != nil {
		t.Errorf("после re-sync a.deb отсутствует: %v", err)
	}
}

func TestSyncCancelStopsWorkers(t *testing.T) {
	env := newMirrorEnv(t)
	// сделаем upstream медленным: deb отдаётся после сигнала
	release := make(chan struct{})
	slowFiles := map[string][]byte{
		"/pkg/a.deb": []byte("deb-a"),
		"/pkg/b.deb": []byte("deb-b"),
	}
	env.repo.server.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".deb") {
			<-release
		}
		w.Header().Set("ETag", `"`+r.URL.Path+`"`)
		_, _ = w.Write(slowFiles[r.URL.Path])
	}))
	defer srv.Close()
	// обновим remote на новый URL
	env.remote.BaseURL = srv.URL
	if err := env.remotes.UpdateRemote(context.Background(), env.remote); err != nil {
		t.Fatal(err)
	}
	// ttl кеша remotes 30с — сдвинем часы вперёд, чтобы адаптер перечитал
	env.clock.Advance(31 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	p := &recordingProgress{}
	done := make(chan error, 1)
	go func() {
		done <- env.mirror.Sync(ctx, env.remote, p)
	}()
	// дадим enumerate пройти (метаданные отдаются быстро), затем отменим
	time.Sleep(100 * time.Millisecond)
	cancel()
	err := <-done
	if err == nil {
		t.Fatal("отменённый sync должен вернуть ошибку")
	}
	// отпустим горутины upstream, чтобы shutdown не висел
	close(release)
}

// TestSyncStreamingLimiterBigObject — тело 3×burst проходит sync
// без ошибок, полоса соблюдается в процессе скачивания (потоковый
// лимитер, аудит 2026-08-27): burst байт уходит мгновенно, хвост
// 2×burst растягивается на ≈2×burst/полосу.
func TestSyncStreamingLimiterBigObject(t *testing.T) {
	const bandwidth = 4096
	body := bytes.Repeat([]byte("x"), 3*bandwidth)
	files := map[string][]byte{"/pkg/big.deb": body}
	repo := newMiniRepo(files)
	t.Cleanup(repo.Close)
	clock := testutil.NewManualClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC))
	storage := testutil.NewFakeStorage(clock)
	index := testutil.NewFakeObjectIndex()
	remotes := testutil.NewFakeRemoteStore()
	remote, err := remotes.CreateRemote(context.Background(), domain.Remote{
		Name: "pkg", Ecosystem: "t", BaseURL: repo.URL(),
		Mode: domain.ModeMirror, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	eco := testutil.FakeEcosystem{
		NameOf: "t", Base: repo.URL(), MutableTTL: time.Minute,
		EnumeratePaths: []string{"/big.deb"},
	}
	cache := cacheengine.New(storage, index, repo.server.Client(), clock,
		cacheengine.Config{StaleIfError: true}, metrics.NewCache())
	jobs := testutil.NewFakeJobStore()
	mir := New(Config{
		Workers: 1, RetryMax: 1, MaxBandwidth: bandwidth,
		ProgressInterval: 10 * time.Millisecond,
	}, cache, storage, index, remotes, jobs, clock, map[string]port.Ecosystem{"t": eco})

	start := time.Now()
	if err := mir.Sync(context.Background(), remote, &recordingProgress{}); err != nil {
		t.Fatalf("sync объекта 3×burst не должен падать: %v", err)
	}
	elapsed := time.Since(start)
	// burst (4096) мгновенно, хвост 8192 байта по полосе 4096 Б/с ≈ 2с.
	// Допуск: нижний — 1.2с (частичная оплата могла произойти до замера),
	// верхний — 6с (медленный CI).
	if elapsed < 1200*time.Millisecond {
		t.Errorf("sync прошёл за %v — полоса не соблюдалась (ожидался ≥1.2с)", elapsed)
	}
	if elapsed > 6*time.Second {
		t.Errorf("sync затянулся: %v (ожидалось ≈2с)", elapsed)
	}
	if got := repo.count("/pkg/big.deb"); got != 1 {
		t.Errorf("upstream получил %d запросов, хочу 1 (ретраев быть не должно)", got)
	}
	if _, err := storage.Stat(context.Background(), "cache/t/pkg/big.deb"); err != nil {
		t.Errorf("объект отсутствует после sync: %v", err)
	}
}

// TestRecoverInterruptedJobs — рестарт процесса с sync_job в running:
// recovery помечает её failed с причиной «interrupted by restart»,
// прочие состояния не трогает.
func TestRecoverInterruptedJobs(t *testing.T) {
	env := newMirrorEnv(t)
	jobs := env.jobs
	running, err := jobs.CreateJob(context.Background(), domain.SyncJob{
		RemoteID: 1, State: domain.StateRunning, Cursor: "files=3;bytes=100",
	})
	if err != nil {
		t.Fatal(err)
	}
	succeeded, err := jobs.CreateJob(context.Background(), domain.SyncJob{
		RemoteID: 2, State: domain.StateSucceeded,
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, err := jobs.CreateJob(context.Background(), domain.SyncJob{
		RemoteID: 3, State: domain.StatePending,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := env.mirror.RecoverInterruptedJobs(context.Background()); err != nil {
		t.Fatalf("RecoverInterruptedJobs: %v", err)
	}

	j1, err := jobs.Job(context.Background(), running.ID)
	if err != nil {
		t.Fatal(err)
	}
	if j1.State != domain.StateFailed {
		t.Errorf("running → %q, хочу failed", j1.State)
	}
	if !strings.Contains(j1.Cursor, interruptedReason) {
		t.Errorf("cursor = %q, хочу причину %q", j1.Cursor, interruptedReason)
	}
	j2, err := jobs.Job(context.Background(), succeeded.ID)
	if err != nil {
		t.Fatal(err)
	}
	if j2.State != domain.StateSucceeded {
		t.Errorf("succeeded → %q, восстановление не должно трогать", j2.State)
	}
	j3, err := jobs.Job(context.Background(), pending.ID)
	if err != nil {
		t.Fatal(err)
	}
	if j3.State != domain.StatePending {
		t.Errorf("pending → %q, восстановление не должно трогать", j3.State)
	}
}

// TestSyncCancelWritesFinalJobState — отмена sync (shutdown, стоп
// remote) всё равно записывает финальный статус в sync_jobs: финальный
// UpdateJob идёт с context.Background(), а не с отменённым ctx.
func TestSyncCancelWritesFinalJobState(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".deb") {
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
		Name: "pkg", Ecosystem: "t", BaseURL: srv.URL, Mode: domain.ModeMirror, Enabled: true,
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
	jobs := testutil.NewFakeJobStore()
	mir := New(Config{Workers: 1, RetryMax: 0, ProgressInterval: 10 * time.Millisecond},
		cache, storage, index, remotes, jobs, clock, map[string]port.Ecosystem{"t": eco})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- mir.Sync(ctx, remote, &recordingProgress{}) }()
	// дождаться download-фазы (upstream блокирует), затем отменить
	time.Sleep(100 * time.Millisecond)
	cancel()
	if err := <-done; err == nil {
		t.Fatal("отменённый sync должен вернуть ошибку")
	}

	jobsList, jerr := jobs.Jobs(context.Background())
	if jerr != nil || len(jobsList) == 0 {
		t.Fatalf("sync_jobs не записан: %v", jerr)
	}
	if jobsList[0].State != domain.StateFailed {
		t.Errorf("sync_jobs.state = %q, хочу failed (финальный статус после отмены)", jobsList[0].State)
	}
}

// TestSyncStaleStormIsNotFailure — массовый stale при сбойном upstream
// и прогретом кеше: sync успешен, stale-пути считаются отдельно и не
// растят ErrorThreshold (аудит 2026-08-27).
func TestSyncStaleStormIsNotFailure(t *testing.T) {
	// remote.Name = "idx": upstream-путь /idx/a.db попадает в mutable-
	// ветку Classify фейка — stale-serve работает только для mutable.
	files := map[string][]byte{"/idx/a.db": []byte("meta-1")}
	repo := newMiniRepo(files)
	t.Cleanup(repo.Close)
	clock := testutil.NewManualClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC))
	storage := testutil.NewFakeStorage(clock)
	index := testutil.NewFakeObjectIndex()
	remotes := testutil.NewFakeRemoteStore()
	remote, err := remotes.CreateRemote(context.Background(), domain.Remote{
		Name: "idx", Ecosystem: "t", BaseURL: repo.URL(),
		Mode: domain.ModeMirror, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	eco := testutil.FakeEcosystem{
		NameOf: "t", Base: repo.URL(),
		MutableTTL:     50 * time.Millisecond,
		EnumeratePaths: []string{"/a.db"},
	}
	cache := cacheengine.New(storage, index, repo.server.Client(), clock,
		cacheengine.Config{StaleIfError: true, NegativeTTL5xx: 30 * time.Second}, metrics.NewCache())
	jobs := testutil.NewFakeJobStore()
	mir := New(Config{Workers: 1, RetryMax: 2, ProgressInterval: 10 * time.Millisecond},
		cache, storage, index, remotes, jobs, clock, map[string]port.Ecosystem{"t": eco})

	// прогрев: метаданные скачаны, кеш годен
	if err := mir.Sync(context.Background(), remote, &recordingProgress{}); err != nil {
		t.Fatalf("первый sync (прогрев): %v", err)
	}
	// upstream падает, TTL истекает: ревалидация получает 500,
	// но stale-копия в кеше есть
	repo.setFail("/idx/a.db", true)
	clock.Advance(31 * time.Second)

	p2 := &recordingProgress{}
	if err := mir.Sync(context.Background(), remote, p2); err != nil {
		t.Fatalf("stale-шторм не должен ронять sync: %v\nлоги:\n%s", err, strings.Join(p2.logs, "\n"))
	}
	joined := strings.Join(p2.logs, "\n")
	if !strings.Contains(joined, "stale 1") {
		t.Errorf("лог не содержит счётчик stale:\n%s", joined)
	}
	job, jerr := jobs.Job(context.Background(), jobIDForRemote(&mirrorEnv{jobs: jobs}, remote.ID))
	if jerr != nil {
		t.Fatalf("Job: %v", jerr)
	}
	if job.State != domain.StateSucceeded {
		t.Errorf("sync_jobs.state = %q, хочу succeeded", job.State)
	}
	// ровно один поход upstream во втором sync: stale не ретрится
	if got := repo.count("/idx/a.db"); got != 2 {
		t.Errorf("upstream получил %d запросов, хочу 2 (прогрев + ревалидация)", got)
	}
}

// TestSyncSkipsFreshMutable — mutable, свежий по TTL и полный по байтам
// (индекс → BytesKey), не перекачивается каждый sync: diff по индексу.
func TestSyncSkipsFreshMutable(t *testing.T) {
	// remote.Name = "idx": upstream-путь /idx/a.db попадает в mutable-
	// ветку Classify фейка
	files := map[string][]byte{"/idx/a.db": []byte("meta-1")}
	repo := newMiniRepo(files)
	t.Cleanup(repo.Close)
	clock := testutil.NewManualClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC))
	storage := testutil.NewFakeStorage(clock)
	index := testutil.NewFakeObjectIndex()
	remotes := testutil.NewFakeRemoteStore()
	remote, err := remotes.CreateRemote(context.Background(), domain.Remote{
		Name: "idx", Ecosystem: "t", BaseURL: repo.URL(),
		Mode: domain.ModeMirror, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	eco := testutil.FakeEcosystem{
		NameOf: "t", Base: repo.URL(),
		MutableTTL:     time.Minute,
		EnumeratePaths: []string{"/a.db"},
	}
	cache := cacheengine.New(storage, index, repo.server.Client(), clock,
		cacheengine.Config{StaleIfError: true}, metrics.NewCache())
	mir := New(Config{Workers: 1},
		cache, storage, index, remotes, testutil.NewFakeJobStore(), clock,
		map[string]port.Ecosystem{"t": eco})

	if err := mir.Sync(context.Background(), remote, &recordingProgress{}); err != nil {
		t.Fatalf("первый sync: %v", err)
	}
	p2 := &recordingProgress{}
	if err := mir.Sync(context.Background(), remote, p2); err != nil {
		t.Fatalf("второй sync: %v", err)
	}
	// свежий mutable пропущен: upstream не дёрган
	if got := repo.count("/idx/a.db"); got != 1 {
		t.Errorf("upstream получил %d запросов, хочу 1 (свежий mutable не перекачивается)", got)
	}
	joined := strings.Join(p2.logs, "\n")
	if !strings.Contains(joined, "нечего скачивать") {
		t.Errorf("второй sync должен пропустить всё:\n%s", joined)
	}
}

// TestSyncSkipsGarbagePaths — мусорные пути enumerate (не маппятся /
// не классифицируются) не молча теряются: счётчик skipped в логе задачи.
func TestSyncSkipsGarbagePaths(t *testing.T) {
	env := newMirrorEnv(t)
	// у фейка живой путь только /a.deb; второй — мусор (не Resolve'ится
	// в классифицируемый путь)
	eco := env.eco.(testutil.FakeEcosystem)
	eco.EnumeratePaths = []string{"/a.deb", ""}
	env.mirror.ecos["t"] = eco

	p := &recordingProgress{}
	if err := env.mirror.Sync(context.Background(), env.remote, p); err != nil {
		t.Fatalf("sync с мусорным путём не должен падать: %v\nлоги:\n%s", err, strings.Join(p.logs, "\n"))
	}
	joined := strings.Join(p.logs, "\n")
	if !strings.Contains(joined, "1 пропущено") {
		t.Errorf("лог не содержит счётчик пропущенных:\n%s", joined)
	}
	if !strings.Contains(joined, "1 к скачиванию") {
		t.Errorf("лог должен показать 1 путь к скачиванию:\n%s", joined)
	}
}

// TestTopErrors — агрегат причин: сортировка по частоте, потолок n.
func TestTopErrors(t *testing.T) {
	errs := []string{
		"/a: 500", "/a: 500", "/a: 500",
		"/b: timeout", "/b: timeout",
		"/c: 404",
	}
	got := topErrors(errs, 2)
	if len(got) != 2 {
		t.Fatalf("topErrors(…, 2) = %v, хочу 2 строки", got)
	}
	if !strings.HasPrefix(got[0], "3x /a: 500") {
		t.Errorf("первая строка = %q, хочу 3x /a: 500", got[0])
	}
	if !strings.HasPrefix(got[1], "2x /b: timeout") {
		t.Errorf("вторая строка = %q, хочу 2x /b: timeout", got[1])
	}
	// потолок не срезает меньший список
	if got := topErrors([]string{"x"}, 10); len(got) != 1 || got[0] != "1x x" {
		t.Errorf("topErrors одиночной ошибки = %v", got)
	}
}

func TestSyncUnsupportedEcosystem(t *testing.T) {
	// экосистема без Enumerate (FakeEcosystem без EnumeratePaths) —
	// Sync падает с UnsupportedError, sync_jobs → failed.
	clock := testutil.NewManualClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC))
	storage := testutil.NewFakeStorage(clock)
	index := testutil.NewFakeObjectIndex()
	m := metrics.NewCache()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer up.Close()
	cache := cacheengine.New(storage, index, up.Client(), clock,
		cacheengine.Config{StaleIfError: true}, m)
	remotes := testutil.NewFakeRemoteStore()
	remote, _ := remotes.CreateRemote(context.Background(), domain.Remote{
		Name: "fake", Ecosystem: "t", BaseURL: up.URL, Mode: domain.ModeMirror, Enabled: true,
	})
	jobs := testutil.NewFakeJobStore()
	eco := testutil.FakeEcosystem{NameOf: "t", Base: up.URL, MutableTTL: time.Minute}
	mir := New(Config{Workers: 1}, cache, storage, index, remotes, jobs, clock,
		map[string]port.Ecosystem{"t": eco})
	err := mir.Sync(context.Background(), remote, &recordingProgress{})
	var uns *domain.UnsupportedError
	if !errors.As(err, &uns) {
		t.Fatalf("ожидалась *UnsupportedError, получено %v", err)
	}
	job, jerr := jobs.Job(context.Background(), jobIDForRemote(&mirrorEnv{jobs: jobs}, remote.ID))
	if jerr != nil {
		t.Fatalf("Job: %v", jerr)
	}
	if job.State != domain.StateFailed {
		t.Errorf("sync_jobs.state = %q, хочу failed", job.State)
	}
}

func TestSyncDisabledRemote(t *testing.T) {
	env := newMirrorEnv(t)
	env.remote.Enabled = false
	err := env.mirror.Sync(context.Background(), env.remote, &recordingProgress{})
	var ve *domain.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("ожидалась *ValidationError, получено %v", err)
	}
}

func TestSyncUnknownEcosystem(t *testing.T) {
	env := newMirrorEnv(t)
	env.remote.Ecosystem = "no-such"
	err := env.mirror.Sync(context.Background(), env.remote, &recordingProgress{})
	var nf *domain.NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("ожидалась *NotFoundError, получено %v", err)
	}
}

func TestSyncUpdatesSyncJobsProgress(t *testing.T) {
	env := newMirrorEnv(t)
	p := &recordingProgress{}
	if err := env.mirror.Sync(context.Background(), env.remote, p); err != nil {
		t.Fatal(err)
	}
	job, err := env.jobs.Job(context.Background(), jobIDForRemote(env, env.remote.ID))
	if err != nil {
		t.Fatalf("Job: %v", err)
	}
	if !strings.Contains(job.Cursor, "files=") || !strings.Contains(job.Cursor, "bytes=") {
		t.Errorf("cursor не кодирует прогресс: %q", job.Cursor)
	}
	if !job.LastRunAt.Equal(env.clock.Now()) {
		t.Errorf("last_run_at = %v, хочу %v", job.LastRunAt, env.clock.Now())
	}
	// прогресс-репортёр получил кадры и логи
	if p.logCount() == 0 {
		t.Error("прогресс не получил логов")
	}
}

func TestSyncLogsMentionPhases(t *testing.T) {
	env := newMirrorEnv(t)
	p := &recordingProgress{}
	if err := env.mirror.Sync(context.Background(), env.remote, p); err != nil {
		t.Fatal(err)
	}
	// проверки на содержание логов: enumerate, diff, done
	joined := strings.Join(p.logs, "\n")
	for _, want := range []string{"enumerate", "diff", "download", "успешно"} {
		if !strings.Contains(joined, want) {
			t.Errorf("логи не содержат %q; joined=%q", want, joined)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		n    int64
		want string
	}{
		{512, "512 B"},
		{2048, "2.0 KiB"},
		{1 << 20, "1.0 MiB"},
		{1 << 30, "1.0 GiB"},
	}
	for _, c := range cases {
		if got := humanBytes(c.n); got != c.want {
			t.Errorf("humanBytes(%d) = %q, хочу %q", c.n, got, c.want)
		}
	}
}

// jobIDForRemote ищет sync_job по remote_id в env.jobs.
func jobIDForRemote(env *mirrorEnv, remoteID int64) int64 {
	jobs, _ := env.jobs.Jobs(context.Background())
	for _, j := range jobs {
		if j.RemoteID == remoteID {
			return j.ID
		}
	}
	return 0
}
