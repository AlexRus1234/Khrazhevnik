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

//go:build integration

// E2E зеркало xbps (сессия 136): sync качает repodata + пакеты + .sig2
// через cache.Prefetch, повторный sync идёт по diff (Storage.Stat) без
// единого upstream-запроса. Noarch-пакет входит в оба arch-индекса, но
// скачивается один раз (дедуп Enumerate). Расхождение sha256 из индекса
// роняет sync и НЕ коммитит объект (инвариант ARCHITECTURE §4: битый
// upstream не отравляет immutable-кеш); после починки тела и истечения
// negative-окна повторный sync succeeds. Upstream — httptest-фикстура
// (образец mirror_sync_formats_test.go, волна «Зеркало-форматы»).

package integration

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"khrazhevnik/internal/core/config"
	"khrazhevnik/internal/core/engine/auth"
	cacheengine "khrazhevnik/internal/core/engine/cache"
	mirrorengine "khrazhevnik/internal/core/engine/mirror"
	"khrazhevnik/internal/core/metrics"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/core/registry"
	"khrazhevnik/internal/core/web"
	"khrazhevnik/internal/mod/ecosystem/xbps"
	"khrazhevnik/internal/testutil"
)

// Файлы мини-репо: плоский лэйаут Void — индекс в корне, пакет и его
// подпись рядом. Имена — по формуле Enumerate: Filename(pkgver, arch).
const (
	// xbpsMirrorUpPrefix — base-prefix upstream'а в тесте: адаптер видит
	// пути без него, сервер — с ним.
	xbpsMirrorUpPrefix = "/void"

	xbpsMirrorHello    = "/hello-2.12.1_1.x86_64.xbps"
	xbpsMirrorPoison   = "/poison-1.0_1.x86_64.xbps"
	xbpsMirrorNoarch   = "/python3-pip-24.2_1.noarch.xbps"
	xbpsMirrorMustache = "/Mustache-4.1_1.aarch64.xbps"
)

// xbpsMirrorUp — httptest-upstream: два arch-индекса с общим noarch,
// тела пакетов и их .sig2. Счётчик запросов по путям — для контроля
// resume-diff (повторный sync) и noarch-дедупа. Флаг poison подменяет
// тело одного пакета на несоответствующее sha256 индекса.
type xbpsMirrorUp struct {
	mu       sync.Mutex
	requests map[string]int
	total    int
	files    map[string][]byte
	poison   bool
	srv      *httptest.Server
}

func newXbpsMirrorUp(t *testing.T) *xbpsMirrorUp {
	t.Helper()
	hello := []byte("XBPS-MIRROR-HELLO-100-bytes-padding-padding-padding-padding-padding!!")
	poison := []byte("XBPS-MIRROR-POISON-100-bytes-padding-padding-padding-padding-padding!")
	noarch := []byte("XBPS-MIRROR-NOARCH-100-bytes-padding-padding-padding-padding-padding!")
	mustache := []byte("XBPS-MIRROR-MUSTACHE-100-bytes-padding-padding-padding-padding!!!")
	u := &xbpsMirrorUp{requests: map[string]int{}, files: map[string][]byte{}}
	for _, f := range []struct {
		path string
		body []byte
	}{
		{xbpsMirrorHello, hello},
		{xbpsMirrorPoison, poison},
		{xbpsMirrorNoarch, noarch},
		{xbpsMirrorMustache, mustache},
	} {
		u.files[f.path] = f.body
		u.files[f.path+".sig2"] = []byte("SIG2:" + f.path)
	}
	// pkgver в индексе — полный (<name>-<version>_<rev>): Enumerate
	// строит имя файла из pkgver+architecture, а не из ключа словаря.
	// noarch-запись дублируется в обоих arch-индексах (как у Void).
	u.files["/x86_64-repodata"] = buildTestRepoData(t, []repoDataPkg{
		{Name: "hello", Pkgver: "hello-2.12.1_1", Arch: "x86_64", SHA256: sha256Hex(hello), Size: len(hello)},
		{Name: "poison", Pkgver: "poison-1.0_1", Arch: "x86_64", SHA256: sha256Hex(poison), Size: len(poison)},
		{Name: "python3-pip", Pkgver: "python3-pip-24.2_1", Arch: "noarch", SHA256: sha256Hex(noarch), Size: len(noarch)},
	})
	u.files["/aarch64-repodata"] = buildTestRepoData(t, []repoDataPkg{
		{Name: "Mustache", Pkgver: "Mustache-4.1_1", Arch: "aarch64", SHA256: sha256Hex(mustache), Size: len(mustache)},
		{Name: "python3-pip", Pkgver: "python3-pip-24.2_1", Arch: "noarch", SHA256: sha256Hex(noarch), Size: len(noarch)},
	})
	u.srv = httptest.NewServer(http.HandlerFunc(u.serve))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *xbpsMirrorUp) serve(w http.ResponseWriter, r *http.Request) {
	// Ключи фикстуры — upstream-пути БЕЗ base-prefix `/void` (то, что
	// видит адаптер как UpstreamPath); запрос приходит с префиксом.
	key := strings.TrimPrefix(r.URL.Path, xbpsMirrorUpPrefix)
	u.mu.Lock()
	u.requests[key]++
	u.total++
	body, ok := u.files[key]
	tampered := u.poison && key == xbpsMirrorPoison
	u.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	if tampered {
		// Индекс обещает sha256 честного тела, upstream отдаёт чужое:
		// движок обязан уронить sync, не закоммитив объект.
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("XBPS-TAMPERED-PAYLOAD-DOES-NOT-MATCH-INDEX-SHA256"))
		return
	}
	if strings.HasSuffix(key, "-repodata") {
		w.Header().Set("Content-Type", "application/zstd")
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	_, _ = w.Write(body)
}

func (u *xbpsMirrorUp) hits() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.total
}

func (u *xbpsMirrorUp) pathHits(path string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.requests[path]
}

func (u *xbpsMirrorUp) setPoison(v bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.poison = v
}

func (u *xbpsMirrorUp) file(path string) []byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.files[path]
}

// xbpsMirrorEnv — in-process сервер Хражевника на реальных слушателях:
// sqlite + fs + адаптер xbps + mirror-engine за TaskRegistry, ручной
// триггер sync через admin-API. storage и clock выставлены наружу:
// сценарий битой sha256 проверяет отсутствие объекта напрямую и
// двигает ручные часы мимо negative-окна.
type xbpsMirrorEnv struct {
	t       *testing.T
	public  string
	admin   string
	token   string
	storage port.Storage
	clock   *testutil.ManualClock
	cancel  context.CancelFunc
	done    chan error
}

func newXbpsMirrorEnv(t *testing.T, up *httptest.Server) *xbpsMirrorEnv {
	t.Helper()
	dir := t.TempDir()
	confPath := filepath.Join(dir, "khrazhevnik.toml")
	publicAddr := freePort(t)
	adminAddr := freePort(t)
	tomlCfg := "[server]\n" +
		"public_listen = \"" + publicAddr + "\"\n" +
		"admin_listen = \"" + adminAddr + "\"\n\n" +
		"[storage.fs]\n" +
		"path = \"" + filepath.ToSlash(filepath.Join(dir, "store")) + "\"\n\n" +
		"[database]\n" +
		"dsn = \"" + filepath.ToSlash(filepath.Join(dir, "khrazhevnik.db")) + "\"\n\n" +
		"[auth]\n" +
		"jwt_secret = \"integration-secret-integration-secret-0123\"\n"
	if err := os.WriteFile(confPath, []byte(tomlCfg), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(confPath, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	storageFactory, _ := registry.Storage(cfg.Storage.Driver)
	dbFactory, _ := registry.DB(cfg.Database.Driver)
	storage, err := storageFactory(cfg.Storage)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := dbFactory(cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	if closer, ok := catalog.Audit.(interface{ Close() error }); ok {
		t.Cleanup(func() { _ = closer.Close() })
	}
	clock := testutil.NewManualClock(time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC))
	authService, err := auth.New(auth.Config{
		Users: catalog.Users, Tokens: catalog.Tokens, Audit: catalog.Audit, Revocations: catalog.Revocations,
		Clock: clock, Rand: testutil.FixedRand("77777777-7777-4777-8777-777777777777"),
		JWTSecret: cfg.Auth.JWTSecret, SessionTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Negative-кеш включён с продовыми TTL: битая sha256 кладёт объект
	// в negative-кеш на NegativeTTL5xx — сценарий проверяет, что это
	// окно не блокирует повторный sync навсегда.
	cacheEngine := cacheengine.New(storage, catalog.ObjIndex, up.Client(), clock,
		cacheengine.Config{StaleIfError: true, NegativeTTL404: 5 * time.Minute, NegativeTTL5xx: 30 * time.Second},
		metrics.NewCache())
	tasks := web.NewTaskRegistry(2, clock, nil)
	adapter, err := xbps.New(catalog.Remotes, clock)
	if err != nil {
		t.Fatal(err)
	}
	ecos := map[string]port.Ecosystem{xbps.Name: adapter}
	mirrorEngine := mirrorengine.New(mirrorengine.Config{Workers: 1},
		cacheEngine, storage, catalog.ObjIndex, catalog.Remotes, catalog.Jobs, clock, ecos)
	mirrorAPI := mirrorSyncerTest{engine: mirrorEngine, remotes: catalog.Remotes, tasks: tasks}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := &web.Server{
		PublicAddr:    cfg.Server.PublicListen,
		PublicHandler: web.BuildPublicRouter(web.Deps{Log: log, Version: "test", Cache: cacheEngine, Ecosystems: ecos, Storage: storage}),
		AdminAddr:     cfg.Server.AdminListen,
		AdminHandler: web.BuildAdminRouter(web.Deps{
			Log: log, Version: "test", Auth: authService,
			Remotes: catalog.Remotes, Audit: catalog.Audit,
			Tasks: tasks, Mirror: mirrorAPI, Clock: clock,
		}),
		Log:       log,
		WaitTasks: tasks.WaitAll,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	waitHealthy(t, "http://"+adminAddr+"/healthz")
	post(t, "http://"+adminAddr+"/api/v1/setup", `{"username":"admin","password":"password"}`, "", 201)
	token := login(t, adminAddr, "admin", "password")
	return &xbpsMirrorEnv{
		t: t, public: publicAddr, admin: adminAddr, token: token,
		storage: storage, clock: clock, cancel: cancel, done: done,
	}
}

func (e *xbpsMirrorEnv) stop() {
	e.cancel()
	if err := <-e.done; err != nil {
		e.t.Errorf("сервер завершился с ошибкой: %v", err)
	}
}

func (e *xbpsMirrorEnv) createRemote(body string) int64 {
	e.t.Helper()
	raw := post(e.t, "http://"+e.admin+"/api/v1/remotes", body, e.token, 201)
	var out struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		e.t.Fatalf("разбор ответа remote: %v", err)
	}
	return out.ID
}

// syncTerminal — ручной триггер sync + поллинг задачи до терминального
// состояния (бюджет 30с на медленный CI, частота 200мс). Возвращает
// state и текст ошибки.
func (e *xbpsMirrorEnv) syncTerminal(id int64) (string, string) {
	e.t.Helper()
	raw := post(e.t, "http://"+e.admin+"/api/v1/remotes/"+strconv.FormatInt(id, 10)+"/sync", "", e.token, 202)
	var out struct {
		TaskID string `json:"task_id"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		e.t.Fatalf("разбор task_id: %v", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		b := get(e.t, "http://"+e.admin+"/api/v1/tasks/"+out.TaskID, e.token, 200)
		var snap struct {
			State string `json:"state"`
			Error string `json:"error"`
		}
		if err := json.Unmarshal(b, &snap); err == nil {
			if snap.State == "succeeded" || snap.State == "failed" {
				return snap.State, snap.Error
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	e.t.Fatal("sync-задача не завершилась за 30с")
	return "", ""
}

func (e *xbpsMirrorEnv) syncSucceeded(id int64) {
	e.t.Helper()
	if state, errText := e.syncTerminal(id); state != "succeeded" {
		e.t.Fatalf("sync-задача = %q (%s), хочу succeeded", state, errText)
	}
}

// publicGet — GET к публичному порту с ассертом кода и X-Cache.
func (e *xbpsMirrorEnv) publicGet(path, wantCache string) []byte {
	e.t.Helper()
	resp, err := http.Get("http://" + e.public + path)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		e.t.Fatalf("GET %s = %d, хочу 200 (тело %s)", path, resp.StatusCode, b)
	}
	if got := resp.Header.Get("X-Cache"); got != wantCache {
		e.t.Fatalf("GET %s X-Cache = %q, хочу %q", path, got, wantCache)
	}
	return b
}

// TestMirrorSyncXbpsSingleArchAndResume — сценарии (a)/(b): sync качает
// все x86_64-пакеты, noarch и .sig2 (repodata — mutable), повторный sync
// не делает ни одного upstream-запроса (resume-diff по Stat).
func TestMirrorSyncXbpsSingleArchAndResume(t *testing.T) {
	up := newXbpsMirrorUp(t)
	env := newXbpsMirrorEnv(t, up.srv)
	defer env.stop()

	id := env.createRemote(`{"name":"void","ecosystem":"xbps","base_url":"` + up.srv.URL + `/void","mode":"mirror","enabled":true,"sync_interval":0,"include":["x86_64"]}`)
	env.syncSucceeded(id)

	// (a) все x86_64-объекты + noarch + подписи в кеше (публичный HIT =
	// объект лежит в storage; upstream для отдачи не нужен), repodata
	// закеширована как mutable.
	for _, f := range []string{
		xbpsMirrorHello, xbpsMirrorHello + ".sig2",
		xbpsMirrorPoison, xbpsMirrorPoison + ".sig2",
		xbpsMirrorNoarch, xbpsMirrorNoarch + ".sig2",
		"/x86_64-repodata",
	} {
		path := "/xbps/void" + f
		assertBody(t, path, env.publicGet(path, "HIT"), up.file(f))
	}

	// (b) повторный sync — ноль новых загрузок: diff покрыт storage,
	// свежая mutable repodata отдаётся из кеша.
	before := up.hits()
	env.syncSucceeded(id)
	if got := up.hits() - before; got != 0 {
		t.Errorf("повторный sync сделал %d upstream-запросов, хочу 0 (resume-diff)", got)
	}
}

// TestMirrorSyncXbpsMultiArchNoarchDedup — сценарий (c): общий noarch
// пакет входит в оба arch-индекса, но тело скачивается ровно один раз.
func TestMirrorSyncXbpsMultiArchNoarchDedup(t *testing.T) {
	up := newXbpsMirrorUp(t)
	env := newXbpsMirrorEnv(t, up.srv)
	defer env.stop()

	id := env.createRemote(`{"name":"void","ecosystem":"xbps","base_url":"` + up.srv.URL + `/void","mode":"mirror","enabled":true,"sync_interval":0,"include":["x86_64","aarch64"]}`)
	env.syncSucceeded(id)

	if got := up.pathHits("/python3-pip-24.2_1.noarch.xbps"); got != 1 {
		t.Errorf("noarch-тело скачано %d раз, хочу 1 (дедуп в Enumerate)", got)
	}
	for _, f := range []string{
		xbpsMirrorHello,
		xbpsMirrorNoarch,
		xbpsMirrorMustache,
		"/x86_64-repodata",
		"/aarch64-repodata",
	} {
		path := "/xbps/void" + f
		assertBody(t, path, env.publicGet(path, "HIT"), up.file(f))
	}
}

// TestMirrorSyncXbpsChecksumMismatchAborts — сценарий (d): тело пакета
// не совпадает с sha256 индекса → sync failed, объект НЕ закоммичен
// (Abort). После починки upstream и истечения negative-окна повторный
// sync succeeds — отравленный объект не блокирует зеркало навсегда.
func TestMirrorSyncXbpsChecksumMismatchAborts(t *testing.T) {
	up := newXbpsMirrorUp(t)
	env := newXbpsMirrorEnv(t, up.srv)
	defer env.stop()

	up.setPoison(true)
	id := env.createRemote(`{"name":"void","ecosystem":"xbps","base_url":"` + up.srv.URL + `/void","mode":"mirror","enabled":true,"sync_interval":0,"include":["x86_64"]}`)

	state, errText := env.syncTerminal(id)
	if state != "failed" {
		t.Fatalf("sync с битой sha256 = %q (%s), хочу failed", state, errText)
	}
	key := "cache/xbps/" + strconv.FormatInt(id, 10) + xbpsMirrorPoison
	if _, err := env.storage.Stat(context.Background(), key); err == nil {
		t.Fatalf("отравленный объект закоммичен (%s) — инвариант Abort нарушен", key)
	}

	// Починка upstream: тело снова совпадает с sha256 индекса.
	// Битый объект сидит в negative-кеше NegativeTTL5xx (30с); двигаем
	// ручные часы, иначе повторный sync вернёт ту же ошибку из кеша.
	up.setPoison(false)
	env.clock.Advance(31 * time.Second)
	env.syncSucceeded(id)

	path := "/xbps/void" + xbpsMirrorPoison
	assertBody(t, path, env.publicGet(path, "HIT"), up.file(xbpsMirrorPoison))
}
