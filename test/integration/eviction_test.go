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

// E2E авто-очистки старого кеша pull-through прокси (eviction, волна
// «Eviction кеш-прокси», сессии 197–203) на живой сборке компонентов, как
// в wireApp: sqlite-каталог (remotes с политикой 0014 + object_access),
// fs-хранилище, движок кеша, накопитель обращений и движок eviction с
// периодическим проходом, оба HTTP-роутера. Юниты волны покрывают слои в
// изоляции — здесь ловится склейка: обращение → БД → защита версии,
// проход политики → удаление из storage, честный MISS с перекачкой.
//
// Сквозной критерий волны: после прохода кеш отдаёт защищённые версии без
// похода в upstream, удалённая версия при обращении прозрачно
// перекачивается (MISS, «самолечение» — главный аргумент отказа от
// парсинга индексов), обращение к старой версии до прохода продлевает ей
// жизнь. Интервалы инжектятся конфигом теста (100мс у флаша обращений и у
// периода прохода): суточный проход не ждётся (урок сессии 78).
// «Старость» версии создаётся фактом носителя (Chtimes на −100 суток), а
// не ожиданием. Сессия 204.

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "khrazhevnik/internal/mod/db/sqlite"
	_ "khrazhevnik/internal/mod/ecosystem/apt"
	_ "khrazhevnik/internal/mod/storage/fs"

	"khrazhevnik/internal/core/config"
	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/engine/accesskeeper"
	"khrazhevnik/internal/core/engine/auth"
	cacheengine "khrazhevnik/internal/core/engine/cache"
	"khrazhevnik/internal/core/engine/eviction"
	"khrazhevnik/internal/core/metrics"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/core/registry"
	"khrazhevnik/internal/core/web"
	"khrazhevnik/internal/testutil"
)

// evictionVersions — три версии одного пакета в одном каталоге пула:
// семейство eviction у apt — каталог pool/<component>/<l>/<имя>
// (CacheObjectFamily, сессия 199), поэтому версии обязаны лежать рядом.
var evictionVersions = []string{"1.0-1", "2.0-1", "3.0-1"}

// evictionUpstream — фейковый apt-upstream: три .deb одного пакета htop в
// одном pool-каталоге и счётчик обращений по путям. Счётчик именно
// попутный: метаданные (Release/Packages) адаптер на прямом запросе .deb
// не тянет, а «HIT без похода в upstream» проверяется по своему пути.
type evictionUpstream struct {
	mu   sync.Mutex
	hits map[string]int
	body map[string][]byte
	srv  *httptest.Server
}

func newEvictionUpstream(t *testing.T, vers []string) *evictionUpstream {
	t.Helper()
	u := &evictionUpstream{hits: make(map[string]int), body: make(map[string][]byte, len(vers))}
	for _, ver := range vers {
		u.body[evictionUpstreamPath(ver)] = []byte("DEB-" + ver + "-padding-padding-padding-padding-padding!!")
	}
	u.srv = httptest.NewServer(http.HandlerFunc(u.serve))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *evictionUpstream) serve(w http.ResponseWriter, r *http.Request) {
	body, ok := u.body[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	u.mu.Lock()
	u.hits[r.URL.Path]++
	u.mu.Unlock()
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(body)
}

// count — сколько раз путь запрошен у upstream.
func (u *evictionUpstream) count(path string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.hits[path]
}

// evictionEcoPath — экосистемный путь версии: pool/<component>/<l>/<имя>.
// Из него адаптер собирает StorageKey (cache/apt/<id> плюс этот путь,
// apt.go:154) и UpstreamPath.
func evictionEcoPath(ver string) string {
	return "/pool/main/h/htop/htop_" + ver + "_amd64.deb"
}

// evictionUpstreamBase — база BaseURL remote: <srv>/debian. Адаптер
// собирает UpstreamURL как base_url + UpstreamPath, поэтому сервер видит
// /debian/pool/... — не то же самое, что клиентский /apt/<remote>/pool/...
// (раскладка сервера — как у образца apt_proxy_test).
const evictionUpstreamBase = "/debian"

// evictionUpstreamPath — путь версии, которым её видит upstream-сервер:
// база плюс экосистемный путь. Расхождение базы = 404 на первом же GET.
func evictionUpstreamPath(ver string) string {
	return evictionUpstreamBase + evictionEcoPath(ver)
}

// evictionStorageKey — ключ объекта в едином namespace хранения; он же
// ключ object_access (публичный роутер фиксирует HIT по Meta.Key, который
// eviction перечисляет листингом). Путь кеша — без базы upstream: он идёт
// от UpstreamPath.
func evictionStorageKey(remoteID int64, ver string) string {
	return fmt.Sprintf("cache/apt/%d/pool/main/h/htop/htop_%s_amd64.deb", remoteID, ver)
}

// evictionProxyPath — клиентский путь публичного роутера: /<eco>/<remote>/
// плюс экосистемный путь без ведущего «/» (роут /{eco}/*).
func evictionProxyPath(remoteName, ver string) string {
	return "/apt/" + remoteName + evictionEcoPath(ver)
}

// evictionEnv — live-сервер с реальным каталогом, fs-хранилищем, движком
// кеша, накопителем обращений и движком eviction. storeDir и clock
// выставлены наружу ради белых вставок (ModTime файлов, прямой опрос
// object_access) — прецедент retentionEnv/storageGCEnv.
type evictionEnv struct {
	srv      *web.Server
	public   string
	admin    string
	storeDir string
	catalog  *registry.CatalogSet
	clock    *testutil.ManualClock
	keeper   *accesskeeper.Keeper
	runner   *eviction.Runner
}

// newEvictionEnv собирает окружение. defMin/defMax — глобальный дефолт
// конфига [eviction] (tri-state: remote без политики наследует его);
// interval — период периодического прохода (0s — выключен: сценарий
// дёргает API, фон не гоняется с проверками). Часы — замороженное «сейчас»:
// политика сравнивает давность с now (часы движка).
func newEvictionEnv(t *testing.T, defMin, defMax int, interval string) *evictionEnv {
	t.Helper()
	dir := t.TempDir()
	storeDir := filepath.Join(dir, "store")
	publicAddr := freePort(t)
	adminAddr := freePort(t)
	tomlCfg := fmt.Sprintf(`[server]
public_listen = %q
admin_listen = %q

[storage]
access_flush_interval = "100ms"

[storage.fs]
path = %q

[database]
dsn = %q

[auth]
jwt_secret = "integration-secret-integration-secret-0123"

[eviction]
interval = %q
min_versions = %d
max_age_days = %d
`, publicAddr, adminAddr, filepath.ToSlash(storeDir), filepath.ToSlash(filepath.Join(dir, "khrazhevnik.db")),
		interval, defMin, defMax)
	confPath := filepath.Join(dir, "khrazhevnik.toml")
	if err := os.WriteFile(confPath, []byte(tomlCfg), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(confPath, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	storageFactory, err := registry.Storage(cfg.Storage.Driver)
	if err != nil {
		t.Fatal(err)
	}
	dbFactory, err := registry.DB(cfg.Database.Driver)
	if err != nil {
		t.Fatal(err)
	}
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
	clock := testutil.NewManualClock(time.Now())
	authService, err := auth.New(auth.Config{
		Users: catalog.Users, Tokens: catalog.Tokens, Audit: catalog.Audit, Revocations: catalog.Revocations,
		Clock: clock, Rand: testutil.FixedRand("99999999-9999-4999-8999-999999999999"),
		JWTSecret: cfg.Auth.JWTSecret, SessionTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	cacheEngine := cacheengine.New(storage, catalog.ObjIndex, testutil.StaticDoerFactory{Doer: http.DefaultClient}, clock, cacheengine.Config{}, metrics.NewCache())
	// Ecosystems — как в wireApp: карта имён адаптеров, которой публичный
	// роутер резолвит remote прокси-пути по префиксу экосистемы.
	ecosystems := map[string]port.Ecosystem{}
	for _, name := range registry.Ecosystems() {
		factory, err := registry.Ecosystem(name)
		if err != nil {
			continue
		}
		adapter, err := factory(config.Ecosystem{}, registry.EcosystemDeps{Remotes: catalog.Remotes, Clock: clock})
		if err != nil {
			continue
		}
		ecosystems[name] = adapter
	}
	tasks := web.NewTaskRegistry(4, clock, nil)
	// accesskeeper — тот же путь фиксации, что в wire: интервал из
	// конфига теста, хранилище — таблица обращений каталога.
	keeper := accesskeeper.New(catalog.Access, clock, cfg.Storage.AccessFlushInterval.Duration)
	// Адаптеры репо — те же, что у publish/retention: семейства кеш-путей
	// резолвит CacheFamilyResolver генератора экосистемы (сессия 199).
	adapters := wireRepoAdaptersForTest(nil, clock)
	evictionEngine := eviction.New(storage, catalog.Access, adapters, clock,
		domain.Retention{MinVersions: cfg.Eviction.MinVersions, MaxAgeDays: cfg.Eviction.MaxAgeDays})
	// Периодический проход — только при interval > 0 (как в wireEviction):
	// сценарии с ручным API не должны ловить фоновый тик.
	var runner *eviction.Runner
	if cfg.Eviction.Interval.Duration > 0 {
		runner = eviction.NewRunner(evictionEngine, catalog.Remotes, cfg.Eviction.Interval.Duration)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := &web.Server{
		PublicAddr: publicAddr,
		PublicHandler: web.BuildPublicRouter(web.Deps{
			Log: log, Version: "test", Cache: cacheEngine, Ecosystems: ecosystems,
			Storage: storage, Repos: catalog.Repos, AccessRecorder: keeper,
		}),
		AdminAddr: adminAddr,
		AdminHandler: web.BuildAdminRouter(web.Deps{
			Log: log, Version: "test", Auth: authService, Cache: cacheEngine,
			Ecosystems: ecosystems, Remotes: catalog.Remotes, Repos: catalog.Repos,
			Storage: storage, Audit: catalog.Audit, Tasks: tasks, Clock: clock,
			Eviction: evictionAPITest{engine: evictionEngine},
		}),
		Log:             log,
		ShutdownTimeout: 10 * time.Second,
		WaitTasks:       tasks.WaitAll,
	}
	return &evictionEnv{
		srv: srv, public: publicAddr, admin: adminAddr, storeDir: storeDir,
		catalog: &catalog, clock: clock, keeper: keeper, runner: runner,
	}
}

// start поднимает сервер, мёрж обращений и (если он собран конфигом)
// периодический проход; stop (общий с ретеншн-сьюитом) гасит их той же
// отменой и ждёт выхода сервера.
func (env *evictionEnv) start(t *testing.T) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- env.srv.Run(ctx) }()
	waitHealthy(t, "http://"+env.admin+"/healthz")
	env.keeper.Run(ctx)
	if env.runner != nil {
		env.runner.Run(ctx)
	}
	return cancel, done
}

// TestEvictionEndToEnd — сквозной сценарий волны: наполнение кеша прокси
// тремя версиями пакета → бэкдейт → проход политики {2,30} → старейшая
// версия удалена из storage, две живы и отдаются HIT'ом без похода в
// upstream, а удалённая при обращении прозрачно перекачивается (MISS, и
// объект снова в кеше — самолечение вместо 404).
func TestEvictionEndToEnd(t *testing.T) {
	up := newEvictionUpstream(t, evictionVersions)
	env := newEvictionEnv(t, 0, 0, "0s")
	cancel, done := env.start(t)
	defer cancel()
	token := setupEvictionEnvAdmin(t, env)
	remoteID := createProxyRemote(t, env, token, "debian", "apt", up.srv.URL+"/debian",
		&domain.Retention{MinVersions: 2, MaxAgeDays: 30})

	// Наполнение кеша: три версии одного семейства, каждая первым
	// обращением — MISS с загрузкой из upstream.
	fillEvictionCache(t, env, "debian", remoteID, evictionVersions)
	for _, ver := range evictionVersions {
		if n := up.count(evictionUpstreamPath(ver)); n != 1 {
			t.Fatalf("upstream-обращений к %s = %d, хочу 1 (наполнение)", ver, n)
		}
		if !storageFileExists(t, env.storeDir, evictionStorageKey(remoteID, ver)) {
			t.Fatalf("Fetch не создал объект кеша %s", evictionStorageKey(remoteID, ver))
		}
	}
	wantKey := evictionStorageKey(remoteID, evictionVersions[0])

	runEvictionApply(t, env, token, remoteID)

	// Старейшая удалена, защищённый топ-2 на месте.
	if storageFileExists(t, env.storeDir, wantKey) {
		t.Fatalf("проход не удалил кандидата v1 (%s)", wantKey)
	}
	for _, ver := range evictionVersions[1:] {
		if !storageFileExists(t, env.storeDir, evictionStorageKey(remoteID, ver)) {
			t.Errorf("проход удалил защищённую версию v%s", ver)
		}
	}

	// Живые версии — HIT из кеша: upstream по этим путям не дёргается.
	for _, ver := range evictionVersions[1:] {
		status, _, xcache := getProxy(t, env, "debian", ver)
		if status != http.StatusOK || xcache != "HIT" {
			t.Errorf("GET живой v%s = %d/%q, хочу 200/HIT", ver, status, xcache)
		}
		if n := up.count(evictionUpstreamPath(ver)); n != 1 {
			t.Errorf("HIT v%s сходил в upstream (обращений %d, хочу 1)", ver, n)
		}
	}

	// Удалённая версия — прозрачный MISS с перекачкой: клиент не видит
	// 404, тело byte-exact, объект снова в кеше (самолечение).
	status, body, xcache := getProxy(t, env, "debian", evictionVersions[0])
	if status != http.StatusOK || xcache != "MISS" {
		t.Fatalf("GET удалённой v1 = %d/%q, хочу 200/MISS (прозрачная перекачка)", status, xcache)
	}
	if want := up.body[evictionUpstreamPath(evictionVersions[0])]; !bytes.Equal(body, want) {
		t.Errorf("перекачанное тело v1 = %q, хочу %q", body, want)
	}
	if n := up.count(evictionUpstreamPath(evictionVersions[0])); n != 2 {
		t.Errorf("upstream-обращений к v1 после перекачки = %d, хочу 2", n)
	}
	if !storageFileExists(t, env.storeDir, wantKey) {
		t.Errorf("перекачанная v1 не вернулась в кеш (%s)", wantKey)
	}

	stop(t, cancel, done)
}

// TestEvictionAccessProtects — обращение продлевает жизнь версии: HIT по
// старой версии до прохода фиксируется accesskeeper'ом, флаш доезжает до
// object_access, и политика {2,30} её не трогает, хотя по давности загрузки
// она кандидат.
func TestEvictionAccessProtects(t *testing.T) {
	up := newEvictionUpstream(t, evictionVersions)
	env := newEvictionEnv(t, 0, 0, "0s")
	cancel, done := env.start(t)
	defer cancel()
	token := setupEvictionEnvAdmin(t, env)
	remoteID := createProxyRemote(t, env, token, "debian", "apt", up.srv.URL+"/debian",
		&domain.Retention{MinVersions: 2, MaxAgeDays: 30})

	fillEvictionCache(t, env, "debian", remoteID, evictionVersions)

	// Обращение к старейшей версии: объект уже в кеше — HIT, и он
	// фиксируется в накопителе, а затем уезжает в object_access (100мс).
	v1Path := evictionStorageKey(remoteID, evictionVersions[0])
	if status, _, xcache := getProxy(t, env, "debian", evictionVersions[0]); status != http.StatusOK || xcache != "HIT" {
		t.Fatalf("GET v1 = %d/%q, хочу 200/HIT", status, xcache)
	}
	// Время фиксации — из port.Clock (секундная точность — как хранит
	// last_access_at).
	entry := waitCacheAccessRow(t, env, v1Path)
	if !entry.LastAccess.Equal(env.clock.Now().Truncate(time.Second)) {
		t.Errorf("last_access обращения = %s, хочу %s (время фиксации — из port.Clock)",
			entry.LastAccess, env.clock.Now().Truncate(time.Second))
	}

	runEvictionApply(t, env, token, remoteID)

	// Все три живы: топ-2 держит гарантию минимума, v1 — свежее обращение.
	for _, ver := range evictionVersions {
		if !storageFileExists(t, env.storeDir, evictionStorageKey(remoteID, ver)) {
			t.Errorf("проход удалил защищённую версию v%s (топ-N или обращение)", ver)
		}
	}

	stop(t, cancel, done)
}

// TestEvictionNixUnsupported — nix content-addressed: старых версий одного
// пути не бывает, политика к нему неприменима. Проход отказывает
// UnsupportedError, кеш remote не тронут.
func TestEvictionNixUnsupported(t *testing.T) {
	env := newEvictionEnv(t, 0, 0, "0s")
	cancel, done := env.start(t)
	defer cancel()
	token := setupEvictionEnvAdmin(t, env)
	remoteID := createProxyRemote(t, env, token, "cachenix", "nix", "http://127.0.0.1:1/nix",
		&domain.Retention{MinVersions: 2, MaxAgeDays: 30})

	// Белая вставка: объект в кеше nix-remote — проход обязан его пощадить.
	key := fmt.Sprintf("cache/nix/%d/nix-cache-info", remoteID)
	writeStorageFile(t, env.storeDir, key, []byte("StoreDir: /nix/store\n"))

	resp := post(t, fmt.Sprintf("http://%s/api/v1/remotes/%d/eviction/apply", env.admin, remoteID), "", token, 202)
	var out map[string]string
	if err := json.Unmarshal(resp, &out); err != nil {
		t.Fatal(err)
	}
	if out["task_id"] == "" {
		t.Fatalf("202 без task_id: %s", resp)
	}
	state, errText := waitTaskFinal(t, env.admin, token, out["task_id"])
	if state != "failed" {
		t.Fatalf("задача nix-remote = %q, хочу failed (UnsupportedError)", state)
	}
	if !strings.Contains(errText, "nix") {
		t.Errorf("ошибка задачи %q, хочу упоминание nix (UnsupportedError)", errText)
	}
	if !storageFileExists(t, env.storeDir, key) {
		t.Errorf("проход тронул кеш nix-remote: %s исчез", key)
	}

	stop(t, cancel, done)
}

// TestEvictionInheritedDefault — tri-state сквозь конфиг: remote без
// политики наследует глобальный дефолт [eviction] {2,30}, и проход
// периодического runner'а чистит кеш (связка конфиг → движок).
func TestEvictionInheritedDefault(t *testing.T) {
	up := newEvictionUpstream(t, evictionVersions)
	env := newEvictionEnv(t, 2, 30, "100ms")
	cancel, done := env.start(t)
	defer cancel()
	token := setupEvictionEnvAdmin(t, env)
	// Политики в теле нет — remote наследует глобальный дефолт.
	remoteID := createProxyRemote(t, env, token, "debian", "apt", up.srv.URL+"/debian", nil)

	fillEvictionCache(t, env, "debian", remoteID, evictionVersions)

	// Проход (тик 100мс) чистит по унаследованной политике: старейшая
	// удаляется, защищённый топ-2 остаётся.
	waitCacheFileGone(t, env, evictionStorageKey(remoteID, evictionVersions[0]))
	for _, ver := range evictionVersions[1:] {
		if !storageFileExists(t, env.storeDir, evictionStorageKey(remoteID, ver)) {
			t.Errorf("проход удалил защищённую версию v%s", ver)
		}
	}

	stop(t, cancel, done)
}

// evictionAPITest — копия cmd.evictionWebAPI для интеграционного теста:
// обёртка eviction.Engine под web.EvictionAPI (web не импортирует
// engine-пакеты — depguard; срез склеивается в wire, в тесте — здесь).
type evictionAPITest struct {
	engine *eviction.Engine
}

func (a evictionAPITest) Preview(ctx context.Context, remote domain.Remote) (web.EvictionPreview, error) {
	res, reports, err := a.engine.Preview(ctx, remote)
	if err != nil {
		return web.EvictionPreview{}, err
	}
	out := web.EvictionPreview{Totals: evictionTotalsTest(res), Candidates: make([]web.EvictionCandidate, 0, len(reports))}
	for _, rep := range reports {
		out.Candidates = append(out.Candidates, web.EvictionCandidate{
			Key: rep.Key, Family: rep.Family, Size: rep.Size,
			ModTime: rep.ModTime, LastAccess: rep.LastAccess, ProtectedBy: rep.ProtectedBy,
		})
	}
	return out, nil
}

func (a evictionAPITest) Apply(ctx context.Context, remote domain.Remote) (web.EvictionTotals, error) {
	res, err := a.engine.Apply(ctx, remote, false)
	return evictionTotalsTest(res), err
}

// evictionTotalsTest переводит счётчики прохода в web-представление
// (Duration — секундами: гистограмма и JSON живут в одной шкале).
func evictionTotalsTest(res eviction.Result) web.EvictionTotals {
	return web.EvictionTotals{
		DryRun: res.DryRun, DurationSeconds: res.Duration.Seconds(),
		Families: res.Families, ObjectsScanned: res.ObjectsScanned,
		Candidates: res.Candidates, Deleted: res.Deleted,
		FailedDeletes: res.FailedDeletes, BytesFreed: res.BytesFreed,
		ProtectedByMin: res.ProtectedByMin, ProtectedByAccess: res.ProtectedByAccess,
	}
}

// setupEvictionEnvAdmin создаёт первого админа и логинится — общий
// пролог сценариев волны.
func setupEvictionEnvAdmin(t *testing.T, env *evictionEnv) string {
	t.Helper()
	post(t, "http://"+env.admin+"/api/v1/setup", `{"username":"admin","password":"password"}`, "", 201)
	return login(t, env.admin, "admin", "password")
}

// fillEvictionCache наполняет кеш remote версиями пакета: три версии
// одного семейства, каждая первым обращением — MISS с загрузкой из
// upstream. Порядок vers — старшинство по ModTime (v1 самый старый … v3
// самый свежий): топ-2 семейства считает ModTime, а «старше 30 суток»
// обязан быть факт носителя — версии старятся на −100 суток (backdate).
func fillEvictionCache(t *testing.T, env *evictionEnv, remoteName string, remoteID int64, vers []string) {
	t.Helper()
	for _, ver := range vers {
		status, _, xcache := getProxy(t, env, remoteName, ver)
		if status != http.StatusOK {
			t.Fatalf("GET %s = %d, хочу 200", ver, status)
		}
		if xcache != "MISS" {
			t.Fatalf("GET %s X-Cache = %q, хочу MISS (кеш пуст)", ver, xcache)
		}
	}
	backdateCacheVersions(t, env, remoteID, vers)
}

// createProxyRemote создаёт proxy-remote (mode=proxy — обязателен:
// eviction держит инвариант proxy-only САМ и на зеркале молчит). policy
// == nil — поля eviction в теле нет: remote наследует глобальный дефолт
// конфига [eviction].
func createProxyRemote(t *testing.T, env *evictionEnv, token, name, eco, baseURL string, policy *domain.Retention) int64 {
	t.Helper()
	body := fmt.Sprintf(`{"name":%q,"ecosystem":%q,"base_url":%q,"mode":"proxy","enabled":true`, name, eco, baseURL)
	if policy != nil {
		body += fmt.Sprintf(`,"eviction":{"min_versions":%d,"max_age_days":%d}`, policy.MinVersions, policy.MaxAgeDays)
	}
	body += `}`
	resp := post(t, "http://"+env.admin+"/api/v1/remotes", body, token, 201)
	var created map[string]any
	if err := json.Unmarshal(resp, &created); err != nil {
		t.Fatal(err)
	}
	return int64(created["id"].(float64))
}

// getProxy — GET объекта через публичный порт (:29202): статус, тело и
// исход кеша (X-Cache). Путь проверяется от клиентской стороны, а не от
// внутреннего ключа хранилища.
func getProxy(t *testing.T, env *evictionEnv, remoteName, ver string) (int, []byte, string) {
	t.Helper()
	resp, err := http.Get("http://" + env.public + evictionProxyPath(remoteName, ver))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body, resp.Header.Get("X-Cache")
}

// runEvictionApply дёргает боевой проход (POST /remotes/{id}/eviction/apply)
// и ждёт задачу по id из 202-ответа: label «remote-<id>» повторяется между
// вызовами — поллинг списка поймал бы прошлую задачу.
func runEvictionApply(t *testing.T, env *evictionEnv, token string, remoteID int64) {
	t.Helper()
	resp := post(t, fmt.Sprintf("http://%s/api/v1/remotes/%d/eviction/apply", env.admin, remoteID), "", token, 202)
	var out map[string]string
	if err := json.Unmarshal(resp, &out); err != nil {
		t.Fatal(err)
	}
	if out["task_id"] == "" {
		t.Fatalf("202 без task_id: %s", resp)
	}
	waitTaskByID(t, env.admin, token, out["task_id"])
}

// waitTaskFinal ждёт завершения задачи и отдаёт её исход и текст ошибки
// (исход «failed» — ожидаемый, поэтому отдельно от waitTaskByID).
func waitTaskFinal(t *testing.T, adminAddr, token, id string) (string, string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		body := get(t, "http://"+adminAddr+"/api/v1/tasks/"+id, token, 200)
		var task map[string]any
		if err := json.Unmarshal(body, &task); err != nil {
			t.Fatal(err)
		}
		switch task["state"] {
		case "succeeded", "failed":
			errText, _ := task["error"].(string)
			return task["state"].(string), errText
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("задача %s не завершилась за 5с", id)
	return "", ""
}

// backdateCacheVersions старит версии на 100 суток, сохраняя порядок
// (v1 — самая старая … v3 — самая свежая). «Старше 30 суток» — факт
// носителя: без строки обращений давность считается от ModTime.
func backdateCacheVersions(t *testing.T, env *evictionEnv, remoteID int64, vers []string) {
	t.Helper()
	base := env.clock.Now().Add(-100 * 24 * time.Hour)
	for i, ver := range vers {
		ageStorageFile(t, env.storeDir, evictionStorageKey(remoteID, ver), base.Add(time.Duration(i)*time.Hour))
	}
}

// waitCacheAccessRow ждёт, пока обращение доедет до object_access в скоупе
// кеша (прецедент waitAccessRow ретеншна, скоуп другой): фиксация в
// памяти → строка в БД → включение политики. Иначе проход мог бы обогнать
// флаш накопителя и удалить версию как «без обращений».
func waitCacheAccessRow(t *testing.T, env *evictionEnv, key string) domain.ObjectAccess {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		entry, err := env.catalog.Access.AccessEntry(context.Background(), domain.AccessScopeCache, key)
		if err == nil {
			return entry
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("обращение к %s не доехало до object_access за 5с", key)
	return domain.ObjectAccess{}
}

// waitCacheFileGone ждёт удаления объекта периодическим проходом: тик
// асинхронный (100мс) с бюджетом 5с.
func waitCacheFileGone(t *testing.T, env *evictionEnv, key string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !storageFileExists(t, env.storeDir, key) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("объект %s не удалён проходом за 5с", key)
}
