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

// E2E ретеншна личных репозиториев (волна «Ретеншн-политики», сессии
// 164–173) на живой сборке компонентов, как в wireApp: sqlite-каталог
// (repos + object_access + repo_pins), fs-хранилище, publish-движок,
// накопитель обращений и движок ретеншна с периодическим проходом, оба
// HTTP-роутера. Юниты волны покрывают слои в изоляции — здесь ловится
// склейка: обращение → БД → защита версии, удаление → reindex → честный
// индекс, освобождение квоты.
//
// Интервалы инжектятся конфигом теста (100мс у флаша обращений и у
// прохода политики): суточный проход не ждётся (урок сессии 78).
// «Старость» версии создаётся фактом носителя (Chtimes на −100 суток), а
// не ожиданием: свежезагруженная версия политикой не удаляется — без
// строки обращений давность считается от даты загрузки. Сессия 174.

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	publishengine "khrazhevnik/internal/core/engine/publish"
	"khrazhevnik/internal/core/engine/retention"
	"khrazhevnik/internal/core/metrics"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/core/registry"
	"khrazhevnik/internal/core/web"
	"khrazhevnik/internal/testutil"
)

// retentionVersions — пять версий одного пакета в одном каталоге пула:
// семейство ретеншна у apt — каталог pool/<component>/<l>/<имя> (сессия
// 169), поэтому версии обязаны лежать рядом.
var retentionVersions = []string{"1.0-1", "2.0-1", "3.0-1", "4.0-1", "5.0-1"}

// retentionEnv — live-сервер с реальным каталогом, fs-хранилищем,
// publish-движком, накопителем обращений и движком ретеншна. storeDir,
// catalog и clock выставлены наружу ради белых вставок (ModTime файлов,
// прямой опрос object_access) — прецедент storageGCEnv.
type retentionEnv struct {
	srv      *web.Server
	public   string
	admin    string
	storeDir string
	catalog  *registry.CatalogSet
	clock    *testutil.ManualClock
	keeper   *accesskeeper.Keeper
	runner   *retention.Runner
}

// newRetentionEnv собирает окружение с короткими интервалами фоновых
// циклов (100мс): проход политики и флаш обращений наблюдаются в
// пределах теста, а не суток. Часы — замороженное «сейчас»: политика
// сравнивает давность обращения с now, фиксированное прошлое сделало бы
// бэкдейт-версию «будущим» относительно cutoff.
func newRetentionEnv(t *testing.T) *retentionEnv {
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

[retention]
interval = "100ms"
`, publicAddr, adminAddr, filepath.ToSlash(storeDir), filepath.ToSlash(filepath.Join(dir, "khrazhevnik.db")))
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
		Clock: clock, Rand: testutil.FixedRand("88888888-8888-4888-8888-888888888888"),
		JWTSecret: cfg.Auth.JWTSecret, SessionTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	cacheEngine := cacheengine.New(storage, catalog.ObjIndex, testutil.StaticDoerFactory{Doer: http.DefaultClient}, clock, cacheengine.Config{}, metrics.NewCache())
	// Ecosystems — как в wireApp: карта имён адаптеров, по которой
	// admin-роутер гейтит ecosystem при POST/PATCH /repos.
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
	// Адаптеры репо — один набор на publish и retention: семейства и
	// индексы резолвит тот же RepoAdapter (как в wireApp).
	repoAdapters := wireRepoAdaptersForTest(nil, clock)
	publishEngine := publishengine.New(publishengine.Config{MaxObjectSize: cfg.Publish.MaxObjectSize.Bytes}, storage, catalog.Repos, clock, repoAdapters)
	publishAPI := publishSyncerTest{engine: publishEngine, repos: catalog.Repos, tasks: tasks}
	retentionEngine := retention.New(storage, catalog.Repos, catalog.Access, repoAdapters, catalog.Pins, clock)
	runner := retention.NewRunner(retentionEngine, catalog.Repos, cfg.Retention.Interval.Duration)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := &web.Server{
		PublicAddr: publicAddr,
		PublicHandler: web.BuildPublicRouter(web.Deps{
			Log: log, Version: "test", Cache: cacheEngine, Storage: storage,
			Repos: catalog.Repos, AccessRecorder: keeper,
		}),
		AdminAddr: adminAddr,
		AdminHandler: web.BuildAdminRouter(web.Deps{
			Log: log, Version: "test", Auth: authService, Cache: cacheEngine,
			Ecosystems: ecosystems, Repos: catalog.Repos, Storage: storage, Audit: catalog.Audit,
			Tasks: tasks, Publish: publishAPI, Clock: clock,
			Retention: retentionAPITest{engine: retentionEngine, pins: catalog.Pins},
		}),
		Log:             log,
		ShutdownTimeout: 10 * time.Second,
		WaitTasks:       tasks.WaitAll,
	}
	return &retentionEnv{
		srv: srv, public: publicAddr, admin: adminAddr, storeDir: storeDir,
		catalog: &catalog, clock: clock, keeper: keeper, runner: runner,
	}
}

// start поднимает сервер и оба фоновых цикла (мёрж обращений, проход
// политики); stop гасит их той же отменой и ждёт выхода сервера.
func (env *retentionEnv) start(t *testing.T) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- env.srv.Run(ctx) }()
	waitHealthy(t, "http://"+env.admin+"/healthz")
	env.keeper.Run(ctx)
	env.runner.Run(ctx)
	return cancel, done
}

func stop(t *testing.T, cancel context.CancelFunc, done <-chan error) {
	t.Helper()
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("сервер завершился с ошибкой: %v", err)
	}
}

// TestRetentionEndToEnd — сквозной проход политики {3, 90} по пяти
// версиям htop: топ-3 по свежести (v3, v4, v5) и свежее обращение к v1
// держат четыре версии, v2 — единственная жертва. Проверяются живость и
// удаление на носителе, публичная раздача (:29202), честность
// перегенерированного индекса и квота.
func TestRetentionEndToEnd(t *testing.T) {
	env := newRetentionEnv(t)
	cancel, done := env.start(t)
	defer cancel()
	token := setupRetentionEnvAdmin(t, env)
	repoID := createAptRepo(t, env, token)

	uploadVersions(t, env, token, repoID, retentionVersions)
	// Индекс первой генерации: все пять версий на месте.
	status, body := getPublicRepoFile(t, env, packagesPath)
	if status != http.StatusOK {
		t.Fatalf("GET Packages = %d, хочу 200", status)
	}
	for _, ver := range retentionVersions {
		if !strings.Contains(string(body), "Version: "+ver) {
			t.Fatalf("Packages первой генерации без версии %s", ver)
		}
	}

	// Порядок версий задан явно (v1 самый старый … v5 самый свежий):
	// паузы upload'а упорядочивают ModTime, но «старше 90 суток» обязан
	// быть факт носителя.
	backdateVersions(t, env, repoID, retentionVersions)

	// Обращение к v1 через публичный роутер: доступ → фиксация
	// accesskeeper'ом → флаш в object_access (100мс).
	v1Path := "pool/main/h/htop/" + debFileName(retentionVersions[0])
	if st, _ := getPublicRepoFile(t, env, v1Path); st != http.StatusOK {
		t.Fatalf("публичный GET v1 = %d, хочу 200", st)
	}
	// Время фиксации — из port.Clock (секундная точность — как хранит
	// last_access_at).
	entry := waitAccessRow(t, env, debStorageKey(repoID, retentionVersions[0]))
	if !entry.LastAccess.Equal(env.clock.Now().Truncate(time.Second)) {
		t.Errorf("last_access обращения = %s, хочу %s (время фиксации — из port.Clock)",
			entry.LastAccess, env.clock.Now().Truncate(time.Second))
	}

	// Политика включается после фиксации обращения: тик 100мс иначе мог
	// бы обогнать флаш и удалить v1 как «без обращений».
	patchRetentionPolicy(t, env, token, repoID, 0, 3, 90)

	waitFileGone(t, env, debStorageKey(repoID, retentionVersions[1]))
	for _, i := range []int{0, 2, 3, 4} {
		if !storageFileExists(t, env.storeDir, debStorageKey(repoID, retentionVersions[i])) {
			t.Errorf("политика удалила защищённую версию v%s", retentionVersions[i])
		}
	}

	// Публичная раздача: удалённая версия — 404, обращённая жива, хотя
	// старше топ-3 (версированный апстрим-контракт волны).
	if st, _ := getPublicRepoFile(t, env, "pool/main/h/htop/"+debFileName(retentionVersions[1])); st != http.StatusNotFound {
		t.Errorf("публичный GET удалённой v2 = %d, хочу 404", st)
	}
	if st, _ := getPublicRepoFile(t, env, v1Path); st != http.StatusOK {
		t.Errorf("публичный GET v1 после прохода = %d, хочу 200 (защита обращением)", st)
	}

	// Индекс: reindex идёт хвостом того же прохода — удалённой версии в
	// нём нет, живые на месте.
	pkg := waitPackages(t, env, retentionVersions[1])
	for _, ver := range []string{"1.0-1", "3.0-1", "4.0-1", "5.0-1"} {
		if !strings.Contains(pkg, "Version: "+ver) {
			t.Errorf("Packages потерял живую версию %s:\n%s", ver, pkg)
		}
	}

	// Квота: лимит ставится «впритык» по факту носителя — после прохода
	// помещается ровно одна новая версия, вторая упирается в лимит
	// (квота репо считает и индексы). Место, занятое удалённой версией,
	// снова доступно: повторный upload проходит без превышения.
	used := waitRepoUsageStable(t, env, repoID)
	// Проход гасится: загрузка v6 переупорядочивает топ-3 семейства (v3
	// выпадает из него и становится кандидатом) — тик во время проверки
	// квоты менял бы объём репо под ногами. Политика проверена выше.
	if err := env.runner.Stop(context.Background()); err != nil {
		t.Fatalf("останов прохода политики: %v", err)
	}
	deb6, deb7 := retentionDeb(t, "6.0-1"), retentionDeb(t, "7.0-1")
	slack := int64(len(deb6))
	if int64(len(deb7)) > slack {
		slack = int64(len(deb7))
	}
	patchRetentionPolicy(t, env, token, repoID, used+slack, 3, 90)
	putDeb(t, env, token, repoID, "6.0-1", deb6, http.StatusCreated)
	putDeb(t, env, token, repoID, "7.0-1", deb7, http.StatusRequestEntityTooLarge)

	stop(t, cancel, done)
}

// TestRetentionPinEndToEnd — пин как третья защита (сессия 170): политика
// {1, 0} без возрастного порога, поэтому версии держат только топ-1 (v5)
// и пин (v2), остальные удаляются. Анпин возвращает версию в оборот
// политики — следующий проход её забирает.
func TestRetentionPinEndToEnd(t *testing.T) {
	env := newRetentionEnv(t)
	cancel, done := env.start(t)
	defer cancel()
	token := setupRetentionEnvAdmin(t, env)
	repoID := createAptRepo(t, env, token)

	uploadVersions(t, env, token, repoID, retentionVersions)

	pinPath := "pool/main/h/htop/" + debFileName(retentionVersions[1])
	pinURL := fmt.Sprintf("http://%s/api/v1/repos/%d/retention/pins/%s", env.admin, repoID, pinPath)
	putReq(t, pinURL, token, http.StatusNoContent)
	var pinned []string
	if err := json.Unmarshal(get(t, fmt.Sprintf("http://%s/api/v1/repos/%d/retention/pins", env.admin, repoID), token, 200), &pinned); err != nil {
		t.Fatal(err)
	}
	if len(pinned) != 1 || pinned[0] != debStorageKey(repoID, retentionVersions[1]) {
		t.Fatalf("пины = %v, хочу [%s]", pinned, debStorageKey(repoID, retentionVersions[1]))
	}

	// Политика включается после пина: иначе тик успел бы забрать v2.
	patchRetentionPolicy(t, env, token, repoID, 0, 1, 0)
	waitFileGone(t, env, debStorageKey(repoID, retentionVersions[0]))
	for _, i := range []int{1, 4} {
		if !storageFileExists(t, env.storeDir, debStorageKey(repoID, retentionVersions[i])) {
			t.Errorf("политика удалила защищённую версию v%s", retentionVersions[i])
		}
	}
	for _, i := range []int{2, 3} {
		if storageFileExists(t, env.storeDir, debStorageKey(repoID, retentionVersions[i])) {
			t.Errorf("незащищённая версия v%s пережила проход", retentionVersions[i])
		}
	}
	if st, _ := getPublicRepoFile(t, env, pinPath); st != http.StatusOK {
		t.Errorf("публичный GET запиненной v2 = %d, хочу 200", st)
	}

	// Прогноз по факту (сессия 172): в семействе остались v2 и v5 —
	// топ-1 держит v5, пин держит v2. Отчёт перечисляет версии,
	// прошедшие топ-N-фильтр, с причиной защиты (пустая причина —
	// кандидат на удаление), счётчик кандидатов при этом нулевой.
	var preview struct {
		Candidates []struct {
			ProtectedBy string `json:"protected_by"`
		} `json:"candidates"`
		Totals struct {
			Candidates     int64 `json:"candidates"`
			ProtectedByMin int64 `json:"protected_by_min"`
			ProtectedByPin int64 `json:"protected_by_pin"`
		} `json:"totals"`
	}
	previewURL := fmt.Sprintf("http://%s/api/v1/repos/%d/retention/preview", env.admin, repoID)
	if err := json.Unmarshal(get(t, previewURL, token, 200), &preview); err != nil {
		t.Fatal(err)
	}
	if preview.Totals.ProtectedByMin != 1 || preview.Totals.ProtectedByPin != 1 || preview.Totals.Candidates != 0 {
		t.Errorf("прогноз: топ-N %d, пин %d, кандидатов %d — хочу по одной защите и ноль кандидатов",
			preview.Totals.ProtectedByMin, preview.Totals.ProtectedByPin, preview.Totals.Candidates)
	}
	if len(preview.Candidates) != 1 || preview.Candidates[0].ProtectedBy != "pin" {
		t.Errorf("отчёт прогноза = %+v, хочу единственную строку с защитой pin", preview.Candidates)
	}

	// Анпин: защита снята — ближайший проход удаляет v2.
	deleteReq(t, pinURL, token, http.StatusNoContent)
	waitFileGone(t, env, debStorageKey(repoID, retentionVersions[1]))

	stop(t, cancel, done)
}

// TestRetentionDisabledNoop — контракт обратной совместимости: политика
// {0,0} не делает ничего, даже когда версии «старые» (включённая политика
// их бы снесла) и проход тикает.
func TestRetentionDisabledNoop(t *testing.T) {
	env := newRetentionEnv(t)
	cancel, done := env.start(t)
	defer cancel()
	token := setupRetentionEnvAdmin(t, env)
	repoID := createAptRepo(t, env, token) // политика {0,0}

	vers := retentionVersions[:3]
	uploadVersions(t, env, token, repoID, vers)
	backdateVersions(t, env, repoID, vers)

	// Несколько тиков прохода (100мс) — окно, в котором политика
	// обязана молчать.
	time.Sleep(400 * time.Millisecond)
	for _, ver := range vers {
		if !storageFileExists(t, env.storeDir, debStorageKey(repoID, ver)) {
			t.Errorf("политика {0,0} удалила версию v%s", ver)
		}
	}
	// Индекс тоже не тронут: reindex — следствие удалений, а их не было.
	status, body := getPublicRepoFile(t, env, packagesPath)
	if status != http.StatusOK || !strings.Contains(string(body), "Version: "+vers[2]) {
		t.Errorf("индекс изменился при выключенной политике (status %d)", status)
	}

	stop(t, cancel, done)
}

// retentionAPITest — копия cmd.retentionWebAPI для интеграционного теста:
// обёртка retention.Engine под web.RetentionAPI. Пины делегируются
// PinStore'у того же каталога, что у движка (одна таблица repo_pins —
// иначе пин, поставленный API, не увидел бы проход).
type retentionAPITest struct {
	engine *retention.Engine
	pins   port.PinStore
}

func (a retentionAPITest) Preview(ctx context.Context, repo domain.Repo) (web.RetentionPreview, error) {
	res, reports, err := a.engine.Preview(ctx, repo)
	if err != nil {
		return web.RetentionPreview{}, err
	}
	out := web.RetentionPreview{Totals: retentionTotalsTest(res), Candidates: make([]web.RetentionCandidate, 0, len(reports))}
	for _, rep := range reports {
		out.Candidates = append(out.Candidates, web.RetentionCandidate{
			Key: rep.Key, Family: rep.Family, Size: rep.Size,
			ModTime: rep.ModTime, LastAccess: rep.LastAccess, ProtectedBy: rep.ProtectedBy,
		})
	}
	return out, nil
}

func (a retentionAPITest) ApplyAndReindex(ctx context.Context, repo domain.Repo, dryRun bool) (web.RetentionTotals, error) {
	res, err := a.engine.ApplyAndReindex(ctx, repo, dryRun)
	return retentionTotalsTest(res), err
}

func (a retentionAPITest) Pins(ctx context.Context, repoID int64) ([]string, error) {
	return a.pins.Pins(ctx, repoID)
}

func (a retentionAPITest) SetPin(ctx context.Context, repoID int64, key string, pinned bool) error {
	return a.pins.SetPin(ctx, repoID, key, pinned)
}

// retentionTotalsTest переводит счётчики прохода в web-представление
// (Duration — секундами: гистограмма и JSON живут в одной шкале).
func retentionTotalsTest(res retention.Result) web.RetentionTotals {
	return web.RetentionTotals{
		DryRun: res.DryRun, DurationSeconds: res.Duration.Seconds(),
		Families: res.Families, ObjectsScanned: res.ObjectsScanned,
		Candidates: res.Candidates, Deleted: res.Deleted,
		FailedDeletes: res.FailedDeletes, BytesFreed: res.BytesFreed,
		ProtectedByMin: res.ProtectedByMin, ProtectedByAccess: res.ProtectedByAccess,
		ProtectedByPin: res.ProtectedByPin,
	}
}

// setupRetentionEnvAdmin создаёт первого админа и логинится — общий
// пролог сценариев волны.
func setupRetentionEnvAdmin(t *testing.T, env *retentionEnv) string {
	t.Helper()
	post(t, "http://"+env.admin+"/api/v1/setup", `{"username":"admin","password":"password"}`, "", 201)
	return login(t, env.admin, "admin", "password")
}

// createAptRepo создаёт личный apt-репо админа (owner_id=1) без квоты и с
// выключенной политикой: включение — отдельный шаг сценария (версия
// обязана получить обращение или пин до первого тика).
func createAptRepo(t *testing.T, env *retentionEnv, token string) int64 {
	t.Helper()
	body := `{"name":"alice","owner_id":1,"ecosystem":"apt","quota":{"max_bytes":0,"max_objects":0},"retention":{"min_versions":0,"max_age_days":0}}`
	resp := post(t, "http://"+env.admin+"/api/v1/repos", body, token, 201)
	var created map[string]any
	if err := json.Unmarshal(resp, &created); err != nil {
		t.Fatal(err)
	}
	return int64(created["id"].(float64))
}

// patchRetentionPolicy меняет политику и квоту репо (PATCH — full
// replace: остальные поля приходят как есть).
func patchRetentionPolicy(t *testing.T, env *retentionEnv, token string, repoID int64, maxBytes int64, minVersions, maxAgeDays int) {
	t.Helper()
	body := fmt.Sprintf(`{"name":"alice","owner_id":1,"ecosystem":"apt",`+
		`"quota":{"max_bytes":%d,"max_objects":0},`+
		`"retention":{"min_versions":%d,"max_age_days":%d}}`, maxBytes, minVersions, maxAgeDays)
	patchReq(t, fmt.Sprintf("http://%s/api/v1/repos/%d", env.admin, repoID), body, token, 200)
}

// retentionDeb — .deb версии htop: генератор apt читает control (имя
// пакета, версию, архитектуру), тело — из общей сборки соседних тестов.
func retentionDeb(t *testing.T, ver string) []byte {
	t.Helper()
	return buildDebIntegration(t, "Package: htop\nVersion: "+ver+"\nArchitecture: amd64\nDescription: retention scenario\n")
}

// uploadVersions заливает версии по возрастанию времени (пауза 20мс —
// ModTime упорядочен) и дожидается reindex: политика сравнивает версии по
// дате загрузки, поэтому порядок заливки — часть сценария.
func uploadVersions(t *testing.T, env *retentionEnv, token string, repoID int64, vers []string) {
	t.Helper()
	for _, ver := range vers {
		putDeb(t, env, token, repoID, ver, retentionDeb(t, ver), http.StatusCreated)
		time.Sleep(20 * time.Millisecond)
	}
	waitForReindex(t, env.admin, token, repoID)
}

// backdateVersions старит версии на 100 суток, сохраняя порядок v1 … v5.
func backdateVersions(t *testing.T, env *retentionEnv, repoID int64, vers []string) {
	t.Helper()
	base := env.clock.Now().Add(-100 * 24 * time.Hour)
	for i, ver := range vers {
		ageStorageFile(t, env.storeDir, debStorageKey(repoID, ver), base.Add(time.Duration(i)*time.Hour))
	}
}

// debFileName — имя файла версии в пуле.
func debFileName(ver string) string { return "htop_" + ver + ".deb" }

// debStorageKey — ключ объекта в хранилище; он же ключ пина и
// object_access: публичный роутер фиксирует обращение по тому же ключу,
// что перечисляет проход.
func debStorageKey(repoID int64, ver string) string {
	return fmt.Sprintf("repo/%d/apt/pool/main/h/htop/%s", repoID, debFileName(ver))
}

// packagesPath — путь индекса в публичном роутере (заглавная P — роутер
// лоуэркейсит запрос при lookup'е; слаг индекса — из генератора:
// dists/<dist>/<component>/binary-<arch>).
const packagesPath = "dists/stable/main/binary-amd64/Packages"

// putDeb загружает версию через admin-API и проверяет статус: 201 —
// принята, 413 — отвергнута квотой.
func putDeb(t *testing.T, env *retentionEnv, token string, repoID int64, ver string, deb []byte, want int) {
	t.Helper()
	url := fmt.Sprintf("http://%s/api/v1/repos/%d/objects/pool/main/h/htop/%s", env.admin, repoID, debFileName(ver))
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(deb))
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = int64(len(deb))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		t.Fatalf("PUT %s = %d, хочу %d (тело %s)", debFileName(ver), resp.StatusCode, want, body)
	}
}

// putReq — PUT без тела (пины: путь — хвост URL) с проверкой статуса: в
// общем файле хелперов PUT'а нет, а телу здесь не место.
func putReq(t *testing.T, url, bearer string, want int) []byte {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		t.Fatalf("PUT %s = %d, хочу %d (тело %s)", url, resp.StatusCode, want, body)
	}
	return body
}

// getPublicRepoFile — GET объекта личного репо через публичный порт
// (:29202) без auth: путь проверяется от клиентской стороны, а не от
// внутреннего ключа хранилища.
func getPublicRepoFile(t *testing.T, env *retentionEnv, path string) (int, []byte) {
	t.Helper()
	resp, err := http.Get("http://" + env.public + "/repo/alice/" + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

// waitAccessRow ждёт, пока обращение доедет до object_access. Нужен
// порядку сценария: фиксация в памяти → строка в БД → включение
// политики. Иначе тик прохода (100мс) может обогнать флаш накопителя
// (тоже 100мс) и удалить версию как «без обращений» — в проде проход
// суточный, гонка недостижима, в тесте интервалы одного порядка.
func waitAccessRow(t *testing.T, env *retentionEnv, key string) domain.ObjectAccess {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		entry, err := env.catalog.Access.AccessEntry(context.Background(), domain.AccessScopeRepo, key)
		if err == nil {
			return entry
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("обращение к %s не доехало до object_access за 5с", key)
	return domain.ObjectAccess{}
}

// waitFileGone ждёт удаления объекта политикой: тик асинхронный,
// retry-цикл 100мс (ТЗ сессии) с бюджетом 5с — проход включает ещё и
// reindex.
func waitFileGone(t *testing.T, env *retentionEnv, key string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !storageFileExists(t, env.storeDir, key) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("объект %s не удалён политикой за 5с", key)
}

// waitPackages ждёт публичный Packages уже без удалённой версии (reindex
// идёт хвостом прохода, асинхронно от наблюдателя) и отдаёт его тело.
func waitPackages(t *testing.T, env *retentionEnv, goneVer string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if status, body := getPublicRepoFile(t, env, packagesPath); status == http.StatusOK &&
			!strings.Contains(string(body), "Version: "+goneVer) {
			return string(body)
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("индекс не перегенерирован за 5с: версия %s всё ещё в Packages", goneVer)
	return ""
}

// waitRepoUsageStable ждёт, пока состав объектов репо перестанет
// меняться, и отдаёт их суммарный размер: проход завершается целиком
// (удаления → reindex → gc by-hash), а квота считается по живому
// носителю — замер посреди генерации дал бы заниженный лимит. Размер
// считается тем же способом, что у checkQuota: файлы под префиксом репо,
// включая индексы.
func waitRepoUsageStable(t *testing.T, env *retentionEnv, repoID int64) int64 {
	t.Helper()
	base := filepath.Join(env.storeDir, "repo", strconv.FormatInt(repoID, 10))
	prev := int64(-1)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var size int64
		err := filepath.WalkDir(base, func(_ string, d fs.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
			if d.IsDir() {
				return nil
			}
			info, ierr := d.Info()
			if ierr != nil {
				return ierr
			}
			size += info.Size()
			return nil
		})
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("обход %s: %v", base, err)
		}
		if size == prev {
			return size
		}
		prev = size
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("объём репо %d не стабилизировался за 5с", repoID)
	return 0
}
