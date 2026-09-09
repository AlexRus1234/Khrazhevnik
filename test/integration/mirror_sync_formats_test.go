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

// E2E зеркало на реальных форматах upstream (сессия 106): sync-БД
// pacman = tar.gz (факт 2026-09: Arch отдаёт core.db с gzip-магией),
// primary rpm-md = xml.zst (Fedora 41+/Leap 16.0). Полная цепочка:
// admin-API (remote) → ручной sync → enumerate через движок кеша →
// prefetch в хранилище → HIT на публичном порту. Живые upstream'ы
// запрещены — httptest-фикстуры воспроизводят фактические форматы.

package integration

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"khrazhevnik/internal/core/config"
	"khrazhevnik/internal/core/engine/auth"
	cacheengine "khrazhevnik/internal/core/engine/cache"
	mirrorengine "khrazhevnik/internal/core/engine/mirror"
	"khrazhevnik/internal/core/metrics"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/core/registry"
	"khrazhevnik/internal/core/web"
	"khrazhevnik/internal/mod/ecosystem/pacman"
	"khrazhevnik/internal/mod/ecosystem/rpmmmd"
	"khrazhevnik/internal/testutil"
)

// syncPacmanUp — upstream pacman-ноги: core.db как tar.gz (gzip-магия,
// не zstd) + два .pkg.tar.zst. Счётчик — для контроля отсутствия
// upstream-трафика при HIT.
type syncPacmanUp struct {
	hits   atomic.Int64
	pkg1   []byte
	pkg2   []byte
	coreDB []byte
	srv    *httptest.Server
}

// newPacmanGzipDB — gzip-сжатый tar (дубль newPacmanDB из
// pacman_proxy_test.go с gzip вместо zstd: integration — отдельный
// пакет, а фикстура должна нести gzip-магию 1F 8B).
func newPacmanGzipDB(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	for name, content := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(content)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	var gzBuf bytes.Buffer
	zw := gzip.NewWriter(&gzBuf)
	if _, err := zw.Write(tarBuf.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return gzBuf.Bytes()
}

func newSyncPacmanUp(t *testing.T) *syncPacmanUp {
	t.Helper()
	u := &syncPacmanUp{
		pkg1: []byte("PACMAN-SYNC-PKG-1-100-bytes-padding-padding-padding-padding-padding!!"),
		pkg2: []byte("PACMAN-SYNC-PKG-2-100-bytes-padding-padding-padding-padding-padding!!"),
	}
	desc1 := []byte("%FILENAME%\npacman-example-1.0-1-x86_64.pkg.tar.zst\n%NAME%\npacman-example\n%VERSION%\n1.0-1\n")
	desc2 := []byte("%FILENAME%\nsecond-pkg-2.0-1-any.pkg.tar.zst\n%NAME%\nsecond-pkg\n%VERSION%\n2.0-1\n")
	u.coreDB = newPacmanGzipDB(t, map[string][]byte{
		"pacman-example-1.0-1-x86_64/desc": desc1,
		"second-pkg-2.0-1-any/desc":        desc2,
	})
	u.srv = httptest.NewServer(http.HandlerFunc(u.serve))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *syncPacmanUp) serve(w http.ResponseWriter, r *http.Request) {
	u.hits.Add(1)
	switch r.URL.Path {
	case "/archlinux/core/os/x86_64/core.db":
		// Content-Type на парсер не влияет: компрессия детектится по magic.
		w.Header().Set("Content-Type", "application/x-gzip")
		w.Header().Set("ETag", `"coredb-gzip-v1"`)
		_, _ = w.Write(u.coreDB)
	case "/archlinux/core/os/x86_64/pacman-example-1.0-1-x86_64.pkg.tar.zst":
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(u.pkg1)
	case "/archlinux/core/os/x86_64/second-pkg-2.0-1-any.pkg.tar.zst":
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(u.pkg2)
	default:
		http.NotFound(w, r)
	}
}

func (u *syncPacmanUp) hitsNow() int64 { return u.hits.Load() }

// syncRpmUp — upstream rpm-md-ноги: repomd.xml с zst-primary и одним
// .rpm. Чексумма в repomd — реальная sha256 СЖАТОГО primary: после
// Enumerate таблица чексумм наполняется и движок сверяет скачивание.
type syncRpmUp struct {
	hits       atomic.Int64
	rpmBytes   []byte
	repomd     []byte
	primaryZst []byte
	primarySHA string
	srv        *httptest.Server
}

// zstPack — zstd-упаковка primary (дубль zstBytes юнит-пакета легален:
// integration — отдельный пакет).
func zstPack(t *testing.T, raw []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func newSyncRpmUp(t *testing.T) *syncRpmUp {
	t.Helper()
	u := &syncRpmUp{
		rpmBytes: []byte("RPM-SYNC-CONTENT-100-bytes-padding-padding-padding-padding-padding!"),
	}
	u.primaryZst = zstPack(t, []byte(`<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/primary" packages="1">
  <package type="rpm">
    <name>foo</name>
    <location href="Packages/f/foo-1.0-1.x86_64.rpm"/>
  </package>
</metadata>
`))
	sum := sha256.Sum256(u.primaryZst)
	u.primarySHA = hex.EncodeToString(sum[:])
	u.repomd = []byte(`<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo">
  <revision>2026-09-09T12:00:00Z</revision>
  <data type="primary">
    <checksum type="sha256">` + u.primarySHA + `</checksum>
    <location href="repodata/` + u.primarySHA + `-primary.xml.zst"/>
    <timestamp>1769908800</timestamp>
    <size>` + strconv.Itoa(len(u.primaryZst)) + `</size>
  </data>
</repomd>
`)
	u.srv = httptest.NewServer(http.HandlerFunc(u.serve))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *syncRpmUp) serve(w http.ResponseWriter, r *http.Request) {
	u.hits.Add(1)
	switch r.URL.Path {
	case "/fedora/repodata/repomd.xml":
		w.Header().Set("Content-Type", "application/xml")
		w.Header().Set("ETag", `"repomd-zst-v1"`)
		_, _ = w.Write(u.repomd)
	case "/fedora/repodata/" + u.primarySHA + "-primary.xml.zst":
		w.Header().Set("Content-Type", "application/zstd")
		_, _ = w.Write(u.primaryZst)
	case "/fedora/Packages/f/foo-1.0-1.x86_64.rpm":
		w.Header().Set("Content-Type", "application/x-rpm")
		_, _ = w.Write(u.rpmBytes)
	default:
		http.NotFound(w, r)
	}
}

func (u *syncRpmUp) hitsNow() int64 { return u.hits.Load() }

// mirrorFormatsEnv — полный in-process сервер на реальных слушателях
// (по образцу окружения mirror_test.go): sqlite + fs + реальные
// адаптеры экосистем, mirror-engine за TaskRegistry, ручной триггер
// sync через admin-API.
type mirrorFormatsEnv struct {
	t      *testing.T
	public string
	admin  string
	token  string
	cancel context.CancelFunc
	done   chan error
}

func newMirrorFormatsEnv(t *testing.T, up *httptest.Server,
	buildEcos func(remotes port.RemoteStore, clock port.Clock) map[string]port.Ecosystem,
) *mirrorFormatsEnv {
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
	clock := testutil.NewManualClock(time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC))
	authService, err := auth.New(auth.Config{
		Users: catalog.Users, Tokens: catalog.Tokens, Audit: catalog.Audit, Revocations: catalog.Revocations,
		Clock: clock, Rand: testutil.FixedRand("77777777-7777-4777-8777-777777777777"),
		JWTSecret: cfg.Auth.JWTSecret, SessionTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	cacheEngine := cacheengine.New(storage, catalog.ObjIndex, up.Client(), clock,
		cacheengine.Config{}, metrics.NewCache())
	tasks := web.NewTaskRegistry(2, clock, nil)
	ecos := buildEcos(catalog.Remotes, clock)
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
	return &mirrorFormatsEnv{t: t, public: publicAddr, admin: adminAddr, token: token, cancel: cancel, done: done}
}

func (e *mirrorFormatsEnv) stop() {
	e.cancel()
	if err := <-e.done; err != nil {
		e.t.Errorf("сервер завершился с ошибкой: %v", err)
	}
}

func (e *mirrorFormatsEnv) createRemote(body string) int64 {
	raw := post(e.t, "http://"+e.admin+"/api/v1/remotes", body, e.token, 201)
	var out struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		e.t.Fatalf("разбор ответа remote: %v", err)
	}
	return out.ID
}

// syncUntilSucceeded — ручной триггер sync + поллинг статуса задачи
// (бюджет 30с на медленный CI, частота 200мс).
func (e *mirrorFormatsEnv) syncUntilSucceeded(id int64) {
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
			switch snap.State {
			case "succeeded":
				return
			case "failed":
				e.t.Fatalf("sync-задача failed: %s", snap.Error)
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	e.t.Fatal("sync-задача не завершилась за 30с")
}

// publicGet — GET к публичному порту с ассертом кода и X-Cache.
func (e *mirrorFormatsEnv) publicGet(path, wantCache string) []byte {
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

func assertBody(t *testing.T, path string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Fatalf("GET %s: тело %d байт, хочу byte-exact %d байт", path, len(got), len(want))
	}
}

// TestMirrorSyncPacmanGzipDB — sync против upstream с gzip-БД:
// прокси-путь пакета до sync (MISS→HIT), sync (enumerate парсит
// gzip-магию core.db через движок кеша, prefetch второго пакета),
// затем прогретые HIT: core.db и второй пакет — байты byte-exact.
func TestMirrorSyncPacmanGzipDB(t *testing.T) {
	up := newSyncPacmanUp(t)
	env := newMirrorFormatsEnv(t, up.srv, func(remotes port.RemoteStore, clock port.Clock) map[string]port.Ecosystem {
		adapter, err := pacman.New(remotes, clock)
		if err != nil {
			t.Fatal(err)
		}
		return map[string]port.Ecosystem{pacman.Name: adapter}
	})
	defer env.stop()

	id := env.createRemote(`{"name":"arch","ecosystem":"pacman","base_url":"` + up.srv.URL + `/archlinux","mode":"mirror","enabled":true,"sync_interval":0,"include":["core/x86_64"]}`)

	// прокси-путь до sync: первый GET — MISS, второй — HIT.
	pkg1Path := "/pacman/arch/core/os/x86_64/pacman-example-1.0-1-x86_64.pkg.tar.zst"
	assertBody(t, pkg1Path, env.publicGet(pkg1Path, "MISS"), up.pkg1)
	assertBody(t, pkg1Path, env.publicGet(pkg1Path, "HIT"), up.pkg1)

	env.syncUntilSucceeded(id)

	// прогретые sync'ом: core.db скачан enumerate'ом (gzip-парсинг),
	// второй пакет — prefetch'ем диффа.
	dbPath := "/pacman/arch/core/os/x86_64/core.db"
	assertBody(t, dbPath, env.publicGet(dbPath, "HIT"), up.coreDB)
	pkg2Path := "/pacman/arch/core/os/x86_64/second-pkg-2.0-1-any.pkg.tar.zst"
	assertBody(t, pkg2Path, env.publicGet(pkg2Path, "HIT"), up.pkg2)

	// прогретые объекты отдаются без upstream-трафика
	before := up.hitsNow()
	_ = env.publicGet(pkg1Path, "HIT")
	_ = env.publicGet(pkg2Path, "HIT")
	_ = env.publicGet(dbPath, "HIT")
	if got := up.hitsNow() - before; got != 0 {
		t.Errorf("upstream получил %d запросов при HIT из кеша, хочу 0", got)
	}
}

// TestMirrorSyncRpmMdZstPrimary — sync против upstream с
// primary.xml.zst: прокси-путь repomd до sync (MISS→HIT), sync
// (enumerate: repomd → чексуммы → скачивание primary.zst со сверкой
// sha256 сжатых байт → распаковка → prefetch пакета), затем HIT
// primary.zst и пакета — байты byte-exact.
func TestMirrorSyncRpmMdZstPrimary(t *testing.T) {
	up := newSyncRpmUp(t)
	env := newMirrorFormatsEnv(t, up.srv, func(remotes port.RemoteStore, clock port.Clock) map[string]port.Ecosystem {
		adapter, err := rpmmmd.New(remotes, clock)
		if err != nil {
			t.Fatal(err)
		}
		return map[string]port.Ecosystem{rpmmmd.Name: adapter}
	})
	defer env.stop()

	id := env.createRemote(`{"name":"fedora","ecosystem":"rpm-md","base_url":"` + up.srv.URL + `/fedora","mode":"mirror","enabled":true,"sync_interval":0}`)

	// прокси-путь до sync: первый GET — MISS, второй — HIT.
	repomdPath := "/rpm/fedora/repodata/repomd.xml"
	assertBody(t, repomdPath, env.publicGet(repomdPath, "MISS"), up.repomd)
	assertBody(t, repomdPath, env.publicGet(repomdPath, "HIT"), up.repomd)

	env.syncUntilSucceeded(id)

	// прогретые sync'ом: primary.zst скачан enumerate'ом (сверка
	// чексуммы сжатых байт из repomd), пакет — prefetch'ем.
	primaryPath := "/rpm/fedora/repodata/" + up.primarySHA + "-primary.xml.zst"
	assertBody(t, primaryPath, env.publicGet(primaryPath, "HIT"), up.primaryZst)
	rpmPath := "/rpm/fedora/Packages/f/foo-1.0-1.x86_64.rpm"
	assertBody(t, rpmPath, env.publicGet(rpmPath, "HIT"), up.rpmBytes)

	before := up.hitsNow()
	_ = env.publicGet(primaryPath, "HIT")
	_ = env.publicGet(rpmPath, "HIT")
	_ = env.publicGet(repomdPath, "HIT")
	if got := up.hitsNow() - before; got != 0 {
		t.Errorf("upstream получил %d запросов при HIT из кеша, хочу 0", got)
	}
}
