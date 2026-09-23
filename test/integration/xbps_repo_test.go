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

// E2E личного xbps-репо (сессия 143): setup → create repo eco=xbps →
// upload двух .xbps (x86_64 + noarch) → reindex-задача → публичный порт
// отдаёт <arch>-repodata (читается нашим же парсером OpenRepoData +
// ParseIndexPlist) и .sig2 (верифицируются crypto/rsa против
// GET /repo/<name>/xbps-key). Консистентность: пакет, props которого не
// совпадают с именем файла, роняет reindex; после удаления битого
// объекта повторный reindex даёт байт-в-байт тот же индекс (детерминизм
// writer'а сессии 140). «Реальный xbps-install» — distro-нога сессии 144;
// здесь формат доказывается нашими парсерами и stdlib crypto/rsa
// (образец publish_test.go, сессия 14).

package integration

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"khrazhevnik/internal/core/config"
	"khrazhevnik/internal/core/engine/auth"
	publishengine "khrazhevnik/internal/core/engine/publish"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/core/registry"
	"khrazhevnik/internal/core/web"
	"khrazhevnik/internal/mod/ecosystem/xbps"
	"khrazhevnik/internal/testutil"

	_ "khrazhevnik/internal/mod/db/sqlite"
	_ "khrazhevnik/internal/mod/sign/rsasha256"
	_ "khrazhevnik/internal/mod/storage/fs"
)

// Пакеты сценария — реальные имена Void (урок charset/регистра сессии 65):
// Mustache x86_64 (регистр ключа индекса значим) и xtools noarch, который
// обязан появиться в x86_64-группе.
const (
	xbpsRepoName    = "alice"
	xbpsMustacheKey = "Mustache"
	xbpsMustacheVer = "Mustache-4.1_1"
	xbpsMustacheSha = "x86_64"
	xbpsXtoolsKey   = "xtools"
	xbpsXtoolsVer   = "xtools-0.59_1"
	xbpsXtoolsArch  = "noarch"
)

// xbpsRepoIntegrationEnv — in-process сервер на реальных слушателях:
// sqlite-каталог + fs-storage + xbps-генератор с внедрённым
// rsasha256-подписчиком. Отличие от publishIntegrationEnv (apt/openpgp):
// публичному роутеру нужен port.RsaSigner (ручка /xbps-key), а publish-
// движку — адаптер xbps, в который RsaSigner внедрён через
// port.RsaSignerInjector (как wireRepoAdapters в cmd).
func xbpsRepoIntegrationEnv(t *testing.T) (*web.Server, string, string) {
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
		Clock: clock, Rand: testutil.FixedRand("88888888-8888-4888-8888-888888888888"),
		JWTSecret: cfg.Auth.JWTSecret, SessionTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	rsaFactory, err := registry.RsaSigner("rsasha256")
	if err != nil {
		t.Fatalf("registry.RsaSigner rsasha256: %v (blank-import забыли?)", err)
	}
	rsaSigner, err := rsaFactory(config.Signing{KeysDir: filepath.Join(dir, "keys")})
	if err != nil {
		t.Fatalf("rsasha256 factory: %v", err)
	}
	// Ecosystems — как в wireApp: карта имён адаптеров, по которой
	// admin-роутер гейтит ecosystem при POST /repos (сессия 45).
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
	tasks := web.NewTaskRegistry(2, clock, nil)
	publishEngine := publishengine.New(
		publishengine.Config{MaxObjectSize: cfg.Publish.MaxObjectSize.Bytes},
		storage, catalog.Repos, clock, xbpsRepoAdaptersForTest(rsaSigner, clock),
	)
	publishAPI := publishSyncerTest{engine: publishEngine, repos: catalog.Repos, tasks: tasks}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := &web.Server{
		PublicAddr: publicAddr,
		PublicHandler: web.BuildPublicRouter(web.Deps{
			Log: log, Version: "test", Storage: storage,
			Repos: catalog.Repos, RsaSigner: rsaSigner,
		}),
		AdminAddr: adminAddr,
		AdminHandler: web.BuildAdminRouter(web.Deps{
			Log: log, Version: "test", Auth: authService,
			Ecosystems: ecosystems,
			Repos:      catalog.Repos, Storage: storage, Audit: catalog.Audit,
			Tasks: tasks, Publish: publishAPI, Clock: clock,
		}),
		Log:       log,
		ShutdownTimeout: 10 * time.Second,
		WaitTasks: tasks.WaitAll,
	}
	return srv, publicAddr, adminAddr
}

// xbpsRepoAdaptersForTest — копия wireRepoAdapters (cmd/wire.go) с
// внедрением port.RsaSigner (v1 — только xbps) поверх ClockInjector.
// publishIntegrationEnv инжектит лишь port.Signer (apt/openpgp) — xbps
// через него не подписывается, поэтому отдельный хелпер.
func xbpsRepoAdaptersForTest(rsaSigner port.RsaSigner, clock port.Clock) map[string]port.RepoAdapter {
	out := map[string]port.RepoAdapter{}
	for _, name := range registry.Ecosystems() {
		factory, err := registry.RepoAdapter(name)
		if err != nil {
			continue
		}
		adapter, err := factory()
		if err != nil {
			continue
		}
		if rsaSigner != nil {
			if inj, ok := adapter.(port.RsaSignerInjector); ok {
				inj.SetRsaSigner(rsaSigner)
			}
		}
		if clock != nil {
			if inj, ok := adapter.(port.ClockInjector); ok {
				inj.SetClock(clock)
			}
		}
		out[name] = adapter
	}
	return out
}

// xbpsPropsXML — props.plist мини-пакета: ровно поля, которые генератор
// кладёт в index.plist и сверяет с именем файла (pkgname/pkgver/
// architecture). Энтити здесь не нужны — их сценарий оставлен парсеру.
func xbpsPropsXML(name, pkgver, arch string) string {
	return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
		"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n" +
		"<plist version=\"1.0\">\n<dict>\n" +
		"\t<key>pkgname</key>\n\t<string>" + name + "</string>\n" +
		"\t<key>pkgver</key>\n\t<string>" + pkgver + "</string>\n" +
		"\t<key>architecture</key>\n\t<string>" + arch + "</string>\n" +
		"\t<key>short_desc</key>\n\t<string>integration test package</string>\n" +
		"</dict>\n</plist>\n"
}

// buildXbpsIntegration собирает .xbps: классический ar (`!<arch>\n` +
// 60-байтный заголовок члена) с одним props.plist, сжатый целиком в
// zstd — ветка OpenPackage, которую использует генератор. Дубль
// pkgparse-хелпера легален: тесты интеграции самодостаточны.
func buildXbpsIntegration(t *testing.T, propsXML string) []byte {
	t.Helper()
	body := []byte(propsXML)
	var ar bytes.Buffer
	ar.WriteString("!<arch>\n")
	fmt.Fprintf(&ar, "%-16s%-12d%-6d%-6d%-8o%-10d`\n", "props.plist", 0, 0, 0, 0o100644, len(body))
	ar.Write(body)
	if len(body)%2 != 0 {
		ar.WriteByte('\n')
	}
	var out bytes.Buffer
	zw, err := zstd.NewWriter(&out, zstd.WithEncoderLevel(zstd.SpeedFastest))
	if err != nil {
		t.Fatalf("zstd.NewWriter: %v", err)
	}
	if _, err := zw.Write(ar.Bytes()); err != nil {
		t.Fatalf("zstd write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zstd close: %v", err)
	}
	return out.Bytes()
}

// xbpsPutObjectExpect — PUT объекта личного репо с ожидаемым кодом.
func xbpsPutObjectExpect(t *testing.T, adminAddr, token string, repoID int64, path string, body []byte, want int) {
	t.Helper()
	url := fmt.Sprintf("http://%s/api/v1/repos/%d/objects/%s", adminAddr, repoID, path)
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = int64(len(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != want {
		got, _ := io.ReadAll(resp.Body)
		t.Fatalf("PUT %s = %d, хочу %d (тело %s)", path, resp.StatusCode, want, got)
	}
}

// xbpsPutObject — успешный upload (201).
func xbpsPutObject(t *testing.T, adminAddr, token string, repoID int64, path string, body []byte) {
	t.Helper()
	xbpsPutObjectExpect(t, adminAddr, token, repoID, path, body, http.StatusCreated)
}

// xbpsDeleteObject — DELETE объекта; 204 или фатальный.
func xbpsDeleteObject(t *testing.T, adminAddr, token string, repoID int64, path string) {
	t.Helper()
	url := fmt.Sprintf("http://%s/api/v1/repos/%d/objects/%s", adminAddr, repoID, path)
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		got, _ := io.ReadAll(resp.Body)
		t.Fatalf("DELETE %s = %d, хочу 204 (тело %s)", path, resp.StatusCode, got)
	}
}

// xbpsReindex запускает reindex и поллит задачу до терминального
// состояния, возвращая state и текст ошибки.
func xbpsReindex(t *testing.T, adminAddr, token string, repoID int64) (state, errText string) {
	t.Helper()
	raw := post(t, fmt.Sprintf("http://%s/api/v1/repos/%d/reindex", adminAddr, repoID), "", token, 202)
	var out struct {
		TaskID string `json:"task_id"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("разбор task_id: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		b := get(t, "http://"+adminAddr+"/api/v1/tasks/"+out.TaskID, token, 200)
		var snap struct {
			State string `json:"state"`
			Error string `json:"error"`
		}
		if err := json.Unmarshal(b, &snap); err == nil {
			if snap.State == "succeeded" || snap.State == "failed" {
				return snap.State, snap.Error
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("reindex-задача не завершилась за 10с")
	return "", ""
}

// xbpsPublicGet — GET публичного порта с ассертом 200.
func xbpsPublicGet(t *testing.T, url string) []byte {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d, хочу 200 (тело %s)", url, resp.StatusCode, b)
	}
	return b
}

// xbpsParseIndex разворачивает repodata нашим контейнерным парсером
// (131) и стриминг-парсером index.plist (132); closeFn обязателен —
// он владеет zstd-декодером.
func xbpsParseIndex(t *testing.T, repodata []byte) []xbps.IndexEntry {
	t.Helper()
	index, closeFn, err := xbps.OpenRepoData(bytes.NewReader(repodata))
	if err != nil {
		t.Fatalf("OpenRepoData: %v", err)
	}
	var out []xbps.IndexEntry
	if err := xbps.ParseIndexPlist(index, func(e xbps.IndexEntry) error {
		out = append(out, e)
		return nil
	}); err != nil {
		t.Fatalf("ParseIndexPlist: %v", err)
	}
	if _, err := closeFn(); err != nil {
		t.Fatalf("repodata meta: %v", err)
	}
	return out
}

// xbpsPublicKey читает SPKI-PEM публичного ключа инстанса с публичного
// порта: ровно то, что импортирует xbps-клиент при TOFU.
func xbpsPublicKey(t *testing.T, url string) *rsa.PublicKey {
	t.Helper()
	body := xbpsPublicGet(t, url)
	block, _ := pem.Decode(body)
	if block == nil {
		t.Fatalf("xbps-key не PEM: %q", body)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("разбор SPKI xbps-key: %v", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("xbps-key %T, ожидался *rsa.PublicKey", pub)
	}
	return rsaPub
}

// TestXbpsPersonalRepoE2E — сценарии (a)–(e) сессии 143.
func TestXbpsPersonalRepoE2E(t *testing.T) {
	srv, publicAddr, adminAddr := xbpsRepoIntegrationEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	waitHealthy(t, "http://"+adminAddr+"/healthz")

	post(t, "http://"+adminAddr+"/api/v1/setup", `{"username":"admin","password":"password"}`, "", 201)
	token := login(t, adminAddr, "admin", "password")

	repoBody := `{"name":"` + xbpsRepoName + `","owner_id":1,"ecosystem":"xbps","quota":{"max_bytes":0,"max_objects":0}}`
	resp := post(t, "http://"+adminAddr+"/api/v1/repos", repoBody, token, 201)
	var created map[string]any
	if err := json.Unmarshal(resp, &created); err != nil {
		t.Fatal(err)
	}
	repoID := int64(created["id"].(float64))

	// (a) upload двух .xbps: нативный x86_64 и noarch.
	mustache := buildXbpsIntegration(t, xbpsPropsXML(xbpsMustacheKey, xbpsMustacheVer, xbpsMustacheSha))
	xtools := buildXbpsIntegration(t, xbpsPropsXML(xbpsXtoolsKey, xbpsXtoolsVer, xbpsXtoolsArch))
	// publish лоуэркейсит путь (конвенция v1) — ключи в storage и URL ниже.
	mustacheFile := strings.ToLower(xbps.Filename(xbpsMustacheVer, xbpsMustacheSha))
	xtoolsFile := strings.ToLower(xbps.Filename(xbpsXtoolsVer, xbpsXtoolsArch))
	xbpsPutObject(t, adminAddr, token, repoID, mustacheFile, mustache)
	xbpsPutObject(t, adminAddr, token, repoID, xtoolsFile, xtools)

	state, errText := xbpsReindex(t, adminAddr, token, repoID)
	if state != "succeeded" {
		t.Fatalf("reindex = %q (%s), хочу succeeded", state, errText)
	}

	// (b) <arch>-repodata: оба пакета в индексе, noarch — в x86_64-группе,
	// filename-sha256/size — по фактическому телу.
	repodataURL := "http://" + publicAddr + "/repo/" + xbpsRepoName + "/x86_64-repodata"
	repodata := xbpsPublicGet(t, repodataURL)
	entries := xbpsParseIndex(t, repodata)
	if len(entries) != 2 {
		t.Fatalf("в индексе %d записей, хочу 2: %+v", len(entries), entries)
	}
	byName := map[string]xbps.IndexEntry{}
	for _, e := range entries {
		byName[e.PkgName] = e
	}
	m, ok := byName[xbpsMustacheKey]
	if !ok {
		t.Fatalf("в индексе нет записи %q", xbpsMustacheKey)
	}
	if m.Architecture != xbpsMustacheSha || m.PkgVer != xbpsMustacheVer {
		t.Errorf("Mustache: arch=%q pkgver=%q, хочу %q/%q", m.Architecture, m.PkgVer, xbpsMustacheSha, xbpsMustacheVer)
	}
	if want := sha256Hex(mustache); m.FilenameSHA256 != want || m.FilenameSize != int64(len(mustache)) {
		t.Errorf("Mustache: sha256=%q size=%d, хочу %q/%d", m.FilenameSHA256, m.FilenameSize, want, len(mustache))
	}
	x, ok := byName[xbpsXtoolsKey]
	if !ok {
		t.Fatalf("в индексе нет записи %q (noarch не попал в x86_64-группу)", xbpsXtoolsKey)
	}
	if x.Architecture != xbpsXtoolsArch || x.PkgVer != xbpsXtoolsVer {
		t.Errorf("xtools: arch=%q pkgver=%q, хочу %q/%q", x.Architecture, x.PkgVer, xbpsXtoolsArch, xbpsXtoolsVer)
	}
	if want := sha256Hex(xtools); x.FilenameSHA256 != want || x.FilenameSize != int64(len(xtools)) {
		t.Errorf("xtools: sha256=%q size=%d, хочу %q/%d", x.FilenameSHA256, x.FilenameSize, want, len(xtools))
	}

	// (c) .sig2 каждого пакета верифицируется против /xbps-key.
	pub := xbpsPublicKey(t, "http://"+publicAddr+"/repo/"+xbpsRepoName+"/xbps-key")
	for _, tc := range []struct {
		file string
		body []byte
	}{
		{mustacheFile, mustache},
		{xtoolsFile, xtools},
	} {
		sig := xbpsPublicGet(t, "http://"+publicAddr+"/repo/"+xbpsRepoName+"/"+tc.file+".sig2")
		digest := sha256.Sum256(tc.body)
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
			t.Errorf("verify %s.sig2 под /xbps-key: %v", tc.file, err)
		}
	}

	// (d) не-.xbps отклоняется адаптером (400); пакет с props, не
	// совпадающими с именем файла, upload проходит (плоскость +
	// расширение ок), но reindex честно падает на консистентности (141).
	xbpsPutObjectExpect(t, adminAddr, token, repoID, "evil.txt", []byte("nope"), http.StatusBadRequest)
	badFile := "wrongname-1.0_1.x86_64.xbps"
	bad := buildXbpsIntegration(t, xbpsPropsXML(xbpsMustacheKey, xbpsMustacheVer, xbpsMustacheSha))
	xbpsPutObject(t, adminAddr, token, repoID, badFile, bad)
	state, _ = xbpsReindex(t, adminAddr, token, repoID)
	if state != "failed" {
		t.Fatalf("reindex с несогласованным пакетом = %q, хочу failed", state)
	}

	// (e) после удаления битого объекта повторный reindex succeeds и
	// отдаёт байт-в-байт тот же индекс (детерминизм writer'а сессии 140).
	xbpsDeleteObject(t, adminAddr, token, repoID, badFile)
	state, errText = xbpsReindex(t, adminAddr, token, repoID)
	if state != "succeeded" {
		t.Fatalf("повторный reindex = %q (%s), хочу succeeded", state, errText)
	}
	again := xbpsPublicGet(t, repodataURL)
	if !bytes.Equal(repodata, again) {
		t.Errorf("repodata недетерминирована: %d байт до, %d после", len(repodata), len(again))
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("сервер завершился с ошибкой: %v", err)
	}
}
