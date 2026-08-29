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

// E2E publish: реальный sqlite-каталог + apt-генератор + fs-storage:
// setup → login → /api/v1/repos CRUD → PUT .deb → reindex → публичный
// /repo/<name>/dists/stable/... отдаёт Packages, который парсер
// apt.Stanzas читает (свой же парсер из сессии 07 проверяет генератор!).
// Сессия 14.

package integration

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "khrazhevnik/internal/mod/db/sqlite"
	_ "khrazhevnik/internal/mod/ecosystem/apt"
	_ "khrazhevnik/internal/mod/sign/openpgp"
	_ "khrazhevnik/internal/mod/storage/fs"

	"khrazhevnik/internal/core/config"
	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/engine/auth"
	cacheengine "khrazhevnik/internal/core/engine/cache"
	publishengine "khrazhevnik/internal/core/engine/publish"
	"khrazhevnik/internal/core/metrics"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/core/registry"
	"khrazhevnik/internal/core/web"
	"khrazhevnik/internal/testutil"

	gp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// publishIntegrationEnv собирает live-сервер с реальным sqlite-каталогом
// и apt repo-адаптером (через blank-import), как делает wireApp, но в тесте.
// signer (если не nil) внедряется в apt repo-адаптер (InRelease + Release.gpg)
// и в публичный роутер (GET /repo/<name>/key.asc).
func publishIntegrationEnv(t *testing.T, signer port.Signer) (*web.Server, string, string) {
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
	clock := testutil.NewManualClock(time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC))
	authService, err := auth.New(auth.Config{
		Users: catalog.Users, Tokens: catalog.Tokens, Audit: catalog.Audit,
		Clock: clock, Rand: testutil.FixedRand("66666666-6666-4666-8666-666666666666"),
		JWTSecret: cfg.Auth.JWTSecret, SessionTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	cacheEngine := cacheengine.New(storage, catalog.ObjIndex, http.DefaultClient, clock, cacheengine.Config{}, metrics.NewCache())
	tasks := web.NewTaskRegistry(2, clock)
	publishEngine := publishengine.New(publishengine.Config{MaxObjectSize: cfg.Publish.MaxObjectSize.Bytes}, storage, catalog.Repos, clock, wireRepoAdaptersForTest(signer, clock))
	publishAPI := publishSyncerTest{engine: publishEngine, repos: catalog.Repos, tasks: tasks}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := &web.Server{
		PublicAddr:    cfg.Server.PublicListen,
		PublicHandler: web.BuildPublicRouter(web.Deps{Log: log, Version: "test", Cache: cacheEngine, Storage: storage, Repos: catalog.Repos, Signer: signer}),
		AdminAddr:     cfg.Server.AdminListen,
		AdminHandler: web.BuildAdminRouter(web.Deps{
			Log: log, Version: "test", Auth: authService, Cache: cacheEngine,
			Repos: catalog.Repos, Storage: storage, Audit: catalog.Audit,
			Tasks: tasks, Publish: publishAPI, Clock: clock,
		}),
		Log:       log,
		WaitTasks: tasks.WaitAll,
	}
	return srv, publicAddr, adminAddr
}

// publishSyncerTest — копия cmd.publishSyncer для интеграционного теста:
// обёртка publish.Engine под web.PublishAPI. Сигнатуры идентичны.
type publishSyncerTest struct {
	engine *publishengine.Engine
	repos  port.RepoStore
	tasks  *web.TaskRegistry
}

func (p publishSyncerTest) Upload(ctx context.Context, repo domain.Repo, path string, size int64, body io.Reader, force bool) error {
	return p.engine.Upload(ctx, repo, path, size, body, force)
}

func (p publishSyncerTest) DeleteObject(ctx context.Context, repo domain.Repo, path string) error {
	return p.engine.Delete(ctx, repo, path)
}

func (p publishSyncerTest) ListObjects(ctx context.Context, repo domain.Repo) iter.Seq2[port.Meta, error] {
	return p.engine.List(ctx, repo)
}

func (p publishSyncerTest) Reindex(ctx context.Context, repoID int64) (string, error) {
	repo, err := p.repos.Repo(ctx, repoID)
	if err != nil {
		return "", err
	}
	return p.tasks.Start("reindex", repo.Name, func(ctx context.Context, prog web.Progress) error {
		fresh, err := p.repos.Repo(ctx, repoID)
		if err != nil {
			return fmt.Errorf("reindex: repo: %w", err)
		}
		return p.engine.Reindex(ctx, fresh, publishProgressTest{p: prog})
	})
}

type publishProgressTest struct{ p web.Progress }

func (pp publishProgressTest) Update(phase, current string, processed, total int64) {
	pp.p.Update(phase, current, processed, total)
}
func (pp publishProgressTest) Log(line string) { pp.p.Log(line) }

// wireRepoAdaptersForTest — копия wireRepoAdapters из cmd/wire.go.
// signer (если не nil) внедряется в адаптеры через port.SignerInjector,
// clock — через port.ClockInjector (Date в Release).
func wireRepoAdaptersForTest(signer port.Signer, clock port.Clock) map[string]port.RepoAdapter {
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
		if signer != nil {
			if inj, ok := adapter.(port.SignerInjector); ok {
				inj.SetSigner(signer)
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

// buildDebIntegration — собирает валидный .deb с control-станзой,
// без подписи. Возвращает байты .deb.
func buildDebIntegration(t *testing.T, control string) []byte {
	t.Helper()
	var ar bytes.Buffer
	fmt.Fprintf(&ar, "%s", "!<arch>\n")
	// debian-binary
	fmt.Fprintf(&ar, "%-16s%-12d%-6d%-6d%-8o%-10d`\n", "debian-binary/", 0, 0, 0, 0o100644, 4)
	ar.Write([]byte("2.0\n"))
	// control.tar.gz
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	content := []byte(control)
	_ = tw.WriteHeader(&tar.Header{Name: "./control", Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(content)
	_ = tw.Close()
	var gzBuf bytes.Buffer
	gz := gzip.NewWriter(&gzBuf)
	_, _ = gz.Write(tarBuf.Bytes())
	_ = gz.Close()
	fmt.Fprintf(&ar, "%-16s%-12d%-6d%-6d%-8o%-10d`\n", "control.tar.gz/", 0, 0, 0, 0o100644, gzBuf.Len())
	ar.Write(gzBuf.Bytes())
	// data.tar.gz: пустой tar
	var dataTar bytes.Buffer
	dtw := tar.NewWriter(&dataTar)
	_ = dtw.Close()
	var dataGz bytes.Buffer
	dgz := gzip.NewWriter(&dataGz)
	_, _ = dgz.Write(dataTar.Bytes())
	_ = dgz.Close()
	fmt.Fprintf(&ar, "%-16s%-12d%-6d%-6d%-8o%-10d`\n", "data.tar.gz/", 0, 0, 0, 0o100644, dataGz.Len())
	ar.Write(dataGz.Bytes())
	return ar.Bytes()
}

// TestPublishE2E — полный цикл личного репо через HTTP:
// setup admin → create repo → upload .deb → reindex → публичный GET
// Packages парсится apt.Stanzas (свой парсер проверяет генератор).
func TestPublishE2E(t *testing.T) {
	srv, publicAddr, adminAddr := publishIntegrationEnv(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	waitHealthy(t, "http://"+adminAddr+"/healthz")

	// setup admin (POST /setup создаёт первого админа).
	post(t, "http://"+adminAddr+"/api/v1/setup", `{"username":"admin","password":"password"}`, "", 201)
	token := login(t, adminAddr, "admin", "password")

	// create repo: admin (id=1) создаёт репо, owner_id=1.
	repoBody := `{"name":"alice","owner_id":1,"ecosystem":"apt","quota":{"max_bytes":0,"max_objects":0}}`
	resp := post(t, "http://"+adminAddr+"/api/v1/repos", repoBody, token, 201)
	var created map[string]any
	if err := json.Unmarshal(resp, &created); err != nil {
		t.Fatal(err)
	}
	repoID := int64(created["id"].(float64))

	// build .deb (control-stanza с Package/Version/Arch).
	control := "Package: foo\nVersion: 1.0-1\nArchitecture: amd64\nDescription: test\n"
	deb := buildDebIntegration(t, control)

	// PUT .deb через admin API.
	putURL := fmt.Sprintf("http://%s/api/v1/repos/%d/objects/pool/main/f/foo.deb", adminAddr, repoID)
	req, _ := http.NewRequest(http.MethodPut, putURL, bytes.NewReader(deb))
	req.ContentLength = int64(len(deb))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/octet-stream")
	putResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if putResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(putResp.Body)
		t.Fatalf("PUT .deb = %d, тело %s", putResp.StatusCode, body)
	}
	_ = putResp.Body.Close()

	// POST reindex.
	reindexURL := fmt.Sprintf("http://%s/api/v1/repos/%d/reindex", adminAddr, repoID)
	reindexResp := post(t, reindexURL, "", token, 202)
	var taskResp map[string]string
	_ = json.Unmarshal(reindexResp, &taskResp)
	taskID := taskResp["task_id"]

	// Ждём завершения задачи reindex (poll /tasks/{id}).
	deadline := time.Now().Add(3 * time.Second)
	state := ""
	for time.Now().Before(deadline) {
		taskBody := get(t, "http://"+adminAddr+"/api/v1/tasks/"+taskID, token, 200)
		var task map[string]any
		_ = json.Unmarshal(taskBody, &task)
		state, _ = task["state"].(string)
		if state == "succeeded" || state == "failed" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if state != "succeeded" {
		t.Fatalf("reindex не завершился успешно, state=%s", state)
	}

	// Публичный GET Packages: apt-get-клиент обращается с заглавной P,
	// публичный роутер лоуэркейсит запрос при lookup'е в Storage.
	pkgURL := fmt.Sprintf("http://%s/repo/alice/dists/stable/main/binary-amd64/Packages", publicAddr)
	pkgResp, err := http.Get(pkgURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pkgResp.Body.Close()
	if pkgResp.StatusCode != http.StatusOK {
		t.Fatalf("GET Packages = %d, хочу 200", pkgResp.StatusCode)
	}
	pkgBody, _ := io.ReadAll(pkgResp.Body)
	for _, want := range []string{
		"Package: foo",
		"Version: 1.0-1",
		"Filename: pool/main/f/foo.deb",
	} {
		if !strings.Contains(string(pkgBody), want) {
			t.Errorf("Packages не содержит %q:\n%s", want, pkgBody)
		}
	}

	// Публичный GET Release.
	releaseURL := fmt.Sprintf("http://%s/repo/alice/dists/stable/Release", publicAddr)
	releaseResp, err := http.Get(releaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseResp.Body.Close()
	releaseBody, _ := io.ReadAll(releaseResp.Body)
	if releaseResp.StatusCode != http.StatusOK {
		t.Fatalf("GET Release = %d", releaseResp.StatusCode)
	}
	for _, want := range []string{
		"Suite: stable",
		"Components: main",
		"Architectures: amd64",
		"Acquire-By-Hash: yes",
	} {
		if !strings.Contains(string(releaseBody), want) {
			t.Errorf("Release не содержит %q:\n%s", want, releaseBody)
		}
	}

	// Публичный GET самого .deb (проверка раздачи пакетов).
	debURL := fmt.Sprintf("http://%s/repo/alice/pool/main/f/foo.deb", publicAddr)
	debResp, err := http.Get(debURL)
	if err != nil {
		t.Fatal(err)
	}
	defer debResp.Body.Close()
	if debResp.StatusCode != http.StatusOK {
		t.Fatalf("GET .deb = %d, хочу 200", debResp.StatusCode)
	}
	gotDeb, _ := io.ReadAll(debResp.Body)
	if !bytes.Equal(gotDeb, deb) {
		t.Errorf(".deb отдан неверно: want %d байт, got %d", len(deb), len(gotDeb))
	}
	// Cache-Control: immutable для pool/*.
	if cc := debResp.Header.Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Errorf("Cache-Control .deb = %q, want immutable", cc)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("сервер завершился с ошибкой: %v", err)
	}
}

// openpgpSignerForTest собирает port.Signer через реестр (mod/sign/
// openpgp) с keys_dir под t.TempDir(): ключ генерируется на первом
// старте, как в продакшн-wire. Возвращает готовый Signer.
func openpgpSignerForTest(t *testing.T) port.Signer {
	t.Helper()
	keysDir := filepath.Join(t.TempDir(), "keys")
	factory, err := registry.Signer("openpgp")
	if err != nil {
		t.Fatalf("registry.Signer openpgp: %v (blank-import забыли?)", err)
	}
	signer, err := factory(config.Signing{KeysDir: keysDir}, testutil.NewManualClock(time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatalf("openpgp factory: %v", err)
	}
	return signer
}

// waitForReindex запускает reindex и polling /tasks/{id} до succeeded.
func waitForReindex(t *testing.T, adminAddr, token string, repoID int64) {
	t.Helper()
	reindexURL := fmt.Sprintf("http://%s/api/v1/repos/%d/reindex", adminAddr, repoID)
	reindexResp := post(t, reindexURL, "", token, 202)
	var taskResp map[string]string
	_ = json.Unmarshal(reindexResp, &taskResp)
	taskID := taskResp["task_id"]
	deadline := time.Now().Add(5 * time.Second)
	state := ""
	for time.Now().Before(deadline) {
		taskBody := get(t, "http://"+adminAddr+"/api/v1/tasks/"+taskID, token, 200)
		var task map[string]any
		_ = json.Unmarshal(taskBody, &task)
		state, _ = task["state"].(string)
		if state == "succeeded" || state == "failed" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if state != "succeeded" {
		t.Fatalf("reindex не завершился успешно, state=%s", state)
	}
}

// TestPublishSignedE2E — полный цикл личного apt-репо с подписью:
// ключ инстанса генерируется -> upload .deb -> reindex -> публичные
// InRelease (cleartext) и Release.gpg (detached) верифицируются
// go-crypto под ключом, отданным через GET /repo/<name>/key.asc.
// Реальный apt-get update требует Debian-образа — это smoke-тест
// сессии 18; здесь проверка подписей валидным OpenPGP-стеком.
func TestPublishSignedE2E(t *testing.T) {
	signer := openpgpSignerForTest(t)
	srv, publicAddr, adminAddr := publishIntegrationEnv(t, signer)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	waitHealthy(t, "http://"+adminAddr+"/healthz")

	post(t, "http://"+adminAddr+"/api/v1/setup", `{"username":"admin","password":"password"}`, "", 201)
	token := login(t, adminAddr, "admin", "password")

	repoBody := `{"name":"alice","owner_id":1,"ecosystem":"apt","quota":{"max_bytes":0,"max_objects":0}}`
	resp := post(t, "http://"+adminAddr+"/api/v1/repos", repoBody, token, 201)
	var created map[string]any
	if err := json.Unmarshal(resp, &created); err != nil {
		t.Fatal(err)
	}
	repoID := int64(created["id"].(float64))

	deb := buildDebIntegration(t, "Package: foo\nVersion: 1.0-1\nArchitecture: amd64\nDescription: test\n")
	putURL := fmt.Sprintf("http://%s/api/v1/repos/%d/objects/pool/main/f/foo.deb", adminAddr, repoID)
	req, _ := http.NewRequest(http.MethodPut, putURL, bytes.NewReader(deb))
	req.ContentLength = int64(len(deb))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/octet-stream")
	putResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if putResp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(putResp.Body)
		t.Fatalf("PUT .deb = %d, тело %s", putResp.StatusCode, b)
	}
	_ = putResp.Body.Close()

	waitForReindex(t, adminAddr, token, repoID)

	// GET /repo/alice/key.asc — публичный ключ инстанса.
	keyURL := fmt.Sprintf("http://%s/repo/alice/key.asc", publicAddr)
	keyResp, err := http.Get(keyURL)
	if err != nil {
		t.Fatal(err)
	}
	if keyResp.StatusCode != http.StatusOK {
		t.Fatalf("GET key.asc = %d", keyResp.StatusCode)
	}
	keyBody, _ := io.ReadAll(keyResp.Body)
	keyResp.Body.Close()
	if !bytes.Contains(keyBody, []byte("BEGIN PGP PUBLIC KEY BLOCK")) {
		t.Fatalf("key.asc не armored: %q", keyBody)
	}
	kring, err := gp.ReadArmoredKeyRing(bytes.NewReader(keyBody))
	if err != nil {
		t.Fatalf("ReadArmoredKeyRing key.asc: %v", err)
	}
	if len(kring) == 0 {
		t.Fatal("пустой keyring из key.asc")
	}

	// GET Release (сырое тело — то, что подписано).
	releaseURL := fmt.Sprintf("http://%s/repo/alice/dists/stable/Release", publicAddr)
	releaseResp, err := http.Get(releaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if releaseResp.StatusCode != http.StatusOK {
		t.Fatalf("GET Release = %d", releaseResp.StatusCode)
	}
	releaseBody, _ := io.ReadAll(releaseResp.Body)
	releaseResp.Body.Close()

	// GET InRelease — cleartext-подпись Release; verify под ключом.
	inRelURL := fmt.Sprintf("http://%s/repo/alice/dists/stable/InRelease", publicAddr)
	inRelResp, err := http.Get(inRelURL)
	if err != nil {
		t.Fatal(err)
	}
	if inRelResp.StatusCode != http.StatusOK {
		t.Fatalf("GET InRelease = %d", inRelResp.StatusCode)
	}
	inRelBody, _ := io.ReadAll(inRelResp.Body)
	inRelResp.Body.Close()
	if !bytes.Contains(inRelBody, []byte("BEGIN PGP SIGNED MESSAGE")) {
		t.Fatalf("InRelease не cleartext: %q", inRelBody[:min(80, len(inRelBody))])
	}
	block, _ := clearsign.Decode(inRelBody)
	if block == nil {
		t.Fatal("clearsign.Decode InRelease nil")
	}
	want := bytes.ReplaceAll(releaseBody, []byte("\n"), []byte("\r\n"))
	if string(block.Bytes) != string(want) {
		t.Errorf("InRelease payload ≠ Release (CRLF-каноникализed)")
	}
	if _, err := block.VerifySignature(kring, &packet.Config{}); err != nil {
		t.Errorf("InRelease verify под key.asc: %v", err)
	}

	// GET Release.gpg — бинарная detached-подпись Release; verify.
	relGpgURL := fmt.Sprintf("http://%s/repo/alice/dists/stable/Release.gpg", publicAddr)
	relGpgResp, err := http.Get(relGpgURL)
	if err != nil {
		t.Fatal(err)
	}
	if relGpgResp.StatusCode != http.StatusOK {
		t.Fatalf("GET Release.gpg = %d", relGpgResp.StatusCode)
	}
	relGpgBody, _ := io.ReadAll(relGpgResp.Body)
	relGpgResp.Body.Close()
	if bytes.Contains(relGpgBody, []byte("BEGIN PGP")) {
		t.Errorf("Release.gpg должен быть бинарным, не armored")
	}
	if _, err := gp.CheckDetachedSignature(kring, bytes.NewReader(releaseBody), bytes.NewReader(relGpgBody), &packet.Config{}); err != nil {
		t.Errorf("Release.gpg verify под key.asc: %v", err)
	}

	// Tamper: та же сигнатура, подменённый Release — verify обязан упасть.
	tampered := bytes.Replace(releaseBody, []byte("Suite: stable"), []byte("Suite: evil1"), 1)
	if _, err := gp.CheckDetachedSignature(kring, bytes.NewReader(tampered), bytes.NewReader(relGpgBody), &packet.Config{}); err == nil {
		t.Error("ожидалась ошибка verify для tampered Release")
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("сервер завершился с ошибкой: %v", err)
	}
}
