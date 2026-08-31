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

package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"iter"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/engine/auth"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/testutil"
)

// repoEnv — собранные депсы для тестов /api/v1/repos* и публичного
// роутера. Каждый тест — свежие фейки.
type repoEnv struct {
	admin    http.Handler
	public   http.Handler
	auth     *auth.Service
	repos    *testutil.FakeRepoStore
	storage  *testutil.FakeStorage
	publish  *publishStub
	audit    *testutil.FakeAuditLog
	clock    *testutil.ManualClock
	jwtAdmin string
	jwtUser  string
	jwtOther string
	apiAdmin string
}

// publishStub — web.PublishAPI для тестов: реальный движок publish
// тестируется в internal/core/engine/publish; здесь — тривиальные
// обёртки, чтобы проверить API-контракт (RBAC, статусы, ETag).
type publishStub struct {
	storage port.Storage
	uploads map[string][]byte
}

func newPublishStub(storage port.Storage) *publishStub {
	return &publishStub{storage: storage, uploads: map[string][]byte{}}
}

func (p *publishStub) Upload(_ context.Context, repo domain.Repo, path string, _ int64, body io.Reader, force bool) error {
	key := port.RepoPrefix(repo) + "/" + path
	if !force {
		if _, err := p.storage.Stat(context.Background(), key); err == nil {
			return &domain.ConflictError{What: "объект", Key: key}
		}
	}
	b := make([]byte, 1024)
	n, _ := body.Read(b)
	w, err := p.storage.Put(context.Background(), key)
	if err != nil {
		return err
	}
	_, _ = w.Write(b[:n])
	if err := w.Commit(context.Background()); err != nil {
		_ = w.Abort(context.Background())
		return err
	}
	p.uploads[key] = b[:n]
	return nil
}

func (p *publishStub) DeleteObject(_ context.Context, repo domain.Repo, path string) error {
	key := port.RepoPrefix(repo) + "/" + path
	return p.storage.Delete(context.Background(), key)
}

func (p *publishStub) ListObjects(ctx context.Context, repo domain.Repo) iter.Seq2[port.Meta, error] {
	return p.storage.List(ctx, "repo/"+itoaRepo(repo.ID)+"/")
}

func (p *publishStub) Reindex(_ context.Context, _ int64) (string, error) {
	return "reindex-stub", nil
}

// itoaRepo — локальная обёртка strconv, чтобы не плодить импорт.
func itoaRepo(n int64) string {
	if n == 0 {
		return "0"
	}
	const digits = "0123456789"
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = digits[n%10]
		n /= 10
	}
	return string(b[i:])
}

func newRepoEnv(t *testing.T) *repoEnv {
	t.Helper()
	users := testutil.NewFakeUserStore()
	tokens := &handlerTokens{}
	clock := testutil.NewManualClock(time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC))
	a, err := auth.New(auth.Config{
		Users: users, Tokens: tokens, Audit: nil, Revocations: testutil.NewFakeRevocations(),
		Clock: clock, Rand: testutil.FixedRand("55555555-5555-4555-8555-555555555555"),
		JWTSecret: "secret", SessionTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	admin, _ := a.CreateUser(t.Context(), "admin", "password", domain.RoleAdmin)
	user, _ := a.CreateUser(t.Context(), "alice", "password", domain.RoleUser)
	other, _ := a.CreateUser(t.Context(), "bob", "password", domain.RoleUser)
	jwtAdmin, _ := a.IssueSession(t.Context(), admin)
	jwtUser, _ := a.IssueSession(t.Context(), user)
	jwtOther, _ := a.IssueSession(t.Context(), other)
	_, apiAdmin, _ := a.IssueAPIToken(t.Context(), admin, "admin-token", []domain.Scope{domain.ScopeAdmin}, 0)
	repos := testutil.NewFakeRepoStore()
	storage := testutil.NewFakeStorage(clock)
	publish := newPublishStub(storage)
	auditLog := testutil.NewFakeAuditLog()
	tasks := NewTaskRegistry(2, clock)
	adminH := BuildAdminRouter(Deps{
		Log: nil, Version: "test", Auth: a, SetupToken: "setup",
		Repos: repos, Storage: storage, Audit: auditLog,
		Tasks: tasks, Publish: publish, Clock: clock,
	})
	publicH := BuildPublicRouter(Deps{Log: nil, Version: "test", Cache: nil, Ecosystems: nil, Storage: storage, Repos: repos, Signer: &fakeKeySigner{}})
	return &repoEnv{
		admin: adminH, public: publicH, auth: a, repos: repos,
		storage: storage, publish: publish, audit: auditLog, clock: clock,
		jwtAdmin: jwtAdmin, jwtUser: jwtUser, jwtOther: jwtOther, apiAdmin: apiAdmin,
	}
}

// fakeKeySigner — port.Signer для тестов публичного роутера: отдаёт
// фиктивный armored-блок. Реальная подпись метаданных тестируется в
// mod/sign/openpgp и mod/ecosystem/apt.
type fakeKeySigner struct{}

func (fakeKeySigner) Sign(context.Context, io.Reader) (io.Reader, error) {
	return nil, errors.New("not used in /key.asc")
}
func (fakeKeySigner) SignDetached(context.Context, io.Reader) (io.Reader, error) {
	return nil, errors.New("not used in /key.asc")
}
func (fakeKeySigner) PublicKey() ([]byte, error) {
	return []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\nfake\n-----END PGP PUBLIC KEY BLOCK-----\n"), nil
}

func callRepo(env *repoEnv, method, path, body, bearer string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "10.0.0.9:1"
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	env.admin.ServeHTTP(rec, r)
	return rec
}

// createRepoViaAPI — POST /api/v1/repos от админа; возвращает ID.
func createRepoViaAPI(t *testing.T, env *repoEnv, name string, ownerID int64) int64 {
	t.Helper()
	body := `{"name":"` + name + `","owner_id":` + itoaRepo(ownerID) + `,"ecosystem":"apt","quota":{"max_bytes":0,"max_objects":0}}`
	rec := callRepo(env, http.MethodPost, "/api/v1/repos", body, env.jwtAdmin)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create repo = %d, тело %s", rec.Code, rec.Body.String())
	}
	var created repoOut
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	return created.ID
}

// issueRepoWriteToken — выпускает scoped-токен repo:<repoID>:write
// для userID через auth.Service.
func issueRepoWriteToken(t *testing.T, env *repoEnv, userID int64, repoID int64) string {
	t.Helper()
	u, err := env.auth.User(t.Context(), userID)
	if err != nil {
		t.Fatal(err)
	}
	scopes := []domain.Scope{domain.Scope("repo:" + itoaRepo(repoID) + ":write")}
	_, raw, err := env.auth.IssueAPIToken(t.Context(), u, "repo-write", scopes, 0)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestReposAdminCRUD(t *testing.T) {
	env := newRepoEnv(t)
	// Create.
	rec := callRepo(env, http.MethodPost, "/api/v1/repos", `{"name":"alice","owner_id":2,"ecosystem":"apt","quota":{"max_bytes":1024,"max_objects":10}}`, env.jwtAdmin)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d, %s", rec.Code, rec.Body.String())
	}
	var created repoOut
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Name != "alice" || created.OwnerID != 2 || created.Ecosystem != "apt" {
		t.Errorf("create bad: %+v", created)
	}
	if created.Quota.MaxBytes != 1024 || created.Quota.MaxObjects != 10 {
		t.Errorf("quota bad: %+v", created.Quota)
	}
	// List.
	rec = callRepo(env, http.MethodGet, "/api/v1/repos", "", env.jwtAdmin)
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d", rec.Code)
	}
	// Get.
	rec = callRepo(env, http.MethodGet, "/api/v1/repos/1", "", env.jwtAdmin)
	if rec.Code != http.StatusOK {
		t.Fatalf("get = %d", rec.Code)
	}
	// Patch.
	rec = callRepo(env, http.MethodPatch, "/api/v1/repos/1", `{"name":"alice2","owner_id":2,"ecosystem":"apt","quota":{"max_bytes":2048,"max_objects":20}}`, env.jwtAdmin)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch = %d, %s", rec.Code, rec.Body.String())
	}
	var updated repoOut
	_ = json.Unmarshal(rec.Body.Bytes(), &updated)
	if updated.Name != "alice2" || updated.Quota.MaxBytes != 2048 {
		t.Errorf("patch bad: %+v", updated)
	}
	// Delete.
	rec = callRepo(env, http.MethodDelete, "/api/v1/repos/1", "", env.jwtAdmin)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d", rec.Code)
	}
}

func TestReposNonAdminForbidden(t *testing.T) {
	env := newRepoEnv(t)
	// Non-admin JWT cannot create repo.
	rec := callRepo(env, http.MethodPost, "/api/v1/repos", `{"name":"alice","owner_id":2,"ecosystem":"apt","quota":{}}`, env.jwtUser)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin create = %d, want 403", rec.Code)
	}
}

func TestRepoUploadRBAC(t *testing.T) {
	env := newRepoEnv(t)
	// admin creates repo owned by user (id=2 alice).
	repoID := createRepoViaAPI(t, env, "alice", 2)
	body := []byte("hello apt")
	bodyStr := string(body)

	// RBAC матрица:
	cases := []struct {
		name   string
		bearer string
		status int
	}{
		{"admin session", env.jwtAdmin, http.StatusCreated},
		{"admin token", env.apiAdmin, http.StatusCreated},
		{"owner session", env.jwtUser, http.StatusCreated},
		{"scoped token", issueRepoWriteToken(t, env, 2, repoID), http.StatusCreated},
		{"other user", env.jwtOther, http.StatusForbidden},
		{"no auth", "", http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := "pool/main/a/" + strings.ReplaceAll(tc.name, " ", "_") + ".deb"
			req := httptest.NewRequest(http.MethodPut, "/api/v1/repos/"+itoaRepo(repoID)+"/objects/"+path, strings.NewReader(bodyStr))
			req.ContentLength = int64(len(body))
			req.RemoteAddr = "10.0.0.9:1"
			if tc.bearer != "" {
				req.Header.Set("Authorization", "Bearer "+tc.bearer)
			}
			rec := httptest.NewRecorder()
			env.admin.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Errorf("%s: status = %d, want %d, тело %s", tc.name, rec.Code, tc.status, rec.Body.String())
			}
		})
	}
}

func TestRepoUploadConflict(t *testing.T) {
	env := newRepoEnv(t)
	repoID := createRepoViaAPI(t, env, "alice", 2)
	body := []byte("hello apt")
	// First upload.
	req := httptest.NewRequest(http.MethodPut, "/api/v1/repos/"+itoaRepo(repoID)+"/objects/pool/main/a/foo.deb", bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Set("Authorization", "Bearer "+env.jwtAdmin)
	rec := httptest.NewRecorder()
	env.admin.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("первый upload = %d, %s", rec.Code, rec.Body.String())
	}
	// Second upload — conflict (no force).
	req2 := httptest.NewRequest(http.MethodPut, "/api/v1/repos/"+itoaRepo(repoID)+"/objects/pool/main/a/foo.deb", bytes.NewReader(body))
	req2.ContentLength = int64(len(body))
	req2.Header.Set("Authorization", "Bearer "+env.jwtAdmin)
	rec2 := httptest.NewRecorder()
	env.admin.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusConflict {
		t.Fatalf("повторный upload без force = %d, want 409", rec2.Code)
	}
	// Force upload — admin override.
	req3 := httptest.NewRequest(http.MethodPut, "/api/v1/repos/"+itoaRepo(repoID)+"/objects/pool/main/a/foo.deb?force=true", bytes.NewReader([]byte("v2")))
	req3.ContentLength = 2
	req3.Header.Set("Authorization", "Bearer "+env.jwtAdmin)
	rec3 := httptest.NewRecorder()
	env.admin.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusCreated {
		t.Fatalf("upload с force = %d, want 201", rec3.Code)
	}
}

// TestRepoUploadForceAdminOnly — force=admin-сессия (аудит 2026-08-27):
// scoped-токен repo:<id>:write, не-админ-владелец и admin-scoped
// API-токен перезапись опубликованных объектов не делают (403
// admin_required); конфликт без force — 409 как раньше.
func TestRepoUploadForceAdminOnly(t *testing.T) {
	env := newRepoEnv(t)
	repoID := createRepoViaAPI(t, env, "alice", 2)
	path := "/api/v1/repos/" + itoaRepo(repoID) + "/objects/pool/main/a/foo.deb"

	put := func(bearer string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, path+"?force=true", strings.NewReader("v2"))
		req.ContentLength = 2
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		rec := httptest.NewRecorder()
		env.admin.ServeHTTP(rec, req)
		return rec
	}

	// Объект существует (владелец загружает без force).
	first := httptest.NewRequest(http.MethodPut, path, strings.NewReader("v1"))
	first.ContentLength = 2
	first.Header.Set("Authorization", "Bearer "+env.jwtUser)
	rec := httptest.NewRecorder()
	env.admin.ServeHTTP(rec, first)
	if rec.Code != http.StatusCreated {
		t.Fatalf("первый upload владельцем = %d, want 201", rec.Code)
	}

	for name, tc := range map[string]struct {
		bearer string
		status int
	}{
		"scoped token":  {issueRepoWriteToken(t, env, 2, repoID), http.StatusForbidden},
		"owner session": {env.jwtUser, http.StatusForbidden},
		"admin token":   {env.apiAdmin, http.StatusForbidden},
		// без auth RequireRepoAccess отсекает раньше хендлера — 401.
		"no auth": {"", http.StatusUnauthorized},
	} {
		if w := put(tc.bearer); w.Code != tc.status {
			t.Errorf("%s: force = %d, want %d (тело %s)", name, w.Code, tc.status, w.Body.String())
		} else if tc.status == http.StatusForbidden && !strings.Contains(w.Body.String(), "admin_required") {
			t.Errorf("%s: код ошибки = %s, хочу admin_required", name, w.Body.String())
		}
	}
	// Админ-сессия проходит.
	if w := put(env.jwtAdmin); w.Code != http.StatusCreated {
		t.Errorf("admin session: force = %d, want 201 (тело %s)", w.Code, w.Body.String())
	}
	// Повторная загрузка без force — по-прежнему 409 (не сломали).
	req := httptest.NewRequest(http.MethodPut, path, strings.NewReader("v3"))
	req.ContentLength = 2
	req.Header.Set("Authorization", "Bearer "+env.jwtAdmin)
	rec2 := httptest.NewRecorder()
	env.admin.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusConflict {
		t.Errorf("повторный upload без force = %d, want 409", rec2.Code)
	}
}

func TestRepoUploadNoContentLength(t *testing.T) {
	env := newRepoEnv(t)
	repoID := createRepoViaAPI(t, env, "alice", 2)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/repos/"+itoaRepo(repoID)+"/objects/pool/main/a/foo.deb", strings.NewReader("x"))
	// No Content-Length set (chunked); net/http normally sets it for
	// string readers, so manually unset.
	req.ContentLength = -1
	req.Header.Set("Authorization", "Bearer "+env.jwtAdmin)
	rec := httptest.NewRecorder()
	env.admin.ServeHTTP(rec, req)
	if rec.Code != http.StatusLengthRequired {
		t.Fatalf("no Content-Length = %d, want 411", rec.Code)
	}
}

func TestRepoReindex(t *testing.T) {
	env := newRepoEnv(t)
	repoID := createRepoViaAPI(t, env, "alice", 2)
	rec := callRepo(env, http.MethodPost, "/api/v1/repos/"+itoaRepo(repoID)+"/reindex", "", env.jwtAdmin)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("reindex = %d, %s", rec.Code, rec.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["task_id"] == "" {
		t.Errorf("task_id пустой в ответе reindex")
	}
}

// Публичный роутер: раздача объектов репо.
func TestPublicRepoFile(t *testing.T) {
	env := newRepoEnv(t)
	repoID := createRepoViaAPI(t, env, "alice", 2)
	// Upload through admin API.
	body := []byte("hello apt")
	req := httptest.NewRequest(http.MethodPut, "/api/v1/repos/"+itoaRepo(repoID)+"/objects/pool/main/a/foo.deb", bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Set("Authorization", "Bearer "+env.jwtAdmin)
	rec := httptest.NewRecorder()
	env.admin.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload = %d", rec.Code)
	}
	// Public GET without auth.
	getReq := httptest.NewRequest(http.MethodGet, "/repo/alice/pool/main/a/foo.deb", nil)
	getRec := httptest.NewRecorder()
	env.public.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("public GET = %d, want 200", getRec.Code)
	}
	if !bytes.Equal(getRec.Body.Bytes(), body) {
		t.Errorf("body = %q, want %q", getRec.Body.String(), body)
	}
	// Cache-Control: immutable для pool/*.
	if cc := getRec.Header().Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Errorf("Cache-Control = %q, want immutable", cc)
	}
}

func TestPublicRepoFileNotFound(t *testing.T) {
	env := newRepoEnv(t)
	createRepoViaAPI(t, env, "alice", 2)
	// Repo exists, file doesn't.
	req := httptest.NewRequest(http.MethodGet, "/repo/alice/pool/main/a/ghost.deb", nil)
	rec := httptest.NewRecorder()
	env.public.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("public GET ghost = %d, want 404", rec.Code)
	}
	// Repo doesn't exist.
	req2 := httptest.NewRequest(http.MethodGet, "/repo/ghost/pool/main/a/foo.deb", nil)
	rec2 := httptest.NewRecorder()
	env.public.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusNotFound {
		t.Errorf("public GET unknown repo = %d, want 404", rec2.Code)
	}
}

// TestPublicRepoFileInvalidKeyPath — мусорный путь клиента («..»)
// отдаёт 400 invalid_key/«invalid storage path», а не 5xx-флод в
// логах (аудит 2026-08-27).
func TestPublicRepoFileInvalidKeyPath(t *testing.T) {
	env := newRepoEnv(t)
	createRepoViaAPI(t, env, "alice", 2)
	for _, path := range []string{"/repo/alice/../../y", "/repo/alice/pool/../a.deb"} {
		rec := httptest.NewRecorder()
		env.public.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("GET %s = %d, хочу 400 (тело %s)", path, rec.Code, rec.Body.String())
		}
	}
}

func TestPublicRepoKey(t *testing.T) {
	env := newRepoEnv(t)
	createRepoViaAPI(t, env, "alice", 2)
	// /repo/<existing>/key.asc — публичный ключ инстанса.
	req := httptest.NewRequest(http.MethodGet, "/repo/alice/key.asc", nil)
	rec := httptest.NewRecorder()
	env.public.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET key.asc = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("BEGIN PGP PUBLIC KEY BLOCK")) {
		t.Errorf("тело key.asc не armored: %q", rec.Body.String())
	}
}

func TestPublicRepoKey_UnknownRepo404(t *testing.T) {
	env := newRepoEnv(t)
	req := httptest.NewRequest(http.MethodGet, "/repo/ghost/key.asc", nil)
	rec := httptest.NewRecorder()
	env.public.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET key.asc для несуществующего репо = %d, want 404", rec.Code)
	}
}

func TestPublicRepoKey_NilSigner503(t *testing.T) {
	// Без Signer (деградированный режим) /key.asc не регистрируется
	// вообще — BuildPublicRouter пропускает роут. Проверяем что роут
	// отсутствует: запрос уходит в 404 (chi default), а не в handler.
	storage := testutil.NewFakeStorage(testutil.FixedClock(time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)))
	repos := testutil.NewFakeRepoStore()
	h := BuildPublicRouter(Deps{Storage: storage, Repos: repos}) // Signer nil
	req := httptest.NewRequest(http.MethodGet, "/repo/x/key.asc", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET key.asc без Signer = %d, want 404 (роут не зарегистрирован)", rec.Code)
	}
}

// fakeNarKeySigner — port.NarSigner для тестов публичного роутера:
// отдаёт фиктивный «name:pubkey-b64». Реальная narinfo-подпись
// тестируется в mod/sign/ed25519 и mod/ecosystem/nix.
type fakeNarKeySigner struct{}

func (fakeNarKeySigner) Sign(_ []byte) string { return "test:test-pub:test-sig==" }
func (fakeNarKeySigner) PubKeyB64() string    { return "test-pub" }
func (fakeNarKeySigner) Name() string         { return "test" }

// newRepoEnvWithNarSigner — repoEnv с публичным роутером, включающим
// NarSigner (для /nix-key.asc). Пересобирает только public router env,
// сохраняя storage/repos/auth/admin из newRepoEnv (чтобы createRepoViaAPI
// через env.admin создавал репо в том же repos, что видит public router).
func newRepoEnvWithNarSigner(t *testing.T) *repoEnv {
	t.Helper()
	env := newRepoEnv(t)
	// Пересоберём public router с NarSigner, на тех же storage/repos.
	env.public = BuildPublicRouter(Deps{
		Log: nil, Version: "test", Cache: nil, Ecosystems: nil,
		Storage: env.storage, Repos: env.repos,
		Signer:    &fakeKeySigner{},
		NarSigner: &fakeNarKeySigner{},
	})
	return env
}

func TestPublicRepoNixKey(t *testing.T) {
	env := newRepoEnvWithNarSigner(t)
	createRepoViaAPI(t, env, "alice", 2)
	// /repo/<existing>/nix-key.asc — публичный narinfo-ключ инстанса.
	req := httptest.NewRequest(http.MethodGet, "/repo/alice/nix-key.asc", nil)
	rec := httptest.NewRecorder()
	env.public.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET nix-key.asc = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	// Формат trusted-public-keys: «name:pubkey-b64\n».
	want := "test:test-pub\n"
	if rec.Body.String() != want {
		t.Errorf("тело nix-key.asc = %q, want %q", rec.Body.String(), want)
	}
}

func TestPublicRepoNixKey_UnknownRepo404(t *testing.T) {
	env := newRepoEnvWithNarSigner(t)
	req := httptest.NewRequest(http.MethodGet, "/repo/ghost/nix-key.asc", nil)
	rec := httptest.NewRecorder()
	env.public.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET nix-key.asc для несуществующего репо = %d, want 404", rec.Code)
	}
}

func TestPublicRepoNixKey_NilNarSigner404(t *testing.T) {
	// Без NarSigner (деградированный режим) /nix-key.asc не
	// регистрируется вообще — BuildPublicRouter пропускает роут.
	storage := testutil.NewFakeStorage(testutil.FixedClock(time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)))
	repos := testutil.NewFakeRepoStore()
	h := BuildPublicRouter(Deps{Storage: storage, Repos: repos}) // NarSigner nil
	req := httptest.NewRequest(http.MethodGet, "/repo/x/nix-key.asc", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET nix-key.asc без NarSigner = %d, want 404 (роут не зарегистрирован)", rec.Code)
	}
}
