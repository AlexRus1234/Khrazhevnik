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
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/testutil"
)

// failingRepoStore — обёртка store'а репо с инжектируемым сбоем
// RepoByName: connection-error каталога (сессия 50). err=nil возвращает
// обычное поведение фейка (NotFound/успех).
type failingRepoStore struct {
	port.RepoStore
	err error
}

func (s *failingRepoStore) RepoByName(ctx context.Context, name string) (domain.Repo, error) {
	if s.err != nil {
		return domain.Repo{}, s.err
	}
	return s.RepoStore.RepoByName(ctx, name)
}

// uploadRepoObject — upload через admin-API (как делает реальный
// публикующий пользователь) и возврат сохранённых байт для сверки
// byte-exact публичной раздачи.
func uploadRepoObject(t *testing.T, env *repoEnv, repoID int64, path string, body []byte) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/api/v1/repos/"+itoaRepo(repoID)+"/objects/"+path, strings.NewReader(string(body)))
	req.ContentLength = int64(len(body))
	req.Header.Set("Authorization", "Bearer "+env.jwtAdmin)
	rec := httptest.NewRecorder()
	env.admin.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload %s = %d, тело %s", path, rec.Code, rec.Body.String())
	}
}

// getPublic — GET публичного роутера.
func getPublic(t *testing.T, env *repoEnv, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	env.public.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// TestPublicRepoFileHTMLContentIsDownloadedNotRendered — ядро аудита
// 2026-08-30 (stored-XSS): объект, тело которого начинается с
// «<html», отдаётся с Content-Type application/octet-stream (тип по
// расширению, не по содержимому) и nosniff — браузер не рендерит его
// как страницу домена зеркала. Тело при этом byte-exact: заголовки
// ответа не переписывают сохранённые байты.
func TestPublicRepoFileHTMLContentIsDownloadedNotRendered(t *testing.T) {
	env := newRepoEnv(t)
	repoID := createRepoViaAPI(t, env, "alice", 2)
	evil := []byte("<html><script>alert(1)</script></html>")
	// Расширение .deb проходит ValidateObjectPath (apt-адаптер смотрит
	// только на путь) — содержимое не проверяется, в этом и вектор.
	uploadRepoObject(t, env, repoID, "pool/main/e/evil.deb", evil)

	rec := getPublic(t, env, "/repo/alice/pool/main/e/evil.deb")
	if rec.Code != http.StatusOK {
		t.Fatalf("public GET = %d, хочу 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("Content-Type HTML-подобного объекта = %q, хочу application/octet-stream", ct)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, хочу nosniff", got)
	}
	if rec.Body.String() != string(evil) {
		t.Errorf("тело не byte-exact: got %q, want %q", rec.Body.String(), evil)
	}
}

// TestPublicRepoFileContentTypesByExtension — маппинг «не сниффим»:
// .json → application/json; известные пакетные расширения и всё
// неизвестное → application/octet-stream (fail closed к скачиванию).
func TestPublicRepoFileContentTypesByExtension(t *testing.T) {
	for path, want := range map[string]string{
		"pool/main/a/foo.deb":     "application/octet-stream",
		"dists/stable/Release":    "application/octet-stream",
		"dists/stable/Packages":   "application/octet-stream",
		"dists/stable/other.json": "application/json",
		"dists/stable/Release.gz": "application/octet-stream",
		"dists/stable/unknown":    "application/octet-stream",
	} {
		if got := repoContentType(path); got != want {
			t.Errorf("repoContentType(%q) = %q, хочу %q", path, got, want)
		}
	}
}

// TestPublicRepoFileUnknownExtensionOctetStream — объект с
// неизвестным расширением и HTML-подобным телом отдаётся бинарём.
func TestPublicRepoFileUnknownExtensionOctetStream(t *testing.T) {
	env := newRepoEnv(t)
	repoID := createRepoViaAPI(t, env, "alice", 2)
	uploadRepoObject(t, env, repoID, "pool/main/e/evil.html", []byte("<script>alert(1)</script>"))

	rec := getPublic(t, env, "/repo/alice/pool/main/e/evil.html")
	if rec.Code != http.StatusOK {
		t.Fatalf("public GET = %d, хочу 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("Content-Type неизвестного расширения = %q, хочу application/octet-stream", ct)
	}
}

// TestPublicNoSniffOnEveryResponse — NoSniff стоит на всех ответах
// :29202 (сессия 36, задача 3): repo-объекты, key.asc/nix-key.asc и
// healthz — единый middleware публичного роутера.
func TestPublicNoSniffOnEveryResponse(t *testing.T) {
	env := newRepoEnvWithNarSigner(t)
	createRepoViaAPI(t, env, "alice", 2)

	// healthz — базовый ответ роутера.
	rec := getPublic(t, env, "/healthz")
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("healthz: X-Content-Type-Options = %q, хочу nosniff", got)
	}
	// key.asc — эксплицитный text/plain + nosniff не вредит.
	rec = getPublic(t, env, "/repo/alice/key.asc")
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("key.asc: X-Content-Type-Options = %q, хочу nosniff", got)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("key.asc: Content-Type = %q, хочу text/plain (существующий тип не сломан)", ct)
	}
	// nix-key.asc — аналогично.
	rec = getPublic(t, env, "/repo/alice/nix-key.asc")
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("nix-key.asc: X-Content-Type-Options = %q, хочу nosniff", got)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("nix-key.asc: Content-Type = %q, хочу text/plain", ct)
	}
	// 404 — тоже носит nosniff.
	rec = getPublic(t, env, "/repo/ghost/pool/main/a/foo.deb")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET неизвестного репо = %d, хочу 404", rec.Code)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("404: X-Content-Type-Options = %q, хочу nosniff", got)
	}
}

// TestPublicRepoCacheControlImmutable — content-addressed объекты всех
// экосистем получают Cache-Control immutable (сессия 45: раньше —
// только apt pool/, клиенты dnf/pacman/apk/nix реиспейсили пакеты
// понапрасну); индексы (repodata/, dists/) — без него: mutable.
// Исключение сессии 48 — nix narinfo: resign-on-reindex переписывает
// его под тем же ключом, поэтому no-cache, а не immutable; nar/*
// остаётся immutable (байты реально content-addressed).
// Репо rpm-md и nix создаются напрямую в store: env.Ecosystems
// реестра — про upload-гейт админ-API, публичная раздача смотрит
// repo.Ecosystem.
func TestPublicRepoCacheControlImmutable(t *testing.T) {
	env := newRepoEnv(t)
	rpmRepo, err := env.repos.CreateRepo(t.Context(), domain.Repo{Name: "fedora", OwnerID: 2, Ecosystem: "rpm-md", CreatedAt: env.clock.Now()})
	if err != nil {
		t.Fatal(err)
	}
	uploadRepoObject(t, env, rpmRepo.ID, "packages/f/foo-1.0-1.rpm", []byte("rpm"))
	uploadRepoObject(t, env, rpmRepo.ID, "repodata/repomd.xml", []byte("idx"))
	aptRepoID := createRepoViaAPI(t, env, "alice", 2)
	uploadRepoObject(t, env, aptRepoID, "pool/main/a/foo.deb", []byte("deb"))
	uploadRepoObject(t, env, aptRepoID, "dists/stable/Release", []byte("rel"))
	nixRepo, err := env.repos.CreateRepo(t.Context(), domain.Repo{Name: "nixcache", OwnerID: 2, Ecosystem: "nix", CreatedAt: env.clock.Now()})
	if err != nil {
		t.Fatal(err)
	}
	// Алфавит nix-base32 (без e/o/t/u): hash32 — хеш store path
	// narinfo, fileHash52 — хеш файла nar-архива (сессия 47);
	// литерал — по образцу narFileHash52 nix-парсера
	// (mod/ecosystem/nix/parse_test.go), 52 символа по контракту.
	const hash32 = "0123456789abcdfghijklmnpqrsvwxyz"
	const fileHash52 = "x0vm1mkfnqrq3hxjcp2wsz5l8h4cgd9yx0vm1mkfnqrq3hxjcp2w"
	uploadRepoObject(t, env, nixRepo.ID, hash32+".narinfo", []byte("narinfo"))
	uploadRepoObject(t, env, nixRepo.ID, "nar/"+fileHash52+".nar.xz", []byte("nar"))

	const immutable = "public, max-age=31536000, immutable"
	for path, want := range map[string]string{
		"/repo/fedora/packages/f/foo-1.0-1.rpm":        immutable,
		"/repo/fedora/repodata/repomd.xml":             "",
		"/repo/alice/pool/main/a/foo.deb":              immutable,
		"/repo/alice/dists/stable/Release":             "",
		"/repo/nixcache/" + hash32 + ".narinfo":        "no-cache",
		"/repo/nixcache/nar/" + fileHash52 + ".nar.xz": immutable,
	} {
		rec := getPublic(t, env, path)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, хочу 200", path, rec.Code)
		}
		if got := rec.Header().Get("Cache-Control"); got != want {
			t.Errorf("Cache-Control %s = %q, хочу %q", path, got, want)
		}
	}
}

// TestPublicRepoPacmanSuffixImmutable — суффиксный pacman-предикат
// (сессия 62): прежний Contains(".pkg.tar.") матчил slug репо — репо
// с точками в имени «x.pkg.tar.y» давало генерируемый ключ
// x.pkg.tar.y.db, отдающийся immutable (годовой пин мутируемого
// индекса). Теперь .db не иммутабелен ни при каком имени репо, а
// реальный пакет .pkg.tar.zst — иммутабелен.
func TestPublicRepoPacmanSuffixImmutable(t *testing.T) {
	env := newRepoEnv(t)
	repo, err := env.repos.CreateRepo(t.Context(), domain.Repo{Name: "x.pkg.tar.y", OwnerID: 2, Ecosystem: "pacman", CreatedAt: env.clock.Now()})
	if err != nil {
		t.Fatal(err)
	}
	uploadRepoObject(t, env, repo.ID, "x.pkg.tar.y.db", []byte("db"))
	uploadRepoObject(t, env, repo.ID, "pkg-any.pkg.tar.zst", []byte("pkg"))

	const immutable = "public, max-age=31536000, immutable"
	for path, want := range map[string]string{
		"/repo/x.pkg.tar.y/x.pkg.tar.y.db":      "",
		"/repo/x.pkg.tar.y/pkg-any.pkg.tar.zst": immutable,
	} {
		rec := getPublic(t, env, path)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, хочу 200", path, rec.Code)
		}
		if got := rec.Header().Get("Cache-Control"); got != want {
			t.Errorf("Cache-Control %s = %q, хочу %q", path, got, want)
		}
	}
}

// TestPublicRepoCatalogUnavailable503 — сбой каталога БД на публичном
// роутере (сессия 50): ошибка соединения (не NotFound) → 503 «мы
// сломаны», а не 502 «виноват upstream». Фейк-обёртка инжектит сбой в
// boundary, errno носителя не имитируется.
func TestPublicRepoCatalogUnavailable503(t *testing.T) {
	repos := &failingRepoStore{RepoStore: testutil.NewFakeRepoStore(), err: errors.New("dial tcp 10.0.0.9:5432: connection refused")}
	storage := testutil.NewFakeStorage(testutil.FixedClock(time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)))
	h := BuildPublicRouter(Deps{Storage: storage, Repos: repos, Signer: &fakeKeySigner{}, NarSigner: &fakeNarKeySigner{}})
	for _, path := range []string{
		"/repo/alice/pool/main/a/foo.deb",
		"/repo/alice/key.asc",
		"/repo/alice/nix-key.asc",
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("GET %s при сбое каталога = %d, хочу 503", path, rec.Code)
		}
	}
	// 404-путь не изменился: отсутствие репо — не сбой каталога.
	repos.err = nil
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/repo/ghost/pool/main/a/foo.deb", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET несуществующего репо = %d, хочу прежний 404", rec.Code)
	}
}

// TestPublicProxyContentTypeAllowlistWithNoSniff — прокси-заголовок
// живёт под allowlist (сессия 78 отменила passthrough сессии 36):
// честно объявленный upstream'ом text/html больше не доходит до
// браузера — прокси отвечает octet-stream, и рендер в origin зеркала
// невозможен ни при каком upstream. nosniff стоит и здесь; ТЕЛО при
// этом byte-exact — инвариант про байты, не про заголовок.
func TestPublicProxyContentTypeAllowlistWithNoSniff(t *testing.T) {
	const html = "<html><body>mirror index</body></html>"
	h, _, _, _, _ := newProxyEnv(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, html)
	})

	rec := get(t, h, "/t/idx/page")
	if rec.Code != http.StatusOK {
		t.Fatalf("прокси = %d, хочу 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("прокси Content-Type = %q, хочу application/octet-stream (злой upstream-тип срезан)", ct)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("прокси: X-Content-Type-Options = %q, хочу nosniff", got)
	}
	if rec.Body.String() != html {
		t.Errorf("прокси тело = %q, хочу byte-exact %q", rec.Body.String(), html)
	}
}

// TestPublicHeadRoutes — сессия 68: HEAD-роуты раздачи :29202 отдают
// 200 с теми же заголовками, что GET, и пустым телом — раньше HEAD
// ловил 405 (CDN-пробы). Реальный HTTP-стек обязателен: тело на HEAD
// отбрасывает сам net/http, httptest.Recorder записал бы запись
// хендлера как «тело».
func TestPublicHeadRoutes(t *testing.T) {
	env := newRepoEnv(t)
	repoID := createRepoViaAPI(t, env, "alice", 2)
	uploadRepoObject(t, env, repoID, "pool/main/a/foo.deb", []byte("deb"))
	proxyH, _, _, _, _ := newProxyEnv(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/deb")
		w.Header().Set("ETag", `"e1"`)
		_, _ = io.WriteString(w, "payload")
	})

	request := func(h http.Handler, method, path string) (*http.Response, string) {
		t.Helper()
		srv := httptest.NewServer(h)
		t.Cleanup(srv.Close)
		req, err := http.NewRequest(method, srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp, string(body)
	}

	cases := []struct {
		name       string
		handler    http.Handler
		path       string
		bodyPrefix string // ожидаемое тело GET (префикс; "" — не проверять)
		warm       bool   // прогрев кеша перед сверкой: X-Cache GET/HEAD должны совпасть (HIT/HIT)
		headers    []string
	}{
		{"repo-файл", env.public, "/repo/alice/pool/main/a/foo.deb", "deb", false,
			[]string{"Content-Type", "Content-Length", "Cache-Control", "X-Content-Type-Options"}},
		{"repo-ключ", env.public, "/repo/alice/key.asc", "-----BEGIN", false,
			[]string{"Content-Type", "Cache-Control", "X-Content-Type-Options"}},
		{"прокси", proxyH, "/t/pkg/a.deb", "payload", true,
			[]string{"Content-Type", "Content-Length", "ETag", "X-Cache", "X-Content-Type-Options"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.warm {
				// прогрев: первый GET — MISS, HEAD после него — HIT;
				// сверяем заголовки в одинаковом состоянии кеша
				if rec := get(t, tc.handler, tc.path); rec.Code != http.StatusOK {
					t.Fatalf("прогрев GET %s = %d, хочу 200", tc.path, rec.Code)
				}
			}
			getResp, getBody := request(tc.handler, http.MethodGet, tc.path)
			if getResp.StatusCode != http.StatusOK {
				t.Fatalf("GET %s = %d, хочу 200", tc.path, getResp.StatusCode)
			}
			if tc.bodyPrefix != "" && !strings.HasPrefix(getBody, tc.bodyPrefix) {
				t.Fatalf("GET %s тело = %q, хочу префикс %q", tc.path, getBody, tc.bodyPrefix)
			}
			headResp, headBody := request(tc.handler, http.MethodHead, tc.path)
			if headResp.StatusCode != http.StatusOK {
				t.Fatalf("HEAD %s = %d, хочу 200 (раньше был 405)", tc.path, headResp.StatusCode)
			}
			if len(headBody) != 0 {
				t.Errorf("HEAD %s отдал тело %q, хочу пусто", tc.path, headBody)
			}
			for _, hname := range tc.headers {
				if got, want := headResp.Header.Get(hname), getResp.Header.Get(hname); got != want {
					t.Errorf("HEAD %s: %s = %q, у GET %q", tc.path, hname, got, want)
				}
			}
		})
	}
}
