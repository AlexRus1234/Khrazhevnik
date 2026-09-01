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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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

// TestPublicProxyContentTypePassthroughWithNoSniff — прокси-путь
// трогать нельзя: upstream-тип (в т.ч. text/html) передаётся как есть
// из сохранённого meta (byte-exact-инвариант), а nosniff стоит и
// здесь — браузеру запрещена переинтерпретация, но тип честный.
func TestPublicProxyContentTypePassthroughWithNoSniff(t *testing.T) {
	const html = "<html><body>mirror index</body></html>"
	h, _, _, _, _ := newProxyEnv(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, html)
	})

	rec := get(t, h, "/t/idx/page")
	if rec.Code != http.StatusOK {
		t.Fatalf("прокси = %d, хочу 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("прокси Content-Type = %q, хочу text/html из upstream meta (не сломали)", ct)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("прокси: X-Content-Type-Options = %q, хочу nosniff", got)
	}
	if rec.Body.String() != html {
		t.Errorf("прокси тело = %q, хочу byte-exact %q", rec.Body.String(), html)
	}
}
