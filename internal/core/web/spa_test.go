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
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSPAIndex — /ui/ отдаёт index.html (точка входа SPA) с no-cache.
// Работает и со stub-заглушкой (make clean), и с собранным бандлом
// (make web-build): оба содержат <title>khrazhevnik</title>.
func TestSPAIndex(t *testing.T) {
	h := BuildAdminRouter(Deps{Version: "test"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/ui/ = %d, хочу 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, хочу text/html", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-cache") {
		t.Errorf("Cache-Control = %q, хочу no-cache", cc)
	}
	if !strings.Contains(rec.Body.String(), "khrazhevnik") {
		t.Errorf("тело /ui/ не содержит khrazhevnik: %s", rec.Body.String())
	}
}

// TestSPADeepLinkFallback — /ui/<клиентский-роут> отдаёт тот же index.html
// (vue-router берёт навигацию на себя); не 404.
func TestSPADeepLinkFallback(t *testing.T) {
	h := BuildAdminRouter(Deps{Version: "test"})
	indexRec := httptest.NewRecorder()
	h.ServeHTTP(indexRec, httptest.NewRequest(http.MethodGet, "/ui/", nil))
	deepRec := httptest.NewRecorder()
	h.ServeHTTP(deepRec, httptest.NewRequest(http.MethodGet, "/ui/remotes", nil))
	if deepRec.Code != http.StatusOK {
		t.Fatalf("/ui/remotes = %d, хочу 200 (fallback)", deepRec.Code)
	}
	if deepRec.Body.String() != indexRec.Body.String() {
		t.Errorf("deep-link тело отличается от index.html")
	}
	if cc := deepRec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-cache") {
		t.Errorf("fallback Cache-Control = %q, хочу no-cache", cc)
	}
}

// TestSPAIndexPath — прямой запрос /ui/index.html эквивалентен /ui/ и
// тоже отдается с no-cache (не immutable).
func TestSPAIndexPath(t *testing.T) {
	h := BuildAdminRouter(Deps{Version: "test"})
	rootRec := httptest.NewRecorder()
	h.ServeHTTP(rootRec, httptest.NewRequest(http.MethodGet, "/ui/", nil))
	idxRec := httptest.NewRecorder()
	h.ServeHTTP(idxRec, httptest.NewRequest(http.MethodGet, "/ui/index.html", nil))
	if idxRec.Code != http.StatusOK {
		t.Fatalf("/ui/index.html = %d, хочу 200", idxRec.Code)
	}
	if idxRec.Body.String() != rootRec.Body.String() {
		t.Errorf("/ui/index.html тело отличается от /ui/")
	}
	if cc := idxRec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-cache") {
		t.Errorf("/ui/index.html Cache-Control = %q, хочу no-cache", cc)
	}
}

// TestSPAHashedAssetImmutable — хешированные ассеты vite
// (assets/<name>-<hash>.<ext>) отдаются с immutable. Появляются только
// после make web-build; при stub-only сборке (make clean) их нет — skip.
func TestSPAHashedAssetImmutable(t *testing.T) {
	var hashed string
	_ = fs.WalkDir(assetsFS, "assets", func(p string, d fs.DirEntry, err error) error {
		if err != nil || hashed != "" || d.IsDir() {
			return nil
		}
		if strings.HasPrefix(p, "assets/assets/") {
			hashed = strings.TrimPrefix(p, "assets/")
		}
		return nil
	})
	if hashed == "" {
		t.Skip("нет собранных хешированных ассетов — нужен make web-build")
	}
	h := BuildAdminRouter(Deps{Version: "test"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui/"+hashed, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/ui/%s = %d, хочу 200", hashed, rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Errorf("ассет Cache-Control = %q, хочу immutable", cc)
	}
}

// TestSPAUINotOnPublic — SPA живёт только на админском порту; публичный
// роутер (:29202) /ui не обслуживает (там пакеты и /repo).
func TestSPAUINotOnPublic(t *testing.T) {
	pub := BuildPublicRouter(Deps{})
	rec := httptest.NewRecorder()
	pub.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui/", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("public /ui/ = %d, хочу 404 (SPA только на :30202)", rec.Code)
	}
}
