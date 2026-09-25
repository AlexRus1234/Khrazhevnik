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
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"khrazhevnik/internal/core/domain"
)

// TestExportRemotes — GET /remotes/export: пустой список даёт только
// заголовок; два источника — заголовок + две строки формата; заголовки
// Content-Type/Content-Disposition фиксированы.
func TestExportRemotes(t *testing.T) {
	env := newAdminEnv(t)

	rec := callAdmin(env, http.MethodGet, "/api/v1/remotes/export", "", env.jwtAdmin)
	if rec.Code != http.StatusOK {
		t.Fatalf("export пустого списка = %d, тело %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); cd != `attachment; filename="khrazhevnik-remotes.txt"` {
		t.Errorf("Content-Disposition = %q", cd)
	}
	if got, want := rec.Body.String(), domain.FormatRemotes(nil); got != want {
		t.Errorf("пустой экспорт = %q, хочу %q", got, want)
	}

	for _, body := range []string{
		`{"name":"debian","ecosystem":"apt","base_url":"https://deb.debian.org/debian","mode":"proxy","enabled":true,"include":["main","contrib"]}`,
		`{"name":"arch","ecosystem":"pacman","base_url":"https://mirror.archlinux.org","mode":"mirror","enabled":false,"sync_interval":3600000000000,"proxy_url":"direct"}`,
	} {
		if rec := callAdmin(env, http.MethodPost, "/api/v1/remotes", body, env.jwtAdmin); rec.Code != http.StatusCreated {
			t.Fatalf("create = %d, тело %s", rec.Code, rec.Body.String())
		}
	}

	rec = callAdmin(env, http.MethodGet, "/api/v1/remotes/export", "", env.jwtAdmin)
	if rec.Code != http.StatusOK {
		t.Fatalf("export = %d", rec.Code)
	}
	want := "# khrazhevnik remotes export v1\n" +
		"# name|ecosystem|base_url|mode|proxy|enabled|sync_interval|include\n" +
		"debian|apt|https://deb.debian.org/debian|proxy||true||main,contrib\n" +
		"arch|pacman|https://mirror.archlinux.org|mirror|direct|false|1h0m0s|\n"
	if got := rec.Body.String(); got != want {
		t.Errorf("экспорт:\n%q\nхочу:\n%q", got, want)
	}
}

// TestImportRemotesReport — частичный успех: 2 новых, 1 дубль
// существующего, 1 битый интервал → 200 и отчёт 2/1/1; в БД ровно 3
// remote; аудит remote.import с совпадающими счётчиками.
func TestImportRemotesReport(t *testing.T) {
	env := newAdminEnv(t)
	existing := `{"name":"existing","ecosystem":"apt","base_url":"https://e.example","mode":"proxy"}`
	if rec := callAdmin(env, http.MethodPost, "/api/v1/remotes", existing, env.jwtAdmin); rec.Code != http.StatusCreated {
		t.Fatalf("create existing = %d", rec.Code)
	}

	body := "# заголовок\n" +
		"newa|apt|https://a.example|proxy||true||\n" +
		"newb|apt|https://b.example|proxy||true||\n" +
		"existing|apt|https://e.example|proxy||true||\n" +
		"badint|apt|https://c.example|proxy||true|not-a-duration|\n"
	rec := callAdmin(env, http.MethodPost, "/api/v1/remotes/import", body, env.jwtAdmin)
	if rec.Code != http.StatusOK {
		t.Fatalf("import = %d, тело %s", rec.Code, rec.Body.String())
	}
	var rep importReport
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Created) != 2 || rep.Created[0] != "newa" || rep.Created[1] != "newb" {
		t.Errorf("created = %v, хочу [newa newb]", rep.Created)
	}
	if len(rep.Skipped) != 1 || rep.Skipped[0].Name != "existing" || rep.Skipped[0].Line != 4 {
		t.Errorf("skipped = %+v, хочу [{4 existing}]", rep.Skipped)
	}
	if len(rep.Errors) != 1 || rep.Errors[0].Line != 5 || rep.Errors[0].Code != "validation_error" || rep.Errors[0].Reason == "" {
		t.Errorf("errors = %+v, хочу [{5 validation_error <reason>}]", rep.Errors)
	}

	rec = callAdmin(env, http.MethodGet, "/api/v1/remotes", "", env.jwtAdmin)
	var list []remoteOut
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("в БД %d remote, хочу 3", len(list))
	}

	e := lastAudit(t, env.audit)
	if e.Action != "remote.import" || e.Result != domain.AuditOK {
		t.Errorf("аудит = %q/%q, хочу remote.import/ok", e.Action, e.Result)
	}
	if !strings.Contains(e.Detail, `"created":2`) || !strings.Contains(e.Detail, `"skipped":1`) || !strings.Contains(e.Detail, `"errors":1`) {
		t.Errorf("detail = %q, хочу счётчики 2/1/1", e.Detail)
	}
}

// TestImportRemotesInternalDuplicate — две одинаковые name в файле:
// вторая в skipped, создаётся один remote.
func TestImportRemotesInternalDuplicate(t *testing.T) {
	env := newAdminEnv(t)
	body := "dup|apt|https://one.example|proxy||true||\n" +
		"dup|apt|https://two.example|proxy||true||\n"
	rec := callAdmin(env, http.MethodPost, "/api/v1/remotes/import", body, env.jwtAdmin)
	if rec.Code != http.StatusOK {
		t.Fatalf("import = %d, тело %s", rec.Code, rec.Body.String())
	}
	var rep importReport
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Created) != 1 || len(rep.Skipped) != 1 || rep.Skipped[0].Name != "dup" || rep.Skipped[0].Line != 2 {
		t.Errorf("отчёт = %+v, хочу created 1 / skipped [{2 dup}]", rep)
	}
}

// TestImportRemotesEmpty — пустое тело, только комментарий и пустая
// строка → 200 с нулями (не null-срезами).
func TestImportRemotesEmpty(t *testing.T) {
	env := newAdminEnv(t)
	for _, body := range []string{"", "# только комментарий\n", "\n"} {
		rec := callAdmin(env, http.MethodPost, "/api/v1/remotes/import", body, env.jwtAdmin)
		if rec.Code != http.StatusOK {
			t.Fatalf("import %q = %d, тело %s", body, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `"created":[]`) {
			t.Errorf("тело %s, хочу created:[] (не null)", rec.Body.String())
		}
		var rep importReport
		if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
			t.Fatal(err)
		}
		if len(rep.Created) != 0 || len(rep.Skipped) != 0 || len(rep.Errors) != 0 {
			t.Errorf("отчёт %+v, хочу нули", rep)
		}
	}
}

// TestImportRemotesTooManyLines — 1001 строка → 400 import_too_many.
func TestImportRemotesTooManyLines(t *testing.T) {
	env := newAdminEnv(t)
	body := strings.Repeat("x|apt|https://h.example|proxy||true||\n", 1001)
	rec := callAdmin(env, http.MethodPost, "/api/v1/remotes/import", body, env.jwtAdmin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("1001 строка = %d, хочу 400 (тело %s)", rec.Code, rec.Body.String())
	}
	var e apiError
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("тело = %q, хочу apiError", rec.Body.String())
	}
	if e.Code != "import_too_many" {
		t.Errorf("код = %q, хочу import_too_many", e.Code)
	}
}

// TestImportRemotesProxyURL — строка с socks5-прокси создаёт remote с
// proxy_url (поле 5 формата).
func TestImportRemotesProxyURL(t *testing.T) {
	env := newAdminEnv(t)
	body := "p|apt|https://h.example|proxy|socks5://u:p@h:1080|true||\n"
	rec := callAdmin(env, http.MethodPost, "/api/v1/remotes/import", body, env.jwtAdmin)
	if rec.Code != http.StatusOK {
		t.Fatalf("import = %d, тело %s", rec.Code, rec.Body.String())
	}
	rec = callAdmin(env, http.MethodGet, "/api/v1/remotes", "", env.jwtAdmin)
	var list []remoteOut
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ProxyURL != "socks5://u:p@h:1080" {
		t.Errorf("list = %+v, хочу один remote с proxy_url", list)
	}
}
