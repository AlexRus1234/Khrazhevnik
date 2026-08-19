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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthz(t *testing.T) {
	for name, h := range map[string]http.Handler{
		"public": BuildPublicRouter(Deps{Version: "test"}),
		"admin":  BuildAdminRouter(Deps{Version: "test"}),
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("/healthz = %d, хочу 200", rec.Code)
			}
			if got := rec.Body.String(); got != "ok" {
				t.Errorf("тело healthz = %q, хочу \"ok\"", got)
			}
			if rec.Header().Get(RequestIDHeader) == "" {
				t.Error("X-Request-Id не выставлен")
			}
		})
	}
}

func TestRequestIDPassthrough(t *testing.T) {
	const incoming = "req-12345678"
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set(RequestIDHeader, incoming)
	BuildPublicRouter(Deps{}).ServeHTTP(rec, req)

	if got := rec.Header().Get(RequestIDHeader); got != incoming {
		t.Errorf("валидный входящий request id заменён: %q", got)
	}
}

func TestRequestIDInvalidReplaced(t *testing.T) {
	for _, bad := range []string{"short", "с-кириллицей-и-лишним", "", "0123456789012345678901234567890123456789012345678901234567890123456789"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		req.Header.Set(RequestIDHeader, bad)
		BuildPublicRouter(Deps{}).ServeHTTP(rec, req)

		got := rec.Header().Get(RequestIDHeader)
		if got == "" || got == bad {
			t.Errorf("невалидный request id %q прошёл как есть: %q", bad, got)
		}
	}
}

func TestRequestIDFromContext(t *testing.T) {
	var fromCtx string
	rec := httptest.NewRecorder()
	h := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		fromCtx = RequestIDFromContext(r.Context())
	})
	RequestID(h).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if fromCtx == "" {
		t.Error("request id не попал в контекст")
	}
}

func TestAdminAPIStub(t *testing.T) {
	rec := httptest.NewRecorder()
	BuildAdminRouter(Deps{Version: "v42"}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("/api/v1/ = %d, хочу 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"khrazhevnik", "v1", "v42"} {
		if !strings.Contains(body, want) {
			t.Errorf("ответ API не содержит %q: %s", want, body)
		}
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, хочу json", ct)
	}
}

func TestNotFound(t *testing.T) {
	rec := httptest.NewRecorder()
	BuildPublicRouter(Deps{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/no/such/path", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("неизвестный путь = %d, хочу 404", rec.Code)
	}
}

func TestLogRequests(t *testing.T) {
	buf := &bytes.Buffer{}
	log := slog.New(slog.NewJSONHandler(buf, nil))

	h := http.NewServeMux()
	h.HandleFunc("/ok", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h.HandleFunc("/boom", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) })

	r := BuildPublicRouter(Deps{})
	_ = r // роутеры уже несут middleware; тестируем сам middleware
	logged := RequestID(LogRequests(log)(h))

	logged.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/ok", nil))
	logged.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/boom", nil))

	out := buf.String()
	for _, want := range []string{`"msg":"http"`, `"/ok"`, `"/boom"`, `"request_id"`} {
		if !strings.Contains(out, want) {
			t.Errorf("в логе нет %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, `"level":"ERROR"`) {
		t.Errorf("5xx не поднят до error:\n%s", out)
	}
}
