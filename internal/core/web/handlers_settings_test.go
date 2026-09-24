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
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
)

// fakeSettingsStore — port.UpstreamProxyStore в памяти для web-тестов
// (контракт самих драйверов крыт контрактным suite, сессия 154).
type fakeSettingsStore struct {
	mu  sync.Mutex
	val string
}

func (s *fakeSettingsStore) UpstreamProxy(context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.val, nil
}

func (s *fakeSettingsStore) SetUpstreamProxy(_ context.Context, v string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.val = v
	return nil
}

// newSettingsEnv — админ-роутер с Settings-феиком (newAdminEnv собирает
// Deps без Settings — маршрут тогда работает в деградации).
func newSettingsEnv(t *testing.T) (*adminEnv, *fakeSettingsStore) {
	t.Helper()
	env := newAdminEnv(t)
	store := &fakeSettingsStore{}
	// Пересобираем роутер с теми же фейками плюс Settings: auth-сервис
	// и issued-токены живут вне роутера, перевыпуск не нужен.
	h := BuildAdminRouter(Deps{
		Log: nil, Version: "test", Auth: env.auth, SetupToken: "setup",
		Remotes: env.remotes, Audit: env.audit, Tasks: env.tasks,
		Clock: env.clock, Settings: store,
	})
	env.handler = h
	return env, store
}

// TestSettingsUpstreamProxyContract — сессия 156: GET пустой БД →
// {"value":""}; PUT невалидного → 400 validation_error; PUT
// socks5-URL с паролем → 200, повторный GET → значение; PUT "" → 200
// и GET → "". Пароль в audit-detail замаскирован.
func TestSettingsUpstreamProxyContract(t *testing.T) {
	env, store := newSettingsEnv(t)

	// GET пустой БД — "".
	rec := callAdmin(env, http.MethodGet, "/api/v1/settings/upstream-proxy", "", env.jwtAdmin)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d, тело %s", rec.Code, rec.Body.String())
	}
	var out upstreamProxyValue
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Value != "" {
		t.Fatalf("пустая БД вернула %q, хочу \"\"", out.Value)
	}

	// PUT невалидного — 400 validation_error, стор не тронут.
	rec = callAdmin(env, http.MethodPut, "/api/v1/settings/upstream-proxy", `{"value":"ftp://h"}`, env.jwtAdmin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT ftp:// = %d, тело %s", rec.Code, rec.Body.String())
	}
	var e apiError
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil || e.Code != "validation_error" {
		t.Fatalf("код ошибки = %q (тело %s), хочу validation_error", e.Code, rec.Body.String())
	}
	if got, _ := store.UpstreamProxy(t.Context()); got != "" {
		t.Fatalf("невалидное значение попало в стор: %q", got)
	}

	// PUT socks5 с паролем — 200 и эхо значения; GET отдаёт его же.
	const socks = "socks5://u:p@h:1080"
	rec = callAdmin(env, http.MethodPut, "/api/v1/settings/upstream-proxy", `{"value":"`+socks+`"}`, env.jwtAdmin)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT socks5 = %d, тело %s", rec.Code, rec.Body.String())
	}
	out = upstreamProxyValue{}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Value != socks {
		t.Fatalf("эхо PUT = %+v (тело %s), хочу %q", out, rec.Body.String(), socks)
	}
	rec = callAdmin(env, http.MethodGet, "/api/v1/settings/upstream-proxy", "", env.jwtAdmin)
	out = upstreamProxyValue{}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Value != socks {
		t.Fatalf("повторный GET = %+v, хочу %q", out, socks)
	}

	// PUT «direct» валиден.
	rec = callAdmin(env, http.MethodPut, "/api/v1/settings/upstream-proxy", `{"value":"direct"}`, env.jwtAdmin)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT direct = %d, тело %s", rec.Code, rec.Body.String())
	}
	if got, _ := store.UpstreamProxy(t.Context()); got != domain.ProxyDirect {
		t.Fatalf("direct не сохранился: %q", got)
	}

	// PUT "" — сброс до env-фолбэка; GET → "".
	rec = callAdmin(env, http.MethodPut, "/api/v1/settings/upstream-proxy", `{"value":""}`, env.jwtAdmin)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT пустого = %d, тело %s", rec.Code, rec.Body.String())
	}
	rec = callAdmin(env, http.MethodGet, "/api/v1/settings/upstream-proxy", "", env.jwtAdmin)
	out = upstreamProxyValue{}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Value != "" {
		t.Fatalf("GET после сброса = %+v, хочу \"\"", out)
	}

	// Аудит последней мутации: action settings.update, пароля нет —
	// только маска domain.MaskProxyURL.
	entries, err := env.audit.AuditEntries(t.Context(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("аудит пуст, хочу записи settings.update")
	}
	last := entries[len(entries)-1]
	if last.Action != "settings.update" {
		t.Fatalf("action = %q, хочу settings.update", last.Action)
	}
	if strings.Contains(last.Detail, "p@") || strings.Contains(last.Detail, ":p@h") {
		t.Fatalf("пароль прокси утёк в аудит: %q", last.Detail)
	}
	wantMask := `{"value":"socks5://***@h:1080"}`
	var sawMask bool
	for _, en := range entries {
		if en.Action == "settings.update" && en.Detail == wantMask {
			sawMask = true
		}
	}
	if !sawMask {
		t.Fatalf("нет audit-записи с маской %q; записи: %+v", wantMask, entries)
	}
}

// TestSettingsUpstreamProxyDegraded — Settings nil (деградация):
// GET отдаёт пустое значение (честный env-фолбэк), PUT — 503.
func TestSettingsUpstreamProxyDegraded(t *testing.T) {
	env := newAdminEnv(t)

	rec := callAdmin(env, http.MethodGet, "/api/v1/settings/upstream-proxy", "", env.jwtAdmin)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET в деградации = %d, тело %s", rec.Code, rec.Body.String())
	}
	var out upstreamProxyValue
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Value != "" {
		t.Fatalf("тело %+v, хочу пустое value", out)
	}

	rec = callAdmin(env, http.MethodPut, "/api/v1/settings/upstream-proxy", `{"value":"direct"}`, env.jwtAdmin)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("PUT в деградации = %d, хочу 503", rec.Code)
	}
}

// TestSettingsUpstreamProxyAuthMatrix — маршрут admin-only, как /remotes.
func TestSettingsUpstreamProxyAuthMatrix(t *testing.T) {
	env, _ := newSettingsEnv(t)
	for _, tc := range []struct {
		name, bearer string
		want         int
	}{
		{"no auth", "", http.StatusUnauthorized},
		{"user role", env.jwtUser, http.StatusForbidden},
		{"admin session", env.jwtAdmin, http.StatusOK},
		{"admin api token", env.apiAdmin, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := callAdmin(env, http.MethodGet, "/api/v1/settings/upstream-proxy", "", tc.bearer)
			if rec.Code != tc.want {
				t.Fatalf("GET = %d, хочу %d (тело %s)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// компиляционная проверка: фейк реализует порт.
var _ port.UpstreamProxyStore = (*fakeSettingsStore)(nil)
