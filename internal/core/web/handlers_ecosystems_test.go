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
	"slices"
	"testing"

	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/testutil"
)

// newEcosystemsEnv — админ-роутер с заданной картой адаптеров (newAdminEnv
// собирает Deps без Ecosystems — маршрут тогда отдаёт пустой список).
func newEcosystemsEnv(t *testing.T, ecos map[string]port.Ecosystem) *adminEnv {
	t.Helper()
	env := newAdminEnv(t)
	// Пересобираем роутер с теми же фейками плюс Ecosystems: auth-сервис
	// и выпущенные токены живут вне роутера, перевыпуск не нужен.
	h := BuildAdminRouter(Deps{
		Log: nil, Version: "test", Auth: env.auth, SetupToken: "setup",
		Remotes: env.remotes, Audit: env.audit, Tasks: env.tasks,
		Clock: env.clock, Ecosystems: ecos,
	})
	env.handler = h
	return env
}

// fakeEcosystems — карта «имя → фейк-адаптер» по списку имён: хендлер
// справочника читает только ключи, значения нужны для типа карты.
func fakeEcosystems(names ...string) map[string]port.Ecosystem {
	m := make(map[string]port.Ecosystem, len(names))
	for _, n := range names {
		m[n] = testutil.FakeEcosystem{NameOf: n}
	}
	return m
}

// TestEcosystemsFullRegistrySorted — полный реестр (шесть экосистем
// v1) → 200, массив из шести имён в лексическом порядке.
func TestEcosystemsFullRegistrySorted(t *testing.T) {
	env := newEcosystemsEnv(t, fakeEcosystems("apt", "rpm-md", "pacman", "apk", "nix", "xbps"))

	rec := callAdmin(env, http.MethodGet, "/api/v1/ecosystems", "", env.jwtAdmin)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /ecosystems = %d, тело %s", rec.Code, rec.Body.String())
	}
	var out ecosystemsOut
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	want := []string{"apk", "apt", "nix", "pacman", "rpm-md", "xbps"}
	if !slices.Equal(out.Ecosystems, want) {
		t.Fatalf("ecosystems = %v, хочу %v (отсортировано по алфавиту)", out.Ecosystems, want)
	}
}

// TestEcosystemsOnlyEnabled — сборка с одной включённой экосистемой →
// 200 ровно с ней: выключенных и незарегистрированных в ответе нет
// (карта Deps собирается wire'ом из реестра по конфигу).
func TestEcosystemsOnlyEnabled(t *testing.T) {
	env := newEcosystemsEnv(t, fakeEcosystems("apt"))

	rec := callAdmin(env, http.MethodGet, "/api/v1/ecosystems", "", env.jwtAdmin)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /ecosystems = %d, тело %s", rec.Code, rec.Body.String())
	}
	var out ecosystemsOut
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(out.Ecosystems, []string{"apt"}) {
		t.Fatalf("ecosystems = %v, хочу [apt] (только включённые)", out.Ecosystems)
	}
}

// TestEcosystemsAuthMatrix — тот же adminAuth, что у прочих admin-роутов:
// без токена 401, опознанная не-админ сессия 403.
func TestEcosystemsAuthMatrix(t *testing.T) {
	env := newEcosystemsEnv(t, fakeEcosystems("apt"))

	rec := callAdmin(env, http.MethodGet, "/api/v1/ecosystems", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("без токена = %d, хочу 401", rec.Code)
	}
	rec = callAdmin(env, http.MethodGet, "/api/v1/ecosystems", "", env.jwtUser)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("не-админ = %d, хочу 403", rec.Code)
	}
}
