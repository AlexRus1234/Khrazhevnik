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

// FakeEcosystem — двойник port.Ecosystem для тестов движка кеша и
// HTTP-доставки: пути /<name>/pkg/… — immutable, /<name>/idx/… —
// mutable с настраиваемым TTL, всё остальное — ошибка классификации.

package testutil

import (
	"strings"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
)

// FakeEcosystem маппит пути публичного порта на base URL upstream'а.
type FakeEcosystem struct {
	// NameOf — имя экосистемы (префикс путей).
	NameOf string
	// Base — корень upstream (например, httptest-сервер).
	Base string
	// MutableTTL — TTL для путей idx/, используемый Classify.
	MutableTTL time.Duration
}

// Name возвращает имя экосистемы.
func (e FakeEcosystem) Name() string { return e.NameOf }

// URLPrefix возвращает префикс путей публичного порта. У фейка префикс
// совпадает с именем (как у apt).
func (e FakeEcosystem) URLPrefix() string { return e.NameOf }

// Resolve переводит /<name>/<rest> в Target. Ключ хранения всегда
// нижний регистр: реальный upstream-путь может содержать заглавные
// (Packages.gz), а доменные ключи — только [a-z0-9/._-].
func (e FakeEcosystem) Resolve(ecosystemPath string) (port.Target, bool) {
	prefix := "/" + e.NameOf + "/"
	if !strings.HasPrefix(ecosystemPath, prefix) {
		return port.Target{}, false
	}
	rest := strings.TrimPrefix(ecosystemPath, prefix)
	return port.Target{
		UpstreamURL:  e.Base + "/" + rest,
		UpstreamPath: "/" + rest,
		StorageKey:   "cache/" + e.NameOf + "/" + strings.ToLower(rest),
	}, true
}

// Classify делит объекты по префиксам: pkg/ — immutable, idx/ — mutable.
func (e FakeEcosystem) Classify(upstreamPath string) (domain.Class, error) {
	switch {
	case strings.HasPrefix(upstreamPath, "/pkg/"):
		return domain.Immutable(), nil
	case strings.HasPrefix(upstreamPath, "/idx/"):
		return domain.Mutable(e.MutableTTL), nil
	}
	return domain.Class{}, &domain.ValidationError{What: "путь upstream", Value: upstreamPath, Reason: "нет схемы pkg/ или idx/"}
}
