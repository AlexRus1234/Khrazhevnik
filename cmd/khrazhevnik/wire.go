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

// Продакшн-wiring: сборка зависимостей из config через compile-time
// реестр. Модули подключаются сюда blank-import'ами (первый —
// fs/sqlite в сессии 04); это единственное место, где core знает о
// существовании модулей.

package main

import (
	"context"
	crand "crypto/rand"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"khrazhevnik/internal/core/config"
	"khrazhevnik/internal/core/engine/auth"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/core/registry"

	// Модули: регистрация в compile-time реестре. Каждая новая
	// экосистема/драйвер добавляется сюда одной строкой.
	_ "khrazhevnik/internal/mod/db/sqlite"
	_ "khrazhevnik/internal/mod/storage/fs"
)

// App — собранные зависимости сервера; поля набирают движки
// (аутентификация — сессия 05, кеш — 06, метрики — 09).
type App struct {
	Clock      port.Clock
	Rand       port.Rand
	Storage    port.Storage
	Catalog    registry.CatalogSet
	Auth       *auth.Service
	HTTP       port.Doer
	Ecosystems map[string]port.Ecosystem
}

// outboundHTTPTimeout — таймаут запросов upstream; движок кеша
// уточнит под стриминг больших объектов в сессии 06.
const outboundHTTPTimeout = 60 * time.Second

// wireApp собирает App: фабрики драйверов — из реестра, экосистемы —
// по включённым секциям [ecosystem.*]. Сборка без единого модуля
// деградирует до healthz-only с громкой ошибкой в логе: пустой реестр
// из-за забытых blank-import'ов не должен маскироваться под живой
// сервер, полностью блокируя и старт нельзя — healthz нужен оркестратору.
func wireApp(cfg config.Config, log *slog.Logger) (*App, error) {
	if registry.Empty() {
		log.Error("модули не слинкованы — деградированный режим (только /healthz): " +
			"добавьте blank-import'ы модулей в cmd/khrazhevnik/wire.go")
		return &App{
			Clock: systemClock{},
			Rand:  uuidRand{},
			HTTP:  outboundHTTPClient(),
		}, nil
	}

	storageFactory, err := registry.Storage(cfg.Storage.Driver)
	if err != nil {
		return nil, err
	}
	dbFactory, err := registry.DB(cfg.Database.Driver)
	if err != nil {
		return nil, err
	}

	storage, err := storageFactory(cfg.Storage)
	if err != nil {
		return nil, fmt.Errorf("хранилище %q: %w", cfg.Storage.Driver, err)
	}
	catalog, err := dbFactory(cfg.Database)
	if err != nil {
		return nil, fmt.Errorf("каталог %q: %w", cfg.Database.Driver, err)
	}
	ecosystems, err := wireEcosystems(cfg)
	if err != nil {
		return nil, err
	}

	authService, err := auth.New(auth.Config{Users: catalog.Users, Tokens: catalog.Tokens, Audit: catalog.Audit, Clock: systemClock{}, Rand: uuidRand{}, JWTSecret: cfg.Auth.JWTSecret, SessionTTL: cfg.Auth.SessionTTL.Duration})
	if err != nil {
		return nil, err
	}
	return &App{
		Clock:      systemClock{},
		Rand:       uuidRand{},
		Storage:    storage,
		Catalog:    catalog,
		Auth:       authService,
		HTTP:       outboundHTTPClient(),
		Ecosystems: ecosystems,
	}, nil
}

// wireEcosystems создаёт адаптеры для включённых секций конфига;
// секция с неизвестным реестру именем — понятная ошибка старта.
func wireEcosystems(cfg config.Config) (map[string]port.Ecosystem, error) {
	ecosystems := make(map[string]port.Ecosystem)
	for name, ecoCfg := range cfg.Ecosystem {
		if !ecoCfg.Enabled {
			continue
		}
		factory, err := registry.Ecosystem(name)
		if err != nil {
			return nil, err
		}
		adapter, err := factory(ecoCfg)
		if err != nil {
			return nil, fmt.Errorf("экосистема %q: %w", name, err)
		}
		ecosystems[name] = adapter
	}
	return ecosystems, nil
}

// WaitTasks — хук graceful shutdown: ждёт фоновые задачи после
// остановки HTTP. Потребители (sync-воркеры зеркал) появятся в M2;
// пока возвращаемся сразу.
func (a *App) WaitTasks(context.Context) error { return nil }

// outboundHTTPClient — Doer для запросов upstream.
func outboundHTTPClient() *http.Client {
	return &http.Client{Timeout: outboundHTTPTimeout}
}

// systemClock — port.Clock поверх time.Now (системные реализации
// живут в wire: тесты подменяют через testutil).
type systemClock struct{}

// Now возвращает текущее время.
func (systemClock) Now() time.Time { return time.Now() }

// uuidRand — port.Rand поверх crypto/rand (RFC-4122 v4, без внешних
// зависимостей: 16 байт + биты версии/варианта).
type uuidRand struct{}

// UUID4 генерирует канонический UUID v4 (8-4-4-4-12, lowercase).
func (uuidRand) UUID4() (string, error) {
	var b [16]byte
	if _, err := crand.Read(b[:]); err != nil {
		return "", fmt.Errorf("rand: чтение crypto/rand: %w", err)
	}
	b[6] = b[6]&0x0f | 0x40 // версия 4
	b[8] = b[8]&0x3f | 0x80 // вариант RFC-4122
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
