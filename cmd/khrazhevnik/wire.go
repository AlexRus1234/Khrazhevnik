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
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"khrazhevnik/internal/core/config"
	"khrazhevnik/internal/core/engine/auth"
	cacheengine "khrazhevnik/internal/core/engine/cache"
	mirrorengine "khrazhevnik/internal/core/engine/mirror"
	"khrazhevnik/internal/core/metrics"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/core/registry"
	"khrazhevnik/internal/core/web"

	// Модули: регистрация в compile-time реестре. Каждая новая
	// экосистема/драйвер добавляется сюда одной строкой.
	_ "khrazhevnik/internal/mod/db/sqlite"
	_ "khrazhevnik/internal/mod/ecosystem/apk"
	_ "khrazhevnik/internal/mod/ecosystem/apt"
	_ "khrazhevnik/internal/mod/ecosystem/pacman"
	_ "khrazhevnik/internal/mod/ecosystem/rpmmmd"
	_ "khrazhevnik/internal/mod/storage/fs"
)

// App — собранные зависимости сервера; поля набирают движки
// (аутентификация — сессия 05, кеш — 06, метрики и задачи — 09,
// зеркало — 11).
type App struct {
	Clock          port.Clock
	Rand           port.Rand
	Storage        port.Storage
	Catalog        registry.CatalogSet
	Auth           *auth.Service
	HTTP           port.Doer
	Ecosystems     map[string]port.Ecosystem
	Cache          *cacheengine.Engine
	Tasks          *web.TaskRegistry
	MetricsHandler http.Handler
	// Mirror — API-адаптер движка зеркал для /remotes/{id}/sync (сессия 11).
	// nil в деградированном режиме (без модулей); API-триггер sync
	// отдаёт 503 mirror_unavailable.
	Mirror web.MirrorSync
	// Scheduler — фоновый планировщик зеркал; nil, если авто-sync
	// отключён (нет mirror-remotes с SyncInterval>0). Stop вызывается
	// из graceful shutdown каскада.
	Scheduler *mirrorengine.Scheduler
}

// Таймауты upstream-соединения: обрыв установки соединения и ожидания
// заголовков (10s каждое); тела стримятся без общего потолка — обрыв
// отслеживает контекст запроса клиента, а не часы (большой пакет на
// медленном зеркале — не ошибка).
const upstreamConnectTimeout = 10 * time.Second

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
	ecosystems, err := wireEcosystems(cfg, catalog.Remotes)
	if err != nil {
		return nil, err
	}

	authService, err := auth.New(auth.Config{Users: catalog.Users, Tokens: catalog.Tokens, Audit: catalog.Audit, Clock: systemClock{}, Rand: uuidRand{}, JWTSecret: cfg.Auth.JWTSecret, SessionTTL: cfg.Auth.SessionTTL.Duration})
	if err != nil {
		return nil, err
	}
	httpClient := outboundHTTPClient()
	cacheEngine := cacheengine.New(storage, catalog.ObjIndex, httpClient, systemClock{}, cacheengine.Config{StaleIfError: cfg.Cache.StaleIfError, MaxObjectSize: cfg.Cache.MaxObjectSize.Bytes, NegativeTTL404: cfg.Cache.NegativeTTL404.Duration, NegativeTTL5xx: cfg.Cache.NegativeTTL5xx.Duration}, metrics.NewCache())
	tasks := web.NewTaskRegistry(cfg.Mirror.Workers, systemClock{})
	mirrorEngine := mirrorengine.New(mirrorengine.Config{
		Workers:        cfg.Mirror.Workers,
		MaxBandwidth:   cfg.Mirror.MaxBandwidth.Bytes,
		RetryMax:       mirrorengine.DefaultRetryMax,
		ErrorThreshold: mirrorengine.DefaultErrorThreshold,
	}, cacheEngine, storage, catalog.Remotes, catalog.Jobs, systemClock{}, ecosystems)
	// mirrorAPI — обёртка mirror.Engine → web.MirrorSync: запускает
	// Sync как задачу TaskRegistry (kind=sync, label=remote.Name).
	// Замыкание живёт в wire (cmd — место склейки), чтобы engine/mirror
	// не зависел от web (depguard: engine → web запрещён архитектурно).
	mirrorAPI := mirrorSyncer{engine: mirrorEngine, remotes: catalog.Remotes, tasks: tasks}
	scheduler := mirrorengine.NewScheduler(mirrorEngine, catalog.Remotes, uuidRand{}, systemClock{}, cfg.Mirror.IntervalJitter.Duration)
	if err := scheduler.Start(context.Background()); err != nil {
		log.Error("mirror scheduler: старт не удался, авто-sync отключён", "err", err)
		scheduler = nil
	}
	var metricsHandler http.Handler
	if cfg.Metrics.Enabled {
		metricsHandler = metrics.NewHandler(cacheEngine.Metrics(), prometheus.NewRegistry()).MetricsHandler()
	}
	return &App{
		Clock:          systemClock{},
		Rand:           uuidRand{},
		Storage:        storage,
		Catalog:        catalog,
		Auth:           authService,
		HTTP:           httpClient,
		Ecosystems:     ecosystems,
		Cache:          cacheEngine,
		Tasks:          tasks,
		MetricsHandler: metricsHandler,
		Mirror:         mirrorAPI,
		Scheduler:      scheduler,
	}, nil
}

// mirrorSyncer — обёртка mirror.Engine под web.MirrorSync: запуск
// синхронизации remote как фоновой задачи TaskRegistry. Живёт в
// wire (cmd) — единственное место, где core/engine и core/web
// склеиваются; engine/mirror не импортирует web (depguard).
type mirrorSyncer struct {
	engine  *mirrorengine.Engine
	remotes port.RemoteStore
	tasks   *web.TaskRegistry
}

// Sync запускает mirror.Engine.Sync через TaskRegistry.Start.
func (m mirrorSyncer) Sync(ctx context.Context, remoteID int64) (string, error) {
	remote, err := m.remotes.Remote(ctx, remoteID)
	if err != nil {
		return "", err
	}
	return m.tasks.Start("sync", remote.Name, func(ctx context.Context, p web.Progress) error {
		// перечитаем remote — настройки могли поменяться между запросом
		// и запуском воркера; берём свежие в начале sync.
		fresh, err := m.remotes.Remote(ctx, remoteID)
		if err != nil {
			return fmt.Errorf("sync: remote: %w", err)
		}
		return m.engine.Sync(ctx, fresh, mirrorProgress{p: p})
	})
}

// mirrorProgress — адаптер web.Progress → mirror.Progress: оба
// интерфейса идентичны по сигнатуре (Update/Log), но это разные
// типы; замыкание переводит вызовы без аллокаций.
type mirrorProgress struct{ p web.Progress }

func (mp mirrorProgress) Update(phase, current string, processed, total int64) {
	mp.p.Update(phase, current, processed, total)
}
func (mp mirrorProgress) Log(line string) { mp.p.Log(line) }

// wireEcosystems создаёт адаптеры для включённых секций конфига;
// секция с неизвестным реестру именем — понятная ошибка старта.
// EcosystemDeps передаёт срезы каталога (Remotes) и Clock — первый
// адаптер, которому они нужны (apt), появился в сессии 07; прочие
// экосистемы берут из Deps своё, оставляя неиспользуемое нулевым.
func wireEcosystems(cfg config.Config, remotes port.RemoteStore) (map[string]port.Ecosystem, error) {
	ecosystems := make(map[string]port.Ecosystem)
	deps := registry.EcosystemDeps{Remotes: remotes, Clock: systemClock{}}
	for name, ecoCfg := range cfg.Ecosystem {
		if !ecoCfg.Enabled {
			continue
		}
		factory, err := registry.Ecosystem(name)
		if err != nil {
			return nil, err
		}
		adapter, err := factory(ecoCfg, deps)
		if err != nil {
			return nil, fmt.Errorf("экосистема %q: %w", name, err)
		}
		ecosystems[name] = adapter
	}
	return ecosystems, nil
}

// WaitTasks — хук graceful shutdown: отменяет ctx-дерево фоновых
// задач и ждёт их завершения в рамках таймаута каскада (server.go).
// Зеркало: сначала стопаем scheduler (per-remote тикеры), затем
// TaskRegistry (ручные sync и потенциальные publish — сессия 14).
func (a *App) WaitTasks(ctx context.Context) error {
	if a.Scheduler != nil {
		if err := a.Scheduler.Stop(ctx); err != nil {
			return err
		}
	}
	if a.Tasks == nil {
		return nil
	}
	return a.Tasks.WaitAll(ctx)
}

// outboundHTTPClient — Doer для запросов upstream: таймауты только на
// соединение и заголовки; тело живёт столько, сколько живёт контекст.
func outboundHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: upstreamConnectTimeout, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:   upstreamConnectTimeout,
			ResponseHeaderTimeout: upstreamConnectTimeout,
		},
	}
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

// Int64 возвращает неотрицательное псевдослучайное число в [0, max):
// 8 байт crypto/rand как uint64, приведённое к диапазону. Используется
// планировщиком зеркал для джиттера интервалов sync.
func (uuidRand) Int64(max int64) int64 {
	if max <= 0 {
		return 0
	}
	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		return 0
	}
	n := int64(b[0])<<56 | int64(b[1])<<48 | int64(b[2])<<40 | int64(b[3])<<32 |
		int64(b[4])<<24 | int64(b[5])<<16 | int64(b[6])<<8 | int64(b[7])
	if n < 0 {
		n = -n
	}
	return n % max
}
