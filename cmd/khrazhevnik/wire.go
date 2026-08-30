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
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"khrazhevnik/internal/core/config"
	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/engine/auth"
	cacheengine "khrazhevnik/internal/core/engine/cache"
	mirrorengine "khrazhevnik/internal/core/engine/mirror"
	publishengine "khrazhevnik/internal/core/engine/publish"
	"khrazhevnik/internal/core/metrics"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/core/registry"
	"khrazhevnik/internal/core/web"

	// Модули: регистрация в compile-time реестре. Каждая новая
	// экосистема/драйвер добавляется сюда одной строкой.
	_ "khrazhevnik/internal/mod/db/mariadb"
	_ "khrazhevnik/internal/mod/db/postgres"
	_ "khrazhevnik/internal/mod/db/sqlite"
	_ "khrazhevnik/internal/mod/ecosystem/apk"
	_ "khrazhevnik/internal/mod/ecosystem/apt"
	_ "khrazhevnik/internal/mod/ecosystem/nix"
	_ "khrazhevnik/internal/mod/ecosystem/pacman"
	_ "khrazhevnik/internal/mod/ecosystem/rpmmmd"
	_ "khrazhevnik/internal/mod/sign/ed25519"
	_ "khrazhevnik/internal/mod/sign/openpgp"
	_ "khrazhevnik/internal/mod/storage/fs"
	_ "khrazhevnik/internal/mod/storage/s3"
)

// App — собранные зависимости сервера; поля набирают движки
// (аутентификация — сессия 05, кеш — 06, метрики и задачи — 09,
// зеркало — 11, publish — 14).
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
	// Publish — API-адаптер движка publish для /repos/{id}/* (сессия 14):
	// upload/delete/list + reindex через TaskRegistry. nil в деградированном
	// режиме; хендлеры отдают 503 publish_unavailable.
	Publish web.PublishAPI
	// Scheduler — фоновый планировщик зеркал; nil, если авто-sync
	// отключён (нет mirror-remotes с SyncInterval>0). Stop вызывается
	// из graceful shutdown каскада.
	Scheduler *mirrorengine.Scheduler
	// Signer — подписчик метаданных личных репозиториев (InRelease +
	// Release.gpg для apt, сессия 15). nil в деградированном режиме
	// (keygen не удался или модуль не слинкован): apt-репо работают
	// без подписи (trusted=yes), /key.asc отдаёт 503.
	Signer port.Signer
	// NarSigner — nix narinfo-подписчик (ed25519, сессия 16). nil в
	// деградированном режиме: nix narinfo не переподписываются (отдаются
	// как есть, подписи upstream валидны, если клиент им доверяет).
	NarSigner port.NarSigner
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

	authService, err := auth.New(auth.Config{
		Users:         catalog.Users,
		Tokens:        catalog.Tokens,
		Revocations:   catalog.Revocations,
		Audit:         catalog.Audit,
		Clock:         systemClock{},
		Rand:          uuidRand{},
		JWTSecret:     cfg.Auth.JWTSecret,
		SessionTTL:    cfg.Auth.SessionTTL.Duration,
		BcryptCost:    cfg.Auth.BcryptCost,
		TouchInterval: cfg.Auth.TouchInterval.Duration,
		ErrorHook:     func(err error) { log.Error("auth", "err", err) },
	})
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
	}, cacheEngine, storage, catalog.ObjIndex, catalog.Remotes, catalog.Jobs, systemClock{}, ecosystems)
	// recovery sync_jobs: записи, зависшие в running после рестарта
	// процесса, помечаются failed — живых воркеров для них больше нет.
	// Сбой каталога не блокирует старт: retry произойдёт на следующем
	// перезапуске, зависшая запись безвредна для прокси.
	if err := mirrorEngine.RecoverInterruptedJobs(context.Background()); err != nil {
		log.Error("mirror: recovery sync_jobs", "err", err)
	}
	// mirrorAPI — обёртка mirror.Engine → web.MirrorSync: запускает
	// Sync как задачу TaskRegistry (kind=sync, label=remote.Name).
	// Замыкание живёт в wire (cmd — место склейки), чтобы engine/mirror
	// не зависел от web (depguard: engine → web запрещён архитектурно).
	mirrorAPI := mirrorSyncer{engine: mirrorEngine, remotes: catalog.Remotes, tasks: tasks}
	// publishEngine — движок личных репозиториев; RepoAdapter'ы
	// собираются из compile-time реестра (только apt в M3; прочие —
	// сессия 16). Отсутствие адаптера — не ошибка старта: upload падёт
	// на ValidateObjectPath с UnsupportedError; reindex — то же.
	// Signer — подписчик метаданных (openpgp, сессия 15): генерирует
	// ключ инстанса в cfg.Signing.KeysDir на первом старте, грузит на
	// повторных. nil в деградированном режиме (модуль не слинкован или
	// keygen упал — логируем и работаем без подписи). Внедряется в
	// RepoAdapter'ы через port.SignerInjector (v1 — только apt).
	signer := wireSigner(cfg, log)
	narSigner := wireNarSigner(cfg, log)
	publishAdapters := wireRepoAdapters(signer, narSigner, systemClock{})
	publishEngine := publishengine.New(publishengine.Config{MaxObjectSize: cfg.Publish.MaxObjectSize.Bytes}, storage, catalog.Repos, systemClock{}, publishAdapters)
	publishAPI := publishSyncer{engine: publishEngine, repos: catalog.Repos, tasks: tasks}
	scheduler := mirrorengine.NewScheduler(mirrorEngine, catalog.Remotes, uuidRand{}, systemClock{}, cfg.Mirror.IntervalJitter.Duration)
	// reconcile-цикл переживает транзиентные сбои БД (ретрай на тике),
	// ошибки — в лог; старт не может «отключить» авто-sync.
	scheduler.ErrorHook = func(err error) { log.Error("mirror scheduler", "err", err) }
	scheduler.Start(context.Background())
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
		Publish:        publishAPI,
		Scheduler:      scheduler,
		Signer:         signer,
		NarSigner:      narSigner,
	}, nil
}

// wireRepoAdapters собирает RepoAdapter'ы из compile-time реестра по
// именам известных экосистем. В M3 зарегистрированы apt (сессия 14),
// rpm-md/pacman/apk/nix (сессия 16); прочие возвращают ошибку при
// lookup (registry.RepoAdapter) и пропускаются. signer (если не nil)
// внедряется в адаптеры, реализующие port.SignerInjector (v1 — apt:
// InRelease + Release.gpg; rpm-md/pacman/apk: detached индекс-sig);
// clock внедряется в адаптеры с метками времени в индексах
// (port.ClockInjector — apt Release/rpm-md repomd, сессия 24).
// narSigner (если не nil) внедряется в адаптеры, реализующие
// port.NarSignerInjector (v1 — nix: переподпись narinfo). Возвращает
// карту name → RepoAdapter для движка publish.
func wireRepoAdapters(signer port.Signer, narSigner port.NarSigner, clock port.Clock) map[string]port.RepoAdapter {
	out := map[string]port.RepoAdapter{}
	for _, name := range registry.Ecosystems() {
		factory, err := registry.RepoAdapter(name)
		if err != nil {
			continue // не зарегистрирован — пропускаем
		}
		adapter, err := factory()
		if err != nil {
			continue
		}
		if signer != nil {
			if inj, ok := adapter.(port.SignerInjector); ok {
				inj.SetSigner(signer)
			}
		}
		if clock != nil {
			if inj, ok := adapter.(port.ClockInjector); ok {
				inj.SetClock(clock)
			}
		}
		if narSigner != nil {
			if inj, ok := adapter.(port.NarSignerInjector); ok {
				inj.SetNarSigner(narSigner)
			}
		}
		out[name] = adapter
	}
	return out
}

// wireNarSigner собирает nix narinfo-подписчик из compile-time реестра
// (ed25519, сессия 16). Отсутствие регистрации или ошибка — не фатально:
// логируем и возвращаем nil (nix narinfo не переподписываются, отдаются
// как есть). Ключ генерируется на первом старте в cfg.Signing.KeysDir
// (файл nix-ed25519.key, 0600), грузится на повторных.
func wireNarSigner(cfg config.Config, log *slog.Logger) port.NarSigner {
	factory, err := registry.NarSigner("ed25519")
	if err != nil {
		log.Error("nix signing: модуль ed25519 не слинкован — narinfo не переподписываются", "err", err)
		return nil
	}
	signer, err := factory(cfg.Signing)
	if err != nil {
		log.Error("nix signing: инициализация nar-подписчика не удалась — narinfo не переподписываются", "err", err, "keys_dir", cfg.Signing.KeysDir)
		return nil
	}
	log.Info("nix signing: narinfo-ключ готов", "keys_dir", cfg.Signing.KeysDir, "pubkey", signer.PubKeyB64())
	return signer
}

// wireSigner собирает подписчик метаданных из compile-time реестра
// (openpgp, сессия 15). Отсутствие регистрации или ошибка keygen —
// не фатально: логируем и возвращаем nil (publish работает без
// подписи, /key.asc отдаёт 503). Ключ генерируется на первом старте
// в cfg.Signing.KeysDir, грузится на повторных.
func wireSigner(cfg config.Config, log *slog.Logger) port.Signer {
	factory, err := registry.Signer("openpgp")
	if err != nil {
		log.Error("signing: модуль openpgp не слинкован — репозитории без подписи", "err", err)
		return nil
	}
	signer, err := factory(cfg.Signing, systemClock{})
	if err != nil {
		log.Error("signing: инициализация подписчика не удалась — репозитории без подписи", "err", err, "keys_dir", cfg.Signing.KeysDir)
		return nil
	}
	log.Info("signing: ключ инстанса готов", "keys_dir", cfg.Signing.KeysDir)
	return signer
}

// publishSyncer — обёртка publish.Engine под web.PublishAPI: запуск
// reindex как фоновой задачи TaskRegistry (kind=reindex, label=
// repo.Name). Живёт в wire (cmd) — единственное место, где core/engine
// и core/web склеиваются; engine/publish не импортирует web (depguard).
type publishSyncer struct {
	engine *publishengine.Engine
	repos  port.RepoStore
	tasks  *web.TaskRegistry
}

// Upload делегирует движку publish (RBAC уже проверен middleware).
func (p publishSyncer) Upload(ctx context.Context, repo domain.Repo, path string, size int64, body io.Reader, force bool) error {
	return p.engine.Upload(ctx, repo, path, size, body, force)
}

// DeleteObject делегирует движку publish.
func (p publishSyncer) DeleteObject(ctx context.Context, repo domain.Repo, path string) error {
	return p.engine.Delete(ctx, repo, path)
}

// ListObjects делегирует движку publish (iter.Seq2 пробрасывается как
// есть — горутина Storage.List под капотом; ошибка листинга идёт в
// хендлер отдельным значением, не «пустым списком»).
func (p publishSyncer) ListObjects(ctx context.Context, repo domain.Repo) iter.Seq2[port.Meta, error] {
	return p.engine.List(ctx, repo)
}

// Reindex запускает publish.Engine.Reindex через TaskRegistry.Start.
func (p publishSyncer) Reindex(ctx context.Context, repoID int64) (string, error) {
	repo, err := p.repos.Repo(ctx, repoID)
	if err != nil {
		return "", err
	}
	return p.tasks.Start("reindex", repo.Name, func(ctx context.Context, prog web.Progress) error {
		// Перечитаем репо: квота/имя могли поменяться между запросом и
		// запуском воркера; берём свежие в начале reindex.
		fresh, err := p.repos.Repo(ctx, repoID)
		if err != nil {
			return fmt.Errorf("reindex: repo: %w", err)
		}
		return p.engine.Reindex(ctx, fresh, publishProgress{p: prog})
	})
}

// publishProgress — адаптер web.Progress → publish.Progress: оба
// интерфейса идентичны по сигнатуре (Update/Log), но это разные типы;
// замыкание переводит вызовы без аллокаций (как mirrorProgress).
type publishProgress struct{ p web.Progress }

func (pp publishProgress) Update(phase, current string, processed, total int64) {
	pp.p.Update(phase, current, processed, total)
}
func (pp publishProgress) Log(line string) { pp.p.Log(line) }

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

// Доли бюджета каскада задач (server.waitTasks передаёт 30s целиком;
// HTTP-фаза уже позади). Одна ошибка стадии больше не прерывает
// остальные (аудит 2026-08-30, сессия 35):Scheduler, съевший весь
// бюджет, оставлял ноль WaitAll и DrainBackgroundDeletes — ровно в
// том деградированном сценарии, где дренаж нужнее всего.
const (
	schedulerStopBudget = 10 * time.Second
	tasksWaitBudget     = 15 * time.Second
	drainDeletesBudget  = 5 * time.Second
)

// WaitTasks — хук graceful shutdown: отменяет ctx-дерево фоновых
// задач и ждёт их завершения в рамках таймаута каскада (server.go).
// Зеркало: сначала стопаем scheduler (per-remote тикеры), затем
// TaskRegistry (ручные sync и потенциальные publish — сессия 14),
// затем дожимаем фоновые удаления прошлых версий mutable-объектов.
// Каждой стадии — своя доля бюджета; ошибки агрегируются, ни одна
// стадия не пропускается из-за ошибки предыдущей.
func (a *App) WaitTasks(ctx context.Context) error {
	var errs []error
	if a.Scheduler != nil {
		sctx, cancel := context.WithTimeout(ctx, schedulerStopBudget)
		defer cancel()
		if err := a.Scheduler.Stop(sctx); err != nil {
			errs = append(errs, fmt.Errorf("scheduler stop: %w", err))
		}
	}
	if a.Tasks != nil {
		tctx, cancel := context.WithTimeout(ctx, tasksWaitBudget)
		defer cancel()
		if err := a.Tasks.WaitAll(tctx); err != nil {
			errs = append(errs, fmt.Errorf("tasks wait: %w", err))
		}
	}
	if a.Cache != nil {
		dctx, cancel := context.WithTimeout(ctx, drainDeletesBudget)
		defer cancel()
		if err := a.Cache.DrainBackgroundDeletes(dctx); err != nil {
			errs = append(errs, fmt.Errorf("background deletes: %w", err))
		}
	}
	return errors.Join(errs...)
}

// NotifyRemotesChanged — хук для web.Deps: будит reconcile-цикл
// планировщика после admin-мутаций remotes. nil-Scheduler (деградация)
// — no-op.
func (a *App) NotifyRemotesChanged() {
	if a.Scheduler != nil {
		a.Scheduler.Notify()
	}
}

// outboundHTTPClient — Doer для запросов upstream: таймауты только на
// соединение и заголовки; тело живёт столько, сколько живёт контекст.
// DisableCompression: иначе Go-транспорт сам шлёт Accept-Encoding: gzip
// и прозрачно расживает ответ — в кеш записались бы расжатые байты с
// ETag сжатого варианта и без Content-Encoding (инвариант «метаданные
// upstream побайтово» сломан для всех upstream с динамическим gzip).
// Клиентские заголовки и так не форвардятся (engine строит новый GET),
// поэтому upstream всегда получает identity.
func outboundHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DisableCompression:    true,
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
