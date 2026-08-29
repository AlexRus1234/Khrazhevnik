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

// Package mirror — движок синхронизации зеркал: фоновый sync upstream-
// репозитория в локальный кеш. Переиспользует cache.Engine для скачивания
// (общий singleflight/TTL/метрики с прокси) — зеркало не лезет в сеть
// само, а греет тот же кеш, который отдаёт клиентам. Новое здесь — обход
// метаданных (Ecosystem.Enumerate), worker pool и resume по diff.
//
// Resume идёт по диффу, а не по курсору: sync_jobs не хранит список
// путей, каждый запуск пересчитывает (Storage.Stat отфильтровывает
// уже скачанные). Это идемпотентно и дешевле очереди в БД. Если sync
// прерван посередине, повторный запуск дочитает только хвост.
package mirror

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"khrazhevnik/internal/core/domain"
	cacheengine "khrazhevnik/internal/core/engine/cache"
	"khrazhevnik/internal/core/port"
)

// Config — параметры движка зеркала.
type Config struct {
	// Workers — число горутин в worker pool параллельных prefetch'ей.
	Workers int
	// MaxBandwidth — лимит суммарной скорости скачивания, байт/сек;
	// 0 — безлимит. Потоковый token-bucket: байты оплачиваются
	// limiter'ом по мере копирования в хранилище (куски ≤ burst),
	// поэтому тело любого размера проходит, а средняя скорость
	// держится на полосе (первый burst байт может вспыхнуть мгновенно).
	MaxBandwidth int64
	// RetryMax — число повторов одного пути при сбое (3 по умолчанию).
	RetryMax int
	// ErrorThreshold — доля ошибок, после которой sync-задача считается
	// failed (0.05 = 5%). 0 = любое число ошибок терпимо.
	ErrorThreshold float64
	// ProgressInterval — как часто воркер батчит обновления sync_jobs
	// в БД (по времени). 0 = дефолт 2с.
	ProgressInterval time.Duration
}

// Дефолты согласованных сессией значений.
const (
	defaultRetryMax         = 3
	defaultErrorThreshold   = 0.05
	defaultProgressInterval = 2 * time.Second
)

// DefaultRetryMax — экспортируемая копия для wire (конфиг там собирается
// из config.Mirror, у которого нет этих полей; зеркало держит свои
// гиперпараметры отдельно, ближе к коду, а не к TOML).
const DefaultRetryMax = defaultRetryMax

// DefaultErrorThreshold — то же для ErrorThreshold.
const DefaultErrorThreshold = defaultErrorThreshold

// Progress — репортёр прогресса фоновой задачи (web.TaskRegistry).
// Mirror не знает о TaskRegistry, только о тонком интерфейсе —
// тесты подменяют без запуска реального реестра.
type Progress interface {
	Update(phase, current string, processed, total int64)
	Log(line string)
}

// Engine — движок синхронизации зеркал.
type Engine struct {
	cache   *cacheengine.Engine
	storage port.Storage
	index   port.ObjectIndex
	remotes port.RemoteStore
	jobs    port.JobStore
	clock   port.Clock
	ecos    map[string]port.Ecosystem
	cfg     Config
	// limiter — общая корзина полосы на все sync движка; nil — безлимит.
	// Потоковый: платёж идёт внутри копирования (cache.PrefetchThrottled),
	// не пост-фактум — объекты крупнее burst больше не валят sync.
	limiter *rate.Limiter
}

// New создаёт движок зеркала. ecoOf — карта экосистем по имени (та же,
// что у прокси-роутера); remote.Ecosystem ищется в ней. nil-карта —
// sync любого remote падает с NotFound (деградированный режим).
// index — ObjectIndex кеша: diff сравнивает mutable-пути по индексной
// записи (байты лежат под версионированными ключами).
func New(cfg Config, c *cacheengine.Engine, storage port.Storage, index port.ObjectIndex, remotes port.RemoteStore, jobs port.JobStore, clock port.Clock, ecos map[string]port.Ecosystem) *Engine {
	if cfg.Workers < 1 {
		cfg.Workers = 1
	}
	if cfg.RetryMax < 0 {
		cfg.RetryMax = defaultRetryMax
	}
	if cfg.ErrorThreshold <= 0 {
		cfg.ErrorThreshold = defaultErrorThreshold
	}
	if cfg.ProgressInterval <= 0 {
		cfg.ProgressInterval = defaultProgressInterval
	}
	if clock == nil {
		// Обоснование фолбэка (аудит item 21): продакшн-wire всегда
		// передаёт часы явно; системная реализация остаётся для
		// вызовов без wire (unit-тесты со значением по умолчанию),
		// чтобы нулевые зависимости не паниковали в рантайме.
		clock = systemClock{}
	}
	var limiter *rate.Limiter
	if cfg.MaxBandwidth > 0 {
		limiter = rate.NewLimiter(rate.Limit(cfg.MaxBandwidth), int(cfg.MaxBandwidth))
	}
	return &Engine{
		cache: c, storage: storage, index: index, remotes: remotes, jobs: jobs,
		clock: clock, ecos: ecos, cfg: cfg, limiter: limiter,
	}
}

// throttle — оплата байт по мере копирования: куски ≤ burst (контракт
// rate.Limiter.WaitN: n > burst мгновенно возвращает ошибку, поэтому
// большие тела платят частями). nil — безлимит.
func (e *Engine) throttle() cacheengine.Throttle {
	if e.limiter == nil {
		return nil
	}
	burst := int(e.cfg.MaxBandwidth)
	return func(ctx context.Context, n int) error {
		for n > 0 {
			take := min(n, burst)
			if err := e.limiter.WaitN(ctx, take); err != nil {
				return err
			}
			n -= take
		}
		return nil
	}
}

// Sync синхронизирует remote: enumerate → diff → worker pool prefetch.
// Блокирует до завершения; вызывающий — воркер TaskRegistry. Прогресс
// пишется в p (кадры) и sync_jobs (батч по ProgressInterval). Отмена ctx
// гасит воркеры; sync_jobs помечается failed. Ошибочные пути ретрятся
// до RetryMax; задача failed если доля ошибок > ErrorThreshold.
func (e *Engine) Sync(ctx context.Context, remote domain.Remote, p Progress) error {
	if p == nil {
		p = noopProgress{}
	}
	if e.cache == nil {
		return fmt.Errorf("mirror: cache engine не сконфигурирован")
	}
	eco, ok := e.ecos[remote.Ecosystem]
	if !ok {
		return &domain.NotFoundError{What: "экосистема", Key: remote.Ecosystem}
	}
	if !remote.Enabled {
		return &domain.ValidationError{What: "remote", Value: remote.Name, Reason: "выключен"}
	}
	job, err := e.startJob(ctx, remote)
	if err != nil {
		return fmt.Errorf("mirror: sync_jobs: %w", err)
	}
	p.Log(fmt.Sprintf("sync remote %s (eco=%s) старт", remote.Name, remote.Ecosystem))

	// Фаза 1: enumerate (метаданные качаются через cache-движок).
	p.Update("enumerate", remote.Name, 0, 0)
	mf := metaFetcher{engine: e.cache, eco: eco}
	paths, err := eco.Enumerate(ctx, remote, mf)
	if err != nil {
		var uns *domain.UnsupportedError
		if errors.As(err, &uns) {
			p.Log(fmt.Sprintf("enumerate не поддерживается: %v", err))
			_ = e.failJob(job, err)
			return err
		}
		_ = e.failJob(job, err)
		return fmt.Errorf("mirror: enumerate: %w", err)
	}
	p.Log(fmt.Sprintf("enumerate: %d путей", len(paths)))

	// Фаза 2: diff — отфильтровать уже скачанные (индекс + Stat).
	p.Update("diff", fmt.Sprintf("%s: %d путей", remote.Name, len(paths)), 0, int64(len(paths)))
	dr, err := e.diff(ctx, eco, remote, paths)
	if err != nil {
		_ = e.failJob(job, err)
		return fmt.Errorf("mirror: diff: %w", err)
	}
	p.Log(fmt.Sprintf("diff: %d к скачиванию, %d пропущено", len(dr.toSync), dr.skipped))
	if len(dr.toSync) == 0 {
		_ = e.succeedJob(job, 0, 0)
		p.Update("done", remote.Name, 0, 0)
		p.Log("sync завершён: нечего скачивать")
		return nil
	}

	// Фаза 3: worker pool prefetch.
	p.Update("download", remote.Name, 0, int64(len(dr.toSync)))
	res := e.download(ctx, eco, remote, dr.toSync, p)
	p.Log(fmt.Sprintf("download: скачано %d, ошибок %d, stale %d, %s",
		res.done, res.failed, res.stale, humanBytes(res.bytes)))
	if len(res.errors) > 0 {
		// топ-10 причин — в лог задачи: без агрегата причины путей
		// терялись (res.errors собирался, но не читался)
		for _, line := range topErrors(res.errors, 10) {
			p.Log("ошибка: " + line)
		}
	}

	if res.failed > 0 && float64(res.failed)/float64(len(dr.toSync)) > e.cfg.ErrorThreshold {
		err := fmt.Errorf("sync: %d из %d путей упали (>%.0f%%)", res.failed, len(dr.toSync), e.cfg.ErrorThreshold*100)
		_ = e.failJob(job, err)
		p.Log("sync завершён ошибкой: " + err.Error())
		return err
	}
	_ = e.succeedJob(job, res.done, res.bytes)
	p.Update("done", remote.Name, int64(res.done), int64(len(dr.toSync)))
	p.Log("sync завершён успешно")
	return nil
}

// downloadResult — итог worker pool.
type downloadResult struct {
	done   int
	failed int
	stale  int
	bytes  int64
	errors []string
}

// download запускает worker pool по toSync (ecosystem-пути с ведущим /).
func (e *Engine) download(ctx context.Context, eco port.Ecosystem, remote domain.Remote, toSync []string, p Progress) downloadResult {
	in := make(chan string)
	out := make(chan pathResult)
	var wg sync.WaitGroup

	for range e.cfg.Workers {
		wg.Add(1)
		go e.worker(ctx, eco, &wg, in, out)
	}
	// feeder: правит пути в канал, выход по ctx.Done.
	feedDone := make(chan struct{})
	go func() {
		defer close(in)
		defer close(feedDone)
		for _, path := range toSync {
			select {
			case in <- path:
			case <-ctx.Done():
				return
			}
		}
	}()

	collectDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(out)
		close(collectDone)
	}()

	// collector: считает прогресс, батчит sync_jobs по интервалу.
	var res downloadResult
	var processed atomic.Int64
	lastFlush := e.clock.Now()
	totals := int64(len(toSync))
	for pr := range out {
		processed.Add(1)
		switch {
		case pr.err != nil:
			res.failed++
			res.errors = append(res.errors, pr.path+": "+pr.err.Error())
		case pr.stale:
			// объект отдан из кеша при сбойном upstream — деградация,
			// не сбой: в failed не попадает и ErrorThreshold не растит
			res.stale++
			res.done++
			res.bytes += pr.bytes
		default:
			res.done++
			res.bytes += pr.bytes
		}
		p.Update("download", remote.Name, processed.Load(), totals)
		if e.clock.Now().Sub(lastFlush) >= e.cfg.ProgressInterval {
			_ = e.touchJob(ctx, remote, processed.Load(), res.bytes)
			lastFlush = e.clock.Now()
		}
	}
	<-feedDone
	<-collectDone
	return res
}

// pathResult — итог одного prefetch.
type pathResult struct {
	path  string
	bytes int64
	stale bool
	err   error
}

// worker тянет пути из in, prefetch'ит с retry (полоса платится
// потоково внутри копирования), пишет результат в out.
func (e *Engine) worker(ctx context.Context, eco port.Ecosystem, wg *sync.WaitGroup, in <-chan string, out chan<- pathResult) {
	defer wg.Done()
	for path := range in {
		if ctx.Err() != nil {
			out <- pathResult{path: path, err: ctx.Err()}
			return
		}
		res, err := e.prefetchWithRetry(ctx, eco, path)
		if err != nil {
			var stale *domain.StaleError
			if errors.As(err, &stale) {
				// stale ≠ failure: объект отдан из кеша — это деградация
				// при сбойном upstream, ретраить нечего и не нужно
				out <- pathResult{path: path, bytes: res.Bytes, stale: true}
				continue
			}
			out <- pathResult{path: path, err: err}
			continue
		}
		out <- pathResult{path: path, bytes: res.Bytes}
	}
}

// prefetchWithRetry повторяет prefetch до RetryMax раз; NotFound
// не ретрится (upstream удалил объект — это не сбой сети), StaleError
// не ретрится (объект отдан из кеша — результат уже получен).
func (e *Engine) prefetchWithRetry(ctx context.Context, eco port.Ecosystem, ecosystemPath string) (cacheengine.PrefetchResult, error) {
	var lastErr error
	for attempt := 0; attempt <= e.cfg.RetryMax; attempt++ {
		if ctx.Err() != nil {
			return cacheengine.PrefetchResult{}, ctx.Err()
		}
		res, err := e.cache.PrefetchThrottled(ctx, eco, ecosystemPath, e.throttle())
		if err == nil {
			return res, nil
		}
		var stale *domain.StaleError
		if errors.As(err, &stale) {
			return res, err
		}
		var nf *domain.NotFoundError
		if errors.As(err, &nf) {
			return res, err
		}
		lastErr = err
	}
	return cacheengine.PrefetchResult{}, lastErr
}

// diffResult — итог diff: пути к скачиванию и мусорные пути enumerate
// (не маппятся и не классифицируются — молча терять их нельзя, счётчик
// попадает в лог задачи).
type diffResult struct {
	toSync  []string
	skipped int
}

// diff фильтрует пути, уже присутствующие в кеше. Immutable — по Stat
// логического ключа; mutable — по индексу: байты лежат под
// версионированными ключами, поэтому Stat логического ключа считал их
// отсутствующими и перекачивал каждый sync. Свежий по TTL mutable
// пропускается; протухший идёт в prefetch — тот ревалидируется
// conditional-запросом (304 бесплатен) и даёт stale при сбойном
// upstream. Ошибка индекса (кроме NotFound) — fail-closed: транзиентный
// сбой БД не должен «опустошать» diff.
func (e *Engine) diff(ctx context.Context, eco port.Ecosystem, remote domain.Remote, upstreamPaths []string) (diffResult, error) {
	var out diffResult
	for _, up := range upstreamPaths {
		if ctx.Err() != nil {
			return diffResult{}, ctx.Err()
		}
		ecoPath := "/" + eco.URLPrefix() + "/" + remote.Name + up
		target, ok := eco.Resolve(ecoPath)
		if !ok {
			out.skipped++
			continue
		}
		class, err := eco.Classify(target.UpstreamPath)
		if err != nil {
			// enumerate отдал путь, который экосистема не понимает
			out.skipped++
			continue
		}
		present := false
		if class.Kind == domain.KindMutable {
			meta, mErr := e.index.ObjectMeta(ctx, target.StorageKey)
			switch {
			case mErr == nil:
				_, sErr := e.storage.Stat(ctx, meta.BytesKey())
				present = sErr == nil && !meta.Expired(e.clock.Now())
			case isNotFound(mErr):
				// нет записи — качать
			default:
				return diffResult{}, mErr
			}
		} else if _, err := e.storage.Stat(ctx, target.StorageKey); err == nil {
			present = true
		}
		if present {
			continue
		}
		out.toSync = append(out.toSync, ecoPath)
	}
	return out, nil
}

// topErrors — агрегат причин ошибок: до n самых частых сообщений с
// числом повторов (детерминированный порядок: частота, затем текст).
func topErrors(errs []string, n int) []string {
	counts := make(map[string]int, len(errs))
	for _, e := range errs {
		counts[e]++
	}
	type row struct {
		msg string
		n   int
	}
	rows := make([]row, 0, len(counts))
	for msg, c := range counts {
		rows = append(rows, row{msg, c})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].n != rows[j].n {
			return rows[i].n > rows[j].n
		}
		return rows[i].msg < rows[j].msg
	})
	if len(rows) > n {
		rows = rows[:n]
	}
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = fmt.Sprintf("%dx %s", r.n, r.msg)
	}
	return out
}

// metaFetcher — port.MetaFetcher поверх cache.Engine: биндит экосистему,
// отдаёт тело метаданных через тот же fetch, что и прокси (singleflight,
// TTL, метрики). Закрыть тело обязан вызывающий (Ecosystem.Enumerate).
type metaFetcher struct {
	engine *cacheengine.Engine
	eco    port.Ecosystem
}

func (m metaFetcher) Fetch(ctx context.Context, ecosystemPath string) (io.ReadCloser, error) {
	obj, err := m.engine.Fetch(ctx, m.eco, ecosystemPath)
	if err != nil {
		return nil, err
	}
	return obj.Body, nil
}

// noopProgress — заглушка, чтобы Sync можно было звать без репортёра
// (например, из тестов, где прогресс не проверяется).
type noopProgress struct{}

func (noopProgress) Update(string, string, int64, int64) {}
func (noopProgress) Log(string)                          {}

// systemClock — port.Clock поверх time.Now (зеркало без явных часов
// в тестах получает системную реализацию).
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// humanBytes — компактное число байт для лога задачи.
func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
