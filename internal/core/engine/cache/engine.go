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

// Package cache — pull-through движок кеша: immutable-объекты
// скачиваются один раз навсегда, mutable-объекты ревалидируются
// conditional-запросами. Замена mutable-версии идёт через запись под
// новый ключ и фоновое удаление старого, чтобы читатели старой версии
// не зависели от rename поверх открытого файла (невозможен на Windows);
// сбой удаления оставляет осиротевший ключ — выметающей чистки в v1
// нет (см. ROADMAP).
package cache

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/metrics"
	"khrazhevnik/internal/core/port"
)

// Config задаёт ограничения pull-through кеша. TTL mutable-объектов
// движку не нужен: его определяет классификатор экосистемы.
type Config struct {
	StaleIfError   bool
	MaxObjectSize  int64
	NegativeTTL404 time.Duration
	NegativeTTL5xx time.Duration
}

// negative — запись negative-кеша: до какого момента отдавать ошибку
// без похода upstream.
type negative struct {
	until time.Time
	err   error
}

// Потолки in-memory таблиц. Почему выметается произвольная запись, а не
// LRU: обе таблицы — только оптимизация (fail-fast ошибок и warm-кеш
// заголовков), точность вытеснения на правильность не влияет, а
// полноценный LRU здесь — лишняя сложность и аллокации.
const (
	negativeCap = 10000
	metaCap     = 10000
	// deleteConcurrency — потолок параллельных фоновых удалений прошлых
	// версий mutable-объектов: всплеск замен не должен выметать носитель.
	deleteConcurrency = 4
)

// Статусы исхода кеша для X-Cache.
const (
	statusHit   = "HIT"
	statusMiss  = "MISS"
	statusStale = "STALE"
)

// Engine реализует byte-preserving pull-through кеш.
type Engine struct {
	storage port.Storage
	index   port.ObjectIndex
	doer    port.Doer
	clock   port.Clock
	cfg     Config
	metrics *metrics.Cache
	flights singleflight.Group
	mu      sync.RWMutex
	// meta — заголовки immutable-объектов (ETag/Content-Type/
	// LastModified): fs-хранилище их не знает, а плодить по строке в
	// БД на каждый пакет нельзя. После перезапуска теряются — это
	// снижает только точность заголовков, не корректность.
	meta map[string]domain.ObjectMeta
	// negative — TTL-кеш последних 404/5xx, чтобы клиенты не
	// дергали upstream зря. Перезапуск очищает — это осознанно.
	negative map[string]negative
	// nonce различает версии между запусками процесса; seq нумерует
	// записи внутри запуска — вместе дают уникальный ключ версии.
	nonce uint64
	seq   atomic.Uint64

	// Фоновые удаления прошлых версий: семафор ограничивает
	// параллелизм, счётчик+idle-канал — Drain при shutdown (не
	// sync.WaitGroup: Add с нулевым счётчиком concurrently с Wait
	// паникует в новом Go, а revalidate может завершиться посреди
	// Drain'а).
	delSem     chan struct{}
	delMu      sync.Mutex
	delPending int
	delIdle    chan struct{} // закрывается при delPending == 0
}

// New создаёт движок кеша.
func New(storage port.Storage, index port.ObjectIndex, doer port.Doer, clock port.Clock, cfg Config, m *metrics.Cache) *Engine {
	if m == nil {
		m = metrics.NewCache()
	}
	return &Engine{
		storage:  storage,
		index:    index,
		doer:     doer,
		clock:    clock,
		cfg:      cfg,
		metrics:  m,
		meta:     make(map[string]domain.ObjectMeta),
		negative: make(map[string]negative),
		nonce:    uint64(clock.Now().UnixNano()),
		delSem:   make(chan struct{}, deleteConcurrency),
	}
}

// Fetch возвращает независимый поток объекта из кеша или upstream.
func (e *Engine) Fetch(ctx context.Context, eco port.Ecosystem, ecosystemPath string) (port.Object, error) {
	obj, _, err := e.fetch(ctx, eco, ecosystemPath)
	return obj, err
}

// FetchStatus — Fetch с исходом кеша (HIT|MISS|STALE) для заголовка
// X-Cache. Статус честный: считается по факту сработавшей ветки, а не
// предсказанием до похода в кеш.
func (e *Engine) FetchStatus(ctx context.Context, eco port.Ecosystem, ecosystemPath string) (port.Object, string, error) {
	return e.fetch(ctx, eco, ecosystemPath)
}

// PrefetchResult — итог prefetch: статус кеша и размер объекта для
// прогресса зеркала. Downloaded — байты, реальнотянутые из upstream
// (0 у HIT и 304-ревалидации); Bytes — полный размер объекта в кеше.
type PrefetchResult struct {
	Status     string
	Bytes      int64
	Downloaded int64
}

// Throttle — плата за байты по мере копирования в хранилище: wait
// блокирует, пока n байт не «оплачены». Зеркало передаёт обёртку
// rate.Limiter (полоса mirror.max_bandwidth), прокси-путь зовётся
// без ограничителя (nil). Разбиение n до burst лимитера — забота
// реализации wait: движок знает только «сколько байт ушло в Write».
type Throttle func(ctx context.Context, n int) error

// Prefetch скачивает объект в кеш, не открывая тело вызывающему —
// зеркало греет кеш пакетами, клиентам байты отдаёт прокси-роутер.
// HIT — объект уже в кеше, ничего не качает; MISS — скачивает;
// STALE — отдал протухшую копию вместо ошибки upstream (как Fetch).
// Метрики учитываются тем же путём, что и Fetch.
func (e *Engine) Prefetch(ctx context.Context, eco port.Ecosystem, ecosystemPath string) (PrefetchResult, error) {
	return e.PrefetchThrottled(ctx, eco, ecosystemPath, nil)
}

// PrefetchThrottled — Prefetch с потоковым ограничителем полосы:
// байты оплачиваются wait'ом по мере копирования в хранилище (а не
// пост-фактум), поэтому тело любого размера проходит, полоса
// соблюдается в процессе скачивания.
func (e *Engine) PrefetchThrottled(ctx context.Context, eco port.Ecosystem, ecosystemPath string, wait Throttle) (PrefetchResult, error) {
	target, ok := eco.Resolve(ecosystemPath)
	if !ok {
		return PrefetchResult{}, &domain.NotFoundError{What: "путь", Key: ecosystemPath}
	}
	class, err := eco.Classify(target.UpstreamPath)
	if err != nil {
		return PrefetchResult{}, err
	}
	if err := class.Validate(); err != nil {
		return PrefetchResult{}, err
	}
	m := e.metrics.ForEcosystem(eco.Name())
	if class.Kind == domain.KindImmutable {
		return e.prefetchImmutable(ctx, target, class, m, wait)
	}
	return e.prefetchMutable(ctx, target, class, m, wait)
}

// prefetchImmutable — Stat-only HIT-путь (тело не открывается); MISS
// идёт через тот же singleflight, что и Fetch — параллельные Fetch и
// Prefetch на один ключ не дёрнут upstream дважды.
func (e *Engine) prefetchImmutable(ctx context.Context, target port.Target, class domain.Class, m *metrics.Cache, wait Throttle) (PrefetchResult, error) {
	if err := e.negativeError(target.StorageKey); err != nil {
		return PrefetchResult{}, err
	}
	if meta, err := e.storage.Stat(ctx, target.StorageKey); err == nil {
		m.Hits.Add(1)
		return PrefetchResult{Status: statusHit, Bytes: meta.Size}, nil
	}
	m.Misses.Add(1)
	_, err, _ := e.flights.Do(target.StorageKey, func() (any, error) {
		if _, statErr := e.storage.Stat(ctx, target.StorageKey); statErr == nil {
			return nil, nil
		}
		om, _, ferr := e.fetchOnce(ctx, target, class, nil, wait)
		if ferr != nil {
			return nil, ferr
		}
		// prefetch не отдаёт тело наружу; метаданные immutable'а
		// уже спрятаны в in-memory таблице fetchOnce'ом.
		_ = om
		return nil, nil
	})
	if err != nil {
		return PrefetchResult{}, err
	}
	meta, err := e.storage.Stat(ctx, target.StorageKey)
	if err != nil {
		return PrefetchResult{}, err
	}
	return PrefetchResult{Status: statusMiss, Bytes: meta.Size, Downloaded: meta.Size}, nil
}

// prefetchMutable — ревалидация без отдачи тела; индекс обновляется
// тем же путём, что и Fetch. HIT — индекс свеж и байты на месте.
//
//nolint:gocyclo // mutable-prefetch: ветки HIT/negative/revalidate/stale — одна атомарная операция
func (e *Engine) prefetchMutable(ctx context.Context, target port.Target, class domain.Class, m *metrics.Cache, wait Throttle) (PrefetchResult, error) {
	indexed, indexErr := e.index.ObjectMeta(ctx, target.StorageKey)
	if indexErr == nil && !indexed.Expired(e.clock.Now()) {
		if meta, err := e.storage.Stat(ctx, indexed.BytesKey()); err == nil {
			m.Hits.Add(1)
			return PrefetchResult{Status: statusHit, Bytes: meta.Size}, nil
		}
	}
	if negErr := e.negativeError(target.StorageKey); negErr != nil {
		if indexErr == nil {
			if _, _, ok := e.staleServe(ctx, negErr, &indexed, m); ok {
				return PrefetchResult{Status: statusStale, Bytes: indexed.Size}, &domain.StaleError{Have: indexed.ETag}
			}
		}
		return PrefetchResult{}, negErr
	}
	m.Misses.Add(1)
	var old *domain.ObjectMeta
	if indexErr == nil {
		old = &indexed
	}
	res, err, _ := e.flights.Do(target.StorageKey, func() (any, error) {
		return e.revalidate(ctx, target, class, &old, wait)
	})
	if err != nil {
		if _, _, ok := e.staleServe(ctx, err, old, m); ok {
			return PrefetchResult{Status: statusStale, Bytes: old.Size}, &domain.StaleError{Have: old.ETag}
		}
		return PrefetchResult{}, err
	}
	if res == nil {
		// индекс освежен параллельным полётом — перечитываем
		cur, curErr := e.index.ObjectMeta(ctx, target.StorageKey)
		if curErr != nil {
			return PrefetchResult{}, curErr
		}
		meta, err := e.storage.Stat(ctx, cur.BytesKey())
		if err != nil {
			return PrefetchResult{}, err
		}
		m.Hits.Add(1)
		return PrefetchResult{Status: statusHit, Bytes: meta.Size}, nil
	}
	r, ok := res.(*mutableResult)
	if !ok {
		return PrefetchResult{}, fmt.Errorf("кеш: prefetch: неожиданный тип результата полёта %T", res)
	}
	meta, err := e.storage.Stat(ctx, r.meta.BytesKey())
	if err != nil {
		return PrefetchResult{}, err
	}
	if r.revalidated {
		// 304 — байты не тянули, индекс продлён
		m.Hits.Add(1)
		return PrefetchResult{Status: statusHit, Bytes: meta.Size}, nil
	}
	return PrefetchResult{Status: statusMiss, Bytes: meta.Size, Downloaded: meta.Size}, nil
}

// AddBytesToClients records bytes copied by the HTTP delivery layer.
func (e *Engine) AddBytesToClients(n int64) { e.metrics.AddBytesToClients(n) }

// Metrics возвращает ссылку на счётчики кеша — для админ-API
// (GET /api/v1/cache/stats) и Prometheus-экспозиции (web-слой строит
// metrics.NewHandler на этом же *Cache).
func (e *Engine) Metrics() *metrics.Cache { return e.metrics }

func (e *Engine) fetch(ctx context.Context, eco port.Ecosystem, ecosystemPath string) (port.Object, string, error) {
	target, ok := eco.Resolve(ecosystemPath)
	if !ok {
		return port.Object{}, "", &domain.NotFoundError{What: "путь", Key: ecosystemPath}
	}
	class, err := eco.Classify(target.UpstreamPath)
	if err != nil {
		return port.Object{}, "", err
	}
	if err := class.Validate(); err != nil {
		return port.Object{}, "", err
	}
	if class.Kind == domain.KindImmutable {
		return e.fetchImmutable(ctx, target, class, e.metrics.ForEcosystem(eco.Name()))
	}
	return e.fetchMutable(ctx, target, class, e.metrics.ForEcosystem(eco.Name()))
}

func (e *Engine) fetchImmutable(ctx context.Context, target port.Target, class domain.Class, m *metrics.Cache) (port.Object, string, error) {
	if err := e.negativeError(target.StorageKey); err != nil {
		return port.Object{}, "", err
	}
	// resilience: refetch при сбойном HIT — сбой чтения кеша (в т.ч.
	// недоступное хранилище) деградирует в MISS; лежащий целиком носитель
	// вернёт UnavailableError с write-пути fetch'а (503), а не 503 на
	// каждом чтении (сессия 60).
	if obj, err := e.cached(ctx, target.StorageKey); err == nil {
		m.Hits.Add(1)
		return obj, statusHit, nil
	}
	m.Misses.Add(1)
	_, err, _ := e.flights.Do(target.StorageKey, func() (any, error) {
		if _, statErr := e.storage.Stat(ctx, target.StorageKey); statErr == nil {
			return nil, nil
		}
		_, _, err := e.fetchOnce(ctx, target, class, nil, nil)
		return nil, err
	})
	if err != nil {
		return port.Object{}, "", err
	}
	obj, err := e.cached(ctx, target.StorageKey)
	if err != nil {
		return port.Object{}, "", err
	}
	return obj, statusMiss, nil
}

// mutableResult — итог успешной ревалидации: участники singleflight
// получают его от исполнителя полёта, а не пересобирают сами.
type mutableResult struct {
	meta        domain.ObjectMeta
	revalidated bool
}

func (e *Engine) fetchMutable(ctx context.Context, target port.Target, class domain.Class, m *metrics.Cache) (port.Object, string, error) {
	indexed, indexErr := e.index.ObjectMeta(ctx, target.StorageKey)
	if indexErr == nil && !indexed.Expired(e.clock.Now()) {
		// resilience: refetch при сбойном HIT — как в fetchImmutable
		// (сессия 60): сбой чтения кеша деградирует в ревалидацию,
		// а не обрывает раздачу.
		if obj, err := e.cachedAt(ctx, indexed); err == nil {
			m.Hits.Add(1)
			return obj, statusHit, nil
		}
	}
	// свежий 404/5xx не должен долбить upstream каждым клиентом
	if negErr := e.negativeError(target.StorageKey); negErr != nil {
		if indexErr == nil {
			if obj, stale, ok := e.staleServe(ctx, negErr, &indexed, m); ok {
				return obj, statusStale, stale
			}
		}
		return port.Object{}, "", negErr
	}
	m.Misses.Add(1)
	var old *domain.ObjectMeta
	if indexErr == nil {
		old = &indexed
	}
	res, err, _ := e.flights.Do(target.StorageKey, func() (any, error) {
		return e.revalidate(ctx, target, class, &old, nil)
	})
	if err != nil {
		if obj, stale, ok := e.staleServe(ctx, err, old, m); ok {
			return obj, statusStale, stale
		}
		return port.Object{}, "", err
	}
	if res == nil {
		// исполнитель полёта увидел свежую запись — перечитываем индекс
		return e.serveReloaded(ctx, target, m)
	}
	r, ok := res.(*mutableResult)
	if !ok {
		return port.Object{}, "", fmt.Errorf("кеш: неожиданный тип результата полёта %T", res)
	}
	obj, err := e.cachedAt(ctx, r.meta)
	if err != nil {
		return port.Object{}, "", err
	}
	if r.revalidated {
		m.Hits.Add(1)
		return obj, statusHit, nil
	}
	return obj, statusMiss, nil
}

// revalidate — тело singleflight-полёта mutable-объекта: двойная
// проверка индекса (участник прошлого полёта мог уже освежить),
// conditional-запрос и запись результата. nil, nil — индекс свежий.
// wait (полоса зеркала) пробрасывается в копирование; прокси-путь
// зовётся с nil — клиентский трафик не троттлится.
func (e *Engine) revalidate(ctx context.Context, target port.Target, class domain.Class, old **domain.ObjectMeta, wait Throttle) (any, error) {
	cur, curErr := e.index.ObjectMeta(ctx, target.StorageKey)
	if curErr == nil {
		if !cur.Expired(e.clock.Now()) {
			return nil, nil
		}
		*old = &cur
	} else {
		*old = nil
	}
	meta, rev, fetchErr := e.fetchOnce(ctx, target, class, *old, wait)
	if fetchErr != nil {
		return nil, fetchErr
	}
	e.forgetNegative(target.StorageKey)
	return &mutableResult{meta: meta, revalidated: rev}, nil
}

// serveReloaded отдаёт запись, освеженную параллельным полётом.
func (e *Engine) serveReloaded(ctx context.Context, target port.Target, m *metrics.Cache) (port.Object, string, error) {
	cur, curErr := e.index.ObjectMeta(ctx, target.StorageKey)
	if curErr != nil {
		return port.Object{}, "", curErr
	}
	obj, err := e.cachedAt(ctx, cur)
	if err != nil {
		return port.Object{}, "", err
	}
	m.Hits.Add(1)
	return obj, statusHit, nil
}

// staleServe отдаёт протухшую копию вместо ошибки upstream
// (RFC 5861 stale-if-error). Только для сбойного upstream: 404 —
// авторитетное «объекта больше нет», маскировать его stale-копией
// нельзя.
func (e *Engine) staleServe(ctx context.Context, cause error, old *domain.ObjectMeta, m *metrics.Cache) (port.Object, *domain.StaleError, bool) {
	var up *domain.UpstreamError
	if old == nil || !e.cfg.StaleIfError || !errors.As(cause, &up) {
		return port.Object{}, nil, false
	}
	obj, err := e.cachedAt(ctx, *old)
	if err != nil {
		return port.Object{}, nil, false
	}
	m.StaleServed.Add(1)
	return obj, &domain.StaleError{Have: old.ETag}, true
}

//nolint:gocyclo // разбор статуса, bounded-стрим и транзакционный коммит — одна атомарная операция
func (e *Engine) fetchOnce(ctx context.Context, target port.Target, class domain.Class, old *domain.ObjectMeta, wait Throttle) (domain.ObjectMeta, bool, error) {
	headers := map[string]string{}
	if old != nil {
		if old.ETag != "" {
			headers["If-None-Match"] = old.ETag
		}
		if !old.LastModified.IsZero() {
			headers["If-Modified-Since"] = old.LastModified.UTC().Format(time.RFC1123)
		}
	}
	req, err := port.NewGETRequest(ctx, target.UpstreamURL, headers)
	if err != nil {
		return domain.ObjectMeta{}, false, &domain.UpstreamError{URL: target.UpstreamURL, Err: err}
	}
	resp, err := e.doer.Do(req)
	if err != nil {
		e.metrics.UpstreamErrors.Add(1)
		return domain.ObjectMeta{}, false, &domain.UpstreamError{URL: target.UpstreamURL, Err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode == 304 && old != nil {
		updated := *old
		updated.ExpiresAt = e.clock.Now().Add(class.TTL)
		// RFC 9110 разрешает серверу обновлять валидаторы в 304:
		// свежие ETag/Last-Modified продлевают будущие conditional
		// запросы, а не только TTL.
		if etag := resp.Header.Get("ETag"); etag != "" {
			updated.ETag = etag
		}
		if t, parseErr := parseHTTPTime(resp.Header.Get("Last-Modified")); parseErr == nil {
			updated.LastModified = t
		}
		if err := e.index.PutObjectMeta(ctx, updated); err != nil {
			return domain.ObjectMeta{}, false, err
		}
		return updated, true, nil
	}
	if resp.StatusCode == 404 {
		e.metrics.UpstreamErrors.Add(1)
		err := &domain.NotFoundError{What: "upstream объект", Key: target.UpstreamPath}
		e.rememberNegative(target.StorageKey, e.cfg.NegativeTTL404, err)
		return domain.ObjectMeta{}, false, err
	}
	if resp.StatusCode >= 500 {
		e.metrics.UpstreamErrors.Add(1)
		err := &domain.UpstreamError{URL: target.UpstreamURL, Status: resp.StatusCode}
		e.rememberNegative(target.StorageKey, e.cfg.NegativeTTL5xx, err)
		return domain.ObjectMeta{}, false, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return domain.ObjectMeta{}, false, &domain.UpstreamError{URL: target.UpstreamURL, Status: resp.StatusCode}
	}
	if e.cfg.MaxObjectSize > 0 && resp.ContentLength > e.cfg.MaxObjectSize {
		// отказ до чтения тела: лимит известен из заголовка
		return domain.ObjectMeta{}, false, &domain.TooLargeError{Size: resp.ContentLength, Limit: e.cfg.MaxObjectSize}
	}
	writeKey := target.StorageKey
	if class.Kind == domain.KindMutable {
		writeKey = e.versionedKey(target.StorageKey)
	}
	w, err := e.storage.Put(ctx, writeKey)
	if err != nil {
		return domain.ObjectMeta{}, false, err
	}
	n, err := e.copyBody(ctx, w, resp.Body, resp.ContentLength, target.Checksum, target.UpstreamURL, wait)
	if err != nil {
		_ = w.Abort(context.Background())
		var cm *checksumMismatch
		if errors.As(err, &cm) {
			// Битый/подменённый upstream не должен отравить immutable
			// («навсегда») кеш: объект не закоммичен, повторные
			// запросы до конца TTL не долбят upstream.
			e.metrics.UpstreamErrors.Add(1)
			e.rememberNegative(target.StorageKey, e.cfg.NegativeTTL5xx, err)
		}
		return domain.ObjectMeta{}, false, err
	}
	if err := w.Commit(ctx); err != nil {
		_ = w.Abort(context.Background())
		return domain.ObjectMeta{}, false, err
	}
	meta := domain.ObjectMeta{
		Key:         target.StorageKey,
		StorageKey:  writeKey,
		Size:        n,
		ETag:        resp.Header.Get("ETag"),
		ContentType: resp.Header.Get("Content-Type"),
	}
	if v := resp.Header.Get("Last-Modified"); v != "" {
		if t, parseErr := parseHTTPTime(v); parseErr == nil {
			meta.LastModified = t
		}
	}
	if class.Kind == domain.KindMutable {
		meta.ExpiresAt = e.clock.Now().Add(class.TTL)
		if err := e.index.PutObjectMeta(ctx, meta); err != nil {
			return domain.ObjectMeta{}, false, err
		}
		if old != nil {
			e.deleteInBackground(old)
		}
	} else {
		e.rememberMeta(target.StorageKey, meta)
	}
	return meta, false, nil
}

// throttledWriter — writer-обёртка вокруг копирования: перед записью
// куска ожидает разрешения лимитера. Куски приходят размером с буфер
// io.Copy — разбиение до burst лимитера — забота wait'а (mirror),
// который знает burst своей корзины.
type throttledWriter struct {
	dst  io.Writer
	wait Throttle
	ctx  context.Context
}

// Write реализует io.Writer: сначала полная оплата куска, затем запись.
// Ошибка wait (отмена ctx) прерывает копирование — upstream-тело
// выбрасывается вызывающим через Abort.
func (t *throttledWriter) Write(p []byte) (int, error) {
	if err := t.wait(t.ctx, len(p)); err != nil {
		return 0, err
	}
	return t.dst.Write(p)
}

// checksumMismatch — тело не сошлось с чексуммой из индекса
// экосистемы. Локальный тип: наружу уходит обёрнутым в
// *domain.UpstreamError, а различать его внутри движка нужно только
// для negative-cache (несовпадение — сбой upstream, не клиента).
type checksumMismatch struct {
	algo, want, got string
}

// Error реализует интерфейс error.
func (e *checksumMismatch) Error() string {
	return fmt.Sprintf("checksum mismatch (%s): ожидалось %s, получено %s", e.algo, e.want, e.got)
}

// hexHash — streaming-хеш с hex-итогом: один интерфейс для
// sha256/sha1/md5, чтобы copyBody не ветвился по алгоритмам.
type hexHash struct {
	hash.Hash
}

// SumHex возвращает hex-дайджест скорманных байт.
func (h hexHash) SumHex() string { return fmt.Sprintf("%x", h.Sum(nil)) }

// checksumHasher выбирает streaming-хеш под алгоритм из индекса
// экосистемы; неизвестный алгоритм (как и отсутствие чексуммы) — nil:
// верифицировать нечем, это честная деградация к Content-Length.
func checksumHasher(algo string) hexHash {
	switch strings.ToLower(algo) {
	case "sha256", "sha-256":
		return hexHash{sha256.New()}
	case "sha1", "sha-1":
		return hexHash{sha1.New()}
	case "md5":
		return hexHash{md5.New()}
	}
	return hexHash{}
}

// parseHTTPTime разбирает HTTP-date в форматах RFC 9110: IMF-fixdate
// (RFC1123/RFC1123Z), obsolete RFC850 и asctime. Цепочка раскладок —
// как у net/http.ParseTime (в engine нет net/http — депгард), но с
// добавкой RFC1123Z. Неизвестный формат — ошибка: валидатор просто не
// запомнится, это деградация к полному скачиванию, не поломка.
func parseHTTPTime(v string) (time.Time, error) {
	for _, layout := range []string{
		time.RFC1123,
		time.RFC1123Z,
		time.RFC850,
		time.ANSIC,
	} {
		if t, err := time.Parse(layout, v); err == nil {
			return t, nil
		}
	}
	return time.Time{}, &domain.ValidationError{What: "HTTP-date", Value: v, Reason: "нераспознанный формат"}
}

// copyBody стримит тело в writer с проверками: лимит на лету (chunked
// без Content-Length тоже ограничен), сверка с заявленной длиной и —
// если индекс экосистемы знает хеш объекта — hashing-tee со сверкой
// sha256/sha1/md5: объект с «чужими» байтами коммита не увидит
// (Abort у вызывающего). wait (Throttle зеркала) оборачивает запись:
// байты оплачиваются по мере копирования, до записи куска.
func (e *Engine) copyBody(ctx context.Context, w port.Writer, body io.Reader, length int64, sum port.Checksum, url string, wait Throttle) (int64, error) {
	src := body
	if e.cfg.MaxObjectSize > 0 {
		// +1 байт: чтобы отличить «ровно лимит» от «лимит превышен»
		src = io.LimitReader(body, e.cfg.MaxObjectSize+1)
	}
	var dst io.Writer = w
	if wait != nil {
		dst = &throttledWriter{dst: dst, wait: wait, ctx: ctx}
	}
	var hasher hexHash
	if h := checksumHasher(sum.Algo); h.Hash != nil {
		hasher = h
		dst = io.MultiWriter(dst, h)
	}
	n, err := io.Copy(dst, src)
	if err != nil {
		// 502 = только upstream, 503 = наш носитель: классифицированную
		// адаптером недоступность хранилища (сбой записи тела) не
		// заворачиваем в UpstreamError (сессия 60).
		var un *domain.UnavailableError
		if errors.As(err, &un) {
			return n, err
		}
		return n, &domain.UpstreamError{URL: url, Err: err}
	}
	if e.cfg.MaxObjectSize > 0 && n > e.cfg.MaxObjectSize {
		return n, &domain.TooLargeError{Size: n, Limit: e.cfg.MaxObjectSize}
	}
	if length >= 0 && n != length {
		return n, &domain.UpstreamError{URL: url, Err: fmt.Errorf("content-length: получено %d байт, заявлено %d", n, length)}
	}
	if hasher.Hash != nil {
		got := hasher.SumHex()
		// Индексы пишут hex в lowercase, но сверяем регистронезависимо:
		// чужой формат не должен превращаться в poisoning-отказ.
		if !strings.EqualFold(got, sum.Hex) {
			return n, &domain.UpstreamError{
				URL: url,
				Err: &checksumMismatch{algo: sum.Algo, want: sum.Hex, got: got},
			}
		}
	}
	e.metrics.BytesFromUpstream.Add(n)
	return n, nil
}

func (e *Engine) cached(ctx context.Context, key string) (port.Object, error) {
	obj, err := e.storage.Get(ctx, key)
	if err != nil {
		return port.Object{}, err
	}
	e.mu.RLock()
	meta, ok := e.meta[key]
	e.mu.RUnlock()
	if ok {
		obj.Meta.ETag, obj.Meta.ContentType = meta.ETag, meta.ContentType
		obj.Meta.ModTime = meta.LastModified
	}
	return obj, nil
}

// cachedAt достаёт объект по индексной записи: StorageKey говорит, где
// лежат байты (пустой — сам Key, записи до версионирования).
func (e *Engine) cachedAt(ctx context.Context, meta domain.ObjectMeta) (port.Object, error) {
	key := meta.StorageKey
	if key == "" {
		key = meta.Key
	}
	obj, err := e.storage.Get(ctx, key)
	if err != nil {
		return port.Object{}, err
	}
	obj.Meta.ETag, obj.Meta.ContentType, obj.Meta.ModTime = meta.ETag, meta.ContentType, meta.LastModified
	return obj, nil
}

// versionedKey строит ключ новой версии mutable-объекта: суффикс из
// nonce запуска и номера записи, charset допустим domain.ValidateKey.
func (e *Engine) versionedKey(key string) string {
	return key + "-v" + strconv.FormatUint(e.nonce, 36) + strconv.FormatUint(e.seq.Add(1), 36)
}

// deleteInBackground подчищает прошлую версию после успешной замены.
// Ошибки сознательно игнорируются: читатели старой версии могут
// держать файл открытым (Windows не удаляет открытые файлы); сбойное
// удаление оставляет осиротевшую версию — выметающей чистки хранилища
// в v1 нет, накопление фиксирует ROADMAP (ревью 2026-09-03).
//
// Голая горутина (до аудита 2026-08-27) не имела ни потолка
// параллелизма, ни ожидания при shutdown — процесс убивал удаление
// посреди storage.Delete. Семафор ограничивает всплеск,
// DrainBackgroundDeletes дожимает очередь в каскаде остановки.
func (e *Engine) deleteInBackground(old *domain.ObjectMeta) {
	key := old.StorageKey
	if key == "" {
		key = old.Key
	}
	e.delMu.Lock()
	if e.delPending == 0 {
		e.delIdle = make(chan struct{})
	}
	e.delPending++
	e.delMu.Unlock()
	go func() {
		e.delSem <- struct{}{}
		e.deleteOnce(key)
	}()
}

// deleteOnce выполняет одно удаление с гарантией счётчиков: паника
// storage.Delete изолируется (лог + метрика); без recover delPending
// оставался бы навечно несбалансированным и DrainBackgroundDeletes
// зависал на shutdown (аудит 2026-08-27).
func (e *Engine) deleteOnce(key string) {
	defer func() {
		if rec := recover(); rec != nil {
			e.metrics.BackgroundPanics.Add(1)
			slog.Default().Error("фоновое удаление: паника",
				"key", key, "panic", rec, "stack", string(debug.Stack()))
		}
		<-e.delSem
		e.delMu.Lock()
		e.delPending--
		if e.delPending == 0 {
			close(e.delIdle)
		}
		e.delMu.Unlock()
	}()
	_ = e.storage.Delete(context.Background(), key)
}

// DrainBackgroundDeletes ждёт завершения всех фоновых удалений или
// отмены ctx. Встраивается в graceful shutdown: web-сервер уже ждёт
// фоновые задачи 30s — удаление дожимается в том же пути.
func (e *Engine) DrainBackgroundDeletes(ctx context.Context) error {
	for {
		e.delMu.Lock()
		idle, pending := e.delIdle, e.delPending
		e.delMu.Unlock()
		if pending == 0 {
			return nil
		}
		select {
		case <-idle:
			// idle закрыт, но после него могли добавить новые — цикл
			// перепроверит счётчик
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (e *Engine) rememberMeta(key string, meta domain.ObjectMeta) {
	e.mu.Lock()
	if len(e.meta) >= metaCap {
		for k := range e.meta {
			delete(e.meta, k)
			break
		}
	}
	e.meta[key] = meta
	e.mu.Unlock()
}

func (e *Engine) negativeError(key string) error {
	e.mu.RLock()
	n, ok := e.negative[key]
	e.mu.RUnlock()
	if ok && e.clock.Now().Before(n.until) {
		e.metrics.NegativeHits.Add(1)
		return n.err
	}
	return nil
}

func (e *Engine) rememberNegative(key string, ttl time.Duration, err error) {
	if ttl <= 0 {
		return
	}
	e.mu.Lock()
	if len(e.negative) >= negativeCap {
		for k := range e.negative {
			delete(e.negative, k)
			break
		}
	}
	e.negative[key] = negative{until: e.clock.Now().Add(ttl), err: err}
	e.mu.Unlock()
}

func (e *Engine) forgetNegative(key string) {
	e.mu.Lock()
	delete(e.negative, key)
	e.mu.Unlock()
}
