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
// новый ключ и фоновую чистку старого, чтобы читатели старой версии
// не зависели от rename поверх открытого файла (невозможен на Windows).
package cache

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
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

// AddBytesToClients records bytes copied by the HTTP delivery layer.
func (e *Engine) AddBytesToClients(n int64) { e.metrics.AddBytesToClients(n) }

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
	if obj, err := e.cached(ctx, target.StorageKey); err == nil {
		m.Hits.Add(1)
		return obj, statusHit, nil
	}
	m.Misses.Add(1)
	_, err, _ := e.flights.Do(target.StorageKey, func() (any, error) {
		if _, statErr := e.storage.Stat(ctx, target.StorageKey); statErr == nil {
			return nil, nil
		}
		_, _, err := e.fetchOnce(ctx, target, class, nil)
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
		return e.revalidate(ctx, target, class, &old)
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
func (e *Engine) revalidate(ctx context.Context, target port.Target, class domain.Class, old **domain.ObjectMeta) (any, error) {
	cur, curErr := e.index.ObjectMeta(ctx, target.StorageKey)
	if curErr == nil {
		if !cur.Expired(e.clock.Now()) {
			return nil, nil
		}
		*old = &cur
	} else {
		*old = nil
	}
	meta, rev, fetchErr := e.fetchOnce(ctx, target, class, *old)
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
func (e *Engine) fetchOnce(ctx context.Context, target port.Target, class domain.Class, old *domain.ObjectMeta) (domain.ObjectMeta, bool, error) {
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
	n, err := e.copyBody(w, resp.Body, resp.ContentLength)
	if err != nil {
		_ = w.Abort(context.Background())
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
		if t, parseErr := time.Parse(time.RFC1123, v); parseErr == nil {
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

// copyBody стримит тело в writer с проверками: лимит на лету (chunked
// без Content-Length тоже ограничен) и сверка с заявленной длиной.
func (e *Engine) copyBody(w port.Writer, body io.Reader, length int64) (int64, error) {
	src := body
	if e.cfg.MaxObjectSize > 0 {
		// +1 байт: чтобы отличить «ровно лимит» от «лимит превышен»
		src = io.LimitReader(body, e.cfg.MaxObjectSize+1)
	}
	n, err := io.Copy(w, src)
	if err != nil {
		return n, &domain.UpstreamError{Err: err}
	}
	if e.cfg.MaxObjectSize > 0 && n > e.cfg.MaxObjectSize {
		return n, &domain.TooLargeError{Size: n, Limit: e.cfg.MaxObjectSize}
	}
	if length >= 0 && n != length {
		return n, &domain.UpstreamError{Err: fmt.Errorf("content-length: получено %d байт, заявлено %d", n, length)}
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
// держать файл открытым (Windows не удаляет открытые файлы); остатки
// подберёт фоновая чистка хранилища (сессии 09/11).
func (e *Engine) deleteInBackground(old *domain.ObjectMeta) {
	key := old.StorageKey
	if key == "" {
		key = old.Key
	}
	go func() {
		_ = e.storage.Delete(context.Background(), key)
	}()
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
