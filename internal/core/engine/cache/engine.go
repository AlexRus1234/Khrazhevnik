package cache

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/metrics"
	"khrazhevnik/internal/core/port"
)

// Config задаёт ограничения pull-through кеша.
type Config struct {
	MutableTTL     time.Duration
	StaleIfError   bool
	MaxObjectSize  int64
	NegativeTTL404 time.Duration
	NegativeTTL5xx time.Duration
}

type negative struct {
	until time.Time
	err   error
}

// Engine реализует byte-preserving pull-through кеш.
type Engine struct {
	storage  port.Storage
	index    port.ObjectIndex
	doer     port.Doer
	clock    port.Clock
	cfg      Config
	metrics  *metrics.Cache
	flights  singleflight.Group
	mu       sync.RWMutex
	meta     map[string]domain.ObjectMeta
	negative map[string]negative
}

// FetchStatus is the delivery-friendly form of Fetch. The status is only a
// cache hint; the object and error remain the authoritative result.
func (e *Engine) FetchStatus(ctx context.Context, eco port.Ecosystem, path string) (port.Object, string, error) {
	status := "MISS"
	if target, ok := eco.Resolve(path); ok {
		if class, err := eco.Classify(target.UpstreamPath); err == nil {
			if class.Kind == domain.KindImmutable {
				if _, err := e.storage.Stat(ctx, target.StorageKey); err == nil {
					status = "HIT"
				}
			} else if meta, err := e.index.ObjectMeta(ctx, target.StorageKey); err == nil && !meta.Expired(e.clock.Now()) {
				status = "HIT"
			}
		}
	}
	obj, err := e.Fetch(ctx, eco, path)
	var stale *domain.StaleError
	if errors.As(err, &stale) {
		status = "STALE"
	}
	return obj, status, err
}

// AddBytesToClients records bytes copied by the HTTP delivery layer.
func (e *Engine) AddBytesToClients(n int64) { e.metrics.AddBytesToClients(n) }

// New создаёт движок кеша.
func New(storage port.Storage, index port.ObjectIndex, doer port.Doer, clock port.Clock, cfg Config, m *metrics.Cache) *Engine {
	if m == nil {
		m = metrics.NewCache()
	}
	return &Engine{storage: storage, index: index, doer: doer, clock: clock, cfg: cfg, metrics: m, meta: make(map[string]domain.ObjectMeta), negative: make(map[string]negative)}
}

// Fetch возвращает независимый поток объекта из кеша или upstream.
func (e *Engine) Fetch(ctx context.Context, eco port.Ecosystem, ecosystemPath string) (port.Object, error) {
	target, ok := eco.Resolve(ecosystemPath)
	if !ok {
		return port.Object{}, &domain.NotFoundError{What: "путь", Key: ecosystemPath}
	}
	class, err := eco.Classify(target.UpstreamPath)
	if err != nil {
		return port.Object{}, err
	}
	if err := class.Validate(); err != nil {
		return port.Object{}, err
	}
	m := e.metrics.ForEcosystem(eco.Name())
	if class.Kind == domain.KindImmutable {
		if err := e.negativeError(target.StorageKey); err != nil {
			return port.Object{}, err
		}
		if obj, err := e.cached(ctx, target.StorageKey); err == nil {
			m.Hits.Add(1)
			return obj, nil
		}
		m.Misses.Add(1)
		_, err, _ := e.flights.Do(target.StorageKey, func() (any, error) {
			if _, statErr := e.storage.Stat(ctx, target.StorageKey); statErr == nil {
				return nil, nil
			}
			return nil, e.fetchOnce(ctx, target, class, nil)
		})
		if err != nil {
			return port.Object{}, err
		}
		return e.cached(ctx, target.StorageKey)
	}
	return e.fetchMutable(ctx, target, class, m)
}

func (e *Engine) fetchMutable(ctx context.Context, target port.Target, class domain.Class, m *metrics.Cache) (port.Object, error) {
	indexed, indexErr := e.index.ObjectMeta(ctx, target.StorageKey)
	if indexErr == nil && !indexed.Expired(e.clock.Now()) {
		obj, err := e.cachedWithMeta(ctx, target.StorageKey, indexed)
		if err == nil {
			m.Hits.Add(1)
			return obj, nil
		}
	}
	m.Misses.Add(1)
	var old *domain.ObjectMeta
	if indexErr == nil {
		old = &indexed
	}
	_, err, _ := e.flights.Do(target.StorageKey, func() (any, error) {
		cur, err := e.index.ObjectMeta(ctx, target.StorageKey)
		if err == nil && !cur.Expired(e.clock.Now()) {
			return nil, nil
		}
		if err == nil {
			old = &cur
		}
		return nil, e.fetchOnce(ctx, target, class, old)
	})
	if err != nil {
		if old != nil && e.cfg.StaleIfError {
			if obj, getErr := e.cachedWithMeta(ctx, target.StorageKey, *old); getErr == nil {
				m.StaleServed.Add(1)
				return obj, &domain.StaleError{Have: old.ETag, Want: ""}
			}
		}
		return port.Object{}, err
	}
	return e.cached(ctx, target.StorageKey)
}

//nolint:gocyclo // status handling, bounded streaming, and transactional commit are one atomic operation.
func (e *Engine) fetchOnce(ctx context.Context, target port.Target, class domain.Class, old *domain.ObjectMeta) error {
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
		return &domain.UpstreamError{URL: target.UpstreamURL, Err: err}
	}
	resp, err := e.doer.Do(req)
	if err != nil {
		e.metrics.UpstreamErrors.Add(1)
		return &domain.UpstreamError{URL: target.UpstreamURL, Err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode == 304 && old != nil {
		updated := *old
		updated.ExpiresAt = e.clock.Now().Add(class.TTL)
		return e.index.PutObjectMeta(ctx, updated)
	}
	if resp.StatusCode == 404 {
		e.metrics.UpstreamErrors.Add(1)
		e.rememberNegative(target.StorageKey, e.cfg.NegativeTTL404, &domain.NotFoundError{What: "upstream объект", Key: target.UpstreamPath})
		return &domain.NotFoundError{What: "upstream объект", Key: target.UpstreamPath}
	}
	if resp.StatusCode >= 500 {
		e.metrics.UpstreamErrors.Add(1)
		err := &domain.UpstreamError{URL: target.UpstreamURL, Status: resp.StatusCode}
		e.rememberNegative(target.StorageKey, e.cfg.NegativeTTL5xx, err)
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &domain.UpstreamError{URL: target.UpstreamURL, Status: resp.StatusCode}
	}
	if resp.ContentLength > e.cfg.MaxObjectSize && e.cfg.MaxObjectSize > 0 {
		return &domain.TooLargeError{Size: resp.ContentLength, Limit: e.cfg.MaxObjectSize}
	}
	w, err := e.storage.Put(ctx, target.StorageKey)
	if err != nil {
		return err
	}
	if err = e.copyBody(w, resp.Body, resp.ContentLength); err != nil {
		_ = w.Abort(context.Background())
		return err
	}
	if err = w.Commit(ctx); err != nil {
		_ = w.Abort(context.Background())
		return err
	}
	m := domain.ObjectMeta{Key: target.StorageKey, Size: resp.ContentLength, ETag: resp.Header.Get("ETag"), ContentType: resp.Header.Get("Content-Type"), ExpiresAt: time.Time{}}
	if resp.ContentLength < 0 {
		m.Size = 0
	}
	if v := resp.Header.Get("Last-Modified"); v != "" {
		if t, parseErr := time.Parse(time.RFC1123, v); parseErr == nil {
			m.LastModified = t
		}
	}
	if class.Kind == domain.KindMutable {
		m.ExpiresAt = e.clock.Now().Add(class.TTL)
		if err := e.index.PutObjectMeta(ctx, m); err != nil {
			return err
		}
	}
	e.mu.Lock()
	e.meta[target.StorageKey] = m
	e.mu.Unlock()
	return nil
}

func (e *Engine) copyBody(w port.Writer, body io.Reader, length int64) error {
	limit := e.cfg.MaxObjectSize
	if limit <= 0 {
		limit = 1<<63 - 1
	}
	n, err := io.Copy(w, io.LimitReader(body, limit+1))
	if err != nil {
		return &domain.UpstreamError{Status: 0, Err: err}
	}
	if n > limit {
		return &domain.TooLargeError{Size: n, Limit: limit}
	}
	if length >= 0 && n != length {
		return &domain.UpstreamError{Status: 0, Err: fmt.Errorf("content-length: получено %d, заявлено %d", n, length)}
	}
	e.metrics.BytesFromUpstream.Add(n)
	return nil
}

func (e *Engine) cached(ctx context.Context, key string) (port.Object, error) {
	if err := e.negativeError(key); err != nil {
		return port.Object{}, err
	}
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

func (e *Engine) cachedWithMeta(ctx context.Context, key string, meta domain.ObjectMeta) (port.Object, error) {
	obj, err := e.storage.Get(ctx, key)
	if err != nil {
		return obj, err
	}
	obj.Meta.ETag, obj.Meta.ContentType, obj.Meta.ModTime = meta.ETag, meta.ContentType, meta.LastModified
	return obj, nil
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
	if len(e.negative) >= 10000 {
		for k := range e.negative {
			delete(e.negative, k)
			break
		}
	}
	e.negative[key] = negative{until: e.clock.Now().Add(ttl), err: err}
	e.mu.Unlock()
}
