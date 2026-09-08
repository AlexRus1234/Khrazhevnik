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

package cache

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/metrics"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/testutil"
)

// testUpstream — httptest-upstream с подменяемым хендлером и счётчиком
// запросов по путям.
type testUpstream struct {
	mu      sync.Mutex
	handler http.HandlerFunc
	perPath map[string]*atomic.Int64
	server  *httptest.Server
}

func newTestUpstream(t *testing.T, h http.HandlerFunc) *testUpstream {
	t.Helper()
	u := &testUpstream{handler: h, perPath: map[string]*atomic.Int64{}}
	u.server = httptest.NewServer(u)
	t.Cleanup(u.server.Close)
	return u
}

func (u *testUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	counter, ok := u.perPath[r.URL.Path]
	if !ok {
		counter = &atomic.Int64{}
		u.perPath[r.URL.Path] = counter
	}
	h := u.handler
	u.mu.Unlock()
	counter.Add(1)
	h(w, r)
}

func (u *testUpstream) set(h http.HandlerFunc) {
	u.mu.Lock()
	u.handler = h
	u.mu.Unlock()
}

func (u *testUpstream) count(path string) int64 {
	u.mu.Lock()
	defer u.mu.Unlock()
	if c, ok := u.perPath[path]; ok {
		return c.Load()
	}
	return 0
}

func (u *testUpstream) URL() string { return u.server.URL }

// testEnv — движок с фейками и ручными часами.
type testEnv struct {
	engine  *Engine
	eco     port.Ecosystem
	storage *testutil.FakeStorage
	index   port.ObjectIndex
	clock   *testutil.ManualClock
	m       *metrics.Cache
	up      *testUpstream
}

var testStart = time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)

func newTestEnv(t *testing.T, cfg Config, h http.HandlerFunc) *testEnv {
	t.Helper()
	up := newTestUpstream(t, h)
	clock := testutil.NewManualClock(testStart)
	storage := testutil.NewFakeStorage(clock)
	index := testutil.NewFakeObjectIndex()
	m := metrics.NewCache()
	eco := testutil.FakeEcosystem{NameOf: "t", Base: up.URL(), MutableTTL: 40 * time.Second}
	engine := New(storage, index, up.server.Client(), clock, cfg, m)
	return &testEnv{engine: engine, eco: eco, storage: storage, index: index, clock: clock, m: m, up: up}
}

func defaultConfig() Config {
	return Config{StaleIfError: true, NegativeTTL404: 5 * time.Minute, NegativeTTL5xx: 30 * time.Second}
}

// fetch — FetchStatus с полным чтением тела и закрытием.
func fetch(t *testing.T, e *Engine, eco port.Ecosystem, path string) (string, string, error) {
	t.Helper()
	obj, status, err := e.FetchStatus(context.Background(), eco, path)
	if obj.Body == nil {
		return "", status, err
	}
	defer func() { _ = obj.Body.Close() }()
	body, readErr := io.ReadAll(obj.Body)
	if readErr != nil {
		t.Fatalf("чтение тела %s: %v", path, readErr)
	}
	return string(body), status, err
}

func fixedHandler(body, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("ETag", `"pkg"`)
		_, _ = io.WriteString(w, body)
	}
}

// mutableHandler отдаёт body с ETag и отвечает 304 на совпадающий
// If-None-Match.
func mutableHandler(body, etag string) http.HandlerFunc {
	lastMod := testStart.Format(http.TimeFormat)
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", etag)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Last-Modified", lastMod)
		_, _ = io.WriteString(w, body)
	}
}

func TestImmutableMissThenHit(t *testing.T) {
	env := newTestEnv(t, defaultConfig(), fixedHandler("hello", "application/deb"))

	body, status, err := fetch(t, env.engine, env.eco, "/t/pkg/a.deb")
	if err != nil || body != "hello" || status != "MISS" {
		t.Fatalf("первый Fetch = %q %s %v", body, status, err)
	}
	body, status, err = fetch(t, env.engine, env.eco, "/t/pkg/a.deb")
	if err != nil || body != "hello" || status != "HIT" {
		t.Fatalf("второй Fetch = %q %s %v", body, status, err)
	}
	if got := env.up.count("/pkg/a.deb"); got != 1 {
		t.Fatalf("upstream получил %d запросов, хочу 1", got)
	}
	perEco := env.m.ForEcosystem("t")
	if perEco.Hits.Load() != 1 || perEco.Misses.Load() != 1 {
		t.Fatalf("hits/misses = %d/%d, хочу 1/1", perEco.Hits.Load(), perEco.Misses.Load())
	}
}

func TestPackagesCounter(t *testing.T) {
	env := newTestEnv(t, defaultConfig(), fixedHandler("hello", "application/deb"))

	if _, status, err := fetch(t, env.engine, env.eco, "/t/pkg/a.deb"); err != nil || status != "MISS" {
		t.Fatalf("immutable MISS = %s %v", status, err)
	}
	perEco := env.m.ForEcosystem("t")
	if got := perEco.Packages.Load(); got != 1 {
		t.Fatalf("Packages после MISS = %d, хочу 1", got)
	}
	if _, status, err := fetch(t, env.engine, env.eco, "/t/pkg/a.deb"); err != nil || status != "HIT" {
		t.Fatalf("immutable HIT = %s %v", status, err)
	}
	if got := perEco.Packages.Load(); got != 1 {
		t.Fatalf("Packages после HIT = %d, хочу 1 (HIT не инкрементирует)", got)
	}
	// mutable-индекс — служебная метадата: его оборот виден в
	// hits/misses, счётчик пакетов не растёт.
	if _, status, err := fetch(t, env.engine, env.eco, "/t/idx/Packages.gz"); err != nil || status != "MISS" {
		t.Fatalf("mutable MISS = %s %v", status, err)
	}
	if got := perEco.Packages.Load(); got != 1 {
		t.Fatalf("Packages после mutable MISS = %d, хочу 1", got)
	}
	// prefetch-ветка зеркала сходится в тот же fetchOnce — один
	// инкремент на оба пути.
	if _, err := env.engine.PrefetchThrottled(context.Background(), env.eco, "/t/pkg/b.deb", nil); err != nil {
		t.Fatal(err)
	}
	if got := perEco.Packages.Load(); got != 2 {
		t.Fatalf("Packages после prefetch = %d, хочу 2", got)
	}
}

func TestImmutableSingleflight(t *testing.T) {
	release := make(chan struct{})
	env := newTestEnv(t, defaultConfig(), func(w http.ResponseWriter, _ *http.Request) {
		<-release
		_, _ = io.WriteString(w, "one")
	})

	const n = 50
	var wg sync.WaitGroup
	results := make([]string, n)
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			body, _, err := fetch(t, env.engine, env.eco, "/t/pkg/a.deb")
			if err != nil {
				t.Errorf("конкурентный Fetch: %v", err)
				return
			}
			results[i] = body
		}()
	}
	close(start)
	time.Sleep(150 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := env.up.count("/pkg/a.deb"); got != 1 {
		t.Fatalf("upstream получил %d запросов, хочу 1 (singleflight)", got)
	}
	for i, body := range results {
		if body != "one" {
			t.Errorf("горутина %d получила %q", i, body)
		}
	}
}

func TestUpstreamBodyTruncated(t *testing.T) {
	env := newTestEnv(t, defaultConfig(), func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.Header().Set("Content-Type", "application/deb")
		_, _ = io.WriteString(w, "short")
		panic(http.ErrAbortHandler)
	})

	_, _, err := fetch(t, env.engine, env.eco, "/t/pkg/a.deb")
	var up *domain.UpstreamError
	if !errors.As(err, &up) {
		t.Fatalf("обрыв тела = %v, хочу UpstreamError", err)
	}
	if objects := storageCount(t, env.storage); objects != 0 {
		t.Fatalf("после обрыва в хранилище %d объектов, хочу 0 (Abort)", objects)
	}

	env.up.set(fixedHandler("recovered", "application/deb"))
	body, _, err := fetch(t, env.engine, env.eco, "/t/pkg/a.deb")
	if err != nil || body != "recovered" {
		t.Fatalf("повтор после обрыва = %q, %v", body, err)
	}
}

// trackingReader считает чтения — чтобы доказать, что при отказе по
// Content-Length тело не качается вовсе.
type trackingReader struct {
	reads atomic.Int64
	data  strings.Reader
}

func (r *trackingReader) Read(p []byte) (int, error) {
	r.reads.Add(1)
	return r.data.Read(p)
}

// fakeDoer подставляет готовый ответ без HTTP-сервера: для сценариев,
// которые реальный сервер не воспроизведёт честно (врущий
// Content-Length без обрыва соединения).
type fakeDoer struct {
	resp http.Response
	body io.Reader
}

func (d *fakeDoer) Do(*http.Request) (*http.Response, error) {
	resp := d.resp
	resp.Body = io.NopCloser(d.body)
	return &resp, nil
}

func newFakeDoer(contentLength int64, body string) *fakeDoer {
	return &fakeDoer{
		resp: http.Response{StatusCode: 200, ContentLength: contentLength, Header: http.Header{}},
		body: strings.NewReader(body),
	}
}

func engineWithDoer(t *testing.T, cfg Config, doer port.Doer) *testEnv {
	t.Helper()
	clock := testutil.NewManualClock(testStart)
	env := &testEnv{
		engine:  New(testutil.NewFakeStorage(clock), testutil.NewFakeObjectIndex(), doer, clock, cfg, nil),
		eco:     testutil.FakeEcosystem{NameOf: "t", Base: "http://up.test", MutableTTL: 40 * time.Second},
		storage: nil,
		index:   nil,
		clock:   clock,
		m:       nil,
		up:      nil,
	}
	return env
}

func TestContentLengthLies(t *testing.T) {
	t.Run("заявлено больше чем отправлено", func(t *testing.T) {
		env := engineWithDoer(t, defaultConfig(), newFakeDoer(10, "123"))
		_, _, err := fetch(t, env.engine, env.eco, "/t/pkg/a.deb")
		var up *domain.UpstreamError
		if !errors.As(err, &up) {
			t.Fatalf("ошибка = %v, хочу UpstreamError", err)
		}
	})
	t.Run("отправлено больше чем заявлено", func(t *testing.T) {
		env := engineWithDoer(t, defaultConfig(), newFakeDoer(3, "12345"))
		_, _, err := fetch(t, env.engine, env.eco, "/t/pkg/a.deb")
		var up *domain.UpstreamError
		if !errors.As(err, &up) {
			t.Fatalf("ошибка = %v, хочу UpstreamError", err)
		}
	})
}

func TestMaxObjectSize(t *testing.T) {
	t.Run("отказ до тела по Content-Length", func(t *testing.T) {
		cfg := defaultConfig()
		cfg.MaxObjectSize = 10
		tracked := &trackingReader{data: *strings.NewReader(strings.Repeat("x", 100))}
		doer := &fakeDoer{resp: http.Response{StatusCode: 200, ContentLength: 100, Header: http.Header{}}, body: tracked}
		env := engineWithDoer(t, cfg, doer)
		_, _, err := fetch(t, env.engine, env.eco, "/t/pkg/big.deb")
		var tooLarge *domain.TooLargeError
		if !errors.As(err, &tooLarge) {
			t.Fatalf("ошибка = %v, хочу TooLargeError", err)
		}
		if got := tracked.reads.Load(); got != 0 {
			t.Fatalf("тело прочитано %d раз, хочу 0 (отказ до чтения)", got)
		}
	})
	t.Run("chunked превышен на лету", func(t *testing.T) {
		cfg := defaultConfig()
		cfg.MaxObjectSize = 10
		env := engineWithDoer(t, cfg, newFakeDoer(-1, strings.Repeat("x", 12)))
		_, _, err := fetch(t, env.engine, env.eco, "/t/pkg/chunked.deb")
		var tooLarge *domain.TooLargeError
		if !errors.As(err, &tooLarge) {
			t.Fatalf("ошибка = %v, хочу TooLargeError", err)
		}
	})
	t.Run("immutable ровно в лимит проходит", func(t *testing.T) {
		cfg := defaultConfig()
		cfg.MaxObjectSize = 4
		env := engineWithDoer(t, cfg, newFakeDoer(4, "abcd"))
		body, status, err := fetch(t, env.engine, env.eco, "/t/pkg/exact.deb")
		if err != nil || body != "abcd" || status != "MISS" {
			t.Fatalf("Fetch = %q %s %v", body, status, err)
		}
	})
}

func TestMutableLifecycle(t *testing.T) {
	env := newTestEnv(t, defaultConfig(), mutableHandler("one", `"v1"`))

	// первый слив: MISS, индекс и байты записаны
	body, status, err := fetch(t, env.engine, env.eco, "/t/idx/Packages")
	if err != nil || body != "one" || status != "MISS" {
		t.Fatalf("первый Fetch = %q %s %v", body, status, err)
	}

	// в пределах TTL — HIT без похода upstream
	body, status, err = fetch(t, env.engine, env.eco, "/t/idx/Packages")
	if err != nil || body != "one" || status != "HIT" {
		t.Fatalf("Fetch в TTL = %q %s %v", body, status, err)
	}
	if got := env.up.count("/idx/Packages"); got != 1 {
		t.Fatalf("upstream получил %d запросов, хочу 1", got)
	}

	// TTL истёк → revalidate → 304 → HIT, expires продлён
	env.clock.Advance(41 * time.Second)
	body, status, err = fetch(t, env.engine, env.eco, "/t/idx/Packages")
	if err != nil || body != "one" || status != "HIT" {
		t.Fatalf("Fetch после 304 = %q %s %v", body, status, err)
	}
	if got := env.up.count("/idx/Packages"); got != 2 {
		t.Fatalf("upstream получил %d запросов, хочу 2 (revalidate)", got)
	}

	// запись индекса действительно освежена: без нового истечения HIT
	// (ключ — case-чувствительный, как путь upstream, сессия 19)
	meta, err := env.index.ObjectMeta(context.Background(), "cache/t/idx/Packages")
	if err != nil || !meta.ExpiresAt.After(env.clock.Now()) {
		t.Fatalf("после 304 expires не продлён: %+v, %v", meta, err)
	}

	// TTL снова истёк → 200 с новым содержимым → MISS, замена версии
	env.clock.Advance(41 * time.Second)
	env.up.set(mutableHandler("two", `"v2"`))
	body, status, err = fetch(t, env.engine, env.eco, "/t/idx/Packages")
	if err != nil || body != "two" || status != "MISS" {
		t.Fatalf("Fetch после замены = %q %s %v", body, status, err)
	}

	// старая версия вычищается фоном — ждём, пока останется одна
	deadline := time.Now().Add(2 * time.Second)
	for storageCountPrefix(t, env.storage, "cache/t/idx/") != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := storageCountPrefix(t, env.storage, "cache/t/idx/"); got != 1 {
		t.Fatalf("в хранилище %d версий, хочу 1 (фоновой чисткой)", got)
	}

	// и новый объект отдаётся из кеша
	body, status, err = fetch(t, env.engine, env.eco, "/t/idx/Packages")
	if err != nil || body != "two" || status != "HIT" {
		t.Fatalf("Fetch новой версии = %q %s %v", body, status, err)
	}
}

func TestMutableSingleflight(t *testing.T) {
	release := make(chan struct{})
	env := newTestEnv(t, defaultConfig(), func(w http.ResponseWriter, _ *http.Request) {
		<-release
		_, _ = io.WriteString(w, "idx")
	})

	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 25 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _, err := fetch(t, env.engine, env.eco, "/t/idx/Packages")
			if err != nil {
				t.Errorf("конкурентный mutable Fetch: %v", err)
			}
		}()
	}
	close(start)
	time.Sleep(150 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := env.up.count("/idx/Packages"); got != 1 {
		t.Fatalf("upstream получил %d запросов, хочу 1 (singleflight)", got)
	}
}

func TestStaleIfError(t *testing.T) {
	t.Run("5xx отдаёт stale с StaleError", func(t *testing.T) {
		env := newTestEnv(t, defaultConfig(), mutableHandler("one", `"v1"`))
		if _, _, err := fetch(t, env.engine, env.eco, "/t/idx/Packages"); err != nil {
			t.Fatal(err)
		}
		env.clock.Advance(41 * time.Second)
		env.up.set(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) })

		body, status, err := fetch(t, env.engine, env.eco, "/t/idx/Packages")
		var stale *domain.StaleError
		if !errors.As(err, &stale) || status != "STALE" || body != "one" {
			t.Fatalf("stale = %q %s %v", body, status, err)
		}
	})

	t.Run("повтор в окне negative не дергает upstream", func(t *testing.T) {
		env := newTestEnv(t, defaultConfig(), mutableHandler("one", `"v1"`))
		if _, _, err := fetch(t, env.engine, env.eco, "/t/idx/Packages"); err != nil {
			t.Fatal(err)
		}
		env.clock.Advance(41 * time.Second)
		env.up.set(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) })
		if _, _, err := fetch(t, env.engine, env.eco, "/t/idx/Packages"); err == nil {
			t.Fatal("первый 500 не вернул ошибку")
		}
		for range 3 {
			body, status, err := fetch(t, env.engine, env.eco, "/t/idx/Packages")
			var stale *domain.StaleError
			if !errors.As(err, &stale) || status != "STALE" || body != "one" {
				t.Fatalf("stale из negative = %q %s %v", body, status, err)
			}
		}
		if got := env.up.count("/idx/Packages"); got != 2 {
			t.Fatalf("upstream получил %d запросов, хочу 2", got)
		}
	})

	t.Run("выключенный stale_if_error даёт upstream-ошибку", func(t *testing.T) {
		cfg := defaultConfig()
		cfg.StaleIfError = false
		env := newTestEnv(t, cfg, mutableHandler("one", `"v1"`))
		if _, _, err := fetch(t, env.engine, env.eco, "/t/idx/Packages"); err != nil {
			t.Fatal(err)
		}
		env.clock.Advance(41 * time.Second)
		env.up.set(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) })

		_, _, err := fetch(t, env.engine, env.eco, "/t/idx/Packages")
		var up *domain.UpstreamError
		if !errors.As(err, &up) {
			t.Fatalf("ошибка = %v, хочу UpstreamError (без stale)", err)
		}
	})

	t.Run("404 не маскируется stale", func(t *testing.T) {
		env := newTestEnv(t, defaultConfig(), mutableHandler("one", `"v1"`))
		if _, _, err := fetch(t, env.engine, env.eco, "/t/idx/Packages"); err != nil {
			t.Fatal(err)
		}
		env.clock.Advance(41 * time.Second)
		env.up.set(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(404) })

		_, _, err := fetch(t, env.engine, env.eco, "/t/idx/Packages")
		var nf *domain.NotFoundError
		if !errors.As(err, &nf) {
			t.Fatalf("ошибка = %v, хочу NotFoundError", err)
		}
	})
}

func TestNegativeCacheImmutable(t *testing.T) {
	env := newTestEnv(t, defaultConfig(), func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(404) })

	for range 5 {
		_, _, err := fetch(t, env.engine, env.eco, "/t/pkg/missing.deb")
		var nf *domain.NotFoundError
		if !errors.As(err, &nf) {
			t.Fatalf("ошибка = %v, хочу NotFoundError", err)
		}
	}
	if got := env.up.count("/pkg/missing.deb"); got != 1 {
		t.Fatalf("upstream получил %d запросов, хочу 1 (negative)", got)
	}
	if got := env.m.ForEcosystem("t").NegativeHits.Load(); got != 4 {
		t.Fatalf("negative_hits = %d, хочу 4", got)
	}

	// TTL negative истёк — снова идём upstream
	env.clock.Advance(6 * time.Minute)
	_, _, err := fetch(t, env.engine, env.eco, "/t/pkg/missing.deb")
	if err == nil {
		t.Fatal("после истечения negative объект найден")
	}
	if got := env.up.count("/pkg/missing.deb"); got != 2 {
		t.Fatalf("upstream получил %d запросов, хочу 2", got)
	}
}

func TestNegativeCacheMutable(t *testing.T) {
	cfg := defaultConfig()
	cfg.NegativeTTL5xx = 30 * time.Second
	env := newTestEnv(t, cfg, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(404) })

	for range 3 {
		_, _, err := fetch(t, env.engine, env.eco, "/t/idx/Gone")
		var nf *domain.NotFoundError
		if !errors.As(err, &nf) {
			t.Fatalf("ошибка = %v, хочу NotFoundError", err)
		}
	}
	if got := env.up.count("/idx/Gone"); got != 1 {
		t.Fatalf("upstream получил %d запросов, хочу 1 (negative mutable)", got)
	}

	// 5xx тоже кешируется негативно
	env.up.set(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(502) })
	for range 3 {
		_, _, err := fetch(t, env.engine, env.eco, "/t/idx/Down")
		var up *domain.UpstreamError
		if !errors.As(err, &up) {
			t.Fatalf("ошибка = %v, хочу UpstreamError", err)
		}
	}
	if got := env.up.count("/idx/Down"); got != 1 {
		t.Fatalf("upstream получил %d запросов, хочу 1 (negative 5xx)", got)
	}
}

func TestMetricsConverge(t *testing.T) {
	env := newTestEnv(t, defaultConfig(), fixedHandler("hello", "application/deb"))

	// 1 miss + 2 hit по 5 байт
	for range 3 {
		_, _, err := fetch(t, env.engine, env.eco, "/t/pkg/a.deb")
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := env.m.ForEcosystem("t").BytesFromUpstream.Load(); got != 5 {
		t.Fatalf("bytes_from_upstream = %d, хочу 5", got)
	}
	perEco := env.m.ForEcosystem("t")
	if perEco.Hits.Load() != 2 || perEco.Misses.Load() != 1 {
		t.Fatalf("hits/misses = %d/%d, хочу 2/1", perEco.Hits.Load(), perEco.Misses.Load())
	}

	env.engine.AddBytesToClients("t", 7)
	if got := perEco.BytesToClients.Load(); got != 7 {
		t.Fatalf("bytes_to_clients = %d, хочу 7", got)
	}
}

func TestFetchErrors(t *testing.T) {
	env := newTestEnv(t, defaultConfig(), fixedHandler("x", "text/plain"))

	t.Run("путь вне экосистемы", func(t *testing.T) {
		_, _, err := fetch(t, env.engine, env.eco, "/other/pkg/a.deb")
		var nf *domain.NotFoundError
		if !errors.As(err, &nf) {
			t.Fatalf("ошибка = %v, хочу NotFoundError", err)
		}
	})
	t.Run("классификация не распознала путь", func(t *testing.T) {
		_, _, err := fetch(t, env.engine, env.eco, "/t/junk/x")
		var ve *domain.ValidationError
		if !errors.As(err, &ve) {
			t.Fatalf("ошибка = %v, хочу ValidationError", err)
		}
	})
	t.Run("невалидный класс от адаптера", func(t *testing.T) {
		_, err := env.engine.Fetch(context.Background(), newBadClassEco(), "/t/idx/x")
		var ve *domain.ValidationError
		if !errors.As(err, &ve) {
			t.Fatalf("ошибка = %v, хочу ValidationError", err)
		}
	})
}

// badClassEco — адаптер, возвращающий mutable без TTL (ошибка валидации).
type badClassEco struct{ testutil.FakeEcosystem }

func (badClassEco) Classify(string) (domain.Class, error) {
	return domain.Class{Kind: domain.KindMutable}, nil
}

func newBadClassEco() badClassEco {
	return badClassEco{FakeEcosystem: testutil.FakeEcosystem{NameOf: "t", Base: "http://up.test"}}
}

func TestFetchWithoutStatus(t *testing.T) {
	env := newTestEnv(t, defaultConfig(), fixedHandler("plain", "text/plain"))
	obj, err := env.engine.Fetch(context.Background(), env.eco, "/t/pkg/b.deb")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = obj.Body.Close() }()
	body, _ := io.ReadAll(obj.Body)
	if string(body) != "plain" {
		t.Fatalf("тело = %q", body)
	}
}

func TestNewDefaults(t *testing.T) {
	// nil-метрики заменяются на собственный набор — движок не паникует
	env := engineWithDoer(t, defaultConfig(), newFakeDoer(-1, "z"))
	if _, _, err := fetch(t, env.engine, env.eco, "/t/pkg/c.deb"); err != nil {
		t.Fatalf("Fetch с nil-метриками: %v", err)
	}
	if env.engine.metrics == nil {
		t.Fatal("метрики не подставлены")
	}
}

func TestVersionedKey(t *testing.T) {
	env := newTestEnv(t, defaultConfig(), fixedHandler("x", "text/plain"))
	base := "cache/t/idx/packages"
	first := env.engine.versionedKey(base)
	second := env.engine.versionedKey(base)
	if first == second {
		t.Fatalf("ключи версий совпали: %q", first)
	}
	for _, key := range []string{first, second} {
		if err := domain.ValidateKey(key); err != nil {
			t.Fatalf("ключ версии %q не прошёл ValidateKey: %v", key, err)
		}
		if !strings.HasPrefix(key, base) {
			t.Fatalf("ключ версии %q без базового префикса %q", key, base)
		}
	}
}

func TestInMemoryCaps(t *testing.T) {
	env := newTestEnv(t, defaultConfig(), nil)

	nf := &domain.NotFoundError{What: "тест", Key: "k"}
	for i := range negativeCap + 50 {
		env.engine.rememberNegative("cache/t/pkg/n"+strings.TrimSpace(itoa(i)), time.Minute, nf)
	}
	if got := len(env.engine.negative); got != negativeCap {
		t.Fatalf("negative размер = %d, хочу %d", got, negativeCap)
	}

	meta := domain.ObjectMeta{Key: "cache/t/pkg/m"}
	for i := range metaCap + 50 {
		meta.Key = "cache/t/pkg/m" + strings.TrimSpace(itoa(i))
		env.engine.rememberMeta(meta.Key, meta)
	}
	if got := len(env.engine.meta); got != metaCap {
		t.Fatalf("meta размер = %d, хочу %d", got, metaCap)
	}

	// forgetNegative реально убирает запись
	env.engine.rememberNegative("cache/t/pkg/x", time.Minute, nf)
	env.engine.forgetNegative("cache/t/pkg/x")
	if _, ok := env.engine.negative["cache/t/pkg/x"]; ok {
		t.Fatal("forgetNegative не удалил запись")
	}
}

// itoa — локальный strconv без лишнего импорта в тесте.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func storageCount(t *testing.T, s *testutil.FakeStorage) int {
	t.Helper()
	return storageCountPrefix(t, s, "")
}

func storageCountPrefix(t *testing.T, s *testutil.FakeStorage, prefix string) int {
	t.Helper()
	count := 0
	for range s.List(context.Background(), prefix) {
		count++
	}
	return count
}

func TestPrefetchImmutableHitThenMiss(t *testing.T) {
	env := newTestEnv(t, defaultConfig(), fixedHandler("hello", "application/deb"))
	// первый Prefetch — MISS, скачивает
	res, err := env.engine.Prefetch(context.Background(), env.eco, "/t/pkg/a.deb")
	if err != nil || res.Status != "MISS" || res.Bytes != 5 || res.Downloaded != 5 {
		t.Fatalf("Prefetch MISS = %+v, %v", res, err)
	}
	// второй — HIT, не качает
	res, err = env.engine.Prefetch(context.Background(), env.eco, "/t/pkg/a.deb")
	if err != nil || res.Status != "HIT" || res.Downloaded != 0 {
		t.Fatalf("Prefetch HIT = %+v, %v", res, err)
	}
	if got := env.up.count("/pkg/a.deb"); got != 1 {
		t.Fatalf("upstream получил %d запросов, хочу 1", got)
	}
}

func TestPrefetchAndFetchShareSingleflight(t *testing.T) {
	// параллельные Prefetch и Fetch на один ключ — один запрос upstream
	release := make(chan struct{})
	env := newTestEnv(t, defaultConfig(), func(w http.ResponseWriter, _ *http.Request) {
		<-release
		_, _ = io.WriteString(w, "shared")
	})
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if i := mutRand(2); i == 0 {
				_, _ = env.engine.Prefetch(context.Background(), env.eco, "/t/pkg/a.deb")
			} else {
				_, _, _ = env.engine.FetchStatus(context.Background(), env.eco, "/t/pkg/a.deb")
			}
		}()
	}
	close(start)
	time.Sleep(120 * time.Millisecond)
	close(release)
	wg.Wait()
	if got := env.up.count("/pkg/a.deb"); got != 1 {
		t.Fatalf("upstream получил %d запросов, хочу 1 (shared singleflight)", got)
	}
}

// mutRand — детерминированный «случайный» 0..n-1 из времени, чтобы
// тест не зависел от math/rand (который здесь не импортирован).
func mutRand(n int) int {
	if n <= 0 {
		return 0
	}
	return int(time.Now().UnixNano()) % n
}

func TestPrefetchMutableRevalidates(t *testing.T) {
	env := newTestEnv(t, defaultConfig(), mutableHandler("one", `"v1"`))
	// первый prefetch — MISS, скачивает
	res, err := env.engine.Prefetch(context.Background(), env.eco, "/t/idx/Packages")
	if err != nil || res.Status != "MISS" || res.Downloaded != 3 {
		t.Fatalf("Prefetch mutable MISS = %+v, %v", res, err)
	}
	// в пределах TTL — HIT без upstream
	res, err = env.engine.Prefetch(context.Background(), env.eco, "/t/idx/Packages")
	if err != nil || res.Status != "HIT" || res.Downloaded != 0 {
		t.Fatalf("Prefetch mutable HIT = %+v, %v", res, err)
	}
	if got := env.up.count("/idx/Packages"); got != 1 {
		t.Fatalf("upstream получил %d запросов, хочу 1", got)
	}
	// TTL истёк → 304 → HIT, Downloaded=0
	env.clock.Advance(41 * time.Second)
	res, err = env.engine.Prefetch(context.Background(), env.eco, "/t/idx/Packages")
	if err != nil || res.Status != "HIT" || res.Downloaded != 0 {
		t.Fatalf("Prefetch mutable 304 = %+v, %v", res, err)
	}
}

func TestPrefetchErrors(t *testing.T) {
	env := newTestEnv(t, defaultConfig(), fixedHandler("x", "text/plain"))
	t.Run("путь вне экосистемы", func(t *testing.T) {
		_, err := env.engine.Prefetch(context.Background(), env.eco, "/other/pkg/a.deb")
		var nf *domain.NotFoundError
		if !errors.As(err, &nf) {
			t.Fatalf("ошибка = %v, хочу NotFoundError", err)
		}
	})
	t.Run("классификация не распознала путь", func(t *testing.T) {
		_, err := env.engine.Prefetch(context.Background(), env.eco, "/t/junk/x")
		var ve *domain.ValidationError
		if !errors.As(err, &ve) {
			t.Fatalf("ошибка = %v, хочу ValidationError", err)
		}
	})
}
