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
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/metrics"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/testutil"
)

// Ошибочные пути: сбои хранилища/индекса посреди операции и редкие
// статусы upstream. Каждый двойник ломает ровно одну зависимость.

// flakyStorage роняет Get на заданных номерах вызовов: окно между
// проверкой кеша и полётом upstream — единственный способ покрыть
// расхождение «Stat видит, Get — нет».
type flakyStorage struct {
	*testutil.FakeStorage
	mu     sync.Mutex
	next   int
	failOn map[int]bool
}

func (s *flakyStorage) Get(ctx context.Context, key string) (port.Object, error) {
	s.mu.Lock()
	s.next++
	fail := s.failOn[s.next]
	s.mu.Unlock()
	if fail {
		return port.Object{}, &domain.NotFoundError{What: "объект", Key: key}
	}
	return s.FakeStorage.Get(ctx, key)
}

// errIndex всегда падает на записи: имитация недоступной БД индекса.
type errIndex struct{ *testutil.FakeObjectIndex }

func (errIndex) PutObjectMeta(context.Context, domain.ObjectMeta) error {
	return errors.New("индекс недоступен")
}

// failCommitStorage возвращает writer, чей Commit всегда падает.
type failCommitStorage struct{ *testutil.FakeStorage }

type failCommitWriter struct{ written int }

func (w *failCommitWriter) Write(p []byte) (int, error) {
	w.written += len(p)
	return len(p), nil
}

func (*failCommitWriter) Commit(context.Context) error { return errors.New("commit failed") }

func (*failCommitWriter) Abort(context.Context) error { return nil }

func (failCommitStorage) Put(ctx context.Context, key string) (port.Writer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &failCommitWriter{}, nil
}

// errReader ломается на первом чтении: обрыв тела без HTTP-сервера.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("обрыв соединения") }

// glitchStorage роняет следующие n вызовов Get/Stat заданной ошибкой:
// сбойный HIT деградирует в MISS с refetch'ом (resilience, сессия 60).
type glitchStorage struct {
	*testutil.FakeStorage
	mu   sync.Mutex
	left int
	err  error
}

func (s *glitchStorage) take() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.left > 0 {
		s.left--
		return true
	}
	return false
}

func (s *glitchStorage) Get(ctx context.Context, key string) (port.Object, error) {
	if s.take() {
		return port.Object{}, s.err
	}
	return s.FakeStorage.Get(ctx, key)
}

func (s *glitchStorage) Stat(ctx context.Context, key string) (port.Meta, error) {
	if s.take() {
		return port.Meta{}, s.err
	}
	return s.FakeStorage.Stat(ctx, key)
}

// unavailStorageWith — хранилище с отказом write-пути в заданной точке:
// классифицированный UnavailableError (что теперь отдают fs/s3 на сбое
// носителя, сессия 60). Чтение живёт.
type unavailPoint string

const (
	unavailAtPut    unavailPoint = "put"
	unavailAtWrite  unavailPoint = "write"
	unavailAtCommit unavailPoint = "commit"
)

type unavailWriter struct{ point unavailPoint }

func storageUnavailable() error {
	return &domain.UnavailableError{What: "хранилище", Reason: "сбой носителя"}
}

func (w *unavailWriter) Write(p []byte) (int, error) {
	if w.point == unavailAtWrite {
		return 0, storageUnavailable()
	}
	return len(p), nil
}

func (w *unavailWriter) Commit(context.Context) error {
	if w.point == unavailAtCommit {
		return storageUnavailable()
	}
	return nil
}

func (*unavailWriter) Abort(context.Context) error { return nil }

type unavailWriteStorage struct {
	*testutil.FakeStorage
	point unavailPoint
}

func (s unavailWriteStorage) Put(ctx context.Context, key string) (port.Writer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.point == unavailAtPut {
		return nil, storageUnavailable()
	}
	return &unavailWriter{point: s.point}, nil
}

// newEnvWith — окружение с подменёнными зависимостями.
func newEnvWith(t *testing.T, cfg Config, h http.HandlerFunc, storage port.Storage, index port.ObjectIndex) *testEnv {
	t.Helper()
	up := newTestUpstream(t, h)
	clock := testutil.NewManualClock(testStart)
	if storage == nil {
		storage = testutil.NewFakeStorage(clock)
	}
	if index == nil {
		index = testutil.NewFakeObjectIndex()
	}
	m := metrics.NewCache()
	eco := testutil.FakeEcosystem{NameOf: "t", Base: up.URL(), MutableTTL: 40 * time.Second}
	return &testEnv{
		engine:  New(storage, index, up.server.Client(), clock, cfg, m),
		eco:     eco,
		storage: testutil.NewFakeStorage(clock),
		index:   index,
		clock:   clock,
		m:       m,
		up:      up,
	}
}

func TestImmutableStorageGlitches(t *testing.T) {
	t.Run("Get мигнул, Stat увидел — объект отдаётся", func(t *testing.T) {
		base := testutil.NewFakeStorage(testutil.NewManualClock(testStart))
		storage := &flakyStorage{FakeStorage: base, failOn: map[int]bool{1: true}}
		env := newEnvWith(t, defaultConfig(), fixedHandler("x", "text/plain"), storage, nil)

		body, status, err := fetch(t, env.engine, env.eco, "/t/pkg/a.deb")
		if err != nil || body != "x" || status != "MISS" {
			t.Fatalf("Fetch после мигания Get = %q %s %v", body, status, err)
		}
	})
	t.Run("Get падает и после загрузки — ошибка наружу", func(t *testing.T) {
		base := testutil.NewFakeStorage(testutil.NewManualClock(testStart))
		storage := &flakyStorage{FakeStorage: base, failOn: map[int]bool{1: true, 2: true}}
		env := newEnvWith(t, defaultConfig(), fixedHandler("x", "text/plain"), storage, nil)

		_, _, err := fetch(t, env.engine, env.eco, "/t/pkg/a.deb")
		var nf *domain.NotFoundError
		if !errors.As(err, &nf) {
			t.Fatalf("ошибка = %v, хочу NotFoundError", err)
		}
	})
}

func TestMutableBytesMissing(t *testing.T) {
	t.Run("индекс свеж, байты исчезли — ошибка от хранилища", func(t *testing.T) {
		env := newEnvWith(t, defaultConfig(), mutableHandler("one", `"v1"`), nil, nil)
		if _, _, err := fetch(t, env.engine, env.eco, "/t/idx/Packages"); err != nil {
			t.Fatal(err)
		}
		// Ключ — case-чувствительный (сессия 19): регистр как в пути.
		meta, err := env.index.ObjectMeta(context.Background(), "cache/t/idx/Packages")
		if err != nil {
			t.Fatal(err)
		}
		if err := env.engine.storage.Delete(context.Background(), meta.StorageKey); err != nil {
			t.Fatal(err)
		}

		_, _, err = fetch(t, env.engine, env.eco, "/t/idx/Packages")
		var nf *domain.NotFoundError
		if !errors.As(err, &nf) {
			t.Fatalf("ошибка = %v, хочу NotFoundError от хранилища", err)
		}
	})
	t.Run("байты исчезли перед 304 — ошибка после ревалидации", func(t *testing.T) {
		env := newEnvWith(t, defaultConfig(), mutableHandler("one", `"v1"`), nil, nil)
		if _, _, err := fetch(t, env.engine, env.eco, "/t/idx/Packages"); err != nil {
			t.Fatal(err)
		}
		env.clock.Advance(41 * time.Second)
		if err := env.engine.storage.Delete(context.Background(), "cache/t/idx/Packages-v"+versionSuffix(env, 1)); err != nil {
			t.Fatal(err)
		}

		_, _, err := fetch(t, env.engine, env.eco, "/t/idx/Packages")
		var nf *domain.NotFoundError
		if !errors.As(err, &nf) {
			t.Fatalf("ошибка = %v, хочу NotFoundError после 304", err)
		}
	})
	t.Run("байты исчезли, upstream 500 — stale недоступен, ошибка наружу", func(t *testing.T) {
		env := newEnvWith(t, defaultConfig(), mutableHandler("one", `"v1"`), nil, nil)
		if _, _, err := fetch(t, env.engine, env.eco, "/t/idx/Packages"); err != nil {
			t.Fatal(err)
		}
		env.clock.Advance(41 * time.Second)
		env.up.set(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) })
		if err := env.engine.storage.Delete(context.Background(), "cache/t/idx/Packages-v"+versionSuffix(env, 1)); err != nil {
			t.Fatal(err)
		}

		_, _, err := fetch(t, env.engine, env.eco, "/t/idx/Packages")
		var up *domain.UpstreamError
		if !errors.As(err, &up) {
			t.Fatalf("ошибка = %v, хочу UpstreamError без stale", err)
		}
	})
}

// versionSuffix повторяет base36-суффикс N-й версии (nonce запуска +
// seq): тестам нужно удалить конкретную версию напрямую.
func versionSuffix(env *testEnv, n uint64) string {
	return strconv.FormatUint(env.engine.nonce, 36) + strconv.FormatUint(n, 36)
}

func TestLegacyIndexWithoutStorageKey(t *testing.T) {
	// записи до версионирования: StorageKey пуст, байты под самим Key
	env := newEnvWith(t, defaultConfig(), func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ignored"))
	}, nil, nil)
	w, err := env.engine.storage.Put(context.Background(), "cache/t/idx/legacy")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("old-bytes")); err != nil {
		t.Fatal(err)
	}
	if err := w.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	legacy := domain.ObjectMeta{
		Key: "cache/t/idx/legacy", ETag: `"e0"`, ContentType: "text/plain",
		LastModified: testStart, ExpiresAt: testStart.Add(time.Hour),
	}
	if err := env.index.PutObjectMeta(context.Background(), legacy); err != nil {
		t.Fatal(err)
	}

	body, status, err := fetch(t, env.engine, env.eco, "/t/idx/legacy")
	if err != nil || body != "old-bytes" || status != "HIT" {
		t.Fatalf("legacy Fetch = %q %s %v", body, status, err)
	}

	// замена legacy-записи: новая версия под версионным ключом,
	// фоновая чистка бьёт по самому Key (пустой StorageKey у old)
	env.clock.Advance(61 * time.Minute)
	env.up.set(mutableHandler("new-bytes", `"e1"`))
	body, status, err = fetch(t, env.engine, env.eco, "/t/idx/legacy")
	if err != nil || body != "new-bytes" || status != "MISS" {
		t.Fatalf("замена legacy = %q %s %v", body, status, err)
	}
}

func TestIndexWriteFailures(t *testing.T) {
	t.Run("запись индекса после 200 падает", func(t *testing.T) {
		env := newEnvWith(t, defaultConfig(), mutableHandler("one", `"v1"`), nil, nil)
		_, _, err := fetch(t, env.engine, env.eco, "/t/idx/Packages")
		if err != nil {
			t.Fatal(err)
		}
		env.engine.index = errIndex{env.index.(*testutil.FakeObjectIndex)}
		env.clock.Advance(41 * time.Second)
		env.up.set(mutableHandler("two", `"v2"`))

		_, _, err = fetch(t, env.engine, env.eco, "/t/idx/Packages")
		if err == nil {
			t.Fatal("падение записи индекса не вернуло ошибку")
		}
	})
	t.Run("запись индекса после 304 падает", func(t *testing.T) {
		env := newEnvWith(t, defaultConfig(), mutableHandler("one", `"v1"`), nil, nil)
		_, _, err := fetch(t, env.engine, env.eco, "/t/idx/Packages")
		if err != nil {
			t.Fatal(err)
		}
		env.engine.index = errIndex{env.index.(*testutil.FakeObjectIndex)}
		env.clock.Advance(41 * time.Second)

		_, _, err = fetch(t, env.engine, env.eco, "/t/idx/Packages")
		if err == nil {
			t.Fatal("падение продления индекса не вернуло ошибку")
		}
	})
}

func TestUpstreamOddStatuses(t *testing.T) {
	t.Run("редирект без Location — UpstreamError", func(t *testing.T) {
		doer := &fakeDoer{resp: http.Response{StatusCode: 301, ContentLength: 0, Header: http.Header{}}}
		doer.body = errReader{}
		env := engineWithDoer(t, defaultConfig(), doer)
		_, _, err := fetch(t, env.engine, env.eco, "/t/pkg/a.deb")
		var up *domain.UpstreamError
		if !errors.As(err, &up) {
			t.Fatalf("ошибка = %v, хочу UpstreamError", err)
		}
	})
	t.Run("невалидный URL upstream — UpstreamError", func(t *testing.T) {
		env := engineWithDoer(t, defaultConfig(), newFakeDoer(-1, "x"))
		env.eco = testutil.FakeEcosystem{NameOf: "t", Base: "://bad", MutableTTL: time.Minute}
		_, _, err := fetch(t, env.engine, env.eco, "/t/pkg/a.deb")
		var up *domain.UpstreamError
		if !errors.As(err, &up) {
			t.Fatalf("ошибка = %v, хочу UpstreamError", err)
		}
	})
	t.Run("обрыв тела на чтении — UpstreamError", func(t *testing.T) {
		doer := &fakeDoer{resp: http.Response{StatusCode: 200, ContentLength: 10, Header: http.Header{}}}
		doer.body = errReader{}
		env := engineWithDoer(t, defaultConfig(), doer)
		_, _, err := fetch(t, env.engine, env.eco, "/t/pkg/a.deb")
		var up *domain.UpstreamError
		if !errors.As(err, &up) {
			t.Fatalf("ошибка = %v, хочу UpstreamError", err)
		}
	})
}

func TestStorageFailures(t *testing.T) {
	t.Run("отменённый контекст — Put не открывается", func(t *testing.T) {
		env := engineWithDoer(t, defaultConfig(), newFakeDoer(1, "x"))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := env.engine.Fetch(ctx, env.eco, "/t/pkg/a.deb")
		if err == nil {
			t.Fatal("отменённый контекст не дал ошибку")
		}
	})
	t.Run("Commit падает — Abort и ошибка наружу", func(t *testing.T) {
		clock := testutil.NewManualClock(testStart)
		base := testutil.NewFakeStorage(clock)
		env := &testEnv{
			engine:  New(failCommitStorage{base}, testutil.NewFakeObjectIndex(), newFakeDoer(1, "x"), clock, defaultConfig(), nil),
			eco:     testutil.FakeEcosystem{NameOf: "t", Base: "http://up.test", MutableTTL: time.Minute},
			storage: base,
			index:   testutil.NewFakeObjectIndex(),
			clock:   clock,
			m:       nil,
			up:      nil,
		}
		_, _, err := fetch(t, env.engine, env.eco, "/t/pkg/a.deb")
		if err == nil {
			t.Fatal("падение Commit не вернуло ошибку")
		}
		if objects := storageCount(t, env.storage); objects != 0 {
			t.Fatalf("после падения Commit в хранилище %d объектов", objects)
		}
	})
}

// TestStorageWriteUnavailablePassThrough — write-путь (сессия 60):
// классифицированный адаптером сбой носителя проходит сквозь движок без
// заворота в UpstreamError — 503 «наш инстанс», а не 502 «виноват
// upstream».
func TestStorageWriteUnavailablePassThrough(t *testing.T) {
	cases := []struct {
		name  string
		point unavailPoint
	}{
		{"Put отказал", unavailAtPut},
		{"Write отказал", unavailAtWrite},
		{"Commit отказал", unavailAtCommit},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			base := testutil.NewFakeStorage(testutil.NewManualClock(testStart))
			env := newEnvWith(t, defaultConfig(), fixedHandler("x", "text/plain"), unavailWriteStorage{base, c.point}, nil)
			_, _, err := fetch(t, env.engine, env.eco, "/t/pkg/a.deb")
			var un *domain.UnavailableError
			if !errors.As(err, &un) {
				t.Fatalf("ошибка = %v, хочу UnavailableError", err)
			}
			var up *domain.UpstreamError
			if errors.As(err, &up) {
				t.Fatalf("сбой носителя замаскирован под upstream: %v", err)
			}
		})
	}
}

// TestHITDegradesToMissOnStorageGlitch — сбой Get/Stat на тёплом кеше
// деградирует в MISS: refetch с upstream возвращает объект клиенту
// (resilience не сломана, сессия 60), а не обрывает раздачу.
func TestHITDegradesToMissOnStorageGlitch(t *testing.T) {
	base := testutil.NewFakeStorage(testutil.NewManualClock(testStart))
	env := newEnvWith(t, defaultConfig(), fixedHandler("x", "text/plain"), base, nil)
	if _, status, err := fetch(t, env.engine, env.eco, "/t/pkg/a.deb"); err != nil || status != "MISS" {
		t.Fatalf("прогрев = %s %v", status, err)
	}
	env.engine.storage = &glitchStorage{
		FakeStorage: base, left: 2,
		err: &domain.UnavailableError{What: "хранилище", Reason: "сбой носителя"},
	}
	body, status, err := fetch(t, env.engine, env.eco, "/t/pkg/a.deb")
	if err != nil || body != "x" || status != "MISS" {
		t.Fatalf("после сбоя HIT = %q %s %v", body, status, err)
	}
	if got := env.up.count("/pkg/a.deb"); got != 2 {
		t.Fatalf("upstream получил %d запросов, хочу 2 (прогрев + refetch)", got)
	}
}

func TestNegativeDisabledByTTL(t *testing.T) {
	// NegativeTTL404 = 0: negative-кеш выключен, каждый запрос идёт upstream
	cfg := defaultConfig()
	cfg.NegativeTTL404 = 0
	env := newTestEnv(t, cfg, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(404) })

	for range 3 {
		_, _, err := fetch(t, env.engine, env.eco, "/t/pkg/gone.deb")
		var nf *domain.NotFoundError
		if !errors.As(err, &nf) {
			t.Fatalf("ошибка = %v, хочу NotFoundError", err)
		}
	}
	if got := env.up.count("/pkg/gone.deb"); got != 3 {
		t.Fatalf("upstream получил %d запросов, хочу 3 (negative выключен)", got)
	}
}
