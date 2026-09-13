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

// Range-раздача (волна Range-206, сессия 110): FetchMeta обязан совпасть
// с FetchStatus по мете/статусу/ошибке, но не открывать тело; OpenBody/
// OpenRange открывают срез по ключу хранилища.

package cache

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/testutil"
)

// fetchStatusMeta — FetchStatus с закрытием тела: сравнение меты без
// утечки ридеров.
func fetchStatusMeta(t *testing.T, e *Engine, eco port.Ecosystem, path string) (port.Meta, string, error) {
	t.Helper()
	obj, status, err := e.FetchStatus(context.Background(), eco, path)
	if obj.Body != nil {
		_ = obj.Body.Close()
	}
	return obj.Meta, status, err
}

// sameErrType сравнивает ошибки по динамическому типу: доменный контракт
// (NotFound/Stale/Upstream), не текст.
func sameErrType(a, b error) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return reflect.TypeOf(a) == reflect.TypeOf(b)
}

// assertMetaParity проверяет, что FetchMeta и FetchStatus на одинаковом
// состоянии отдают одну мету, статус и ошибку.
func assertMetaParity(t *testing.T, metaEnv, statusEnv *testEnv, path, wantStatus string) {
	t.Helper()
	gotMeta, gotStatus, gotErr := metaEnv.engine.FetchMeta(context.Background(), metaEnv.eco, path)
	wantMeta, wantStatusActual, wantErr := fetchStatusMeta(t, statusEnv.engine, statusEnv.eco, path)
	if gotStatus != wantStatus || wantStatusActual != wantStatus {
		t.Fatalf("%s: статус FetchMeta=%q FetchStatus=%q, хочу %q", path, gotStatus, wantStatusActual, wantStatus)
	}
	if !sameErrType(gotErr, wantErr) {
		t.Fatalf("%s: ошибка FetchMeta=%v FetchStatus=%v", path, gotErr, wantErr)
	}
	if gotMeta.Key != wantMeta.Key || gotMeta.Size != wantMeta.Size ||
		gotMeta.ETag != wantMeta.ETag || gotMeta.ContentType != wantMeta.ContentType ||
		!gotMeta.ModTime.Equal(wantMeta.ModTime) {
		t.Fatalf("%s: мета FetchMeta=%+v FetchStatus=%+v", path, gotMeta, wantMeta)
	}
}

func TestFetchMetaMatchesFetchStatus(t *testing.T) {
	t.Run("immutable HIT", func(t *testing.T) {
		h := fixedHandler("hello", "application/deb")
		a, b := newTestEnv(t, defaultConfig(), h), newTestEnv(t, defaultConfig(), h)
		for _, e := range []*testEnv{a, b} {
			if _, status, err := fetch(t, e.engine, e.eco, "/t/pkg/a.deb"); err != nil || status != "MISS" {
				t.Fatalf("прогрев = %s %v", status, err)
			}
		}
		assertMetaParity(t, a, b, "/t/pkg/a.deb", statusHit)
	})

	t.Run("immutable MISS", func(t *testing.T) {
		h := fixedHandler("hello", "application/deb")
		a, b := newTestEnv(t, defaultConfig(), h), newTestEnv(t, defaultConfig(), h)
		assertMetaParity(t, a, b, "/t/pkg/a.deb", statusMiss)
	})

	t.Run("mutable HIT", func(t *testing.T) {
		h := mutableHandler("one", `"v1"`)
		a, b := newTestEnv(t, defaultConfig(), h), newTestEnv(t, defaultConfig(), h)
		for _, e := range []*testEnv{a, b} {
			if _, status, err := fetch(t, e.engine, e.eco, "/t/idx/Packages"); err != nil || status != "MISS" {
				t.Fatalf("прогрев = %s %v", status, err)
			}
		}
		assertMetaParity(t, a, b, "/t/idx/Packages", statusHit)
	})

	t.Run("mutable 304-ревалидация", func(t *testing.T) {
		h := mutableHandler("one", `"v1"`)
		a, b := newTestEnv(t, defaultConfig(), h), newTestEnv(t, defaultConfig(), h)
		for _, e := range []*testEnv{a, b} {
			if _, status, err := fetch(t, e.engine, e.eco, "/t/idx/Packages"); err != nil || status != "MISS" {
				t.Fatalf("прогрев = %s %v", status, err)
			}
			e.clock.Advance(41 * time.Second)
		}
		assertMetaParity(t, a, b, "/t/idx/Packages", statusHit)
	})

	t.Run("mutable MISS", func(t *testing.T) {
		h := mutableHandler("one", `"v1"`)
		a, b := newTestEnv(t, defaultConfig(), h), newTestEnv(t, defaultConfig(), h)
		assertMetaParity(t, a, b, "/t/idx/Packages", statusMiss)
	})

	t.Run("negative 404", func(t *testing.T) {
		h := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) }
		a, b := newTestEnv(t, defaultConfig(), h), newTestEnv(t, defaultConfig(), h)
		assertMetaParity(t, a, b, "/t/pkg/gone.deb", "")
	})

	t.Run("STALE", func(t *testing.T) {
		h := mutableHandler("one", `"v1"`)
		a, b := newTestEnv(t, defaultConfig(), h), newTestEnv(t, defaultConfig(), h)
		for _, e := range []*testEnv{a, b} {
			if _, status, err := fetch(t, e.engine, e.eco, "/t/idx/Packages"); err != nil || status != "MISS" {
				t.Fatalf("прогрев = %s %v", status, err)
			}
			e.clock.Advance(41 * time.Second)
			e.up.set(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) })
		}
		assertMetaParity(t, a, b, "/t/idx/Packages", statusStale)
	})
}

func TestOpenRangeSlice(t *testing.T) {
	env := newTestEnv(t, defaultConfig(), fixedHandler("abcdef", "application/deb"))
	if body, status, err := fetch(t, env.engine, env.eco, "/t/pkg/a.deb"); err != nil || body != "abcdef" || status != "MISS" {
		t.Fatalf("прогрев = %q %s %v", body, status, err)
	}

	meta, status, err := env.engine.FetchMeta(context.Background(), env.eco, "/t/pkg/a.deb")
	if err != nil || status != statusHit {
		t.Fatalf("FetchMeta = %s %v", status, err)
	}

	rc, err := env.engine.OpenRange(context.Background(), meta.Key, 2, 3)
	if err != nil {
		t.Fatalf("OpenRange: %v", err)
	}
	got, readErr := io.ReadAll(rc)
	_ = rc.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != "cde" {
		t.Fatalf("OpenRange = %q, хочу %q", got, "cde")
	}

	var ir *domain.InvalidRangeError
	if _, err := env.engine.OpenRange(context.Background(), meta.Key, 4, 10); !errors.As(err, &ir) {
		t.Fatalf("OpenRange за размером = %v, хочу InvalidRangeError", err)
	}
}

// countingStorage считает открытия тела (Get): FetchMeta обязан не
// трогать его, OpenBody — открыть ровно одно.
type countingStorage struct {
	*testutil.FakeStorage
	opens atomic.Int64
}

func (s *countingStorage) Get(ctx context.Context, key string) (port.Object, error) {
	s.opens.Add(1)
	return s.FakeStorage.Get(ctx, key)
}

func TestFetchMetaDoesNotOpenBody(t *testing.T) {
	env := newTestEnv(t, defaultConfig(), fixedHandler("hello", "application/deb"))
	cs := &countingStorage{FakeStorage: env.storage}
	env.engine.storage = cs

	meta, status, err := env.engine.FetchMeta(context.Background(), env.eco, "/t/pkg/a.deb")
	if err != nil || status != statusMiss {
		t.Fatalf("FetchMeta = %s %v", status, err)
	}
	if got := cs.opens.Load(); got != 0 {
		t.Fatalf("FetchMeta открыла тело %d раз, хочу 0", got)
	}

	rc, err := env.engine.OpenBody(context.Background(), meta.Key)
	if err != nil {
		t.Fatalf("OpenBody: %v", err)
	}
	_ = rc.Close()
	if got := cs.opens.Load(); got != 1 {
		t.Fatalf("OpenBody открыла тело %d раз, хочу 1", got)
	}
}
