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

// Верификация чексумм: объект, чьё тело не сошлось с хешем из индекса
// экосистемы, не коммитится, не выдаётся и попадает в negative-cache.

package cache

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/metrics"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/testutil"
)

// newChecksumEnv — движок с фейковой экосистемой, выдающей заданную
// чексумму в Target каждого Resolve.
func newChecksumEnv(t *testing.T, h http.HandlerFunc, sum port.Checksum) (*Engine, port.Ecosystem, *testUpstream, *testutil.FakeStorage, *metrics.Cache, *testutil.ManualClock) {
	t.Helper()
	up := newTestUpstream(t, h)
	clock := testutil.NewManualClock(testStart)
	storage := testutil.NewFakeStorage(clock)
	index := testutil.NewFakeObjectIndex()
	m := metrics.NewCache()
	eco := testutil.FakeEcosystem{NameOf: "t", Base: up.URL(), Checksum: sum}
	engine := New(storage, index, up.server.Client(), clock, defaultConfig(), m)
	return engine, eco, up, storage, m, clock
}

func TestChecksumMismatchRejected(t *testing.T) {
	// Индекс обещает sha256 «020202…», upstream отдаёт «poisoned»:
	// битый/подменённый источник не должен попасть в immutable-кеш.
	want := strings.Repeat("02", 32)
	engine, eco, up, storage, m, _ := newChecksumEnv(t, fixedHandler("poisoned", "application/deb"),
		port.Checksum{Algo: "sha256", Hex: want})

	_, _, err := fetch(t, engine, eco, "/t/pkg/a.deb")
	var upErr *domain.UpstreamError
	if !errors.As(err, &upErr) {
		t.Fatalf("mismatch = %v, хочу *domain.UpstreamError", err)
	}
	var cm *checksumMismatch
	if !errors.As(err, &cm) {
		t.Fatalf("причина checksum mismatch потеряна: %v", err)
	}
	if cm.got != fmt.Sprintf("%x", sha256.Sum256([]byte("poisoned"))) {
		t.Errorf("полученный дайджест = %q", cm.got)
	}
	if objects := storageCount(t, storage); objects != 0 {
		t.Fatalf("после mismatch в хранилище %d объектов, хочу 0 (Abort)", objects)
	}

	// negative-cache: второй запрос не ходит на upstream.
	hits := up.count("/pkg/a.deb")
	_, _, err = fetch(t, engine, eco, "/t/pkg/a.deb")
	if !errors.As(err, &upErr) {
		t.Fatalf("повторный запрос = %v, хочу ошибку из negative-cache", err)
	}
	if up.count("/pkg/a.deb") != hits {
		t.Fatal("negative-cache не сработал: upstream получил второй запрос")
	}
	if m.ForEcosystem("t").NegativeHits.Load() != 1 {
		t.Fatalf("NegativeHits = %d, хочу 1", m.ForEcosystem("t").NegativeHits.Load())
	}
}

func TestChecksumMismatchErrorAfterNegativeTTL(t *testing.T) {
	// После истечения negative-TTL upstream снова получает запрос.
	engine, eco, up, _, _, clock := newChecksumEnv(t, fixedHandler("poisoned", "application/deb"),
		port.Checksum{Algo: "sha256", Hex: strings.Repeat("02", 32)})
	_, _, _ = fetch(t, engine, eco, "/t/pkg/a.deb")
	hits := up.count("/pkg/a.deb")
	clock.Advance(defaultConfig().NegativeTTL5xx + time.Second)
	_, _, _ = fetch(t, engine, eco, "/t/pkg/a.deb")
	if up.count("/pkg/a.deb") == hits {
		t.Fatal("после TTL negative-cache upstream должен получить запрос")
	}
}

func TestChecksumMatchCommitsAndHits(t *testing.T) {
	body := "clean payload"
	sum := port.Checksum{
		Algo: "sha256",
		Hex:  fmt.Sprintf("%x", sha256.Sum256([]byte(body))),
	}
	engine, eco, up, storage, _, _ := newChecksumEnv(t, fixedHandler(body, "application/deb"), sum)

	got, status, err := fetch(t, engine, eco, "/t/pkg/a.deb")
	if err != nil || status != "MISS" {
		t.Fatalf("первый Fetch = %s, %v", status, err)
	}
	if got != body {
		t.Fatalf("тело = %q, хочу %q", got, body)
	}
	if objects := storageCount(t, storage); objects != 1 {
		t.Fatalf("валидный объект не закоммичен: %d объектов", objects)
	}
	hits := up.count("/pkg/a.deb")
	got, status, err = fetch(t, engine, eco, "/t/pkg/a.deb")
	if err != nil || status != "HIT" || got != body {
		t.Fatalf("повторный Fetch = %s %q, %v", status, got, err)
	}
	if up.count("/pkg/a.deb") != hits {
		t.Fatal("HIT сходил в upstream")
	}
}

func TestChecksumUppercaseHexMatches(t *testing.T) {
	// Индекс с UPPERCASE-hex — не повод отвергать валидные байты.
	body := "upper"
	sum := port.Checksum{
		Algo: "sha256",
		Hex:  strings.ToUpper(fmt.Sprintf("%x", sha256.Sum256([]byte(body)))),
	}
	engine, eco, _, _, _, _ := newChecksumEnv(t, fixedHandler(body, "application/deb"), sum)
	if _, status, err := fetch(t, engine, eco, "/t/pkg/a.deb"); err != nil || status != "MISS" {
		t.Fatalf("UPPERCASE-hex отвергнут: %s, %v", status, err)
	}
}

// TestCopyBodyChecksumAlgos — табличный прогон алгоритмов и отказа
// верификации на неизвестном алгоритме (честная деградация).
func TestCopyBodyChecksumAlgos(t *testing.T) {
	const body = "algo coverage payload"
	cases := []struct {
		name string
		algo string
		hex  func() string
	}{
		{"sha256", "sha256", func() string { return fmt.Sprintf("%x", sha256.Sum256([]byte(body))) }},
		{"sha-256 алиас", "sha-256", func() string { return fmt.Sprintf("%x", sha256.Sum256([]byte(body))) }},
		{"sha1", "sha1", func() string { return fmt.Sprintf("%x", sha1.Sum([]byte(body))) }},
		{"md5", "md5", func() string { return fmt.Sprintf("%x", md5.Sum([]byte(body))) }},
		{"неизвестный алгоритм — не верифицируем", "crc32", func() string { return "не-хекс мусор" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clock := testutil.NewManualClock(testStart)
			storage := testutil.NewFakeStorage(clock)
			engine := New(storage, testutil.NewFakeObjectIndex(), nil, clock, Config{}, metrics.NewCache())
			w, err := storage.Put(context.Background(), "cache/t/obj")
			if err != nil {
				t.Fatal(err)
			}
			_, err = engine.copyBody(context.Background(), w, strings.NewReader(body), metrics.NewCache(), -1,
				port.Checksum{Algo: tc.algo, Hex: tc.hex()}, "http://up/obj", nil)
			if err != nil {
				_ = w.Abort(context.Background())
				t.Fatalf("copyBody(%s) = %v, хочу nil", tc.algo, err)
			}
			if err := w.Commit(context.Background()); err != nil {
				t.Fatal(err)
			}
			obj, err := storage.Get(context.Background(), "cache/t/obj")
			if err != nil {
				t.Fatal(err)
			}
			stored, readErr := io.ReadAll(obj.Body)
			_ = obj.Body.Close()
			if readErr != nil || string(stored) != body {
				t.Fatalf("в хранилище %q (%v), хочу %q", stored, readErr, body)
			}
		})
	}

	// Валидный hex, но чужой дайджест — mismatch.
	clock := testutil.NewManualClock(testStart)
	storage := testutil.NewFakeStorage(clock)
	engine := New(storage, testutil.NewFakeObjectIndex(), nil, clock, Config{}, metrics.NewCache())
	w, _ := storage.Put(context.Background(), "cache/t/obj")
	defer func() { _ = w.Abort(context.Background()) }()
	_, err := engine.copyBody(context.Background(), w, strings.NewReader(body), metrics.NewCache(), -1,
		port.Checksum{Algo: "sha256", Hex: strings.Repeat("00", 32)}, "http://up/obj", nil)
	var upErr *domain.UpstreamError
	if !errors.As(err, &upErr) {
		t.Fatalf("чужой дайджест = %v, хочу *domain.UpstreamError", err)
	}
}
