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

package statskeeper

import (
	"context"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/metrics"
	"khrazhevnik/internal/testutil"
)

var fixedNow = time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)

// TestKeeperLoadSeeds — снапшот из БД сеется в per-eco атомики;
// экосистема, которой в текущем конфиге уже нет, сеется как есть
// (легально: конфиг сменился — счётчик останется в разрезе).
func TestKeeperLoadSeeds(t *testing.T) {
	store := testutil.NewFakeStatsStore()
	if err := store.SaveStatsSnapshot(context.Background(), []domain.CacheStatsRow{
		{Ecosystem: "apt", Hits: 11, Misses: 3, StaleServed: 1, NegativeHits: 2, UpstreamErrors: 4, BytesFromUpstream: 1024, BytesToClients: 2048, Packages: 7, UpdatedAt: fixedNow},
		{Ecosystem: "gone", Hits: 5, UpdatedAt: fixedNow},
	}); err != nil {
		t.Fatal(err)
	}
	m := metrics.NewCache()
	k := New(m, store, testutil.FixedClock(fixedNow), time.Minute)
	if err := k.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	apt := m.ForEcosystem("apt")
	if apt.Hits.Load() != 11 || apt.Misses.Load() != 3 || apt.StaleServed.Load() != 1 ||
		apt.NegativeHits.Load() != 2 || apt.UpstreamErrors.Load() != 4 ||
		apt.BytesFromUpstream.Load() != 1024 || apt.BytesToClients.Load() != 2048 ||
		apt.Packages.Load() != 7 {
		t.Errorf("apt сеется неверно: hits=%d misses=%d stale=%d neg=%d err=%d up=%d down=%d pkgs=%d",
			apt.Hits.Load(), apt.Misses.Load(), apt.StaleServed.Load(), apt.NegativeHits.Load(),
			apt.UpstreamErrors.Load(), apt.BytesFromUpstream.Load(), apt.BytesToClients.Load(), apt.Packages.Load())
	}
	// Корневые поля не трогаются: источник счётчиков — per-eco (сессия 83).
	if m.Hits.Load() != 0 {
		t.Errorf("корневой Hits = %d, хочу 0", m.Hits.Load())
	}
	if m.ForEcosystem("gone").Hits.Load() != 5 {
		t.Errorf("неизвестная экосистема должна сесть как есть, got %d", m.ForEcosystem("gone").Hits.Load())
	}
}

// TestKeeperFlushWrites — флаш собирает per-eco атомики в строку
// снапшота; UpdatedAt — от clock (правило port.Clock).
func TestKeeperFlushWrites(t *testing.T) {
	store := testutil.NewFakeStatsStore()
	m := metrics.NewCache()
	m.ForEcosystem("t").Hits.Add(3)
	m.ForEcosystem("t").Packages.Add(2)
	m.ForEcosystem("t").BytesFromUpstream.Add(512)
	m.Hits.Add(100) // корень не источник — в строку не попадает
	k := New(m, store, testutil.FixedClock(fixedNow), time.Minute)
	if err := k.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	rows, err := store.StatsSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("снапшот из %d строк, хочу 1: %+v", len(rows), rows)
	}
	row := rows[0]
	if row.Ecosystem != "t" || row.Hits != 3 || row.Packages != 2 || row.BytesFromUpstream != 512 {
		t.Errorf("строка снапшота = %+v", row)
	}
	if !row.UpdatedAt.Equal(fixedNow) {
		t.Errorf("UpdatedAt = %v, хочу %v", row.UpdatedAt, fixedNow)
	}
}

// TestKeeperFlushEmpty — пустой реестр экосистем: store не вызывается.
func TestKeeperFlushEmpty(t *testing.T) {
	store := testutil.NewFakeStatsStore()
	k := New(metrics.NewCache(), store, testutil.FixedClock(fixedNow), time.Minute)
	if err := k.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := len(store.Saves()); got != 0 {
		t.Errorf("пустой реестр дал %d снапшотов, хочу 0", got)
	}
}

// TestKeeperRunStop — тикер флашит по интервалу, Stop гасит горутину
// и делает финальный флаш.
func TestKeeperRunStop(t *testing.T) {
	store := testutil.NewFakeStatsStore()
	m := metrics.NewCache()
	m.ForEcosystem("t").Hits.Add(1)
	k := New(m, store, testutil.FixedClock(fixedNow), 20*time.Millisecond)
	k.Run(context.Background())
	deadline := time.Now().Add(2 * time.Second)
	for len(store.Saves()) < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("за 2s тикер дал %d снапшотов, хочу ≥2", len(store.Saves()))
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := k.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	saves := store.Saves()
	if len(saves) < 3 {
		t.Errorf("после Stop %d снапшотов (≥2 тиков + финальный), хочу ≥3", len(saves))
	}
	rows, err := store.StatsSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Ecosystem != "t" || rows[0].Hits != 1 {
		t.Errorf("финальное состояние = %+v, хочу t/hits=1", rows)
	}
}
