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

package sqlite

import (
	"context"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
)

// TestStatsSnapshotRoundtrip — юнит cache_stats на :memory: (контракт
// же на трёх драйверах — общий suite, postgres/mariadb в CI):
// roundtrip → перезапись → reset.
func TestStatsSnapshotRoundtrip(t *testing.T) {
	ctx := context.Background()
	st := openDSN(t, ":memory:")

	rows, err := st.StatsSnapshot(ctx)
	if err != nil || len(rows) != 0 {
		t.Fatalf("снапшот пустой таблицы = %+v, %v; хочу пусто без ошибки", rows, err)
	}
	if err := st.SaveStatsSnapshot(ctx, nil); err != nil {
		t.Fatalf("пустой срез — no-op: %v", err)
	}

	first := []domain.CacheStatsRow{
		{
			Ecosystem: "apt", Hits: 100, Misses: 30, StaleServed: 2,
			NegativeHits: 1, UpstreamErrors: 5, BytesFromUpstream: 1 << 20,
			BytesToClients: 2 << 20, Packages: 42, UpdatedAt: fixed,
		},
		{
			Ecosystem: "nix", Hits: 3, Misses: 1, BytesFromUpstream: 7,
			BytesToClients: 9, Packages: 1, UpdatedAt: fixed,
		},
	}
	if err := st.SaveStatsSnapshot(ctx, first); err != nil {
		t.Fatalf("SaveStatsSnapshot: %v", err)
	}
	rows, err = st.StatsSnapshot(ctx)
	if err != nil || len(rows) != 2 {
		t.Fatalf("снапшот после Save = %+v, %v; хочу 2 строки", rows, err)
	}
	if rows[0].Ecosystem != "apt" || rows[1].Ecosystem != "nix" {
		t.Fatalf("порядок экосистем: %q, %q", rows[0].Ecosystem, rows[1].Ecosystem)
	}
	if rows[0] != first[0] || rows[1] != first[1] {
		t.Fatalf("roundtrip исказил строки: %+v", rows)
	}

	second := []domain.CacheStatsRow{
		{Ecosystem: "apt", Hits: 1, Packages: 2, UpdatedAt: fixed.Add(time.Minute)},
		{Ecosystem: "nix", Hits: 4, Packages: 8, UpdatedAt: fixed.Add(time.Minute)},
	}
	if err := st.SaveStatsSnapshot(ctx, second); err != nil {
		t.Fatalf("перезапись: %v", err)
	}
	rows, err = st.StatsSnapshot(ctx)
	if err != nil || len(rows) != 2 {
		t.Fatalf("снапшот после перезаписи = %+v, %v; хочу 2 строки", rows, err)
	}
	if rows[0] != second[0] || rows[1] != second[1] {
		t.Fatalf("перезапись не заменила строки: %+v", rows)
	}

	if err := st.ResetStats(ctx); err != nil {
		t.Fatalf("ResetStats: %v", err)
	}
	rows, err = st.StatsSnapshot(ctx)
	if err != nil || len(rows) != 0 {
		t.Fatalf("снапшот после Reset = %+v, %v; хочу пусто без ошибки", rows, err)
	}
}
