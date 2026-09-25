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
)

// TestSettingsProxyRoundtrip — юнит port.UpstreamProxyStore на sqlite
// (сессия 154): отсутствие ключа → "" без ошибки; put → get;
// повторный put перезаписывает и обновляет updated_at (через порт
// метка времени не видна — сверка прямым SQL).
func TestSettingsProxyRoundtrip(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)

	got, err := st.UpstreamProxy(ctx)
	if err != nil || got != "" {
		t.Fatalf("прокси пустой БД = %q, %v; хочу \"\" без ошибки", got, err)
	}

	if err := st.SetUpstreamProxy(ctx, "socks5://h:1080", fixed); err != nil {
		t.Fatalf("SetUpstreamProxy: %v", err)
	}
	if got, err = st.UpstreamProxy(ctx); err != nil || got != "socks5://h:1080" {
		t.Fatalf("roundtrip = %q, %v; хочу socks5://h:1080", got, err)
	}
	if n := settingsRows(t, st); n != 1 {
		t.Fatalf("строк в settings после put = %d, хочу 1", n)
	}

	// Повторный put: тот же ключ, новое значение и метка времени.
	later := fixed.Add(time.Hour)
	if err := st.SetUpstreamProxy(ctx, "http://p.example:3128", later); err != nil {
		t.Fatalf("повторный SetUpstreamProxy: %v", err)
	}
	if got, err = st.UpstreamProxy(ctx); err != nil || got != "http://p.example:3128" {
		t.Fatalf("перезапись = %q, %v; хочу http://p.example:3128", got, err)
	}
	if n := settingsRows(t, st); n != 1 {
		t.Fatalf("строк в settings после перезаписи = %d, хочу 1", n)
	}
	var updated int64
	if err := st.db.QueryRow(`SELECT updated_at FROM settings WHERE key = ?`, settingsProxyKey).Scan(&updated); err != nil {
		t.Fatal(err)
	}
	if want := later.Unix(); updated != want {
		t.Fatalf("updated_at = %d, хочу %d (метка перезаписи)", updated, want)
	}
}

// settingsRows — число строк в settings (singleton-контракт).
func settingsRows(t *testing.T, st *Store) int {
	t.Helper()
	var n int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM settings`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
