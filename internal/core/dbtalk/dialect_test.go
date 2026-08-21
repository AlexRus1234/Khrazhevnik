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

package dbtalk

import (
	"testing"
	"time"
)

// fakeDollarDialect — проверка, что shim не зашит под sqlite: плейсхолдеры
// нумеруются и попадают в VALUES по порядку.
type fakeDollarDialect struct{}

func (fakeDollarDialect) Placeholder(n int) string { return "$" + itoa(n) }

func (fakeDollarDialect) UpsertSuffix(key string, cols []string) string {
	return "ON DUPLICATE KEY UPDATE x=1 (" + key + ", " + cols[0] + ")"
}

func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return itoa(n/10) + string(rune('0'+n%10))
}

func TestSQLitePlaceholder(t *testing.T) {
	d := SQLite{}
	if got := d.Placeholder(3); got != "?" {
		t.Fatalf("Placeholder(3) = %q, хочу %q", got, "?")
	}
}

func TestSQLiteUpsertSuffix(t *testing.T) {
	got := SQLite{}.UpsertSuffix("key", []string{"etag", "size"})
	want := "ON CONFLICT (key) DO UPDATE SET etag = excluded.etag, size = excluded.size"
	if got != want {
		t.Fatalf("UpsertSuffix =\n%s\nхочу\n%s", got, want)
	}
}

func TestUpsertSQLite(t *testing.T) {
	got := Upsert(SQLite{}, "object_index", "key",
		[]string{"key", "etag", "size", "content_type", "last_modified", "expires_at"})
	want := "INSERT INTO object_index (key, etag, size, content_type, last_modified, expires_at) " +
		"VALUES (?, ?, ?, ?, ?, ?) " +
		"ON CONFLICT (key) DO UPDATE SET key = excluded.key, etag = excluded.etag, " +
		"size = excluded.size, content_type = excluded.content_type, " +
		"last_modified = excluded.last_modified, expires_at = excluded.expires_at"
	if got != want {
		t.Fatalf("Upsert =\n%s\nхочу\n%s", got, want)
	}
}

func TestUpsertNumberedDialect(t *testing.T) {
	got := Upsert(fakeDollarDialect{}, "t", "k", []string{"a", "b", "c"})
	if want := "INSERT INTO t (a, b, c) VALUES ($1, $2, $3) ON DUPLICATE KEY UPDATE x=1 (k, a)"; got != want {
		t.Fatalf("Upsert =\n%s\nхочу\n%s", got, want)
	}
}

func TestNow(t *testing.T) {
	ts := time.Date(2026, 8, 21, 12, 34, 56, 0, time.UTC)
	if got := Now(ts); got != 1787315696 {
		t.Fatalf("Now = %d, хочу 1787315696", got)
	}
}
