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

// Case-чувствительность apt-ключей: /pool/Foo.deb и /pool/foo.deb на
// case-чувствительном upstream — два разных объекта кеша, байты
// каждого свои. До сессии 19 лоуэркейс StorageKey склеивал их:
// второй клиент получал байты первого (cache poisoning).

package apt

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/engine/cache"
	"khrazhevnik/internal/core/metrics"
	"khrazhevnik/internal/testutil"
)

func TestCacheKeysCaseSensitive(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/pool/Foo.deb", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.debian.binary-package")
		_, _ = io.WriteString(w, "bytes of Foo.deb")
	})
	mux.HandleFunc("/pool/foo.deb", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.debian.binary-package")
		_, _ = io.WriteString(w, "bytes of foo.deb")
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	store := testutil.NewFakeRemoteStore()
	remote, err := store.CreateRemote(context.Background(), domain.Remote{
		Name: "rem", Ecosystem: Name, BaseURL: server.URL, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	clock := testutil.NewManualClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC))
	storage := testutil.NewFakeStorage(clock)
	eco, err := New(store, clock)
	if err != nil {
		t.Fatal(err)
	}
	engine := cache.New(storage, testutil.NewFakeObjectIndex(), server.Client(),
		clock, cache.Config{}, metrics.NewCache())

	fetchBody := func(path string) (string, string) {
		t.Helper()
		obj, status, err := engine.FetchStatus(context.Background(), eco, path)
		if err != nil {
			t.Fatalf("Fetch(%s): %v", path, err)
		}
		defer func() { _ = obj.Body.Close() }()
		b, readErr := io.ReadAll(obj.Body)
		if readErr != nil {
			t.Fatalf("чтение тела %s: %v", path, readErr)
		}
		return string(b), status
	}

	if got, status := fetchBody("/apt/rem/pool/Foo.deb"); status != "MISS" || got != "bytes of Foo.deb" {
		t.Fatalf("Foo.deb: %s %q", status, got)
	}
	// Второй клиент просит foo.deb — лоуэркейс-склейка выдала бы ему
	// байты Foo.deb.
	if got, status := fetchBody("/apt/rem/pool/foo.deb"); status != "MISS" || got != "bytes of foo.deb" {
		t.Fatalf("foo.deb: %s %q (байты чужого объекта?)", status, got)
	}
	// Каждый ключ отдаёт свои байты из кеша.
	if got, status := fetchBody("/apt/rem/pool/Foo.deb"); status != "HIT" || got != "bytes of Foo.deb" {
		t.Fatalf("повторный Foo.deb: %s %q", status, got)
	}
	if got, status := fetchBody("/apt/rem/pool/foo.deb"); status != "HIT" || got != "bytes of foo.deb" {
		t.Fatalf("повторный foo.deb: %s %q", status, got)
	}

	var keys []string
	prefix := "cache/" + Name + "/" + strconv.FormatInt(remote.ID, 10) + "/"
	for meta := range storage.List(context.Background(), prefix) {
		keys = append(keys, meta.Key)
	}
	slices.Sort(keys)
	want := []string{
		prefix + "pool/Foo.deb",
		prefix + "pool/foo.deb",
	}
	if len(keys) != 2 || keys[0] != want[0] || keys[1] != want[1] {
		t.Fatalf("ключи кеша = %v, хочу %v (регистр потерян?)", keys, want)
	}
}
