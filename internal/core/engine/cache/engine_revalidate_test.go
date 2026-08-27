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

// Ревалидация: 304 может обновлять не только TTL, но и валидаторы
// (RFC 9110 §15.4.5) — свежие ETag/Last-Modified должны попадать в
// индекс. Last-Modified парсится во всех форматах HTTP-date, не
// только RFC1123.

package cache

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
)

func TestRevalidate304RefreshesValidators(t *testing.T) {
	newLastMod := time.Date(2026, 8, 26, 9, 0, 0, 0, time.UTC)
	var requests atomic.Int64
	env := newTestEnv(t, defaultConfig(), func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch r.Header.Get("If-None-Match") {
		case `"v1"`:
			// 304 с обновлёнными валидаторами: сервер переехал на v2.
			w.Header().Set("ETag", `"v2"`)
			w.Header().Set("Last-Modified", newLastMod.Format(http.TimeFormat))
			w.WriteHeader(http.StatusNotModified)
		case `"v2"`:
			w.Header().Set("ETag", `"v2"`)
			w.WriteHeader(http.StatusNotModified)
		default:
			w.Header().Set("ETag", `"v1"`)
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Last-Modified", time.Date(2026, 8, 20, 9, 0, 0, 0, time.UTC).Format(http.TimeFormat))
			_, _ = io.WriteString(w, "old body")
		}
	})

	_, status, err := fetch(t, env.engine, env.eco, "/t/idx/file")
	if err != nil || status != "MISS" {
		t.Fatalf("первый Fetch = %s, %v", status, err)
	}

	// TTL истёк → conditional-запрос с «v1» → 304 с «v2».
	env.clock.Advance(41 * time.Second)
	obj, status, err := env.engine.FetchStatus(context.Background(), env.eco, "/t/idx/file")
	if err != nil || status != "HIT" {
		t.Fatalf("ревалидация = %s, %v", status, err)
	}
	defer func() { _ = obj.Body.Close() }()
	if obj.Meta.ETag != `"v2"` {
		t.Fatalf("объект отдал ETag %q, хочу обновлённый \"v2\"", obj.Meta.ETag)
	}
	if !obj.Meta.ModTime.Equal(newLastMod) {
		t.Fatalf("ModTime = %v, хочу %v (Last-Modified из 304 не принят)", obj.Meta.ModTime, newLastMod)
	}

	// Индекс хранит новый ETag: следующий conditional ушёл с «v2».
	meta, err := env.index.ObjectMeta(context.Background(), "cache/t/idx/file")
	if err != nil {
		t.Fatalf("ObjectMeta: %v", err)
	}
	if meta.ETag != `"v2"` || !meta.LastModified.Equal(newLastMod) {
		t.Fatalf("индекс = %+v, хочу ETag \"v2\" и LastModified %v", meta, newLastMod)
	}
	env.clock.Advance(41 * time.Second)
	_, _, err = fetch(t, env.engine, env.eco, "/t/idx/file")
	if err != nil {
		t.Fatalf("повторная ревалидация: %v", err)
	}
	if got := env.up.count("/idx/file"); got != 3 {
		t.Fatalf("upstream получил %d запросов, хочу 3 (ревалидация каждого TTL)", got)
	}
}

func TestFetchLastModifiedAsctime(t *testing.T) {
	// asctime — obsolete, но живой формат (RFC 9110 §5.6.7); раньше
	// молча игнорировался → лишние полные скачивания.
	asctime := "Mon Aug 24 12:00:00 2026"
	env := newTestEnv(t, defaultConfig(), func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Last-Modified", asctime)
		_, _ = io.WriteString(w, "body")
	})
	obj, status, err := env.engine.FetchStatus(context.Background(), env.eco, "/t/pkg/a.deb")
	if err != nil || status != "MISS" {
		t.Fatalf("Fetch = %s, %v", status, err)
	}
	defer func() { _ = obj.Body.Close() }()
	want, parseErr := time.Parse(time.ANSIC, asctime)
	if parseErr != nil {
		t.Fatalf("эталонный asctime не разобрался: %v", parseErr)
	}
	if !obj.Meta.ModTime.Equal(want) {
		t.Fatalf("ModTime = %v, хочу %v (asctime проигнорирован)", obj.Meta.ModTime, want)
	}
}

func TestParseHTTPTime(t *testing.T) {
	cases := []struct {
		in    string
		want  time.Time
		valid bool
	}{
		// IMF-fixdate (RFC1123 с GMT) и RFC1123Z.
		{"Mon, 02 Jan 2006 15:04:05 GMT", time.Date(2006, 1, 2, 15, 4, 5, 0, time.UTC), true},
		{"Mon, 02 Jan 2006 15:04:05 +0300", time.Date(2006, 1, 2, 15, 4, 5, 0, time.FixedZone("", 3*3600)), true},
		// obsolete RFC850.
		{"Monday, 02-Jan-06 15:04:05 GMT", time.Date(2006, 1, 2, 15, 4, 5, 0, time.UTC), true},
		// asctime.
		{"Mon Jan  2 15:04:05 2006", time.Date(2006, 1, 2, 15, 4, 5, 0, time.UTC), true},
		// мусор.
		{"", time.Time{}, false},
		{"yesterday", time.Time{}, false},
		{"02.01.2006 15:04:05", time.Time{}, false},
	}
	for _, tc := range cases {
		got, err := parseHTTPTime(tc.in)
		if !tc.valid {
			if err == nil {
				t.Errorf("parseHTTPTime(%q) = nil, хочу ошибку", tc.in)
			}
			var ve *domain.ValidationError
			if err != nil && !errors.As(err, &ve) {
				t.Errorf("parseHTTPTime(%q) = %T, хочу *domain.ValidationError", tc.in, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseHTTPTime(%q) = %v, хочу nil", tc.in, err)
			continue
		}
		if !got.Equal(tc.want) {
			t.Errorf("parseHTTPTime(%q) = %v, хочу %v", tc.in, got, tc.want)
		}
	}
}
