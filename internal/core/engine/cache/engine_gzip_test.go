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

// Byte-exact инвариант против прозрачного gzip: outbound-клиент собран
// с DisableCompression (как в wire.outboundHTTPClient), поэтому
// Accept-Encoding не подмешивается, а в кеш пишутся ровно те байты,
// что отдал upstream — сжатые, если сервер сжал, и с родным ETag.

package cache

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"sync/atomic"
	"testing"

	"khrazhevnik/internal/core/metrics"
	"khrazhevnik/internal/testutil"
)

func TestGzipUpstreamByteExact(t *testing.T) {
	payload := []byte("the quick brown fox jumps over the lazy dog")
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(payload); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	gzipBody := buf.Bytes()

	var sawAcceptEncoding atomic.Bool
	up := newTestUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		// DisableCompression-клиент не шлёт Accept-Encoding: сервер,
		// жмущий «динамически», сжал бы тело только при его наличии.
		if r.Header.Get("Accept-Encoding") != "" {
			sawAcceptEncoding.Store(true)
		}
		w.Header().Set("Content-Type", "application/deb")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("ETag", `"gz"`)
		_, _ = w.Write(gzipBody)
	})
	clock := testutil.NewManualClock(testStart)
	storage := testutil.NewFakeStorage(clock)
	index := testutil.NewFakeObjectIndex()
	eco := testutil.FakeEcosystem{NameOf: "t", Base: up.URL()}
	// Тот же транспорт, что в wire.outboundHTTPClient: без прозрачной
	// распаковки. up.server.Client() здесь не годится — он жмёт.
	client := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	engine := New(storage, index, client, clock, defaultConfig(), metrics.NewCache())

	body, status, err := fetch(t, engine, eco, "/t/pkg/a.deb")
	if err != nil || status != "MISS" {
		t.Fatalf("первый Fetch = %s, %v", status, err)
	}
	if body != string(gzipBody) {
		t.Fatalf("тело из кеша != байтам upstream-ответа (%d vs %d байт)", len(body), len(gzipBody))
	}
	if sawAcceptEncoding.Load() {
		t.Fatal("outbound-клиент подмешал Accept-Encoding — транспорт жмёт/расживает за спиной кеша")
	}

	// В хранилище лежат ровно байты upstream-ответа (golden-сравнение).
	obj, err := storage.Get(context.Background(), "cache/t/pkg/a.deb")
	if err != nil {
		t.Fatalf("storage.Get: %v", err)
	}
	stored, readErr := io.ReadAll(obj.Body)
	_ = obj.Body.Close()
	if readErr != nil {
		t.Fatalf("чтение из хранилища: %v", readErr)
	}
	if !bytes.Equal(stored, gzipBody) {
		t.Fatalf("в хранилище %d байт, upstream отдал %d", len(stored), len(gzipBody))
	}

	// HIT отдаёт те же байты, upstream больше не дёргается.
	hits := up.count("/pkg/a.deb")
	body, status, err = fetch(t, engine, eco, "/t/pkg/a.deb")
	if err != nil || status != "HIT" || body != string(gzipBody) {
		t.Fatalf("повторный Fetch = %s %q, %v", status, body, err)
	}
	if up.count("/pkg/a.deb") != hits {
		t.Fatal("HIT сходил в upstream")
	}
}
