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

//go:build integration

// E2E Range-раздачи прокси (:29202): httptest-upstream с immutable-объектом
// 64 KiB → наш прокси (живой движок кеша) → 200/206/416 + multipart/If-Range
// byte-exact, MISS↔HIT. Волна «Range-206», сессия 115.

package integration

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	cacheengine "khrazhevnik/internal/core/engine/cache"
	"khrazhevnik/internal/core/metrics"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/core/web"
	"khrazhevnik/internal/testutil"
)

// rangeTestStart — детерминированный момент для движка кеша.
var rangeTestStart = time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)

// rangeBlobFixture — 64 KiB детерминированных байт: любой срез сверяется
// с эталоном побайтово, без знания внутренностей кеша.
func rangeBlobFixture() []byte {
	b := make([]byte, 64<<10)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// rangeRequest — запрос к публичному роутеру с опциональными Range/If-Range.
func rangeRequest(t *testing.T, h http.Handler, method, path, rangeHdr, ifRange string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if rangeHdr != "" {
		req.Header.Set("Range", rangeHdr)
	}
	if ifRange != "" {
		req.Header.Set("If-Range", ifRange)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// rangePart — разобранная часть multipart/byteranges.
type rangePart struct {
	contentRange string
	body         []byte
}

// rangeParts разбирает тело multipart/byteranges по boundary из
// Content-Type (тест-парсер по boundary, без знания точного оверхеда).
func rangeParts(t *testing.T, rec *httptest.ResponseRecorder) []rangePart {
	t.Helper()
	media, params, err := mime.ParseMediaType(rec.Header().Get("Content-Type"))
	if err != nil {
		t.Fatalf("Content-Type %q не парсится: %v", rec.Header().Get("Content-Type"), err)
	}
	if media != "multipart/byteranges" {
		t.Fatalf("media-type = %q, хочу multipart/byteranges", media)
	}
	boundary := params["boundary"]
	if boundary == "" {
		t.Fatalf("нет boundary в Content-Type %q", rec.Header().Get("Content-Type"))
	}
	mr := multipart.NewReader(rec.Body, boundary)
	var parts []rangePart
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("NextPart: %v", err)
		}
		data, err := io.ReadAll(p)
		if err != nil {
			t.Fatalf("чтение части: %v", err)
		}
		parts = append(parts, rangePart{contentRange: p.Header.Get("Content-Range"), body: data})
	}
	return parts
}

// TestProxyRangeEndToEnd — сквозной путь Range через прокси-кеш: полный
// GET (MISS) → одиночный 206 (HIT, повтор идентичен) → суффикс → 416 →
// мусор → multipart → If-Range (ETag из HEAD).
func TestProxyRangeEndToEnd(t *testing.T) {
	fixture := rangeBlobFixture()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pkg/blob.bin" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("ETag", `"blob-v1"`)
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(fixture)
	}))
	t.Cleanup(up.Close)

	clock := testutil.NewManualClock(rangeTestStart)
	engine := cacheengine.New(
		testutil.NewFakeStorage(clock), testutil.NewFakeObjectIndex(),
		testutil.StaticDoerFactory{Doer: up.Client()}, clock,
		cacheengine.Config{StaleIfError: true, NegativeTTL404: 5 * time.Minute, NegativeTTL5xx: 30 * time.Second},
		metrics.NewCache(),
	)
	eco := testutil.FakeEcosystem{NameOf: "t", Base: up.URL, MutableTTL: time.Minute}
	h := web.BuildPublicRouter(web.Deps{
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Version: "test", Cache: engine,
		Ecosystems: map[string]port.Ecosystem{"t": eco},
	})

	const path = "/t/pkg/blob.bin"
	size := int64(len(fixture))

	// Полный GET: MISS, тело byte-exact, ETag для If-Range.
	full := rangeRequest(t, h, http.MethodGet, path, "", "")
	if full.Code != http.StatusOK {
		t.Fatalf("полный GET = %d, хочу 200 (%d байт)", full.Code, full.Body.Len())
	}
	if !bytes.Equal(full.Body.Bytes(), fixture) {
		t.Fatalf("полный GET: тело не byte-exact (%d байт, хочу %d)", full.Body.Len(), size)
	}
	if got := full.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf("полный GET X-Cache = %q, хочу MISS", got)
	}
	if full.Header().Get("ETag") == "" {
		t.Fatal("полный GET без ETag — нечего слать в If-Range")
	}

	// Одиночный диапазон: 206 из прогретого кеша, byte-exact.
	first := rangeRequest(t, h, http.MethodGet, path, "bytes=100-199", "")
	if first.Code != http.StatusPartialContent {
		t.Fatalf("bytes=100-199 = %d, хочу 206 (%d байт)", first.Code, first.Body.Len())
	}
	if !bytes.Equal(first.Body.Bytes(), fixture[100:200]) {
		t.Errorf("bytes=100-199: тело не byte-exact")
	}
	if got, want := first.Header().Get("Content-Range"), fmt.Sprintf("bytes 100-199/%d", size); got != want {
		t.Errorf("Content-Range = %q, хочу %q", got, want)
	}
	if got := first.Header().Get("Content-Length"); got != "100" {
		t.Errorf("Content-Length = %q, хочу 100", got)
	}
	if got := first.Header().Get("Accept-Ranges"); got != "bytes" {
		t.Errorf("Accept-Ranges = %q, хочу bytes", got)
	}
	if got := first.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("первый диапазон X-Cache = %q, хочу HIT", got)
	}

	// Повтор — HIT; заголовки 206 идентичны (контракт сессии 69 на 206).
	repeat := rangeRequest(t, h, http.MethodGet, path, "bytes=100-199", "")
	if repeat.Code != http.StatusPartialContent {
		t.Fatalf("повтор bytes=100-199 = %d, хочу 206", repeat.Code)
	}
	if got := repeat.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("повтор X-Cache = %q, хочу HIT", got)
	}
	for _, hdr := range []string{"Content-Range", "Content-Length", "Content-Type", "Accept-Ranges", "ETag"} {
		if got, want := repeat.Header().Get(hdr), first.Header().Get(hdr); got != want {
			t.Errorf("HIT %s = %q, MISS %q (контракт идентичности заголовков)", hdr, got, want)
		}
	}
	if !bytes.Equal(repeat.Body.Bytes(), first.Body.Bytes()) {
		t.Errorf("повтор: тело отличается от первого 206")
	}

	// Суффиксный диапазон: последние 64 байта.
	suffix := rangeRequest(t, h, http.MethodGet, path, "bytes=-64", "")
	if suffix.Code != http.StatusPartialContent {
		t.Fatalf("bytes=-64 = %d, хочу 206", suffix.Code)
	}
	if !bytes.Equal(suffix.Body.Bytes(), fixture[size-64:]) {
		t.Errorf("bytes=-64: тело не byte-exact")
	}
	if got, want := suffix.Header().Get("Content-Range"), fmt.Sprintf("bytes %d-%d/%d", size-64, size-1, size); got != want {
		t.Errorf("Content-Range = %q, хочу %q", got, want)
	}

	// Начало за концом объекта — 416 + Content-Range: bytes */size.
	unsat := rangeRequest(t, h, http.MethodGet, path, fmt.Sprintf("bytes=%d-", size+10), "")
	if unsat.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("bytes=%d- = %d, хочу 416", size+10, unsat.Code)
	}
	if got, want := unsat.Header().Get("Content-Range"), fmt.Sprintf("bytes */%d", size); got != want {
		t.Errorf("416 Content-Range = %q, хочу %q", got, want)
	}

	// Синтаксический мусор Range — 200-полный (сервер MAY игнорировать).
	garbage := rangeRequest(t, h, http.MethodGet, path, "bytes=abc", "")
	if garbage.Code != http.StatusOK {
		t.Fatalf("bytes=abc = %d, хочу 200-полный", garbage.Code)
	}
	if !bytes.Equal(garbage.Body.Bytes(), fixture) {
		t.Errorf("bytes=abc: тело не полное")
	}

	// Multipart: два диапазона → 206 multipart/byteranges, части byte-exact.
	multi := rangeRequest(t, h, http.MethodGet, path, "bytes=0-9,4096-4105", "")
	if multi.Code != http.StatusPartialContent {
		t.Fatalf("multipart = %d, хочу 206", multi.Code)
	}
	parts := rangeParts(t, multi)
	if len(parts) != 2 {
		t.Fatalf("частей %d, хочу 2", len(parts))
	}
	wantParts := []struct {
		cr   string
		body []byte
	}{
		{fmt.Sprintf("bytes 0-9/%d", size), fixture[0:10]},
		{fmt.Sprintf("bytes 4096-4105/%d", size), fixture[4096:4106]},
	}
	for i, wp := range wantParts {
		if parts[i].contentRange != wp.cr {
			t.Errorf("часть %d: Content-Range = %q, хочу %q", i, parts[i].contentRange, wp.cr)
		}
		if !bytes.Equal(parts[i].body, wp.body) {
			t.Errorf("часть %d: тело не byte-exact", i)
		}
	}

	// If-Range: ETag из HEAD → 206; чужой ETag → 200-полный.
	head := rangeRequest(t, h, http.MethodHead, path, "", "")
	etag := head.Header().Get("ETag")
	if etag == "" {
		t.Fatal("HEAD без ETag — нечего слать в If-Range")
	}
	matched := rangeRequest(t, h, http.MethodGet, path, "bytes=100-199", etag)
	if matched.Code != http.StatusPartialContent {
		t.Fatalf("If-Range (совпавший ETag) = %d, хочу 206", matched.Code)
	}
	if !bytes.Equal(matched.Body.Bytes(), fixture[100:200]) {
		t.Errorf("If-Range совпавший: тело не byte-exact")
	}
	mismatch := rangeRequest(t, h, http.MethodGet, path, "bytes=100-199", `"other"`)
	if mismatch.Code != http.StatusOK {
		t.Fatalf("If-Range (чужой ETag) = %d, хочу 200-полный", mismatch.Code)
	}
	if !bytes.Equal(mismatch.Body.Bytes(), fixture) {
		t.Errorf("If-Range чужой: тело не полное")
	}
}
