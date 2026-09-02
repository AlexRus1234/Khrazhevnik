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

package s3

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/minio/minio-go/v7"

	"khrazhevnik/internal/core/config"
	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/testutil"
)

// compile-time: Storage реализует весь порт.
var _ port.Storage = (*Storage)(nil)

func TestSplitEndpoint(t *testing.T) {
	cases := []struct {
		endpoint, wantHost string
		wantSecure, wantOK bool
	}{
		{"https://play.min.io:9000", "play.min.io:9000", true, true},
		{"http://s3.local:9000", "s3.local:9000", false, true},
		{"s3.example.com", "s3.example.com", false, true},
		{"", "", false, false},
	}
	for _, c := range cases {
		host, secure, ok := splitEndpoint(c.endpoint)
		if host != c.wantHost || secure != c.wantSecure || ok != c.wantOK {
			t.Errorf("splitEndpoint(%q) = (%q,%v,%v), хочу (%q,%v,%v)",
				c.endpoint, host, secure, ok, c.wantHost, c.wantSecure, c.wantOK)
		}
	}
}

func TestContentTypeFor(t *testing.T) {
	if ct := contentTypeFor("cache/apt/1/pool/main/a.deb"); ct != "application/octet-stream" {
		t.Errorf("contentTypeFor(.deb) = %q, хочу application/octet-stream", ct)
	}
	if ct := contentTypeFor("a.txt"); ct == "" {
		t.Error("contentTypeFor(.txt) пуст")
	}
	if ct := contentTypeFor("noext"); ct != "application/octet-stream" {
		t.Errorf("contentTypeFor(noext) = %q, хочу application/octet-stream", ct)
	}
}

func TestNewRejectsEmpty(t *testing.T) {
	if _, err := New(config.S3Storage{}, testutil.FixedRand()); err == nil {
		t.Fatal("New с пустым endpoint не вернул ошибку")
	}
}

// emptyUploadsXML — пустой ListMultipartUploads-ответ фейка.
const emptyUploadsXML = `<?xml version="1.0" encoding="UTF-8"?>
<ListMultipartUploadsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
<IsTruncated>false</IsTruncated>
</ListMultipartUploadsResult>`

// startFakeS3 поднимает локальный HTTP-фейк S3 и возвращает endpoint
// (host:port) для конфига/клиента: New теперь ходит списком multipart
// на старте, внешний endpoint в юнитах повис бы на сети.
func startFakeS3(t *testing.T, f *fakeS3) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

func TestNewCreatesSpoolAndClient(t *testing.T) {
	dir := t.TempDir()
	endpoint := startFakeS3(t, &fakeS3{uploadsXML: emptyUploadsXML})
	s, err := New(config.S3Storage{
		Endpoint: endpoint, Region: "us-east-1",
		Bucket: "khrazhevnik", AccessKeyID: "id", SecretAccessKey: "key",
		SpoolDir: dir,
	}, testutil.FixedRand())
	if err != nil {
		t.Fatal(err)
	}
	if s.bucket != "khrazhevnik" || s.spoolDir != dir {
		t.Fatalf("Storage = %+v", s)
	}
}

// TestNewSweepsSpool — осиротевшие спул-файлы (крэш между Put и
// Commit/Abort) вычищаются на старте: живых writers не бывает.
func TestNewSweepsSpool(t *testing.T) {
	dir := t.TempDir()
	endpoint := startFakeS3(t, &fakeS3{uploadsXML: emptyUploadsXML})
	orphaned := filepath.Join(dir, "orphaned-spool")
	if err := os.WriteFile(orphaned, []byte("dead body"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(config.S3Storage{
		Endpoint: endpoint, Region: "us-east-1",
		Bucket: "khrazhevnik", AccessKeyID: "id", SecretAccessKey: "key",
		SpoolDir: dir,
	}, testutil.FixedRand()); err != nil {
		t.Fatalf("New: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("спул после старта: %d записей (err %v), хочу 0", len(entries), err)
	}
}

// TestCheckKeyTraversal — единая точка traversal работает до обращения
// к S3 (на нулевом Storage, без клиента/сети).
func TestCheckKeyTraversal(t *testing.T) {
	s := &Storage{}
	bad := []string{
		"", "/abs", "a/../b", "../escape", "..", "a//b", "a/./b",
		"Back\\slash", "percent%", "пробел x", "nul\x00byte",
		// UPPER легален с сессии 19 — верхний регистр не traversal.
	}
	for _, key := range bad {
		var ike *domain.InvalidKeyError
		if err := s.checkKey(context.Background(), key); !errors.As(err, &ike) {
			t.Fatalf("checkKey(%q): хочу InvalidKeyError, получено %v", key, err)
		}
	}
}

func TestCheckKeyReservedTmp(t *testing.T) {
	s := &Storage{}
	var ike *domain.InvalidKeyError
	for _, key := range []string{"tmp", "tmp/anything", "tmp/x/y.deb"} {
		if err := s.checkKey(context.Background(), key); !errors.As(err, &ike) {
			t.Fatalf("checkKey(%q): %v", key, err)
		}
	}
}

func TestCheckKeyCanceledContext(t *testing.T) {
	s := &Storage{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.checkKey(ctx, "cache/x"); !errors.Is(err, context.Canceled) {
		t.Fatalf("checkKey с отменённым ctx: %v", err)
	}
}

func TestValidPrefix(t *testing.T) {
	if !validPrefix("") || !validPrefix("cache/apt/") || !validPrefix("cache/apt/1") {
		t.Fatal("validPrefix отклонил валидный префикс")
	}
	// UPPER/ легален с сессии 19 (регистр разрешён в ValidateKey).
	if validPrefix("../") || validPrefix("a?b/") {
		t.Fatal("validPrefix принял недопустимый префикс")
	}
}

func TestMapS3ErrorNotFound(t *testing.T) {
	err := mapS3Error(minio.ErrorResponse{Code: minio.NoSuchKey}, "cache/x")
	var nf *domain.NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("NoSuchKey → хочу NotFoundError, получено %v", err)
	}
	if nf.Key != "cache/x" {
		t.Errorf("NotFound Key = %q", nf.Key)
	}
	if err := mapS3Error(minio.ErrorResponse{Code: minio.NoSuchBucket}, "cache/x"); !errors.As(err, &nf) {
		t.Fatalf("NoSuchBucket → хочу NotFoundError, получено %v", err)
	}
	if err := mapS3Error(nil, "cache/x"); err != nil {
		t.Fatalf("mapS3Error(nil) = %v", err)
	}
	// прочий S3-код ошибки не маппится на NotFound
	if err := mapS3Error(minio.ErrorResponse{Code: "InternalError"}, "cache/x"); errors.As(err, &nf) {
		t.Fatal("InternalError замаскирован под NotFound")
	}
}

// TestMapS3ErrorUnavailable — ошибка без S3-ответа (сеть/endpoint) —
// недоступность хранилища (сессия 50): 503 «мы сломаны», а не 502
// «виноват upstream». S3-ответы с кодом класс не меняют.
func TestMapS3ErrorUnavailable(t *testing.T) {
	var un *domain.UnavailableError
	netErr := errors.New("dial tcp 10.0.0.1:9000: connection refused")
	err := mapS3Error(netErr, "cache/x")
	if !errors.As(err, &un) {
		t.Fatalf("сетевой сбой → хочу UnavailableError, получено %v", err)
	}
	if !errors.Is(err, netErr) {
		t.Fatalf("причина потеряна: %v", err)
	}
	if err := mapS3Error(minio.ErrorResponse{Code: "InternalError"}, "cache/x"); errors.As(err, &un) {
		t.Fatal("S3-ответ с кодом не должен превращаться в UnavailableError")
	}
}

func TestMetaFrom(t *testing.T) {
	m := metaFrom("cache/x", minio.ObjectInfo{
		ETag: "\"abc\"", Size: 42, ContentType: "text/plain",
	})
	if m.Key != "cache/x" || m.Size != 42 || m.ETag != "\"abc\"" || m.ContentType != "text/plain" {
		t.Fatalf("metaFrom = %+v", m)
	}
	if !m.ModTime.IsZero() {
		t.Errorf("ModTime нулевого ObjectInfo не нулевое: %v", m.ModTime)
	}
}

// TestWriterStateMachineWithoutS3 — переходы Writer (повторный Commit/
// Abort, Write после завершения) не требуют клиента: done-флаг
// отрабатывает до обращения к S3.
func TestWriterStateMachineWithoutS3(t *testing.T) {
	ctx := context.Background()
	w := &writer{key: "cache/z", done: true}
	if err := w.Commit(ctx); err == nil {
		t.Fatal("повторный Commit не вернул ошибку")
	}
	wa := &writer{key: "cache/z", done: true}
	if err := wa.Abort(ctx); err == nil {
		t.Fatal("повторный Abort не вернул ошибку")
	}
	wd := &writer{key: "cache/z", done: true}
	if _, err := wd.Write([]byte("x")); err == nil {
		t.Fatal("Write после завершения не вернул ошибку")
	}
}

// TestWriterCommitAfterWriteFailure — сбой Write (диск кончился):
// Commit отказывает понятной ошибкой, не доходя до PutObject.
func TestWriterCommitAfterWriteFailure(t *testing.T) {
	ctx := context.Background()
	w := &writer{key: "cache/z", failed: true, writeErr: errors.New("enospace")}
	if err := w.Commit(ctx); err == nil {
		t.Fatal("Commit после сбоя Write не вернул ошибку")
	}
}

// fakeS3 — локальный HTTP-фейк S3 для sweep-multipart: GET ?uploads
// отдаёт фиксированный XML листинга, GET ?location — us-east-1,
// DELETE ?uploadId считается абортом. Сети и контейнеров не нужно.
type fakeS3 struct {
	uploadsXML string
	aborts     atomic.Int32
}

func (f *fakeS3) handler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/xml")
		switch {
		case q.Has("uploads"):
			_, _ = w.Write([]byte(f.uploadsXML))
		case q.Has("location"):
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>` +
				`<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">us-east-1</LocationConstraint>`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	case http.MethodDelete:
		f.aborts.Add(1)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func newFakeClient(t *testing.T, f *fakeS3) *minio.Client {
	t.Helper()
	cli, err := minio.New(startFakeS3(t, f), &minio.Options{Secure: false})
	if err != nil {
		t.Fatal(err)
	}
	return cli
}

// TestSweepMultipartEmptyNoOp — пустой ListMultipartUploads: sweep
// завершается без аборта.
func TestSweepMultipartEmptyNoOp(t *testing.T) {
	f := &fakeS3{uploadsXML: emptyUploadsXML}
	cli := newFakeClient(t, f)
	sweepMultipart(context.Background(), cli, "khrazhevnik")
	if n := f.aborts.Load(); n != 0 {
		t.Fatalf("абортов при пустом листинге: %d, хочу 0", n)
	}
}

// TestSweepMultipartAbortsOrphan — incomplete-загрузка, осиротевшая
// после SIGKILL, абортится startup-sweep'ом (сессия 44: осколки
// multipart не должны копиться в bucket вечно).
func TestSweepMultipartAbortsOrphan(t *testing.T) {
	f := &fakeS3{uploadsXML: `<?xml version="1.0" encoding="UTF-8"?>
<ListMultipartUploadsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
<IsTruncated>false</IsTruncated>
<Upload>
<Key>cache/orphan.deb</Key>
<UploadId>u1</UploadId>
</Upload>
</ListMultipartUploadsResult>`}
	cli := newFakeClient(t, f)
	sweepMultipart(context.Background(), cli, "khrazhevnik")
	if n := f.aborts.Load(); n != 1 {
		t.Fatalf("абортов после sweep: %d, хочу 1", n)
	}
}
