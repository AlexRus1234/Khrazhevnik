// РҐСЂР°Р¶РµРІРЅРёРє вЂ” РєРµС€-РїСЂРѕРєСЃРё Рё Р·РµСЂРєР°Р»Рѕ linux-СЂРµРїРѕР·РёС‚РѕСЂРёРµРІ
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

package publish

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/testutil"
)

// fakeRepoAdapter вЂ” РїРѕСЂС‚.RepoAdapter РґР»СЏ С‚РµСЃС‚РѕРІ РґРІРёР¶РєР° Р±РµР· СѓС‡Р°СЃС‚РёСЏ
// apt-РјРѕРґСѓР»СЏ. ValidateObjectPath вЂ” РїСЂРѕСЃС‚РѕР№ whitelist pool/*, РіРµРЅРµСЂР°С‚РѕСЂ
// РїРёС€РµС‚ РјР°СЂРєРµСЂРЅС‹Р№ РёРЅРґРµРєСЃРЅС‹Р№ РєР»СЋС‡ Рё СЃС‡РёС‚Р°РµС‚ РІС‹Р·РѕРІС‹ (РґР»СЏ РїСЂРѕРІРµСЂРѕРє
// Reindex).
type fakeRepoAdapter struct {
	name          string
	validateErr   error
	genErr        error
	genCalls      atomic.Int64
	generatedPath string
}

func (a *fakeRepoAdapter) Name() string { return a.name }
func (a *fakeRepoAdapter) ValidateObjectPath(p string) error {
	if a.validateErr != nil {
		return a.validateErr
	}
	if !strings.HasPrefix(p, "pool/") {
		return &domain.ValidationError{What: "РїСѓС‚СЊ", Value: p, Reason: "РґРѕР»Р¶РЅРѕ Р±С‹С‚СЊ pool/*"}
	}
	return nil
}
func (a *fakeRepoAdapter) GenerateIndexes(ctx context.Context, repo domain.Repo, storage port.Storage, p port.RepoProgress) error {
	if a.genErr != nil {
		return a.genErr
	}
	a.genCalls.Add(1)
	p.Update("test", repo.Name, 0, 1)
	// РџРёС€РµРј РјР°СЂРєРµСЂРЅС‹Р№ РёРЅРґРµРєСЃРЅС‹Р№ РєР»СЋС‡; РёРіРЅРѕСЂРёСЂСѓРµРј РѕС€РёР±РєСѓ Р·Р°РїРёСЃРё.
	key := port.RepoPrefix(repo) + "/dists/stable/release"
	w, err := storage.Put(ctx, key)
	if err != nil {
		return err
	}
	_, _ = w.Write([]byte("release-stub"))
	if err := w.Commit(ctx); err != nil {
		_ = w.Abort(context.Background())
		return err
	}
	a.generatedPath = key
	p.Update("test", repo.Name, 1, 1)
	return nil
}

// newTestEngine СЃРѕР±РёСЂР°РµС‚ Engine СЃ storage/repos/clock/adapters РїРѕ
// РїР°СЂР°РјРµС‚СЂР°Рј. РџРѕ СѓРјРѕР»С‡Р°РЅРёСЋ вЂ” РѕРґРёРЅ fakeRepoAdapter "apt" Рё Р±РµР· РєРІРѕС‚С‹.
func newTestEngine(t *testing.T, maxObjectSize int64) (*Engine, *testutil.FakeStorage, *testutil.FakeRepoStore, *fakeRepoAdapter) {
	t.Helper()
	moment := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	clock := testutil.FixedClock(moment)
	storage := testutil.NewFakeStorage(clock)
	repos := testutil.NewFakeRepoStore()
	adapter := &fakeRepoAdapter{name: "apt"}
	e := New(Config{MaxObjectSize: maxObjectSize}, storage, repos, clock, map[string]port.RepoAdapter{"apt": adapter})
	return e, storage, repos, adapter
}

// makeRepo вЂ” СЃРѕР·РґР°С‘С‚ СЂРµРїРѕ РІ RepoStore Рё РІРѕР·РІСЂР°С‰Р°РµС‚ РјРѕРґРµР»СЊ.
func makeRepo(t *testing.T, repos *testutil.FakeRepoStore, name string, owner int64, eco string, quota domain.Quota) domain.Repo {
	t.Helper()
	r, err := repos.CreateRepo(context.Background(), domain.Repo{Name: name, OwnerID: owner, Ecosystem: eco, Quota: quota, CreatedAt: time.Unix(0, 0).UTC()})
	if err != nil {
		t.Fatalf("CreateRepo: %v", err)
	}
	return r
}

func TestUploadBasic(t *testing.T) {
	e, storage, repos, _ := newTestEngine(t, 0)
	r := makeRepo(t, repos, "alice", 1, "apt", domain.Quota{})
	body := []byte("hello apt")
	if err := e.Upload(context.Background(), r, "pool/main/a/alice.deb", int64(len(body)), bytes.NewReader(body), false); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	obj, err := storage.Get(context.Background(), "repo/"+strconv.FormatInt(r.ID, 10)+"/apt/pool/main/a/alice.deb")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, _ := io.ReadAll(obj.Body)
	if !bytes.Equal(got, body) {
		t.Fatalf("СЃРѕРґРµСЂР¶РёРјРѕРµ = %q, want %q", got, body)
	}
}

func TestUploadQuotaBytesExceeded(t *testing.T) {
	e, _, repos, _ := newTestEngine(t, 0)
	r := makeRepo(t, repos, "alice", 1, "apt", domain.Quota{MaxBytes: 10})
	// РџРѕР»РѕР¶РёРј 8 Р±Р°Р№С‚, С‡С‚РѕР±С‹ СЃСѓРјРјР°СЂРЅРѕ СЃ РЅРѕРІС‹Рј (5) РїСЂРµРІС‹СЃРёС‚СЊ 10.
	first := []byte("12345678")
	if err := e.Upload(context.Background(), r, "pool/main/a/alice1.deb", int64(len(first)), bytes.NewReader(first), false); err != nil {
		t.Fatalf("РїРµСЂРІС‹Р№ Upload: %v", err)
	}
	second := []byte("abcde")
	err := e.Upload(context.Background(), r, "pool/main/a/alice2.deb", int64(len(second)), bytes.NewReader(second), false)
	var q *domain.QuotaExceededError
	if !errors.As(err, &q) {
		t.Fatalf("РѕР¶РёРґР°Р»Рё QuotaExceededError, РїРѕР»СѓС‡РёР»Рё %v", err)
	}
	if q.RepoID != r.ID {
		t.Fatalf("RepoID = %d, want %d", q.RepoID, r.ID)
	}
}

func TestUploadQuotaFilesExceeded(t *testing.T) {
	e, _, repos, _ := newTestEngine(t, 0)
	r := makeRepo(t, repos, "alice", 1, "apt", domain.Quota{MaxObjects: 1})
	first := []byte("a")
	if err := e.Upload(context.Background(), r, "pool/main/a/a.deb", 1, bytes.NewReader(first), false); err != nil {
		t.Fatalf("РїРµСЂРІС‹Р№ Upload: %v", err)
	}
	err := e.Upload(context.Background(), r, "pool/main/a/b.deb", 1, bytes.NewReader(first), false)
	var q *domain.QuotaExceededError
	if !errors.As(err, &q) {
		t.Fatalf("РѕР¶РёРґР°Р»Рё QuotaExceededError, РїРѕР»СѓС‡РёР»Рё %v", err)
	}
}

func TestUploadConflictWithoutForce(t *testing.T) {
	e, _, repos, _ := newTestEngine(t, 0)
	r := makeRepo(t, repos, "alice", 1, "apt", domain.Quota{})
	body := []byte("v1")
	if err := e.Upload(context.Background(), r, "pool/main/a/alice.deb", 2, bytes.NewReader(body), false); err != nil {
		t.Fatalf("РїРµСЂРІС‹Р№ Upload: %v", err)
	}
	err := e.Upload(context.Background(), r, "pool/main/a/alice.deb", 2, bytes.NewReader(body), false)
	var conf *domain.ConflictError
	if !errors.As(err, &conf) {
		t.Fatalf("РѕР¶РёРґР°Р»Рё ConflictError, РїРѕР»СѓС‡РёР»Рё %v", err)
	}
}

func TestUploadForceOverwrites(t *testing.T) {
	e, storage, repos, _ := newTestEngine(t, 0)
	r := makeRepo(t, repos, "alice", 1, "apt", domain.Quota{})
	v1 := []byte("v1")
	if err := e.Upload(context.Background(), r, "pool/main/a/alice.deb", 2, bytes.NewReader(v1), false); err != nil {
		t.Fatalf("РїРµСЂРІС‹Р№ Upload: %v", err)
	}
	v2 := []byte("v2")
	if err := e.Upload(context.Background(), r, "pool/main/a/alice.deb", 2, bytes.NewReader(v2), true); err != nil {
		t.Fatalf("Upload СЃ force: %v", err)
	}
	obj, err := storage.Get(context.Background(), "repo/"+strconv.FormatInt(r.ID, 10)+"/apt/pool/main/a/alice.deb")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, _ := io.ReadAll(obj.Body)
	if !bytes.Equal(got, v2) {
		t.Fatalf("РїРѕСЃР»Рµ force СЃРѕРґРµСЂР¶РёРјРѕРµ = %q, want %q", got, v2)
	}
}

func TestUploadTooLargeSingleObject(t *testing.T) {
	e, _, repos, _ := newTestEngine(t, 100)
	r := makeRepo(t, repos, "alice", 1, "apt", domain.Quota{})
	body := bytes.Repeat([]byte("a"), 200)
	err := e.Upload(context.Background(), r, "pool/main/a/big.deb", 200, bytes.NewReader(body), false)
	var tl *domain.TooLargeError
	if !errors.As(err, &tl) {
		t.Fatalf("РѕР¶РёРґР°Р»Рё TooLargeError, РїРѕР»СѓС‡РёР»Рё %v", err)
	}
}

func TestUploadTraversalPath(t *testing.T) {
	e, _, repos, _ := newTestEngine(t, 0)
	r := makeRepo(t, repos, "alice", 1, "apt", domain.Quota{})
	body := []byte("x")
	err := e.Upload(context.Background(), r, "pool/../../etc/passwd", 1, bytes.NewReader(body), false)
	// ValidateKey Р»РѕРІРёС‚ В«..В» в†’ InvalidKeyError.
	var badKey *domain.InvalidKeyError
	if !errors.As(err, &badKey) {
		t.Fatalf("РѕР¶РёРґР°Р»Рё InvalidKeyError РґР»СЏ traversal, РїРѕР»СѓС‡РёР»Рё %v", err)
	}
}

func TestUploadUnknownEcosystem(t *testing.T) {
	e, _, repos, _ := newTestEngine(t, 0)
	r := makeRepo(t, repos, "alice", 1, "rpm-md", domain.Quota{})
	body := []byte("x")
	err := e.Upload(context.Background(), r, "pool/main/a/alice.deb", 1, bytes.NewReader(body), false)
	var unsup *domain.UnsupportedError
	if !errors.As(err, &unsup) {
		t.Fatalf("РѕР¶РёРґР°Р»Рё UnsupportedError, РїРѕР»СѓС‡РёР»Рё %v", err)
	}
}

func TestUploadInvalidObjectPath(t *testing.T) {
	e, _, repos, _ := newTestEngine(t, 0)
	r := makeRepo(t, repos, "alice", 1, "apt", domain.Quota{})
	body := []byte("x")
	// РќРµ pool/* в†’ Р°РґР°РїС‚РµСЂ РѕС‚РІРµСЂРіР°РµС‚.
	err := e.Upload(context.Background(), r, "dists/stable/release", 1, bytes.NewReader(body), false)
	var val *domain.ValidationError
	if !errors.As(err, &val) {
		t.Fatalf("РѕР¶РёРґР°Р»Рё ValidationError, РїРѕР»СѓС‡РёР»Рё %v", err)
	}
}

func TestUploadSizeMismatch(t *testing.T) {
	e, _, repos, _ := newTestEngine(t, 0)
	r := makeRepo(t, repos, "alice", 1, "apt", domain.Quota{})
	body := []byte("abcde")
	// Р—Р°СЏРІР»РµРЅРѕ 10, РїРѕ С„Р°РєС‚Сѓ 5.
	err := e.Upload(context.Background(), r, "pool/main/a/alice.deb", 10, bytes.NewReader(body), false)
	var val *domain.ValidationError
	if !errors.As(err, &val) {
		t.Fatalf("РѕР¶РёРґР°Р»Рё ValidationError РґР»СЏ size mismatch, РїРѕР»СѓС‡РёР»Рё %v", err)
	}
	// РћР±СЉРµРєС‚ РЅРµ РґРѕР»Р¶РµРЅ Р·Р°С„РёРєСЃРёСЂРѕРІР°С‚СЊСЃСЏ (Abort).
	if _, err := e.storage.Stat(context.Background(), "repo/"+strconv.FormatInt(r.ID, 10)+"/apt/pool/main/a/alice.deb"); err == nil {
		t.Fatalf("РѕР±СЉРµРєС‚ Р·Р°РєРѕРјРјРёС‡РµРЅ, С…РѕС‚СЏ РґРѕР»Р¶РµРЅ Р±С‹С‚СЊ aborted")
	}
}

func TestUploadBodyReadError(t *testing.T) {
	e, _, repos, _ := newTestEngine(t, 0)
	r := makeRepo(t, repos, "alice", 1, "apt", domain.Quota{})
	err := e.Upload(context.Background(), r, "pool/main/a/alice.deb", 10, errReader{}, false)
	if err == nil {
		t.Fatalf("РѕР¶РёРґР°Р»Рё РѕС€РёР±РєСѓ С‡С‚РµРЅРёСЏ С‚РµР»Р°")
	}
}

// errReader вЂ” io.Reader, РѕС‚РґР°СЋС‰РёР№ РѕС€РёР±РєСѓ РїРѕСЃР»Рµ РЅРµСЃРєРѕР»СЊРєРёС… Р±Р°Р№С‚.
type errReader struct{}

func (errReader) Read(p []byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestDeleteExisting(t *testing.T) {
	e, _, repos, _ := newTestEngine(t, 0)
	r := makeRepo(t, repos, "alice", 1, "apt", domain.Quota{})
	body := []byte("hello")
	if err := e.Upload(context.Background(), r, "pool/main/a/alice.deb", 5, bytes.NewReader(body), false); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if err := e.Delete(context.Background(), r, "pool/main/a/alice.deb"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestDeleteMissing(t *testing.T) {
	e, _, repos, _ := newTestEngine(t, 0)
	r := makeRepo(t, repos, "alice", 1, "apt", domain.Quota{})
	err := e.Delete(context.Background(), r, "pool/main/a/ghost.deb")
	var nf *domain.NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("РѕР¶РёРґР°Р»Рё NotFoundError, РїРѕР»СѓС‡РёР»Рё %v", err)
	}
}

func TestListObjects(t *testing.T) {
	e, _, repos, _ := newTestEngine(t, 0)
	r := makeRepo(t, repos, "alice", 1, "apt", domain.Quota{})
	for _, p := range []string{"pool/main/a/a.deb", "pool/main/a/b.deb", "pool/main/a/c.deb"} {
		body := []byte("x")
		if err := e.Upload(context.Background(), r, p, 1, bytes.NewReader(body), false); err != nil {
			t.Fatalf("Upload %s: %v", p, err)
		}
	}
	var got []string
	for meta := range e.List(context.Background(), r) {
		got = append(got, meta.Key)
	}
	want := []string{
		"repo/" + strconv.FormatInt(r.ID, 10) + "/apt/pool/main/a/a.deb",
		"repo/" + strconv.FormatInt(r.ID, 10) + "/apt/pool/main/a/b.deb",
		"repo/" + strconv.FormatInt(r.ID, 10) + "/apt/pool/main/a/c.deb",
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("List = %v, want %v", got, want)
	}
}

func TestReindexDelegatesToAdapter(t *testing.T) {
	e, _, repos, adapter := newTestEngine(t, 0)
	r := makeRepo(t, repos, "alice", 1, "apt", domain.Quota{})
	body := []byte("x")
	if err := e.Upload(context.Background(), r, "pool/main/a/alice.deb", 1, bytes.NewReader(body), false); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if err := e.Reindex(context.Background(), r, nil); err != nil {
		t.Fatalf("Reindex: %v", err)
	}
	if adapter.genCalls.Load() != 1 {
		t.Fatalf("GenerateIndexes РІС‹Р·РІР°РЅРѕ %d СЂР°Р·, want 1", adapter.genCalls.Load())
	}
}

func TestReindexNoAdapter(t *testing.T) {
	moment := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	storage := testutil.NewFakeStorage(testutil.FixedClock(moment))
	repos := testutil.NewFakeRepoStore()
	// Нет адаптеров вообще.
	e := New(Config{}, storage, repos, testutil.FixedClock(moment), nil)
	r := makeRepo(t, repos, "alice", 1, "apt", domain.Quota{})
	err := e.Reindex(context.Background(), r, nil)
	var unsup *domain.UnsupportedError
	if !errors.As(err, &unsup) {
		t.Fatalf("ожидали UnsupportedError, получили %v", err)
	}
}

func TestDeleteUnknownEcosystem(t *testing.T) {
	moment := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	storage := testutil.NewFakeStorage(testutil.FixedClock(moment))
	repos := testutil.NewFakeRepoStore()
	// Нет адаптеров — Delete падает на adapter() с UnsupportedError.
	e := New(Config{}, storage, repos, testutil.FixedClock(moment), nil)
	r := makeRepo(t, repos, "alice", 1, "rpm-md", domain.Quota{})
	err := e.Delete(context.Background(), r, "pool/main/a/foo.rpm")
	var unsup *domain.UnsupportedError
	if !errors.As(err, &unsup) {
		t.Fatalf("ожидали UnsupportedError, получили %v", err)
	}
}

func TestUploadCopyBodyOverflow(t *testing.T) {
	e, _, repos, _ := newTestEngine(t, 100)
	r := makeRepo(t, repos, "alice", 1, "apt", domain.Quota{})
	// Заявлено 200 (под лимит), но копирование через LimitReader
	// обрежет до 100 — TooLargeError по факту чтения (n > MaxObjectSize).
	body := bytes.Repeat([]byte("a"), 200)
	err := e.Upload(context.Background(), r, "pool/main/a/big.deb", 200, bytes.NewReader(body), false)
	var tl *domain.TooLargeError
	if !errors.As(err, &tl) {
		t.Fatalf("ожидали TooLargeError от copyBody, получили %v", err)
	}
}

func TestNewDefaults(t *testing.T) {
	// New без clock/adapters заменяет их на системные/пустые.
	e := New(Config{MaxObjectSize: -1}, nil, nil, nil, nil)
	if e.clock == nil {
		t.Errorf("clock должен быть systemClock по умолчанию")
	}
	if e.adapters == nil {
		t.Errorf("adapters должен быть пустой картой по умолчанию")
	}
	if e.cfg.MaxObjectSize != 0 {
		t.Errorf("MaxObjectSize<0 должен стать 0, got %d", e.cfg.MaxObjectSize)
	}
}
