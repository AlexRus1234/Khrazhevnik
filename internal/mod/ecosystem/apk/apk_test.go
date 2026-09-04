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

package apk

import (
	"context"
	"errors"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/testutil"
)

func newTestAdapter(t *testing.T) *Adapter {
	t.Helper()
	a, err := New(testutil.NewFakeRemoteStore(), testutil.NewManualClock(time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestNewValidatesDeps(t *testing.T) {
	if _, err := New(nil, testutil.NewManualClock(time.Now())); err == nil {
		t.Error("New(nil, clock) должен ошибаться")
	}
	if _, err := New(testutil.NewFakeRemoteStore(), nil); err == nil {
		t.Error("New(remotes, nil) должен ошибаться")
	}
}

func TestName(t *testing.T) {
	if got := newTestAdapter(t).Name(); got != "apk" {
		t.Errorf("Name() = %q, хочу apk", got)
	}
}

func TestURLPrefix(t *testing.T) {
	if got := newTestAdapter(t).URLPrefix(); got != "apk" {
		t.Errorf("URLPrefix() = %q, хочу apk", got)
	}
}

type classifyCase struct {
	path string
	kind domain.Kind
	ttl  time.Duration
}

func TestClassifyTable(t *testing.T) {
	a := newTestAdapter(t)
	cases := []classifyCase{
		// Immutable: .apk пакеты.
		{"x86_64/foo-1.0-r0.apk", domain.KindImmutable, 0},
		{"pool/x86_64/bar-2.3-r4.apk", domain.KindImmutable, 0},
		{"aarch64/baz-0.1-r1.apk", domain.KindImmutable, 0},
		// Реальное имя с «+» (сессия 65): исторические gtk+ пакеты Alpine.
		{"x86_64/gtk+2.0-2.24.33-r0.apk", domain.KindImmutable, 0},
		// Mutable{TTL 5m}: APKINDEX и его подписи.
		{"x86_64/APKINDEX.tar.gz", domain.KindMutable, mutableIndexTTL},
		{"aarch64/APKINDEX.tar.gz", domain.KindMutable, mutableIndexTTL},
		{"x86_64/APKINDEX.json", domain.KindMutable, mutableIndexTTL},
		{"x86_64/APKINDEX.tar.gz.sig", domain.KindMutable, mutableIndexTTL},
		{"x86_64/APKINDEX.json.sig", domain.KindMutable, mutableIndexTTL},
		// Mutable{TTL 1h}: ключи.
		{"keys/alpine@example.com-abc123.rsa.pub", domain.KindMutable, mutableKeysTTL},
		// Unknown → conservative Mutable{TTL 1m}.
		{"some/random/path.dat", domain.KindMutable, mutableUnknownTTL},
		{"x86_64/unknown.bin", domain.KindMutable, mutableUnknownTTL},
	}
	for _, tc := range cases {
		got, err := a.Classify(tc.path)
		if err != nil {
			t.Errorf("Classify(%q) err = %v", tc.path, err)
			continue
		}
		if got.Kind != tc.kind {
			t.Errorf("Classify(%q).Kind = %q, хочу %q", tc.path, got.Kind, tc.kind)
		}
		if tc.kind == domain.KindMutable && got.TTL != tc.ttl {
			t.Errorf("Classify(%q).TTL = %v, хочу %v", tc.path, got.TTL, tc.ttl)
		}
	}
}

func TestClassifyEmptyPath(t *testing.T) {
	a := newTestAdapter(t)
	_, err := a.Classify("")
	var ve *domain.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("Classify(\"\") = %v, хочу *ValidationError", err)
	}
}

func TestClassifyRulesCovered(t *testing.T) {
	a := newTestAdapter(t)
	covered := make(map[string]bool, len(a.rules))
	for _, r := range a.rules {
		covered[r.name] = false
	}
	for _, tc := range []string{
		"x86_64/foo-1.0-r0.apk",
		"x86_64/APKINDEX.tar.gz",
		"x86_64/APKINDEX.json",
		"x86_64/APKINDEX.tar.gz.sig",
		"x86_64/APKINDEX.json.sig",
		"keys/alpine@example.com-abc123.rsa.pub",
	} {
		for _, r := range a.rules {
			if r.re.MatchString(tc) {
				covered[r.name] = true
			}
		}
	}
	for name, ok := range covered {
		if !ok {
			t.Errorf("правило %q не покрыто ни одним тест-кейсом", name)
		}
	}
}

// fakeRemotes — RemoteStore с предзаполненными remotes для Resolve.
type fakeRemotes struct{ rs []domain.Remote }

func (f fakeRemotes) CreateRemote(context.Context, domain.Remote) (domain.Remote, error) {
	return domain.Remote{}, nil
}
func (f fakeRemotes) Remote(context.Context, int64) (domain.Remote, error) {
	return domain.Remote{}, nil
}
func (f fakeRemotes) Remotes(context.Context) ([]domain.Remote, error)  { return f.rs, nil }
func (f fakeRemotes) UpdateRemote(context.Context, domain.Remote) error { return nil }
func (f fakeRemotes) DeleteRemote(context.Context, int64) error         { return nil }

func newResolveAdapter(t *testing.T, rs ...domain.Remote) *Adapter {
	t.Helper()
	a, err := New(fakeRemotes{rs: rs}, testutil.NewManualClock(time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestResolveKnownRemote(t *testing.T) {
	a := newResolveAdapter(t, domain.Remote{
		ID: 7, Name: "alpine", Ecosystem: "apk",
		BaseURL: "https://dl-cdn.alpinelinux.org/alpine", Enabled: true,
	})
	target, ok := a.Resolve("/apk/alpine/v3.20/main/x86_64/foo-1.0-r0.apk")
	if !ok {
		t.Fatal("Resolve существующего remote = false")
	}
	wantURL := "https://dl-cdn.alpinelinux.org/alpine/v3.20/main/x86_64/foo-1.0-r0.apk"
	if target.UpstreamURL != wantURL {
		t.Errorf("UpstreamURL = %q, хочу %q", target.UpstreamURL, wantURL)
	}
	if target.UpstreamPath != "/v3.20/main/x86_64/foo-1.0-r0.apk" {
		t.Errorf("UpstreamPath = %q", target.UpstreamPath)
	}
	if target.StorageKey != "cache/apk/7/v3.20/main/x86_64/foo-1.0-r0.apk" {
		t.Errorf("StorageKey = %q", target.StorageKey)
	}
}

func TestResolveRootPath(t *testing.T) {
	a := newResolveAdapter(t, domain.Remote{
		ID: 3, Name: "alpine", BaseURL: "https://dl-cdn.alpinelinux.org/alpine", Enabled: true,
	})
	target, ok := a.Resolve("/apk/alpine")
	if !ok {
		t.Fatal("Resolve корня remote = false")
	}
	if target.UpstreamPath != "/" {
		t.Errorf("UpstreamPath = %q, хочу «/»", target.UpstreamPath)
	}
}

func TestResolveUnknownRemote(t *testing.T) {
	a := newResolveAdapter(t, domain.Remote{ID: 1, Name: "alpine", BaseURL: "https://x", Enabled: true})
	if _, ok := a.Resolve("/apk/fedoris/x86_64/APKINDEX.tar.gz"); ok {
		t.Error("Resolve неизвестного remote должен дать false")
	}
}

func TestResolveDisabledRemote(t *testing.T) {
	a := newResolveAdapter(t, domain.Remote{ID: 1, Name: "alpine", BaseURL: "https://x", Enabled: false})
	if _, ok := a.Resolve("/apk/alpine/APKINDEX.tar.gz"); ok {
		t.Error("Resolve выключенного remote должен дать false")
	}
}

func TestResolveWrongEcosystemPrefix(t *testing.T) {
	a := newResolveAdapter(t, domain.Remote{ID: 1, Name: "alpine", BaseURL: "https://x", Enabled: true})
	for _, path := range []string{
		"/apt/alpine/APKINDEX.tar.gz",
		"/pacman/alpine/APKINDEX.tar.gz",
	} {
		if _, ok := a.Resolve(path); ok {
			t.Errorf("Resolve(%q) с чужим префиксом должен дать false", path)
		}
	}
}

func TestResolveTraversalRemoteName(t *testing.T) {
	a := newResolveAdapter(t, domain.Remote{ID: 1, Name: "alpine", BaseURL: "https://x", Enabled: true})
	for _, path := range []string{
		"/apk/../etc/passwd",
		"/apk/./etc/passwd",
		"/apk//etc/passwd",
		"/apk//",
	} {
		if _, ok := a.Resolve(path); ok {
			t.Errorf("Resolve(%q) должен отвергнуть traversal, но дал ok", path)
		}
	}
}

// blockingRemotes — RemoteStore, чей Remotes() висит до отмены ctx:
// имитирует зависшее соединение с каталогом.
type blockingRemotes struct {
	fakeRemotes
	block bool
}

func (b *blockingRemotes) Remotes(ctx context.Context) ([]domain.Remote, error) {
	if b.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return b.fakeRemotes.Remotes(ctx)
}

// countingRemotes — RemoteStore со счётчиком вызовов Remotes().
type countingRemotes struct {
	fakeRemotes
	calls int
}

func (c *countingRemotes) Remotes(ctx context.Context) ([]domain.Remote, error) {
	c.calls++
	return c.fakeRemotes.Remotes(ctx)
}

func TestLookupRemoteReloadBoundedByTimeout(t *testing.T) {
	// Зависший каталог не держит hot-path дольше шапки: reload
	// срывается по таймауту, отдаётся stale-кеш («старый кеш лучше
	// пустого»).
	store := &blockingRemotes{fakeRemotes: fakeRemotes{rs: []domain.Remote{
		{ID: 5, Name: "alpine", Ecosystem: "apk", BaseURL: "https://dl-cdn.alpinelinux.org/alpine", Enabled: true},
	}}}
	clock := testutil.NewManualClock(time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC))
	a, err := New(store, clock)
	if err != nil {
		t.Fatal(err)
	}
	a.reloadTimeout = 50 * time.Millisecond
	if _, ok := a.Resolve("/apk/alpine/x86_64/APKINDEX.tar.gz"); !ok {
		t.Fatal("первый Resolve не нашёл remote")
	}
	store.block = true
	clock.Advance(remoteCacheTTL)
	done := make(chan bool, 1)
	go func() {
		_, ok := a.Resolve("/apk/alpine/x86_64/APKINDEX.tar.gz")
		done <- ok
	}()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("reload по таймауту упал, но stale-копия из кеша не отдана")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Resolve висит на зависшем каталоге — шапка reload не работает")
	}
}

func TestLookupRemoteReloadCounting(t *testing.T) {
	// Свежий кеш (TTL не истёк) не обращается к RemoteStore вовсе;
	// после истечения TTL — ровно один reload, подхватывающий новые
	// записи.
	store := &countingRemotes{fakeRemotes: fakeRemotes{rs: []domain.Remote{
		{ID: 5, Name: "alpine", Ecosystem: "apk", BaseURL: "https://dl-cdn.alpinelinux.org/alpine", Enabled: true},
	}}}
	clock := testutil.NewManualClock(time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC))
	a, err := New(store, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Resolve("/apk/alpine/x86_64/APKINDEX.tar.gz"); !ok {
		t.Fatal("первый Resolve не нашёл remote")
	}
	if _, ok := a.Resolve("/apk/alpine/x86_64/APKINDEX.tar.gz"); !ok {
		t.Fatal("второй Resolve не нашёл remote")
	}
	if store.calls != 1 {
		t.Fatalf("свежий кеш не должен обращаться к RemoteStore; calls=%d", store.calls)
	}
	store.rs = append(store.rs, domain.Remote{
		ID: 6, Name: "edge", Ecosystem: "apk", BaseURL: "https://dl-cdn.alpinelinux.org/edge", Enabled: true,
	})
	clock.Advance(remoteCacheTTL)
	if _, ok := a.Resolve("/apk/edge/x86_64/APKINDEX.tar.gz"); !ok {
		t.Fatal("после TTL reload не подхватил новый remote")
	}
	if store.calls != 2 {
		t.Errorf("после TTL должен быть ровно один reload; calls=%d", store.calls)
	}
}

func TestResolvePicksUpNewRemote(t *testing.T) {
	store := testutil.NewFakeRemoteStore()
	clock := testutil.NewManualClock(time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC))
	a, err := New(store, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Resolve("/apk/alpine/x86_64/APKINDEX.tar.gz"); ok {
		t.Fatal("до создания remote Resolve не должен находить")
	}
	if _, err := store.CreateRemote(context.Background(), domain.Remote{
		Name: "alpine", Ecosystem: "apk", BaseURL: "https://dl-cdn.alpinelinux.org/alpine", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Resolve("/apk/alpine/x86_64/APKINDEX.tar.gz"); ok {
		t.Fatal("кеш remotes не должен инвалидироваться до TTL")
	}
	clock.Advance(remoteCacheTTL)
	target, ok := a.Resolve("/apk/alpine/v3.20/main/x86_64/APKINDEX.tar.gz")
	if !ok {
		t.Fatal("после TTL кеш remotes не обновился")
	}
	if target.UpstreamURL != "https://dl-cdn.alpinelinux.org/alpine/v3.20/main/x86_64/APKINDEX.tar.gz" {
		t.Errorf("UpstreamURL = %q", target.UpstreamURL)
	}
}

// errorRemoteStore — RemoteStore, чей Remotes() падает по флагу.
type errorRemoteStore struct {
	fakeRemotes
	calls int
	fail  bool
}

func (e *errorRemoteStore) Remotes(ctx context.Context) ([]domain.Remote, error) {
	e.calls++
	if e.fail {
		return nil, errors.New("remote store down")
	}
	return e.fakeRemotes.Remotes(ctx)
}

func TestResolveStaleCacheOnReloadError(t *testing.T) {
	store := &errorRemoteStore{fakeRemotes: fakeRemotes{rs: []domain.Remote{
		{ID: 5, Name: "alpine", Ecosystem: "apk", BaseURL: "https://dl-cdn.alpinelinux.org/alpine", Enabled: true},
	}}}
	clock := testutil.NewManualClock(time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC))
	a, err := New(store, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Resolve("/apk/alpine/x86_64/APKINDEX.tar.gz"); !ok {
		t.Fatal("первый Resolve не нашёл remote")
	}
	store.fail = true
	clock.Advance(remoteCacheTTL)
	if _, ok := a.Resolve("/apk/alpine/x86_64/APKINDEX.tar.gz"); !ok {
		t.Fatal("reload упал, но stale-копия из кеша не отдана")
	}
}

func TestParseApkInclude(t *testing.T) {
	cases := []struct {
		name    string
		include []string
		wantN   int
		wantErr bool
	}{
		{"одна arch", []string{"x86_64"}, 1, false},
		{"несколько", []string{"x86_64", "aarch64"}, 2, false},
		{"пусто", nil, 0, true},
		{"пустой элемент", []string{""}, 0, true},
		{"со слэшем", []string{"x86_64/extra"}, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseApkInclude(tc.include)
			if tc.wantErr {
				if err == nil {
					t.Fatal("хочу ошибку, получил nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("не ждал ошибку: %v", err)
			}
			if len(got) != tc.wantN {
				t.Errorf("len = %d, хочу %d", len(got), tc.wantN)
			}
		})
	}
}

func TestParseApkIncludeValues(t *testing.T) {
	archs, err := parseApkInclude([]string{"x86_64", "aarch64"})
	if err != nil {
		t.Fatal(err)
	}
	if archs[0] != "x86_64" || archs[1] != "aarch64" {
		t.Errorf("archs = %+v", archs)
	}
}

func TestGlobToRegex(t *testing.T) {
	cases := []struct {
		glob string
		path string
		want bool
	}{
		{"**/*.apk", "x86_64/foo.apk", true},
		{"**/*.apk", "foo.apk", true},
		{"**/*.apk", "x86_64/foo.txt", false},
		{"a/**/b", "a/b", true},
		{"a/**/b", "a/x/y/b", true},
		{"a/**/b", "a/x/y/b/c", false},
		{"foo/**", "foo/bar/baz", true},
		{"foo/**", "foo", false},
		{"x?z", "xyz", true},
		{"x?z", "xyyz", false},
		{"x?z", "x/z", false},
		{"a.b", "a.b", true},
		{"a.b", "axb", false},
	}
	for _, tc := range cases {
		re := globToRegex(tc.glob)
		if got := re.MatchString(tc.path); got != tc.want {
			t.Errorf("globToRegex(%q).Match(%q) = %v, хочу %v", tc.glob, tc.path, got, tc.want)
		}
	}
}

func TestEnumerateApkSingleArch(t *testing.T) {
	a := newTestAdapter(t)
	indexText := mustReadTestdata(t, "APKINDEX.golden")
	indexTarGz := newTarGz(t, tarEntries{
		"APKINDEX": indexText,
	})
	meta := fakeMeta{files: map[string][]byte{
		"/apk/alpine/x86_64/APKINDEX.tar.gz": indexTarGz,
	}}
	got, err := a.Enumerate(context.Background(), domain.Remote{
		ID: 1, Name: "alpine", Ecosystem: Name, BaseURL: "https://dl-cdn.alpinelinux.org/alpine",
		Mode: domain.ModeMirror, Enabled: true, Include: []string{"x86_64"},
	}, meta)
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	want := []string{
		"/x86_64/apk-example-1.0-r0.apk",
		"/x86_64/second-pkg-2.0-r1.apk",
	}
	if len(got) != len(want) {
		t.Fatalf("Enumerate = %+v (len %d), хочу %d", got, len(got), len(want))
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("Enumerate[%d] = %q, хочу %q", i, got[i], w)
		}
	}
}

func TestEnumerateApkMultipleArchs(t *testing.T) {
	a := newTestAdapter(t)
	indexText := mustReadTestdata(t, "APKINDEX.golden")
	indexTarGz := newTarGz(t, tarEntries{
		"APKINDEX": indexText,
	})
	meta := fakeMeta{files: map[string][]byte{
		"/apk/alpine/x86_64/APKINDEX.tar.gz":  indexTarGz,
		"/apk/alpine/aarch64/APKINDEX.tar.gz": indexTarGz,
	}}
	got, err := a.Enumerate(context.Background(), domain.Remote{
		ID: 1, Name: "alpine", Ecosystem: Name, Include: []string{"x86_64", "aarch64"},
	}, meta)
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	// оба arch дают одни и те же пути; дедуп по seen — 2 уникальных
	if len(got) != 2 {
		t.Fatalf("Enumerate = %+v (len %d), хочу 2 уникальных (дедуп)", got, len(got))
	}
}

func TestEnumerateApkFiltersEmptyFilepath(t *testing.T) {
	// записи без F: (пустой FilePath) — Enumerate отфильтровывает.
	a := newTestAdapter(t)
	indexText := []byte("P:orphan\nV:1.0\n\nP:good\nF:good-1.0.apk\n\n")
	indexTarGz := newTarGz(t, tarEntries{
		"APKINDEX": indexText,
	})
	meta := fakeMeta{files: map[string][]byte{
		"/apk/alpine/x86_64/APKINDEX.tar.gz": indexTarGz,
	}}
	got, err := a.Enumerate(context.Background(), domain.Remote{
		ID: 1, Name: "alpine", Ecosystem: Name, Include: []string{"x86_64"},
	}, meta)
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if len(got) != 1 || got[0] != "/good-1.0.apk" {
		t.Fatalf("Enumerate = %+v, хочу только /good-1.0.apk", got)
	}
}

func TestEnumerateApkErrors(t *testing.T) {
	a := newTestAdapter(t)
	t.Run("пустой Include — ValidationError", func(t *testing.T) {
		_, err := a.Enumerate(context.Background(), domain.Remote{
			Name: "alpine", Ecosystem: Name, Include: nil,
		}, fakeMeta{})
		var ve *domain.ValidationError
		if !errors.As(err, &ve) {
			t.Fatalf("ошибка = %v, хочу *ValidationError", err)
		}
	})
	t.Run("APKINDEX отсутствует — NotFound", func(t *testing.T) {
		_, err := a.Enumerate(context.Background(), domain.Remote{
			Name: "alpine", Ecosystem: Name, Include: []string{"x86_64"},
		}, fakeMeta{})
		var nf *domain.NotFoundError
		if !errors.As(err, &nf) {
			t.Fatalf("ошибка = %v, хочу *NotFoundError", err)
		}
	})
	t.Run("nil MetaFetcher — ошибка", func(t *testing.T) {
		_, err := a.Enumerate(context.Background(), domain.Remote{
			Name: "alpine", Ecosystem: Name, Include: []string{"x86_64"},
		}, nil)
		if err == nil {
			t.Fatal("nil MetaFetcher должен ошибаться")
		}
	})
}
