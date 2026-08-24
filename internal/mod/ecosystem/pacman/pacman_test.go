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

package pacman

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
	if got := newTestAdapter(t).Name(); got != "pacman" {
		t.Errorf("Name() = %q, хочу pacman", got)
	}
}

func TestURLPrefix(t *testing.T) {
	if got := newTestAdapter(t).URLPrefix(); got != "pacman" {
		t.Errorf("URLPrefix() = %q, хочу pacman", got)
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
		// Immutable: пакеты .pkg.tar.{zst,xz,gz} и их подписи.
		{"core/os/x86_64/foo-1.0-1-x86_64.pkg.tar.zst", domain.KindImmutable, 0},
		{"foo-1.0-1-x86_64.pkg.tar.xz", domain.KindImmutable, 0},
		{"foo-1.0-1-x86_64.pkg.tar.gz", domain.KindImmutable, 0},
		{"core/os/x86_64/foo-1.0-1-x86_64.pkg.tar.zst.sig", domain.KindImmutable, 0},
		{"foo-1.0-1-x86_64.pkg.tar.xz.sig", domain.KindImmutable, 0},
		{"foo-1.0-1-x86_64.pkg.tar.gz.sig", domain.KindImmutable, 0},
		// Mutable{TTL 5m}: репозитарные базы и их подписи.
		{"core/os/x86_64/core.db", domain.KindMutable, mutableDBTTL},
		{"core/os/x86_64/core.files", domain.KindMutable, mutableDBTTL},
		{"core/os/x86_64/core.db.sig", domain.KindMutable, mutableDBTTL},
		{"core/os/x86_64/core.files.sig", domain.KindMutable, mutableDBTTL},
		{"extra/os/x86_64/extra.db", domain.KindMutable, mutableDBTTL},
		// legacy .db.tar.* / .files.tar.*
		{"core/os/x86_64/core.db.tar.gz", domain.KindMutable, mutableDBTTL},
		{"core/os/x86_64/core.db.tar.xz", domain.KindMutable, mutableDBTTL},
		{"core/os/x86_64/core.files.tar.gz", domain.KindMutable, mutableDBTTL},
		{"core/os/x86_64/core.files.tar.xz", domain.KindMutable, mutableDBTTL},
		// Mutable{TTL 1h}: ключи.
		{"keys/alpine@example.com-abc123.rsa.pub", domain.KindMutable, mutableKeysTTL},
		// Unknown → conservative Mutable{TTL 1m}.
		{"some/random/path.dat", domain.KindMutable, mutableUnknownTTL},
		{"core/os/x86_64/unknown.bin", domain.KindMutable, mutableUnknownTTL},
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
		"core/os/x86_64/foo-1.0-1-x86_64.pkg.tar.zst",
		"foo-1.0-1-x86_64.pkg.tar.xz",
		"foo-1.0-1-x86_64.pkg.tar.gz",
		"core/os/x86_64/foo-1.0-1-x86_64.pkg.tar.zst.sig",
		"foo-1.0-1-x86_64.pkg.tar.xz.sig",
		"foo-1.0-1-x86_64.pkg.tar.gz.sig",
		"core/os/x86_64/core.db",
		"core/os/x86_64/core.files",
		"core/os/x86_64/core.db.sig",
		"core/os/x86_64/core.files.sig",
		"core/os/x86_64/core.db.tar.gz",
		"core/os/x86_64/core.files.tar.xz",
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
		ID: 7, Name: "arch", Ecosystem: "pacman",
		BaseURL: "https://mirror.example.com/archlinux", Enabled: true,
	})
	target, ok := a.Resolve("/pacman/arch/core/os/x86_64/foo-1.0-1-x86_64.pkg.tar.zst")
	if !ok {
		t.Fatal("Resolve существующего remote = false")
	}
	wantURL := "https://mirror.example.com/archlinux/core/os/x86_64/foo-1.0-1-x86_64.pkg.tar.zst"
	if target.UpstreamURL != wantURL {
		t.Errorf("UpstreamURL = %q, хочу %q", target.UpstreamURL, wantURL)
	}
	if target.UpstreamPath != "/core/os/x86_64/foo-1.0-1-x86_64.pkg.tar.zst" {
		t.Errorf("UpstreamPath = %q", target.UpstreamPath)
	}
	if target.StorageKey != "cache/pacman/7/core/os/x86_64/foo-1.0-1-x86_64.pkg.tar.zst" {
		t.Errorf("StorageKey = %q", target.StorageKey)
	}
}

func TestResolveRootPath(t *testing.T) {
	a := newResolveAdapter(t, domain.Remote{
		ID: 3, Name: "arch", BaseURL: "https://mirror.example.com/archlinux", Enabled: true,
	})
	target, ok := a.Resolve("/pacman/arch")
	if !ok {
		t.Fatal("Resolve корня remote = false")
	}
	if target.UpstreamPath != "/" {
		t.Errorf("UpstreamPath = %q, хочу «/»", target.UpstreamPath)
	}
}

func TestResolveUnknownRemote(t *testing.T) {
	a := newResolveAdapter(t, domain.Remote{ID: 1, Name: "arch", BaseURL: "https://x", Enabled: true})
	if _, ok := a.Resolve("/pacman/fedoris/core/os/x86_64/core.db"); ok {
		t.Error("Resolve неизвестного remote должен дать false")
	}
}

func TestResolveDisabledRemote(t *testing.T) {
	a := newResolveAdapter(t, domain.Remote{ID: 1, Name: "arch", BaseURL: "https://x", Enabled: false})
	if _, ok := a.Resolve("/pacman/arch/core.db"); ok {
		t.Error("Resolve выключенного remote должен дать false")
	}
}

func TestResolveWrongEcosystemPrefix(t *testing.T) {
	a := newResolveAdapter(t, domain.Remote{ID: 1, Name: "arch", BaseURL: "https://x", Enabled: true})
	for _, path := range []string{
		"/apt/arch/core.db",
		"/rpm/arch/core.db",
	} {
		if _, ok := a.Resolve(path); ok {
			t.Errorf("Resolve(%q) с чужим префиксом должен дать false", path)
		}
	}
}

func TestResolveTraversalRemoteName(t *testing.T) {
	a := newResolveAdapter(t, domain.Remote{ID: 1, Name: "arch", BaseURL: "https://x", Enabled: true})
	for _, path := range []string{
		"/pacman/../etc/passwd",
		"/pacman/./etc/passwd",
		"/pacman//etc/passwd",
		"/pacman//",
	} {
		if _, ok := a.Resolve(path); ok {
			t.Errorf("Resolve(%q) должен отвергнуть traversal, но дал ok", path)
		}
	}
}

func TestResolvePicksUpNewRemote(t *testing.T) {
	store := testutil.NewFakeRemoteStore()
	clock := testutil.NewManualClock(time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC))
	a, err := New(store, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Resolve("/pacman/arch/core.db"); ok {
		t.Fatal("до создания remote Resolve не должен находить")
	}
	if _, err := store.CreateRemote(context.Background(), domain.Remote{
		Name: "arch", Ecosystem: "pacman", BaseURL: "https://mirror.example.com/archlinux", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Resolve("/pacman/arch/core.db"); ok {
		t.Fatal("кеш remotes не должен инвалидироваться до TTL")
	}
	clock.Advance(remoteCacheTTL)
	target, ok := a.Resolve("/pacman/arch/core/os/x86_64/core.db")
	if !ok {
		t.Fatal("после TTL кеш remotes не обновился")
	}
	if target.UpstreamURL != "https://mirror.example.com/archlinux/core/os/x86_64/core.db" {
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
		{ID: 5, Name: "arch", Ecosystem: "pacman", BaseURL: "https://mirror.example.com/archlinux", Enabled: true},
	}}}
	clock := testutil.NewManualClock(time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC))
	a, err := New(store, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Resolve("/pacman/arch/core.db"); !ok {
		t.Fatal("первый Resolve не нашёл remote")
	}
	store.fail = true
	clock.Advance(remoteCacheTTL)
	if _, ok := a.Resolve("/pacman/arch/core.db"); !ok {
		t.Fatal("reload упал, но stale-копия из кеша не отдана")
	}
}

func TestParsePacmanInclude(t *testing.T) {
	cases := []struct {
		name    string
		include []string
		wantN   int
		wantErr bool
	}{
		{"один repo", []string{"core/x86_64"}, 1, false},
		{"несколько", []string{"core/x86_64", "extra/x86_64"}, 2, false},
		{"пусто", nil, 0, true},
		{"без arch", []string{"core"}, 0, true},
		{"пустой элемент", []string{""}, 0, true},
		{"два слэша", []string{"core/x86_64/extra"}, 1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePacmanInclude(tc.include)
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

func TestParsePacmanIncludeRepoArch(t *testing.T) {
	repos, err := parsePacmanInclude([]string{"core/x86_64", "extra/aarch64"})
	if err != nil {
		t.Fatal(err)
	}
	if repos[0].repo != "core" || repos[0].arch != "x86_64" {
		t.Errorf("repos[0] = %+v", repos[0])
	}
	if repos[1].repo != "extra" || repos[1].arch != "aarch64" {
		t.Errorf("repos[1] = %+v", repos[1])
	}
}

func TestEnumeratePacmanDBs(t *testing.T) {
	a := newTestAdapter(t)
	desc1 := mustReadTestdata(t, "desc-1.golden")
	desc2 := mustReadTestdata(t, "desc-2.golden")
	// core.db содержит оба пакета; extra.db — только второй.
	coreDB := newTarZst(t, tarEntries{
		"pacman-example-1.0-1-x86_64/desc": desc1,
		"second-pkg-2.0-1-any/desc":        desc2,
	})
	extraDB := newTarZst(t, tarEntries{
		"second-pkg-2.0-1-any/desc": desc2,
	})
	meta := fakeMeta{files: map[string][]byte{
		"/pacman/arch/core/os/x86_64/core.db":   coreDB,
		"/pacman/arch/extra/os/x86_64/extra.db": extraDB,
	}}
	got, err := a.Enumerate(context.Background(), domain.Remote{
		ID: 1, Name: "arch", Ecosystem: Name, BaseURL: "https://mirror.example.com/archlinux",
		Mode: domain.ModeMirror, Enabled: true, Include: []string{"core/x86_64", "extra/x86_64"},
	}, meta)
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	want := map[string]bool{
		"/core/os/x86_64/pacman-example-1.0-1-x86_64.pkg.tar.zst": true,
		"/core/os/x86_64/second-pkg-2.0-1-any.pkg.tar.xz":         true,
		"/extra/os/x86_64/second-pkg-2.0-1-any.pkg.tar.xz":        true,
	}
	if len(got) != len(want) {
		t.Fatalf("Enumerate = %+v (len %d), хочу %d уникальных", got, len(got), len(want))
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("неожиданный путь %q в %+v", p, got)
		}
	}
}

func TestEnumeratePacmanSingleRepo(t *testing.T) {
	a := newTestAdapter(t)
	desc1 := mustReadTestdata(t, "desc-1.golden")
	coreDB := newTarZst(t, tarEntries{
		"pacman-example-1.0-1-x86_64/desc": desc1,
	})
	meta := fakeMeta{files: map[string][]byte{
		"/pacman/arch/core/os/x86_64/core.db": coreDB,
	}}
	got, err := a.Enumerate(context.Background(), domain.Remote{
		ID: 1, Name: "arch", Ecosystem: Name, Include: []string{"core/x86_64"},
	}, meta)
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if len(got) != 1 || got[0] != "/core/os/x86_64/pacman-example-1.0-1-x86_64.pkg.tar.zst" {
		t.Fatalf("Enumerate = %+v, хочу один путь", got)
	}
}

func TestEnumeratePacmanErrors(t *testing.T) {
	a := newTestAdapter(t)
	t.Run("пустой Include — ValidationError", func(t *testing.T) {
		_, err := a.Enumerate(context.Background(), domain.Remote{
			Name: "arch", Ecosystem: Name, Include: nil,
		}, fakeMeta{})
		var ve *domain.ValidationError
		if !errors.As(err, &ve) {
			t.Fatalf("ошибка = %v, хочу *ValidationError", err)
		}
	})
	t.Run("db отсутствует — NotFound", func(t *testing.T) {
		_, err := a.Enumerate(context.Background(), domain.Remote{
			Name: "arch", Ecosystem: Name, Include: []string{"core/x86_64"},
		}, fakeMeta{})
		var nf *domain.NotFoundError
		if !errors.As(err, &nf) {
			t.Fatalf("ошибка = %v, хочу *NotFoundError", err)
		}
	})
	t.Run("nil MetaFetcher — ошибка", func(t *testing.T) {
		_, err := a.Enumerate(context.Background(), domain.Remote{
			Name: "arch", Ecosystem: Name, Include: []string{"core/x86_64"},
		}, nil)
		if err == nil {
			t.Fatal("nil MetaFetcher должен ошибаться")
		}
	})
}
