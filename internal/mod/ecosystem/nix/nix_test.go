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

package nix

import (
	"context"
	"errors"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/testutil"
)

// hash32 — валидный 32-символьный nix-base32 хеш store path для
// тестов (алфавит nix без e/o/t/u — как у реального nix).
const hash32 = "x0vm1mkfnqrq3hxjcp2wsz5l8h4cgd9y"

// hash32hex — 32 hex-символа с 'e': для nix-классификации НЕ валиден
// (реальные nix-хеши — nix-base32); такой путь падает в conservative.
const hash32hex = "0123456789abcdef0123456789abcdef"

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
	if got := newTestAdapter(t).Name(); got != "nix" {
		t.Errorf("Name() = %q, хочу nix", got)
	}
}

func TestURLPrefix(t *testing.T) {
	if got := newTestAdapter(t).URLPrefix(); got != "nix" {
		t.Errorf("URLPrefix() = %q, хочу nix", got)
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
		// Immutable: nar-архивы (content-addressed по 32 nix-base32).
		{"nar/" + hash32 + ".nar.xz", domain.KindImmutable, 0},
		{"nar/" + hash32 + ".nar", domain.KindImmutable, 0},
		// Mutable{TTL 1h}: narinfo (метаданные пути, byte-exact).
		{hash32 + ".narinfo", domain.KindMutable, mutableNarinfoTTL},
		// Mutable{TTL 1h}: nix-cache-info.
		{"nix-cache-info", domain.KindMutable, mutableCacheInfoTTL},
		// Immutable: логи сборки (адресованы хешем store path).
		{"log/" + hash32 + ".drv", domain.KindImmutable, 0},
		{"log/" + hash32 + ".narinfo", domain.KindImmutable, 0},
		// Unknown → conservative Mutable{TTL 1m}.
		{"some/random/path.dat", domain.KindMutable, mutableUnknownTTL},
		{"nar/not-a-hash.nar.xz", domain.KindMutable, mutableUnknownTTL},
		// 31-символьный «хеш» — не 32: conservative.
		{hash32[:31] + ".narinfo", domain.KindMutable, mutableUnknownTTL},
		// hex-хеш с 'e' — не nix-base32 (у реального nix таких нет):
		// narinfo и nar с ним не попадают в nar/narinfo-ветки —
		// conservative mutable{TTL 1m} (сессия 33).
		{hash32hex + ".narinfo", domain.KindMutable, mutableUnknownTTL},
		{"nar/" + hash32hex + ".nar.xz", domain.KindMutable, mutableUnknownTTL},
		{"nar/" + hash32hex + ".nar", domain.KindMutable, mutableUnknownTTL},
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

func TestClassifyStripsLeadingSlash(t *testing.T) {
	a := newTestAdapter(t)
	got, err := a.Classify("/nar/" + hash32 + ".nar.xz")
	if err != nil {
		t.Fatalf("Classify с ведущим «/»: %v", err)
	}
	if got.Kind != domain.KindImmutable {
		t.Errorf("Classify c ведущим «/»).Kind = %q, хочу immutable", got.Kind)
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
		"nar/" + hash32 + ".nar.xz",
		"nar/" + hash32 + ".nar",
		hash32 + ".narinfo",
		"nix-cache-info",
		"log/" + hash32 + ".drv",
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
		ID: 7, Name: "cache", Ecosystem: "nix",
		BaseURL: "https://cache.nixos.org", Enabled: true,
	})
	target, ok := a.Resolve("/nix/cache/nar/" + hash32 + ".nar.xz")
	if !ok {
		t.Fatal("Resolve существующего remote = false")
	}
	wantURL := "https://cache.nixos.org/nar/" + hash32 + ".nar.xz"
	if target.UpstreamURL != wantURL {
		t.Errorf("UpstreamURL = %q, хочу %q", target.UpstreamURL, wantURL)
	}
	if target.UpstreamPath != "/nar/"+hash32+".nar.xz" {
		t.Errorf("UpstreamPath = %q", target.UpstreamPath)
	}
	if target.StorageKey != "cache/nix/7/nar/"+hash32+".nar.xz" {
		t.Errorf("StorageKey = %q", target.StorageKey)
	}
}

func TestResolveRootPath(t *testing.T) {
	a := newResolveAdapter(t, domain.Remote{
		ID: 3, Name: "cache", BaseURL: "https://cache.nixos.org", Enabled: true,
	})
	target, ok := a.Resolve("/nix/cache")
	if !ok {
		t.Fatal("Resolve корня remote = false")
	}
	if target.UpstreamPath != "/" {
		t.Errorf("UpstreamPath = %q, хочу «/»", target.UpstreamPath)
	}
}

func TestResolveUnknownRemote(t *testing.T) {
	a := newResolveAdapter(t, domain.Remote{ID: 1, Name: "cache", BaseURL: "https://x", Enabled: true})
	if _, ok := a.Resolve("/nix/other/" + hash32 + ".narinfo"); ok {
		t.Error("Resolve неизвестного remote должен дать false")
	}
}

func TestResolveDisabledRemote(t *testing.T) {
	a := newResolveAdapter(t, domain.Remote{ID: 1, Name: "cache", BaseURL: "https://x", Enabled: false})
	if _, ok := a.Resolve("/nix/cache/" + hash32 + ".narinfo"); ok {
		t.Error("Resolve выключенного remote должен дать false")
	}
}

func TestResolveWrongEcosystemPrefix(t *testing.T) {
	a := newResolveAdapter(t, domain.Remote{ID: 1, Name: "cache", BaseURL: "https://x", Enabled: true})
	for _, path := range []string{
		"/apt/cache/" + hash32 + ".narinfo",
		"/apk/cache/nar/" + hash32 + ".nar.xz",
	} {
		if _, ok := a.Resolve(path); ok {
			t.Errorf("Resolve(%q) с чужим префиксом должен дать false", path)
		}
	}
}

func TestResolveTraversalRemoteName(t *testing.T) {
	a := newResolveAdapter(t, domain.Remote{ID: 1, Name: "cache", BaseURL: "https://x", Enabled: true})
	for _, path := range []string{
		"/nix/../etc/passwd",
		"/nix/./etc/passwd",
		"/nix//etc/passwd",
		"/nix//",
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
	if _, ok := a.Resolve("/nix/cache/" + hash32 + ".narinfo"); ok {
		t.Fatal("до создания remote Resolve не должен находить")
	}
	if _, err := store.CreateRemote(context.Background(), domain.Remote{
		Name: "cache", Ecosystem: "nix", BaseURL: "https://cache.nixos.org", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Resolve("/nix/cache/" + hash32 + ".narinfo"); ok {
		t.Fatal("кеш remotes не должен инвалидироваться до TTL")
	}
	clock.Advance(remoteCacheTTL)
	target, ok := a.Resolve("/nix/cache/nar/" + hash32 + ".nar.xz")
	if !ok {
		t.Fatal("после TTL кеш remotes не обновился")
	}
	if target.UpstreamURL != "https://cache.nixos.org/nar/"+hash32+".nar.xz" {
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
		{ID: 5, Name: "cache", Ecosystem: "nix", BaseURL: "https://cache.nixos.org", Enabled: true},
	}}}
	clock := testutil.NewManualClock(time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC))
	a, err := New(store, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Resolve("/nix/cache/" + hash32 + ".narinfo"); !ok {
		t.Fatal("первый Resolve не нашёл remote")
	}
	store.fail = true
	clock.Advance(remoteCacheTTL)
	if _, ok := a.Resolve("/nix/cache/" + hash32 + ".narinfo"); !ok {
		t.Fatal("reload упал, но stale-копия из кеша не отдана")
	}
}

func TestEnumerateUnsupported(t *testing.T) {
	a := newTestAdapter(t)
	_, err := a.Enumerate(context.Background(), domain.Remote{
		Name: "cache", Ecosystem: Name, BaseURL: "https://cache.nixos.org",
	}, nil)
	var uns *domain.UnsupportedError
	if !errors.As(err, &uns) {
		t.Fatalf("Enumerate = %v, хочу *UnsupportedError", err)
	}
}

func TestGlobToRegex(t *testing.T) {
	cases := []struct {
		glob string
		path string
		want bool
	}{
		{"log/**", "log/foo.drv", true},
		{"log/**", "log/a/b/c", true},
		{"log/**", "log", false},
		{"log/**", "nolog/foo", false},
		{"nix-cache-info", "nix-cache-info", true},
		{"nix-cache-info", "nix-cache-infox", false},
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
