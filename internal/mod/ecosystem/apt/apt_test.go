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

package apt

import (
	"context"
	"errors"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/testutil"
)

// newTestAdapter — адаптер с живыми часами и RemoteStore без записей;
// Classify не зависит от remotes, поэтому пустой фейк достаточен.
func newTestAdapter(t *testing.T) *Adapter {
	t.Helper()
	a, err := New(testutil.NewFakeRemoteStore(), testutil.NewManualClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)))
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
	if got := newTestAdapter(t).Name(); got != "apt" {
		t.Errorf("Name() = %q, хочу apt", got)
	}
}

// classifyCase — строка таблицы классификации: путь upstream + ожидаемый
// класс (Kind/TTL). Источник правды для таблицы — сессия 07; дополнения
// к экосистеме расширяют этот список.
type classifyCase struct {
	path string
	kind domain.Kind
	ttl  time.Duration // 0 — не проверять (immutable или unknown)
}

func TestClassifyTable(t *testing.T) {
	a := newTestAdapter(t)
	cases := []classifyCase{
		// Immutable: пакеты и source-тарболы под pool/
		{"pool/main/a/app/app_1.0_amd64.deb", domain.KindImmutable, 0},
		{"pool/main/a/app/app_1.0_all.udeb", domain.KindImmutable, 0},
		{"pool/main/a/app/app_1.0.dsc", domain.KindImmutable, 0},
		{"pool/main/a/app/app_1.0.orig.tar.gz", domain.KindImmutable, 0},
		{"pool/main/a/app/app_1.0.debian.tar.xz", domain.KindImmutable, 0},
		{"pool/main/a/app/app_1.0.tar.zst", domain.KindImmutable, 0},
		{"pool/main/a/app/app_1.0.tar.gz", domain.KindImmutable, 0},
		{"pool/main/a/app/app_1.0.tar.xz", domain.KindImmutable, 0},
		{"pool/main/a/app/app_1.0.tar.lzma", domain.KindImmutable, 0},
		{"pool/contrib/b/pkg/pkg_2.0.ddeb", domain.KindImmutable, 0},
		// by-hash — content-addressed индексы
		{"dists/stable/main/binary-amd64/by-hash/SHA256/abc123", domain.KindImmutable, 0},
		{"dists/stable/main/binary-amd64/by-hash/SHA512/def", domain.KindImmutable, 0},
		{"dists/stable/main/binary-amd64/by-hash/MD5Sum/hash", domain.KindImmutable, 0},
		// Mutable{TTL 5m}: индексы и подписи dists/
		{"dists/stable/Release", domain.KindMutable, mutableIndexTTL},
		{"dists/stable/Release.gpg", domain.KindMutable, mutableIndexTTL},
		{"dists/stable/InRelease", domain.KindMutable, mutableIndexTTL},
		{"dists/stable/main/binary-amd64/Packages", domain.KindMutable, mutableIndexTTL},
		{"dists/stable/main/binary-amd64/Packages.gz", domain.KindMutable, mutableIndexTTL},
		{"dists/stable/main/binary-amd64/Packages.xz", domain.KindMutable, mutableIndexTTL},
		{"dists/stable/main/source/Sources", domain.KindMutable, mutableIndexTTL},
		{"dists/stable/main/source/Sources.xz", domain.KindMutable, mutableIndexTTL},
		{"dists/stable/main/Contents-amd64.gz", domain.KindMutable, mutableIndexTTL},
		{"dists/stable/main/i18n/Translation-en", domain.KindMutable, mutableIndexTTL},
		{"dists/stable/main/dep11/Components-amd64.yml", domain.KindMutable, mutableIndexTTL},
		{"dists/stable/main/cnf/Commands-amd64", domain.KindMutable, mutableIndexTTL},
		// Unknown → conservative Mutable{TTL 1m} (безопасный дефолт)
		{"some/random/path.dat", domain.KindMutable, mutableUnknownTTL},
		{"dists/stable/main/whatever", domain.KindMutable, mutableUnknownTTL},
		{"pool/main/a/app/unknown.bin", domain.KindMutable, mutableUnknownTTL},
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

// TestClassifyRulesCovered проверяет, что каждое правило таблицы
// имеет хотя бы один тест-кейс выше — иначе правило мертво (никогда
// не сработает из-за порядка или опечатки в glob).
func TestClassifyRulesCovered(t *testing.T) {
	a := newTestAdapter(t)
	covered := make(map[string]bool, len(a.rules))
	for _, r := range a.rules {
		covered[r.name] = false
	}
	for _, tc := range []string{
		"pool/main/a/app/app_1.0_amd64.deb",
		"pool/main/a/app/app_1.0_all.udeb",
		"pool/main/a/app/app_1.0.dsc",
		"pool/main/a/app/app_1.0.orig.tar.gz",
		"pool/main/a/app/app_1.0.debian.tar.xz",
		"pool/main/a/app/app_1.0.tar.zst",
		"pool/main/a/app/app_1.0.tar.gz",
		"pool/main/a/app/app_1.0.tar.xz",
		"pool/main/a/app/app_1.0.tar.lzma",
		"pool/contrib/b/pkg/pkg_2.0.ddeb",
		"dists/stable/main/binary-amd64/by-hash/SHA256/abc123",
		"dists/stable/main/binary-amd64/by-hash/SHA512/def",
		"dists/stable/main/binary-amd64/by-hash/MD5Sum/hash",
		"dists/stable/Release",
		"dists/stable/Release.gpg",
		"dists/stable/InRelease",
		"dists/stable/main/binary-amd64/Packages",
		"dists/stable/main/binary-amd64/Packages.gz",
		"dists/stable/main/source/Sources",
		"dists/stable/main/Contents-amd64.gz",
		"dists/stable/main/i18n/Translation-en",
		"dists/stable/main/dep11/Components-amd64.yml",
		"dists/stable/main/cnf/Commands-amd64",
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
	a, err := New(fakeRemotes{rs: rs}, testutil.NewManualClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestResolveKnownRemote(t *testing.T) {
	a := newResolveAdapter(t, domain.Remote{
		ID: 7, Name: "debian", Ecosystem: "apt",
		BaseURL: "https://deb.debian.org/debian", Enabled: true,
	})
	target, ok := a.Resolve("/apt/debian/pool/main/a/app/app_1.0_amd64.deb")
	if !ok {
		t.Fatal("Resolve существующего remote = false")
	}
	wantURL := "https://deb.debian.org/debian/pool/main/a/app/app_1.0_amd64.deb"
	if target.UpstreamURL != wantURL {
		t.Errorf("UpstreamURL = %q, хочу %q", target.UpstreamURL, wantURL)
	}
	if target.UpstreamPath != "/pool/main/a/app/app_1.0_amd64.deb" {
		t.Errorf("UpstreamPath = %q", target.UpstreamPath)
	}
	if target.StorageKey != "cache/apt/7/pool/main/a/app/app_1.0_amd64.deb" {
		t.Errorf("StorageKey = %q", target.StorageKey)
	}
}

func TestResolveUppercaseStorageKeyLowercased(t *testing.T) {
	// StorageKey лоуэркейсит путь (доменный ключ — только [a-z0-9/._-]),
	// но UpstreamURL/Path сохраняют регистр (byte-exact к upstream).
	a := newResolveAdapter(t, domain.Remote{
		ID: 1, Name: "ubuntu", BaseURL: "https://archive.ubuntu.com/ubuntu", Enabled: true,
	})
	target, ok := a.Resolve("/apt/ubuntu/dists/stable/main/binary-amd64/Packages.gz")
	if !ok {
		t.Fatal("Resolve = false")
	}
	if target.UpstreamPath != "/dists/stable/main/binary-amd64/Packages.gz" {
		t.Errorf("UpstreamPath сохранил не оригинальный регистр: %q", target.UpstreamPath)
	}
	if target.StorageKey != "cache/apt/1/dists/stable/main/binary-amd64/packages.gz" {
		t.Errorf("StorageKey не лоуэркейшен: %q", target.StorageKey)
	}
}

func TestResolveRootPath(t *testing.T) {
	// /apt/<remote> без остатка → upstreamPath «/» (корень репозитория)
	a := newResolveAdapter(t, domain.Remote{
		ID: 3, Name: "mint", BaseURL: "https://packages.linuxmint.com/dists", Enabled: true,
	})
	target, ok := a.Resolve("/apt/mint")
	if !ok {
		t.Fatal("Resolve корня remote = false")
	}
	if target.UpstreamPath != "/" {
		t.Errorf("UpstreamPath = %q, хочу «/»", target.UpstreamPath)
	}
	if target.UpstreamURL != "https://packages.linuxmint.com/dists/" {
		t.Errorf("UpstreamURL = %q (BaseURL без trailing / + «/»)", target.UpstreamURL)
	}
}

func TestResolveUnknownRemote(t *testing.T) {
	a := newResolveAdapter(t, domain.Remote{ID: 1, Name: "debian", BaseURL: "https://x", Enabled: true})
	if _, ok := a.Resolve("/apt/fedoris/main/Packages"); ok {
		t.Error("Resolve неизвестного remote должен дать false")
	}
}

func TestResolveDisabledRemote(t *testing.T) {
	a := newResolveAdapter(t, domain.Remote{ID: 1, Name: "debian", BaseURL: "https://x", Enabled: false})
	if _, ok := a.Resolve("/apt/debian/Packages"); ok {
		t.Error("Resolve выключенного remote должен дать false")
	}
}

func TestResolveWrongEcosystemPrefix(t *testing.T) {
	a := newResolveAdapter(t, domain.Remote{ID: 1, Name: "debian", BaseURL: "https://x", Enabled: true})
	if _, ok := a.Resolve("/dnf/debian/Packages"); ok {
		t.Error("Resolve с чужим префиксом экосистемы должен дать false")
	}
}

func TestResolveTraversalRemoteName(t *testing.T) {
	// path-traversal в remote-name: «..» / «.» / слэш не должны
	// пробраться в StorageKey или upstream-путь.
	a := newResolveAdapter(t, domain.Remote{ID: 1, Name: "debian", BaseURL: "https://x", Enabled: true})
	for _, path := range []string{
		"/apt/../etc/passwd",
		"/apt/./etc/passwd",
		"/apt//etc/passwd",
		"/apt//",
	} {
		if _, ok := a.Resolve(path); ok {
			t.Errorf("Resolve(%q) должен отвергнуть traversal, но дал ok", path)
		}
	}
}

func TestResolvePicksUpNewRemote(t *testing.T) {
	// кеш remotes инвалидится по TTL: добавленный remote подхватывается
	// без перезапуска процесса
	store := testutil.NewFakeRemoteStore()
	clock := testutil.NewManualClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC))
	a, err := New(store, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Resolve("/apt/debian/Packages"); ok {
		t.Fatal("до создания remote Resolve не должен находить")
	}
	if _, err := store.CreateRemote(context.Background(), domain.Remote{
		Name: "debian", Ecosystem: "apt", BaseURL: "https://deb.debian.org/debian", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	// кеш ещё свежий (0с < 30с) — remote не виден
	if _, ok := a.Resolve("/apt/debian/Packages"); ok {
		t.Fatal("кеш remotes не должен инвалидироваться до TTL")
	}
	clock.Advance(remoteCacheTTL)
	target, ok := a.Resolve("/apt/debian/dists/stable/Release")
	if !ok {
		t.Fatal("после TTL кеш remotes не обновился")
	}
	if target.UpstreamURL != "https://deb.debian.org/debian/dists/stable/Release" {
		t.Errorf("UpstreamURL = %q", target.UpstreamURL)
	}
}

// errorRemoteStore — RemoteStore, чей Remotes() падает по флагу:
// имитирует БД, которая «лёгла» после прогрева кеша.
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
	// инвариант: reload упал, но в кеше ещё есть remote — отдаём
	// протухшую по TTL копию, не пустую ошибку. Снижает связность
	// с БД: кратковременный сбой каталога не валит прокси.
	store := &errorRemoteStore{fakeRemotes: fakeRemotes{rs: []domain.Remote{
		{ID: 5, Name: "debian", Ecosystem: "apt", BaseURL: "https://deb.debian.org/debian", Enabled: true},
	}}}
	clock := testutil.NewManualClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC))
	a, err := New(store, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Resolve("/apt/debian/Packages"); !ok {
		t.Fatal("первый Resolve не нашёл remote")
	}
	// БД «ложится» + TTL истёк — следующий Resolve пытается reload,
	// неудачно, и должен отдать stale-копию из кеша.
	store.fail = true
	clock.Advance(remoteCacheTTL)
	if _, ok := a.Resolve("/apt/debian/Packages"); !ok {
		t.Fatal("reload упал, но stale-копия из кеша не отдана")
	}
	if store.calls < 2 {
		t.Errorf("reload должен был вызваться повторно после TTL; calls=%d", store.calls)
	}
}

func TestGlobToRegex(t *testing.T) {
	// прямой прогон веток globToRegex: **/, ** (без /), *, ?, literal.
	cases := []struct {
		glob string
		path string
		want bool
	}{
		{"**/*.deb", "pool/a/x.deb", true},
		{"**/*.deb", "x.deb", true},         // **/ = опциональный префикс
		{"**/*.deb", "pool/a/x.txt", false}, // суффикс не тот
		{"a/**/b", "a/b", true},             // **/ = ноль сегментов
		{"a/**/b", "a/x/y/b", true},         // **/ = много сегментов
		{"a/**/b", "a/x/y/b/c", false},      // хвост после b
		{"foo/**", "foo/bar/baz", true},     // ** без / — любой хвост
		{"foo/**", "foo", false},            // без хвоста после /
		{"x?z", "xyz", true},                // ? = один байт без /
		{"x?z", "xyyz", false},              // ? = ровно один
		{"x?z", "x/z", false},               // ? не матчит /
		{"a.b", "a.b", true},                // literal с эскейпом точки
		{"a.b", "axb", false},               // точка — literal, не «любой»
	}
	for _, tc := range cases {
		re := globToRegex(tc.glob)
		if got := re.MatchString(tc.path); got != tc.want {
			t.Errorf("globToRegex(%q).Match(%q) = %v, хочу %v", tc.glob, tc.path, got, tc.want)
		}
	}
}
