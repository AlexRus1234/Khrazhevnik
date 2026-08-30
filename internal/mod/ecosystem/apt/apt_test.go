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
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
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

func TestResolveUppercaseStorageKeyPreserved(t *testing.T) {
	// Регистр сохраняется во всех полях Target (сессия 19):
	// лоуэркейс StorageKey склеивал бы /pool/Foo.deb и /pool/foo.deb
	// в один ключ кеша — poisoning на case-чувствительном upstream.
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
	if target.StorageKey != "cache/apt/1/dists/stable/main/binary-amd64/Packages.gz" {
		t.Errorf("StorageKey потерял регистр: %q", target.StorageKey)
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

// fakeMeta — MetaFetcher, отдающий предзагруженные байты по пути.
// Тесты Enumerate не лезут в сеть: метаданные уже в map.
type fakeMeta struct {
	files map[string][]byte
}

func (m fakeMeta) Fetch(_ context.Context, ecosystemPath string) (io.ReadCloser, error) {
	b, ok := m.files[ecosystemPath]
	if !ok {
		return nil, &domain.NotFoundError{What: "upstream метаданные", Key: ecosystemPath}
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

func mustReadTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("чтение testdata/%s: %v", name, err)
	}
	return b
}

func newEnumerateAdapter(t *testing.T) *Adapter {
	t.Helper()
	a, err := New(testutil.NewFakeRemoteStore(), testutil.NewManualClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestEnumerateAptDistsAndComponents(t *testing.T) {
	a := newEnumerateAdapter(t)
	pkg := mustReadTestdata(t, "Packages.golden")
	meta := fakeMeta{files: map[string][]byte{
		"/apt/debian/dists/stable/Release":                    mustReadTestdata(t, "Release.golden"),
		"/apt/debian/dists/stable/main/binary-amd64/Packages": pkg,
		"/apt/debian/dists/stable/main/binary-arm64/Packages": pkg,
	}}
	// Include = ["stable"] → все компоненты из Release (main/contrib/non-free),
	// но Packages-файл есть только для main; contrib/non-free вернут NotFound —
	// Enumerate падает на первом отсутствующем. Поэтому проверяем включение
	// одной компоненты.
	t.Run("include stable/main отдаёт Filenames", func(t *testing.T) {
		got, err := a.Enumerate(context.Background(), domain.Remote{
			ID: 1, Name: "debian", Ecosystem: Name, BaseURL: "https://deb.debian.org/debian",
			Mode: domain.ModeMirror, Enabled: true, Include: []string{"stable/main"},
		}, meta)
		if err != nil {
			t.Fatalf("Enumerate: %v", err)
		}
		want := []string{
			"/pool/main/a/apt-example/apt-example_1.0-1_amd64.deb",
			"/pool/main/s/second/second_2.0_all.deb",
		}
		// оба arch-файла несут одни и те же Filenames; дедуп оставляет 2.
		if len(got) != len(want) {
			t.Fatalf("Enumerate = %+v (len %d), хочу %d уникальных", got, len(got), len(want))
		}
		gotSet := map[string]bool{}
		for _, p := range got {
			gotSet[p] = true
		}
		for _, w := range want {
			if !gotSet[w] {
				t.Errorf("отсутствует %q в %+v", w, got)
			}
		}
	})
	t.Run("include stable отсеивает чужие компоненты", func(t *testing.T) {
		// все компоненты Release, но Packages есть только для main
		// → Enumerate падает на contrib (нет Packages). Покажем, что
		// фильтр по компоненте ограничивает обход.
		_, err := a.Enumerate(context.Background(), domain.Remote{
			ID: 1, Name: "debian", Ecosystem: Name, Include: []string{"stable"},
		}, meta)
		if err == nil {
			t.Fatal("Enumerate по всем компонентам должен упасть на отсутствующих Packages")
		}
	})
}

func TestEnumerateAptGzFallback(t *testing.T) {
	// Packages отсутствует, но Packages.gz есть — Enumerate распаковывает.
	pkgGz := newGz(t, mustReadTestdata(t, "Packages.golden"))
	a := newEnumerateAdapter(t)
	meta := fakeMeta{files: map[string][]byte{
		"/apt/debian/dists/stable/Release":                       mustReadTestdata(t, "Release.golden"),
		"/apt/debian/dists/stable/main/binary-amd64/Packages.gz": pkgGz,
		"/apt/debian/dists/stable/main/binary-arm64/Packages.gz": pkgGz,
	}}
	got, err := a.Enumerate(context.Background(), domain.Remote{
		ID: 1, Name: "debian", Ecosystem: Name, Include: []string{"stable/main"},
	}, meta)
	if err != nil {
		t.Fatalf("Enumerate .gz fallback: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("Enumerate .gz = %+v, хочу 2 пути", got)
	}
}

// TestEnumerateAptGzZipBomb — аудит 2026-08-30: gzip-бомба вместо
// Packages.gz. Разжатый поток ~2 GiB обязан упереться в
// декомпресс-лимит 1 GiB и дать ErrDecompressTooLarge, а не съесть
// память процесса. Память не меряем — достаточно ошибки на пути
// Enumerate (раньше лимита не было вовсе). Члены бомбы — валидные
// stanza ~512 KiB (поле в пределах лимита парсера): непарсибельный
// контент упёрся бы в строковый лимит readLine (~1 MiB) раньше и
// путь 1 GiB не тестировался бы. Конкатенация gzip-членов —
// multistream, валидна по RFC 1952; вся бомба в сжатом виде ~2 МБ.
func TestEnumerateAptGzZipBomb(t *testing.T) {
	field := bytes.Repeat([]byte("x"), 512<<10) // 512 KiB < 1 MiB-лимита поля
	member := newGz(t, append(append([]byte("Package: p\nV: "), field...), '\n', '\n'))
	bomb := bytes.Repeat(member, 4096) // 4096 × 512 KiB = 2 GiB разжатых
	a := newEnumerateAdapter(t)
	meta := fakeMeta{files: map[string][]byte{
		"/apt/debian/dists/stable/Release":                       mustReadTestdata(t, "Release.golden"),
		"/apt/debian/dists/stable/main/binary-amd64/Packages.gz": bomb,
		"/apt/debian/dists/stable/main/binary-arm64/Packages.gz": bomb,
	}}
	_, err := a.Enumerate(context.Background(), domain.Remote{
		ID: 1, Name: "debian", Ecosystem: Name, Include: []string{"stable/main"},
	}, meta)
	if !errors.Is(err, ErrDecompressTooLarge) {
		t.Fatalf("ожидалась ErrDecompressTooLarge от gzip-бомбы, получено %v", err)
	}
}

func TestEnumerateAptXzOnly(t *testing.T) {
	// upstream публикует только Packages.xz: Enumerate обязана отдать
	// UnsupportedError с причиной «xz», а не NotFound, неотличимый от
	// пустого upstream (аудит-хвост сессии 26).
	a := newEnumerateAdapter(t)
	meta := fakeMeta{files: map[string][]byte{
		"/apt/debian/dists/stable/Release":                       mustReadTestdata(t, "Release.golden"),
		"/apt/debian/dists/stable/main/binary-amd64/Packages.xz": []byte("xz-stream"),
		"/apt/debian/dists/stable/main/binary-arm64/Packages.xz": []byte("xz-stream"),
	}}
	_, err := a.Enumerate(context.Background(), domain.Remote{
		ID: 1, Name: "debian", Ecosystem: Name, Include: []string{"stable/main"},
	}, meta)
	var ue *domain.UnsupportedError
	if !errors.As(err, &ue) {
		t.Fatalf("ошибка = %v, хочу *UnsupportedError", err)
	}
	if !strings.Contains(err.Error(), "xz") {
		t.Errorf("причина не называет формат xz: %v", err)
	}

	// Регрессия: индекса нет вообще ни в одном формате — остаётся
	// NotFound (не UnsupportedError).
	meta = fakeMeta{files: map[string][]byte{
		"/apt/debian/dists/stable/Release": mustReadTestdata(t, "Release.golden"),
	}}
	_, err = a.Enumerate(context.Background(), domain.Remote{
		ID: 1, Name: "debian", Ecosystem: Name, Include: []string{"stable/main"},
	}, meta)
	var nf *domain.NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("без индексов вообще ошибка = %v, хочу *NotFoundError", err)
	}
}

func TestEnumerateAptErrors(t *testing.T) {
	a := newEnumerateAdapter(t)
	t.Run("пустой Include — ValidationError", func(t *testing.T) {
		_, err := a.Enumerate(context.Background(), domain.Remote{
			Name: "debian", Ecosystem: Name, Include: nil,
		}, fakeMeta{})
		var ve *domain.ValidationError
		if !errors.As(err, &ve) {
			t.Fatalf("ошибка = %v, хочу *ValidationError", err)
		}
	})
	t.Run("Release отсутствует — NotFound", func(t *testing.T) {
		_, err := a.Enumerate(context.Background(), domain.Remote{
			Name: "debian", Ecosystem: Name, Include: []string{"stable/main"},
		}, fakeMeta{})
		var nf *domain.NotFoundError
		if !errors.As(err, &nf) {
			t.Fatalf("ошибка = %v, хочу *NotFoundError", err)
		}
	})
	t.Run("nil MetaFetcher — ошибка", func(t *testing.T) {
		_, err := a.Enumerate(context.Background(), domain.Remote{
			Name: "debian", Ecosystem: Name, Include: []string{"stable/main"},
		}, nil)
		if err == nil {
			t.Fatal("nil MetaFetcher должен ошибаться")
		}
	})
}

func TestParseAptInclude(t *testing.T) {
	cases := []struct {
		name    string
		include []string
		wantD   []string
		wantC   map[string]map[string]bool
		wantErr bool
	}{
		{"только dist", []string{"stable"}, []string{"stable"}, map[string]map[string]bool{"stable": {}}, false},
		{"dist/comp", []string{"stable/main"}, []string{"stable"}, map[string]map[string]bool{"stable": {"main": true}}, false},
		{"несколько", []string{"stable/main", "stable/contrib", "bookworm"}, []string{"stable", "bookworm"}, map[string]map[string]bool{"stable": {"main": true, "contrib": true}, "bookworm": {}}, false},
		{"пусто", nil, nil, nil, true},
		{"пустой элемент", []string{""}, nil, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, c, err := parseAptInclude(tc.include)
			if tc.wantErr {
				if err == nil {
					t.Fatal("хочу ошибку, получил nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("не ждал ошибку: %v", err)
			}
			if len(d) != len(tc.wantD) {
				t.Fatalf("dists = %+v, хочу %+v", d, tc.wantD)
			}
			for i := range d {
				if d[i] != tc.wantD[i] {
					t.Errorf("dists[%d] = %q, хочу %q", i, d[i], tc.wantD[i])
				}
			}
			for dist, set := range tc.wantC {
				got := c[dist]
				if len(got) != len(set) {
					t.Errorf("компоненты %s = %+v, хочу %+v", dist, got, set)
					continue
				}
				for k := range set {
					if !got[k] {
						t.Errorf("компонента %s/%s не разрешена", dist, k)
					}
				}
			}
		})
	}
}

// newGz gzip-упаковывает b для теста (.gz fallback Enumerate).
func newGz(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// errReader — заглушка, чтобы silence unused bytes import если нужно.
var _ = strings.TrimSpace
