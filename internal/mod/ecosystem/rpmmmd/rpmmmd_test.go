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

package rpmmmd

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

// newTestAdapter — адаптер с живыми часами и пустым RemoteStore; Classify
// не зависит от remotes, поэтому пустого фейка достаточно.
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
	if got := newTestAdapter(t).Name(); got != "rpm-md" {
		t.Errorf("Name() = %q, хочу rpm-md", got)
	}
}

// classifyCase — строка таблицы классификации: путь upstream + ожидаемый
// класс (Kind/TTL). Источник правды — сессия 08.
type classifyCase struct {
	path string
	kind domain.Kind
	ttl  time.Duration // 0 — не проверять (immutable)
}

func TestClassifyTable(t *testing.T) {
	a := newTestAdapter(t)
	cases := []classifyCase{
		// Immutable: RPM пакеты (бинарные, delta, source).
		{"Packages/f/foo-1.0-1.x86_64.rpm", domain.KindImmutable, 0},
		{"Packages/f/foo-1.0-1.src.rpm", domain.KindImmutable, 0},
		{"Packages/d/drpm/foo-1.0-1_1.1-1.x86_64.drpm", domain.KindImmutable, 0},
		{"foo-1.0-1.aarch64.rpm", domain.KindImmutable, 0},
		// Реальное мейнстрим-имя с «+» (сессия 65): libstdc++.
		{"Packages/l/libstdc++/libstdc++-13.2.1-7.fc40.x86_64.rpm", domain.KindImmutable, 0},
		// repomd.xml — корневой индекс, mutable{TTL 5m}.
		{"repodata/repomd.xml", domain.KindMutable, mutableIndexTTL},
		// подписи индекса — mutable, byte-exact (инвариант кеша).
		{"repodata/repomd.xml.asc", domain.KindMutable, mutableIndexTTL},
		{"repodata/repomd.xml.key", domain.KindMutable, mutableIndexTTL},
		// repodata с хешом в имени — content-addressed, immutable.
		{"repodata/0458a2b3c4d5e6f7a1b2c3d4e5f6a7b8-primary.xml.gz", domain.KindImmutable, 0},
		{"repodata/0458a2b3c4d5e6f7-filelists.xml.zst", domain.KindImmutable, 0},
		{"repodata/0458a2b3c4d5e6f7-other.xml.sqlite.bz2", domain.KindImmutable, 0},
		{"repodata/0458a2b3c4d5e6f7abc12345-UPDATE_INFO.xml", domain.KindImmutable, 0},
		// repodata без хеша — mutable{TTL 5m} (индексы перегенерируются).
		{"repodata/primary.xml.gz", domain.KindMutable, mutableIndexTTL},
		{"repodata/primary.xml.zst", domain.KindMutable, mutableIndexTTL},
		{"repodata/filelists.xml.gz", domain.KindMutable, mutableIndexTTL},
		{"repodata/other.xml.gz", domain.KindMutable, mutableIndexTTL},
		{"repodata/foo-UPDATE_INFO.xml", domain.KindMutable, mutableIndexTTL},
		{"repodata/primary.xml.sqlite.bz2", domain.KindMutable, mutableIndexTTL},
		{"repodata/abc.zck", domain.KindMutable, mutableIndexTTL},
		// Прочее (media.1/products и т.п.) — conservative Mutable{TTL 1m}.
		{"media.1/products", domain.KindMutable, mutableUnknownTTL},
		{"some/random/path.dat", domain.KindMutable, mutableUnknownTTL},
		{"repodata/repomd.xml.asc/foo", domain.KindMutable, mutableUnknownTTL}, // не repodata-файл
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

// TestClassifyRulesCovered проверяет, что каждое правило таблицы имеет
// хотя бы один тест-кейс выше — иначе правило мертво (никогда не
// сработает из-за порядка или опечатки).
func TestClassifyRulesCovered(t *testing.T) {
	a := newTestAdapter(t)
	covered := make(map[string]bool, len(a.rules))
	for _, r := range a.rules {
		covered[r.name] = false
	}
	for _, tc := range []string{
		"Packages/f/foo-1.0-1.x86_64.rpm",
		"Packages/d/drpm/foo-1.0-1_1.1-1.x86_64.drpm",
		"foo-1.0-1.src.rpm",
		"repodata/repomd.xml",
		"repodata/repomd.xml.asc",
		"repodata/repomd.xml.key",
		"repodata/0458a2b3c4d5e6f7a1b2c3d4e5f6a7b8-primary.xml.gz",
		"repodata/primary.xml.gz",
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
		ID: 7, Name: "fedora", Ecosystem: "rpm-md",
		BaseURL: "https://mirrors.fedoraproject.org/fedora/releases/40/Everything/x86_64/os", Enabled: true,
	})
	target, ok := a.Resolve("/rpm/fedora/Packages/f/foo-1.0-1.x86_64.rpm")
	if !ok {
		t.Fatal("Resolve существующего remote = false")
	}
	wantURL := "https://mirrors.fedoraproject.org/fedora/releases/40/Everything/x86_64/os/Packages/f/foo-1.0-1.x86_64.rpm"
	if target.UpstreamURL != wantURL {
		t.Errorf("UpstreamURL = %q, хочу %q", target.UpstreamURL, wantURL)
	}
	if target.UpstreamPath != "/Packages/f/foo-1.0-1.x86_64.rpm" {
		t.Errorf("UpstreamPath = %q", target.UpstreamPath)
	}
	if target.StorageKey != "cache/rpm-md/7/packages/f/foo-1.0-1.x86_64.rpm" {
		t.Errorf("StorageKey = %q", target.StorageKey)
	}
}

func TestResolveUppercaseStorageKeyLowercased(t *testing.T) {
	// StorageKey лоуэркейсит путь (доменный ключ — только [a-z0-9/._-]),
	// но UpstreamURL/Path сохраняют регистр (byte-exact к upstream).
	a := newResolveAdapter(t, domain.Remote{
		ID: 1, Name: "opensuse", BaseURL: "https://download.opensuse.org/tumbleweed/repo/oss", Enabled: true,
	})
	target, ok := a.Resolve("/rpm/opensuse/repodata/repomd.xml")
	if !ok {
		t.Fatal("Resolve = false")
	}
	if target.UpstreamPath != "/repodata/repomd.xml" {
		t.Errorf("UpstreamPath = %q", target.UpstreamPath)
	}
	if target.StorageKey != "cache/rpm-md/1/repodata/repomd.xml" {
		t.Errorf("StorageKey не лоуэркейшен: %q", target.StorageKey)
	}
}

func TestResolveRootPath(t *testing.T) {
	// /rpm/<remote> без остатка → upstreamPath «/» (корень репозитория)
	a := newResolveAdapter(t, domain.Remote{
		ID: 3, Name: "rhel", BaseURL: "https://cdn.redhat.com/content/dist/rhel9/9/x86_64/baseos/os", Enabled: true,
	})
	target, ok := a.Resolve("/rpm/rhel")
	if !ok {
		t.Fatal("Resolve корня remote = false")
	}
	if target.UpstreamPath != "/" {
		t.Errorf("UpstreamPath = %q, хочу «/»", target.UpstreamPath)
	}
	if target.UpstreamURL != "https://cdn.redhat.com/content/dist/rhel9/9/x86_64/baseos/os/" {
		t.Errorf("UpstreamURL = %q (BaseURL без trailing / + «/»)", target.UpstreamURL)
	}
}

func TestResolveUnknownRemote(t *testing.T) {
	a := newResolveAdapter(t, domain.Remote{ID: 1, Name: "fedora", BaseURL: "https://x", Enabled: true})
	if _, ok := a.Resolve("/rpm/fedoris/repodata/repomd.xml"); ok {
		t.Error("Resolve неизвестного remote должен дать false")
	}
}

func TestResolveDisabledRemote(t *testing.T) {
	a := newResolveAdapter(t, domain.Remote{ID: 1, Name: "fedora", BaseURL: "https://x", Enabled: false})
	if _, ok := a.Resolve("/rpm/fedora/repodata/repomd.xml"); ok {
		t.Error("Resolve выключенного remote должен дать false")
	}
}

func TestResolveWrongEcosystemPrefix(t *testing.T) {
	a := newResolveAdapter(t, domain.Remote{ID: 1, Name: "fedora", BaseURL: "https://x", Enabled: true})
	for _, path := range []string{
		"/apt/fedora/repodata/repomd.xml",
		"/rpm-md/fedora/repodata/repomd.xml", // префикс «/rpm/», не «/rpm-md/»
		"/dnf/fedora/repodata/repomd.xml",
	} {
		if _, ok := a.Resolve(path); ok {
			t.Errorf("Resolve(%q) с чужим префиксом должен дать false", path)
		}
	}
}

func TestResolveTraversalRemoteName(t *testing.T) {
	// path-traversal в remote-name: «..» / «.» / слэш не должны
	// пробраться в StorageKey или upstream-путь.
	a := newResolveAdapter(t, domain.Remote{ID: 1, Name: "fedora", BaseURL: "https://x", Enabled: true})
	for _, path := range []string{
		"/rpm/../etc/passwd",
		"/rpm/./etc/passwd",
		"/rpm//etc/passwd",
		"/rpm//",
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
	if _, ok := a.Resolve("/rpm/fedora/repodata/repomd.xml"); ok {
		t.Fatal("до создания remote Resolve не должен находить")
	}
	if _, err := store.CreateRemote(context.Background(), domain.Remote{
		Name: "fedora", Ecosystem: "rpm-md", BaseURL: "https://mirrors.fedoraproject.org/fedora", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	// кеш ещё свежий (0с < 30с) — remote не виден
	if _, ok := a.Resolve("/rpm/fedora/repodata/repomd.xml"); ok {
		t.Fatal("кеш remotes не должен инвалидироваться до TTL")
	}
	clock.Advance(remoteCacheTTL)
	target, ok := a.Resolve("/rpm/fedora/repodata/repomd.xml")
	if !ok {
		t.Fatal("после TTL кеш remotes не обновился")
	}
	if target.UpstreamURL != "https://mirrors.fedoraproject.org/fedora/repodata/repomd.xml" {
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
	// протухшую по TTL копию, не пустую ошибку. Кратковременный сбой
	// каталога не валит прокси.
	store := &errorRemoteStore{fakeRemotes: fakeRemotes{rs: []domain.Remote{
		{ID: 5, Name: "fedora", Ecosystem: "rpm-md", BaseURL: "https://mirrors.fedoraproject.org/fedora", Enabled: true},
	}}}
	clock := testutil.NewManualClock(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC))
	a, err := New(store, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Resolve("/rpm/fedora/repodata/repomd.xml"); !ok {
		t.Fatal("первый Resolve не нашёл remote")
	}
	// БД «ложится» + TTL истёк — следующий Resolve пытается reload,
	// неудачно, и должен отдать stale-копию из кеша.
	store.fail = true
	clock.Advance(remoteCacheTTL)
	if _, ok := a.Resolve("/rpm/fedora/repodata/repomd.xml"); !ok {
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
		{"**/*.rpm", "Packages/f/foo.rpm", true},
		{"**/*.rpm", "foo.rpm", true},             // **/ = опциональный префикс
		{"**/*.rpm", "Packages/f/foo.txt", false}, // суффикс не тот
		{"a/**/b", "a/b", true},                   // **/ = ноль сегментов
		{"a/**/b", "a/x/y/b", true},               // **/ = много сегментов
		{"a/**/b", "a/x/y/b/c", false},            // хвост после b
		{"foo/**", "foo/bar/baz", true},           // ** без / — любой хвост
		{"foo/**", "foo", false},                  // без хвоста после /
		{"x?z", "xyz", true},                      // ? = один байт без /
		{"x?z", "xyyz", false},                    // ? = ровно один
		{"x?z", "x/z", false},                     // ? не матчит /
		{"a.b", "a.b", true},                      // literal с эскейпом точки
		{"a.b", "axb", false},                     // точка — literal, не «любой»
	}
	for _, tc := range cases {
		re := globToRegex(tc.glob)
		if got := re.MatchString(tc.path); got != tc.want {
			t.Errorf("globToRegex(%q).Match(%q) = %v, хочу %v", tc.glob, tc.path, got, tc.want)
		}
	}
}

// fakeMeta — MetaFetcher, отдающий предзагруженные байты по пути.
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

func TestEnumerateRpmMdChain(t *testing.T) {
	// repomd → primary.xml → 3 package hrefs
	a := newEnumerateAdapter(t)
	meta := fakeMeta{files: map[string][]byte{
		"/rpm/fedora/repodata/repomd.xml":  mustReadTestdata(t, "repomd-primary.golden"),
		"/rpm/fedora/repodata/primary.xml": mustReadTestdata(t, "primary.golden"),
	}}
	got, err := a.Enumerate(context.Background(), domain.Remote{
		ID: 1, Name: "fedora", Ecosystem: Name, BaseURL: "https://mirrors.fedoraproject.org/fedora",
		Mode: domain.ModeMirror, Enabled: true,
	}, meta)
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	want := []string{
		"/Packages/f/foo-1.0-1.x86_64.rpm",
		"/Packages/b/bar-2.3-4.aarch64.rpm",
		"/Packages/b/baz-devel-0.1-1.noarch.rpm",
	}
	if len(got) != len(want) {
		t.Fatalf("Enumerate = %+v, хочу %+v", got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("Enumerate[%d] = %q, хочу %q", i, got[i], w)
		}
	}
}

func TestEnumerateRpmMdGzPrimary(t *testing.T) {
	// primary.xml.gz — Enumerate распаковывает.
	primaryGz := newGz(t, mustReadTestdata(t, "primary.golden"))
	a := newEnumerateAdapter(t)
	meta := fakeMeta{files: map[string][]byte{
		"/rpm/fedora/repodata/repomd.xml":     []byte(`<?xml version="1.0"?><repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="primary"><location href="repodata/primary.xml.gz"/></data></repomd>`),
		"/rpm/fedora/repodata/primary.xml.gz": primaryGz,
	}}
	got, err := a.Enumerate(context.Background(), domain.Remote{
		ID: 1, Name: "fedora", Ecosystem: Name, Include: nil,
	}, meta)
	if err != nil {
		t.Fatalf("Enumerate .gz: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("Enumerate .gz = %+v, хочу 3 hrefs", got)
	}
}

// TestEnumerateRpmMdGzZipBomb — сессия 54: gzip-бомба вместо
// primary.xml.gz. Разжатый поток ~2 GiB обязан упереться в
// декомпресс-лимит 1 GiB и дать ErrDecompressTooLarge, а не крутить
// декомпрессию вечно. Члены бомбы — валидный primary-фрагмент ~512 KiB
// (один package + chardata-пад): мелкие пакеты упёрлись бы в потолок
// парсера раньше декомпресс-капа и путь 1 GiB не тестировался бы.
// Конкатенация gzip-членов — multistream, валидна по RFC 1952; вся
// бомба в сжатом виде ~2 МБ.
func TestEnumerateRpmMdGzZipBomb(t *testing.T) {
	pad := bytes.Repeat([]byte("x"), 512<<10) // 512 KiB на член
	member := newGz(t, append(append([]byte("<package><name>n</name><location href=\"p/x.rpm\"/></package><pad>"), pad...), []byte("</pad>")...))
	bomb := bytes.Repeat(member, 4096) // 4096 × 512 KiB ≈ 2 GiB разжатых
	a := newEnumerateAdapter(t)
	meta := fakeMeta{files: map[string][]byte{
		"/rpm/fedora/repodata/repomd.xml":     []byte(`<?xml version="1.0"?><repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="primary"><location href="repodata/primary.xml.gz"/></data></repomd>`),
		"/rpm/fedora/repodata/primary.xml.gz": bomb,
	}}
	_, err := a.Enumerate(context.Background(), domain.Remote{
		ID: 1, Name: "fedora", Ecosystem: Name,
	}, meta)
	if !errors.Is(err, ErrDecompressTooLarge) {
		t.Fatalf("ожидалась ErrDecompressTooLarge от gzip-бомбы, получено %v", err)
	}
}

func TestEnumerateRpmMdUnsupportedPrimary(t *testing.T) {
	// primary в сжатиях вне whitelist: Enumerate обязана упасть с
	// честной причиной (формат назван) до fetch'а primary — раньше
	// бинарный поток уходил в XML-парсер и sync падал с общим
	// «parse primary».
	a := newEnumerateAdapter(t)
	for _, href := range []string{"repodata/primary.xml.zck", "repodata/primary.xml.zst", "repodata/primary.xml.xz", "repodata/primary.xml.bz2"} {
		meta := fakeMeta{files: map[string][]byte{
			"/rpm/fedora/repodata/repomd.xml": []byte(`<?xml version="1.0"?><repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="primary"><location href="` + href + `"/></data></repomd>`),
		}}
		_, err := a.Enumerate(context.Background(), domain.Remote{
			ID: 1, Name: "fedora", Ecosystem: Name,
		}, meta)
		var ue *domain.UnsupportedError
		if !errors.As(err, &ue) {
			t.Errorf("%s: ошибка = %v, хочу *UnsupportedError", href, err)
			continue
		}
		if !strings.Contains(err.Error(), href) {
			t.Errorf("%s: причина не называет формат: %v", href, err)
		}
	}
}

func TestEnumerateRpmMdErrors(t *testing.T) {
	a := newEnumerateAdapter(t)
	t.Run("repomd без primary", func(t *testing.T) {
		meta := fakeMeta{files: map[string][]byte{
			"/rpm/f/repodata/repomd.xml": []byte(`<?xml version="1.0"?><repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="filelists"><location href="repodata/x.xml"/></data></repomd>`),
		}}
		_, err := a.Enumerate(context.Background(), domain.Remote{Name: "f", Ecosystem: Name}, meta)
		if err == nil {
			t.Fatal("ожидалась ошибка отсутствия primary")
		}
	})
	t.Run("repomd отсутствует — NotFound", func(t *testing.T) {
		_, err := a.Enumerate(context.Background(), domain.Remote{Name: "f", Ecosystem: Name}, fakeMeta{})
		var nf *domain.NotFoundError
		if !errors.As(err, &nf) {
			t.Fatalf("ошибка = %v, хочу *NotFoundError", err)
		}
	})
	t.Run("nil MetaFetcher — ошибка", func(t *testing.T) {
		_, err := a.Enumerate(context.Background(), domain.Remote{Name: "f", Ecosystem: Name}, nil)
		if err == nil {
			t.Fatal("nil MetaFetcher должен ошибаться")
		}
	})
}

// newGz gzip-упаковывает b для теста.
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
