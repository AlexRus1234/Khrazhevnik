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
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/testutil"
)

// tagSpec — одна пара (tag, string-значение) для сборки main header
// фикстуры. строки идут в data-секцию nul-terminated; int32 —
// 4-байтно-выравнены.
type tagSpec struct {
	tag   uint32
	str   string
	i32   uint32
	isInt bool
}

// buildHeaderStruct собирает header struct (magic+ver+reserved+nindex+
// dataLen+index+data) из тегов. Data-секция: строки nul-terminated без
// выравнивания, int32 — 4-байтно-выравнены. Помогает собрать и sig
// (пустой), и main header.
func buildHeaderStruct(tags []tagSpec) []byte {
	var data []byte
	offsets := make([]int, len(tags))
	for i, t := range tags {
		if t.isInt {
			for len(data)%4 != 0 {
				data = append(data, 0)
			}
			offsets[i] = len(data)
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], t.i32)
			data = append(data, b[:]...)
		} else {
			offsets[i] = len(data)
			data = append(data, t.str...)
			data = append(data, 0)
		}
	}
	var index []byte
	for i, t := range tags {
		var b [16]byte
		binary.BigEndian.PutUint32(b[0:], t.tag)
		if t.isInt {
			binary.BigEndian.PutUint32(b[4:], typeInt32)
		} else {
			binary.BigEndian.PutUint32(b[4:], typeString)
		}
		binary.BigEndian.PutUint32(b[8:], uint32(offsets[i]))
		binary.BigEndian.PutUint32(b[12:], 1)
		index = append(index, b[:]...)
	}
	out := []byte{0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0} // magic+ver+reserved
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[:4], uint32(len(tags)))
	binary.BigEndian.PutUint32(hdr[4:], uint32(len(data)))
	out = append(out, hdr[:]...)
	out = append(out, index...)
	out = append(out, data...)
	return out
}

// buildRPM собирает минимальный валидный .rpm: 96-байтный lead + пустой
// sig header (16 байт, уже 8-выравнен) + main header с тегами name/
// version/release/epoch/arch/summary/description/license/url/size/
// buildtime. Без payload — генератор payload не читает, а SHA256
// считается по всему потоку (lead+sig+main).
func buildRPM(name, ver, rel, arch, summary string, size, buildtime int64) []byte {
	var lead [leadSize]byte
	lead[0] = 0xed
	lead[1] = 0xab
	lead[2] = 0xee
	lead[3] = 0xdb
	lead[4] = 3 // major
	// 6-7 type, 8-9 archnum, 10..75 name (66 байт)
	copy(lead[10:], name+"-"+ver+"-"+rel+"."+arch)
	binary.BigEndian.PutUint16(lead[76:], 1) // osnum
	binary.BigEndian.PutUint16(lead[78:], 5) // sigtype = HEADER
	sigHeader := buildHeaderStruct(nil)      // пустой sig (16 байт)
	mainHeader := buildHeaderStruct([]tagSpec{
		{tag: tagName, str: name},
		{tag: tagVersion, str: ver},
		{tag: tagRelease, str: rel},
		{tag: tagArch, str: arch},
		{tag: tagSummary, str: summary},
		{tag: tagDescription, str: summary},
		{tag: tagLicense, str: "MIT"},
		{tag: tagURL, str: "https://example.com"},
		{tag: tagEpoch, i32: 0, isInt: true},
		{tag: tagSize, i32: uint32(size), isInt: true},
		{tag: tagBuildTime, i32: uint32(buildtime), isInt: true},
	})
	out := make([]byte, 0, len(lead)+len(sigHeader)+len(mainHeader))
	out = append(out, lead[:]...)
	out = append(out, sigHeader...)
	out = append(out, mainHeader...)
	return out
}

func TestParseRPMHeaderGolden(t *testing.T) {
	rpm := buildRPM("foo", "1.0", "1", "x86_64", "test package", 4096, 1724323200)
	hdr, err := ParseRPMHeader(bytes.NewReader(rpm))
	if err != nil {
		t.Fatalf("ParseRPMHeader: %v", err)
	}
	if hdr.Name != "foo" {
		t.Errorf("Name = %q", hdr.Name)
	}
	if hdr.Version != "1.0" {
		t.Errorf("Version = %q", hdr.Version)
	}
	if hdr.Release != "1" {
		t.Errorf("Release = %q", hdr.Release)
	}
	if hdr.Arch != "x86_64" {
		t.Errorf("Arch = %q", hdr.Arch)
	}
	if hdr.Summary != "test package" {
		t.Errorf("Summary = %q", hdr.Summary)
	}
	if hdr.License != "MIT" {
		t.Errorf("License = %q", hdr.License)
	}
	if hdr.Size != 4096 {
		t.Errorf("Size = %d", hdr.Size)
	}
	if hdr.BuildTime != 1724323200 {
		t.Errorf("BuildTime = %d", hdr.BuildTime)
	}
	if hdr.Epoch != 0 {
		t.Errorf("Epoch = %d", hdr.Epoch)
	}
}

func TestParseRPMHeaderBadLeadMagic(t *testing.T) {
	// первые 4 байта не 0xEDABEEODB → ErrInvalidRPM.
	rpm := buildRPM("foo", "1.0", "1", "x86_64", "x", 1, 1)
	rpm[0] = 0x00
	_, err := ParseRPMHeader(bytes.NewReader(rpm))
	if !errors.Is(err, ErrInvalidRPM) {
		t.Fatalf("ожидалась ErrInvalidRPM, получено %v", err)
	}
}

func TestParseRPMHeaderBadHeaderMagic(t *testing.T) {
	// верный lead, но sig header magic битый.
	var lead [leadSize]byte
	lead[0], lead[1], lead[2], lead[3] = 0xed, 0xab, 0xee, 0xdb
	lead[4] = 3
	binary.BigEndian.PutUint16(lead[78:], 5)
	buf := append(lead[:], []byte{0x00, 0x00, 0x00, 0x01}...) // битый sig magic
	_, err := ParseRPMHeader(bytes.NewReader(buf))
	if !errors.Is(err, ErrInvalidRPM) {
		t.Fatalf("ожидалась ErrInvalidRPM, получено %v", err)
	}
}

func TestParseRPMHeaderTruncated(t *testing.T) {
	// обрезанный поток посреди lead → ErrInvalidRPM.
	rpm := buildRPM("foo", "1.0", "1", "x86_64", "x", 1, 1)
	_, err := ParseRPMHeader(bytes.NewReader(rpm[:10]))
	if !errors.Is(err, ErrInvalidRPM) {
		t.Fatalf("ожидалась ErrInvalidRPM для обрезки, получено %v", err)
	}
}

func TestParseRPMHeaderTruncatedMidMain(t *testing.T) {
	// обрезан main data: lead + sig + main preamble, но data не дописан.
	rpm := buildRPM("foo", "1.0", "1", "x86_64", "x", 1, 1)
	// срезаем последние 4 байта (часть data) → io.ReadFull main data падает.
	_, err := ParseRPMHeader(bytes.NewReader(rpm[:len(rpm)-4]))
	if !errors.Is(err, ErrInvalidRPM) {
		t.Fatalf("ожидалась ErrInvalidRPM для обрезки main data, получено %v", err)
	}
}

func TestParseRPMHeaderMissingTags(t *testing.T) {
	// main header без name → ErrInvalidRPM (нет обязательных тегов).
	var lead [leadSize]byte
	lead[0], lead[1], lead[2], lead[3] = 0xed, 0xab, 0xee, 0xdb
	lead[4] = 3
	binary.BigEndian.PutUint16(lead[78:], 5)
	sig := buildHeaderStruct(nil)
	// main header с одним не-обязательным тегом (license), без name/version/release/arch.
	main := buildHeaderStruct([]tagSpec{{tag: tagLicense, str: "MIT"}})
	out := append(append(lead[:], sig...), main...)
	_, err := ParseRPMHeader(bytes.NewReader(out))
	if !errors.Is(err, ErrInvalidRPM) {
		t.Fatalf("ожидалась ErrInvalidRPM для main без обязательных тегов, получено %v", err)
	}
}

func TestParseRPMHeaderSigHeaderPadding(t *testing.T) {
	// sig header с data не кратным 8 → padding добивается до 8. Проверяем,
	// что padding-логика читает main header верно. sig с одним строковым
	// тегом "abc" → data=4 байта (с nul); sigPayload = 16(index)+4(data)=20,
	// pad=(8-(20%8))%8=4. Между sig и main вставляем 4 байта padding.
	var lead [leadSize]byte
	lead[0], lead[1], lead[2], lead[3] = 0xed, 0xab, 0xee, 0xdb
	lead[4] = 3
	binary.BigEndian.PutUint16(lead[78:], 5)
	sig := buildHeaderStruct([]tagSpec{{tag: 1000, str: "abc"}}) // sig с одним тегом
	main := buildHeaderStruct([]tagSpec{
		{tag: tagName, str: "foo"},
		{tag: tagVersion, str: "1.0"},
		{tag: tagRelease, str: "1"},
		{tag: tagArch, str: "x86_64"},
	})
	final := append([]byte{}, lead[:]...)
	final = append(final, sig...)
	final = append(final, make([]byte, 4)...) // 4 байта padding
	final = append(final, main...)
	hdr, err := ParseRPMHeader(bytes.NewReader(final))
	if err != nil {
		t.Fatalf("ParseRPMHeader с sig padding: %v", err)
	}
	if hdr.Name != "foo" {
		t.Errorf("Name = %q (sig padding не прочитан корректно)", hdr.Name)
	}
}

func TestGeneratorName(t *testing.T) {
	g := &Generator{}
	if g.Name() != Name {
		t.Errorf("Name = %q, want %q", g.Name(), Name)
	}
}

func TestValidateObjectPath(t *testing.T) {
	g := &Generator{}
	cases := []struct {
		path string
		want bool
	}{
		{"packages/f/foo-1.0-1.x86_64.rpm", true},
		{"packages/f/foo.src.rpm", true},
		{"packages/f/foo-1.0.drpm", true},
		{"repodata/primary.xml.gz", false},
		{"repodata/repomd.xml", false},
		{"foo.txt", false},
		{"", false},
	}
	for _, c := range cases {
		err := g.ValidateObjectPath(c.path)
		got := err == nil
		if got != c.want {
			t.Errorf("ValidateObjectPath(%q) = %v, want ok=%v", c.path, err, c.want)
		}
	}
}

// putRpm складывает .rpm-байты в FakeStorage по ключу под префиксом
// repo/<id>/rpm-md. Возвращает полный ключ.
func putRpm(t *testing.T, storage *testutil.FakeStorage, repo domain.Repo, name string, rpm []byte) string {
	t.Helper()
	key := port.RepoPrefix(repo) + "/" + name
	w, err := storage.Put(context.Background(), key)
	if err != nil {
		t.Fatalf("storage.Put %s: %v", key, err)
	}
	if _, err := w.Write(rpm); err != nil {
		t.Fatalf("w.Write %s: %v", key, err)
	}
	if err := w.Commit(context.Background()); err != nil {
		t.Fatalf("w.Commit %s: %v", key, err)
	}
	return key
}

func readStorage(t *testing.T, storage *testutil.FakeStorage, key string) []byte {
	t.Helper()
	obj, err := storage.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("Get %s: %v", key, err)
	}
	defer obj.Body.Close()
	b, err := io.ReadAll(obj.Body)
	if err != nil {
		t.Fatalf("ReadAll %s: %v", key, err)
	}
	return b
}

func TestGenerateIndexesSingleRpm(t *testing.T) {
	moment := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	storage := testutil.NewFakeStorage(testutil.FixedClock(moment))
	repo := domain.Repo{ID: 1, Name: "alice", Ecosystem: Name}
	rpm := buildRPM("foo", "1.0", "1", "x86_64", "test package", 4096, 1724323200)
	putRpm(t, storage, repo, "packages/f/foo-1.0-1.x86_64.rpm", rpm)

	g := &Generator{}
	if err := g.GenerateIndexes(context.Background(), repo, storage, nil); err != nil {
		t.Fatalf("GenerateIndexes: %v", err)
	}

	// primary.xml.gz существует; распаковываем и проверяем содержимое.
	priGz := readStorage(t, storage, "repo/1/rpm-md/repodata/primary.xml.gz")
	gz, err := gzip.NewReader(bytes.NewReader(priGz))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	primary, _ := io.ReadAll(gz)
	pStr := string(primary)
	for _, want := range []string{
		"<name>foo</name>",
		"<arch>x86_64</arch>",
		`<version epoch="0" ver="1.0" rel="1"/>`,
		"<checksum type=\"sha256\">",
		"<summary>test package</summary>",
		"<location href=\"packages/f/foo-1.0-1.x86_64.rpm\"/>",
		"<rpm:license>MIT</rpm:license>",
	} {
		if !strings.Contains(pStr, want) {
			t.Errorf("primary.xml не содержит %q:\n%s", want, pStr)
		}
	}
	// checksum в primary.xml = sha256 всего .rpm.
	wantSha := sha256Hex(rpm)
	if !strings.Contains(pStr, ">"+wantSha+"</checksum>") {
		t.Errorf("primary.xml не содержит sha256 %s файла", wantSha)
	}
	// size package = размер файла .rpm.
	wantSizeLine := fmt.Sprintf("<size package=\"%d\"", len(rpm))
	if !strings.Contains(pStr, wantSizeLine) {
		t.Errorf("primary.xml не содержит %q: %s", wantSizeLine, pStr)
	}

	// repomd.xml: data type=primary с location href и чексуммами.
	repomd := readStorage(t, storage, "repo/1/rpm-md/repodata/repomd.xml")
	rStr := string(repomd)
	for _, want := range []string{
		"<data type=\"primary\">",
		"<location href=\"repodata/primary.xml.gz\"/>",
		"<checksum type=\"sha256\">" + sha256Hex(priGz) + "</checksum>",
		"<open-checksum type=\"sha256\">" + sha256Hex(primary) + "</open-checksum>",
	} {
		if !strings.Contains(rStr, want) {
			t.Errorf("repomd.xml не содержит %q:\n%s", want, rStr)
		}
	}
}

// roundtrip: список .rpm → primary.xml.gz → ParsePrimary → те же hrefs.
func TestGenerateIndexesRoundtrip(t *testing.T) {
	moment := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	storage := testutil.NewFakeStorage(testutil.FixedClock(moment))
	repo := domain.Repo{ID: 1, Name: "alice", Ecosystem: Name}
	putRpm(t, storage, repo, "packages/b/bar-2.3-4.aarch64.rpm", buildRPM("bar", "2.3", "4", "aarch64", "b", 100, 1))
	putRpm(t, storage, repo, "packages/b/baz-devel-0.1-1.noarch.rpm", buildRPM("baz-devel", "0.1", "1", "noarch", "bz", 100, 1))
	putRpm(t, storage, repo, "packages/f/foo-1.0-1.x86_64.rpm", buildRPM("foo", "1.0", "1", "x86_64", "f", 100, 1))

	g := &Generator{}
	if err := g.GenerateIndexes(context.Background(), repo, storage, nil); err != nil {
		t.Fatalf("GenerateIndexes: %v", err)
	}

	priGz := readStorage(t, storage, "repo/1/rpm-md/repodata/primary.xml.gz")
	gz, err := gzip.NewReader(bytes.NewReader(priGz))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	hrefs, err := collectPrimary(ParsePrimary(gz))
	if err != nil {
		t.Fatalf("ParsePrimary roundtrip: %v", err)
	}
	want := []string{
		"packages/b/bar-2.3-4.aarch64.rpm",
		"packages/b/baz-devel-0.1-1.noarch.rpm",
		"packages/f/foo-1.0-1.x86_64.rpm",
	}
	if len(hrefs) != len(want) {
		t.Fatalf("hrefs = %+v, хочу %+v", hrefs, want)
	}
	for i, h := range want {
		if hrefs[i] != h {
			t.Errorf("hrefs[%d] = %q, хочу %q", i, hrefs[i], h)
		}
	}
}

func TestGenerateIndexesEmptyRepo(t *testing.T) {
	moment := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	storage := testutil.NewFakeStorage(testutil.FixedClock(moment))
	repo := domain.Repo{ID: 1, Name: "alice", Ecosystem: Name}

	g := &Generator{}
	if err := g.GenerateIndexes(context.Background(), repo, storage, nil); err != nil {
		t.Fatalf("GenerateIndexes пустой репо: %v", err)
	}
	// primary.xml.gz существует (packages="0"), repomd.xml существует.
	priGz := readStorage(t, storage, "repo/1/rpm-md/repodata/primary.xml.gz")
	gz, _ := gzip.NewReader(bytes.NewReader(priGz))
	primary, _ := io.ReadAll(gz)
	if !strings.Contains(string(primary), `packages="0"`) {
		t.Errorf("primary.xml пустого репо не packages=\"0\": %s", primary)
	}
	_ = readStorage(t, storage, "repo/1/rpm-md/repodata/repomd.xml")
}

func TestGenerateIndexesWrongEcosystem(t *testing.T) {
	moment := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	storage := testutil.NewFakeStorage(testutil.FixedClock(moment))
	repo := domain.Repo{ID: 1, Name: "alice", Ecosystem: "apt"}
	g := &Generator{}
	err := g.GenerateIndexes(context.Background(), repo, storage, nil)
	var unsup *domain.UnsupportedError
	if !errors.As(err, &unsup) {
		t.Fatalf("ожидали UnsupportedError, получили %v", err)
	}
}

func TestGenerateIndexesContextCanceled(t *testing.T) {
	moment := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	storage := testutil.NewFakeStorage(testutil.FixedClock(moment))
	repo := domain.Repo{ID: 1, Name: "alice", Ecosystem: Name}
	putRpm(t, storage, repo, "packages/f/foo-1.0-1.x86_64.rpm", buildRPM("foo", "1.0", "1", "x86_64", "f", 1, 1))
	g := &Generator{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := g.GenerateIndexes(ctx, repo, storage, nil); err == nil {
		t.Fatal("ожидали ошибку отменённого контекста")
	}
}

// recordingProgress ловит кадры Update для проверки фаз.
type recordingProgress struct {
	updates []string
	logs    []string
}

func (r *recordingProgress) Update(phase, current string, processed, total int64) {
	r.updates = append(r.updates, fmt.Sprintf("%s/%s/%d/%d", phase, current, processed, total))
}
func (r *recordingProgress) Log(line string) { r.logs = append(r.logs, line) }

func TestGenerateIndexesProgress(t *testing.T) {
	moment := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	storage := testutil.NewFakeStorage(testutil.FixedClock(moment))
	repo := domain.Repo{ID: 1, Name: "alice", Ecosystem: Name}
	putRpm(t, storage, repo, "packages/f/foo.rpm", buildRPM("foo", "1.0", "1", "x86_64", "f", 1, 1))
	g := &Generator{}
	rec := &recordingProgress{}
	if err := g.GenerateIndexes(context.Background(), repo, storage, rec); err != nil {
		t.Fatalf("GenerateIndexes: %v", err)
	}
	phases := map[string]bool{}
	for _, u := range rec.updates {
		phases[strings.SplitN(u, "/", 2)[0]] = true
	}
	for _, want := range []string{"enumerate", "header", "write"} {
		if !phases[want] {
			t.Errorf("фаза %s не отработала: %v", want, rec.updates)
		}
	}
	if !slices.ContainsFunc(rec.logs, func(s string) bool { return strings.Contains(s, "индексы записаны") }) {
		t.Errorf("нет строки завершения: %v", rec.logs)
	}
}

// fakeSigner — port.Signer для теста подписи repomd.xml.asc: возвращает
// детерминированный маркер, чтобы тест не зависел от openpgp-генерации.
type fakeSigner struct{}

func (fakeSigner) Sign(_ context.Context, _ io.Reader) (io.Reader, error) {
	return bytes.NewReader([]byte("cleartext-stub")), nil
}
func (fakeSigner) SignDetached(_ context.Context, _ io.Reader) (io.Reader, error) {
	return bytes.NewReader([]byte("detached-stub")), nil
}
func (fakeSigner) PublicKey() ([]byte, error) { return []byte("pub-stub"), nil }

func TestGenerateIndexesUnsignedNoAsc(t *testing.T) {
	moment := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	storage := testutil.NewFakeStorage(testutil.FixedClock(moment))
	repo := domain.Repo{ID: 1, Name: "alice", Ecosystem: Name}
	putRpm(t, storage, repo, "packages/f/foo.rpm", buildRPM("foo", "1.0", "1", "x86_64", "f", 1, 1))
	g := &Generator{}
	if err := g.GenerateIndexes(context.Background(), repo, storage, nil); err != nil {
		t.Fatalf("GenerateIndexes: %v", err)
	}
	if _, err := storage.Get(context.Background(), "repo/1/rpm-md/repodata/repomd.xml.asc"); err == nil {
		t.Error("без Signer создан repomd.xml.asc")
	}
}

func TestGenerateIndexesSignedWritesAsc(t *testing.T) {
	moment := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	storage := testutil.NewFakeStorage(testutil.FixedClock(moment))
	repo := domain.Repo{ID: 1, Name: "alice", Ecosystem: Name}
	putRpm(t, storage, repo, "packages/f/foo.rpm", buildRPM("foo", "1.0", "1", "x86_64", "f", 1, 1))
	g := &Generator{signer: fakeSigner{}}
	rec := &recordingProgress{}
	if err := g.GenerateIndexes(context.Background(), repo, storage, rec); err != nil {
		t.Fatalf("GenerateIndexes: %v", err)
	}
	asc := readStorage(t, storage, "repo/1/rpm-md/repodata/repomd.xml.asc")
	if string(asc) != "detached-stub" {
		t.Errorf("repomd.xml.asc = %q, хочу detached-stub", asc)
	}
	phases := map[string]bool{}
	for _, u := range rec.updates {
		phases[strings.SplitN(u, "/", 2)[0]] = true
	}
	if !phases["sign"] {
		t.Errorf("фаза sign не отработала: %v", rec.updates)
	}
}

// errSignFail — синтетическая ошибка подписчика для error-ветки.
var errSignFail = errors.New("synthetic signer failure")

type failSigner struct{}

func (failSigner) Sign(context.Context, io.Reader) (io.Reader, error) { return nil, errSignFail }
func (failSigner) SignDetached(context.Context, io.Reader) (io.Reader, error) {
	return nil, errSignFail
}
func (failSigner) PublicKey() ([]byte, error) { return nil, nil }

func TestGenerateIndexesSignedSignerErrorFails(t *testing.T) {
	moment := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	storage := testutil.NewFakeStorage(testutil.FixedClock(moment))
	repo := domain.Repo{ID: 1, Name: "alice", Ecosystem: Name}
	putRpm(t, storage, repo, "packages/f/foo.rpm", buildRPM("foo", "1.0", "1", "x86_64", "f", 1, 1))
	g := &Generator{signer: failSigner{}}
	err := g.GenerateIndexes(context.Background(), repo, storage, nil)
	if !errors.Is(err, errSignFail) {
		t.Fatalf("ожидали errSignFail, got %v", err)
	}
}

func TestSetSigner(t *testing.T) {
	g := &Generator{}
	if g.signer != nil {
		t.Fatal("новый Generator уже имеет signer")
	}
	s := fakeSigner{}
	g.SetSigner(s)
	if g.signer == nil {
		t.Error("SetSigner не сохранил signer")
	}
}

// sanity: buildRPM даёт файл, чья sha256 отлична от нулевого массива
// (защита от случайно-пустой фикстуры, что завалило бы checksum-тесты).
func TestBuildRPMNonEmpty(t *testing.T) {
	rpm := buildRPM("foo", "1.0", "1", "x86_64", "x", 1, 1)
	if len(rpm) < leadSize+16 {
		t.Fatalf("buildRPM слишком короткий: %d байт", len(rpm))
	}
	sum := sha256.Sum256(rpm)
	if bytes.Equal(sum[:], make([]byte, 32)) {
		t.Fatal("sha256(buildRPM) нулевой — фикстура пуста")
	}
	_ = hex.EncodeToString
}
