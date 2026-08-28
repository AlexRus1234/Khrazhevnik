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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"iter"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	gp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/klauspost/compress/zstd"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/testutil"
)

// writeArMember дописывает один член в ar-архив (60-байтный заголовок +
// контент + padding до 2-байтной границы). Заголовок — формат System V
// (как в .deb), имена добиваются пробелом до 16 байт.
func writeArMember(buf *bytes.Buffer, name string, content []byte) {
	fmt.Fprintf(buf, "%-16s%-12d%-6d%-6d%-8o%-10d`\n", name+"/", 0, 0, 0, 0o100644, len(content))
	buf.Write(content)
	if len(content)%2 == 1 {
		buf.WriteByte('\n')
	}
}

// buildDeb собирает валидный .deb из control-станзы. data-секция —
// пустой tar.gz (генератор её не трогает). control.tar.gz — tar с
// ./control, gz-компресс. Возвращаем байты .deb и sha256.
func buildDeb(t *testing.T, control string) ([]byte, string) {
	t.Helper()
	var ar bytes.Buffer
	ar.WriteString("!<arch>\n")
	writeArMember(&ar, "debian-binary", []byte("2.0\n"))

	// control.tar.gz: tar с ./control.
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	content := []byte(control)
	if err := tw.WriteHeader(&tar.Header{Name: "./control", Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatalf("tw.WriteHeader control: %v", err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatalf("tw.Write control: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tw.Close: %v", err)
	}
	var gzBuf bytes.Buffer
	gz := gzip.NewWriter(&gzBuf)
	if _, err := gz.Write(tarBuf.Bytes()); err != nil {
		t.Fatalf("gz.Write control.tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gz.Close: %v", err)
	}
	writeArMember(&ar, "control.tar.gz", gzBuf.Bytes())

	// data.tar.gz: пустой tar (один заголовок EOF).
	var dataTar bytes.Buffer
	dtw := tar.NewWriter(&dataTar)
	if err := dtw.Close(); err != nil {
		t.Fatalf("dtw.Close: %v", err)
	}
	var dataGz bytes.Buffer
	dgz := gzip.NewWriter(&dataGz)
	if _, err := dgz.Write(dataTar.Bytes()); err != nil {
		t.Fatalf("dgz.Write data.tar: %v", err)
	}
	if err := dgz.Close(); err != nil {
		t.Fatalf("dgz.Close: %v", err)
	}
	writeArMember(&ar, "data.tar.gz", dataGz.Bytes())

	deb := ar.Bytes()
	h := sha256.Sum256(deb)
	return deb, hex.EncodeToString(h[:])
}

func TestReadControlGolden(t *testing.T) {
	control := "Package: foo\nVersion: 1.0-1\nArchitecture: amd64\nDescription: test package\n long line\n"
	deb, _ := buildDeb(t, control)
	stanza, err := readControl(bytes.NewReader(deb))
	if err != nil {
		t.Fatalf("readControl: %v", err)
	}
	if got := stanza.Get("Package"); got != "foo" {
		t.Errorf("Package = %q, want foo", got)
	}
	if got := stanza.Get("Version"); got != "1.0-1" {
		t.Errorf("Version = %q", got)
	}
	if got := stanza.Get("Description"); got != "test package\nlong line" {
		t.Errorf("Description = %q", got)
	}
}

func TestReadControlMissingControlMember(t *testing.T) {
	// ar без control.tar.* — только debian-binary и data.tar.gz.
	var ar bytes.Buffer
	ar.WriteString("!<arch>\n")
	writeArMember(&ar, "debian-binary", []byte("2.0\n"))
	writeArMember(&ar, "data.tar.gz", []byte("fake"))
	_, err := readControl(bytes.NewReader(ar.Bytes()))
	if err == nil || !strings.Contains(err.Error(), "control.tar.*") {
		t.Fatalf("ожидали ошибку отсутствия control.tar, получили %v", err)
	}
}

func TestReadControlBadArMagic(t *testing.T) {
	_, err := readControl(bytes.NewReader([]byte("not an ar file")))
	if err == nil || !strings.Contains(err.Error(), "ar-magic") {
		t.Fatalf("ожидали ошибку magic, получили %v", err)
	}
}

func TestGeneratorName(t *testing.T) {
	g := &Generator{}
	if g.Name() != Name {
		t.Errorf("Name = %q, want %q", g.Name(), Name)
	}
}

// buildDebZstd — то же, что buildDeb, но control.tar сжимается zstd
// (проверка decompressControl по сигнатуре 28 b5 2f fd).
func buildDebZstd(t *testing.T, control string) []byte {
	t.Helper()
	var ar bytes.Buffer
	ar.WriteString("!<arch>\n")
	writeArMember(&ar, "debian-binary", []byte("2.0\n"))

	// control.tar.zst: tar → zstd.
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	content := []byte(control)
	if err := tw.WriteHeader(&tar.Header{Name: "./control", Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatalf("tw.WriteHeader control: %v", err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatalf("tw.Write control: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tw.Close: %v", err)
	}
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatalf("zstd.NewWriter: %v", err)
	}
	zstdBytes := enc.EncodeAll(tarBuf.Bytes(), make([]byte, 0, len(tarBuf.Bytes())))
	writeArMember(&ar, "control.tar.zst", zstdBytes)

	// data.tar.gz: простой gz-пустышка.
	var dataTar bytes.Buffer
	dtw := tar.NewWriter(&dataTar)
	_ = dtw.Close()
	var dataGz bytes.Buffer
	dgz := gzip.NewWriter(&dataGz)
	_, _ = dgz.Write(dataTar.Bytes())
	_ = dgz.Close()
	writeArMember(&ar, "data.tar.gz", dataGz.Bytes())
	return ar.Bytes()
}

func TestReadControlZstd(t *testing.T) {
	control := "Package: bar\nVersion: 2.0\nArchitecture: all\nDescription: short\n"
	deb := buildDebZstd(t, control)
	stanza, err := readControl(bytes.NewReader(deb))
	if err != nil {
		t.Fatalf("readControl zstd: %v", err)
	}
	if got := stanza.Get("Package"); got != "bar" {
		t.Errorf("Package = %q, want bar", got)
	}
}

func TestWriteStanzaMultiline(t *testing.T) {
	s := newStanza()
	s.Set("Description", "short\nsecond\nthird\n\nfifth")
	var buf bytes.Buffer
	writeStanza(&buf, s)
	out := buf.String()
	// Multiline deb822: «Description: short\n second\n third\n .\n fifth\n»
	if !strings.Contains(out, "Description: short\n") {
		t.Errorf("первая строка не на месте: %q", out)
	}
	if !strings.Contains(out, " second\n") {
		t.Errorf("продолжение без ведущего пробела: %q", out)
	}
	if !strings.Contains(out, " .\n") {
		t.Errorf("пустая строка-продолжение не « .»: %q", out)
	}
}

// buildDebNoControl — .deb с control.tar.gz, в котором НЕТ ./control
// (проверка readControlTar на «не содержит ./control»).
func buildDebNoControl(t *testing.T) []byte {
	t.Helper()
	var ar bytes.Buffer
	ar.WriteString("!<arch>\n")
	writeArMember(&ar, "debian-binary", []byte("2.0\n"))

	// control.tar.gz: tar без ./control — только ./postinst.
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	if err := tw.WriteHeader(&tar.Header{Name: "./postinst", Mode: 0o644, Size: 4, Typeflag: tar.TypeReg}); err != nil {
		t.Fatalf("tw.WriteHeader postinst: %v", err)
	}
	if _, err := tw.Write([]byte("echo")); err != nil {
		t.Fatalf("tw.Write postinst: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tw.Close: %v", err)
	}
	var gzBuf bytes.Buffer
	gz := gzip.NewWriter(&gzBuf)
	if _, err := gz.Write(tarBuf.Bytes()); err != nil {
		t.Fatalf("gz.Write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gz.Close: %v", err)
	}
	writeArMember(&ar, "control.tar.gz", gzBuf.Bytes())
	return ar.Bytes()
}

func TestReadControlTarNoControl(t *testing.T) {
	deb := buildDebNoControl(t)
	_, err := readControl(bytes.NewReader(deb))
	if err == nil || !strings.Contains(err.Error(), "не содержит ./control") {
		t.Fatalf("ожидали ошибку отсутствия ./control, получили %v", err)
	}
}

// brokenArReader — Reader, отдающий короткий ar-маг, но дальше EOF
// без заголовков членов (проверка readControl на «control.tar.* не найден»).
func TestReadControlEmptyAr(t *testing.T) {
	deb := []byte("!<arch>\n")
	_, err := readControl(bytes.NewReader(deb))
	if err == nil || !strings.Contains(err.Error(), "control.tar.*") {
		t.Fatalf("ожидали ошибку отсутствия control.tar, получили %v", err)
	}
}

// buildDebTarWithBadControl — control.tar.gz с ./control, но tar внутри
// невалиден (битый gzip-заголовок после сигнатуры).
func TestReadControlDecompressError(t *testing.T) {
	var ar bytes.Buffer
	ar.WriteString("!<arch>\n")
	writeArMember(&ar, "debian-binary", []byte("2.0\n"))
	// контроль.tar.gz: заголовок gzip, но дальше мусор → ошибка gzip.
	badGz := []byte{0x1f, 0x8b, 0xff, 0xff, 0xff, 0xff}
	writeArMember(&ar, "control.tar.gz", badGz)
	_, err := readControl(bytes.NewReader(ar.Bytes()))
	if err == nil {
		t.Fatalf("ожидали ошибку распаковки/чтения control")
	}
}

func TestGenerateIndexesContextCanceled(t *testing.T) {
	moment := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	storage := testutil.NewFakeStorage(testutil.FixedClock(moment))
	repo := domain.Repo{ID: 1, Name: "alice", Ecosystem: "apt"}
	putDeb(t, storage, repo, "pool/main/f/foo.deb", "Package: foo\nVersion: 1.0\nArchitecture: amd64\nDescription: f\n")

	g := &Generator{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := g.GenerateIndexes(ctx, repo, storage, nil)
	if err == nil {
		t.Fatalf("ожидали ошибку отменённого контекста")
	}
}

func TestValidateObjectPath(t *testing.T) {
	g := &Generator{}
	cases := []struct {
		path string
		want bool // true → нет ошибки
	}{
		{"pool/main/a/foo.deb", true},
		{"pool/main/a/foo.udeb", true},
		{"pool/main/a/foo.ddeb", true},
		{"pool/main/a/foo.dsc", true},
		{"pool/main/a/foo.orig.tar.gz", true},
		{"pool/main/a/foo.debian.tar.xz", true},
		{"dists/stable/main/binary-amd64/Packages", false},
		{"notpool/foo.deb", false},
		{"pool/main/a/foo.rar", false},
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

// putDeb складывает .deb-байты в FakeStorage по ключу pool/main/.../<name>.deb
// под префиксом repo/<id>/apt. Возвращает ключ.
func putDeb(t *testing.T, storage *testutil.FakeStorage, repo domain.Repo, name, control string) string {
	t.Helper()
	deb, _ := buildDeb(t, control)
	key := port.RepoPrefix(repo) + "/" + name
	w, err := storage.Put(context.Background(), key)
	if err != nil {
		t.Fatalf("storage.Put %s: %v", key, err)
	}
	if _, err := w.Write(deb); err != nil {
		t.Fatalf("w.Write %s: %v", key, err)
	}
	if err := w.Commit(context.Background()); err != nil {
		t.Fatalf("w.Commit %s: %v", key, err)
	}
	return key
}

// readStorage достаёт байты объекта по ключу; тестам удобнее, чем
// копировать io.ReadAll каждый раз.
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

func TestGenerateIndexesSingleDeb(t *testing.T) {
	moment := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	clock := testutil.FixedClock(moment)
	storage := testutil.NewFakeStorage(clock)
	repo := domain.Repo{ID: 1, Name: "alice", Ecosystem: "apt"}
	control := "Package: foo\nVersion: 1.0-1\nArchitecture: amd64\nDescription: test\n"
	debKey := putDeb(t, storage, repo, "pool/main/f/foo.deb", control)

	g := &Generator{}
	if err := g.GenerateIndexes(context.Background(), repo, storage, nil); err != nil {
		t.Fatalf("GenerateIndexes: %v", err)
	}

	// Packages: одна stanza с mandatory полями Filename/Size/SHA256.
	pkg := readStorage(t, storage, "repo/1/apt/dists/stable/main/binary-amd64/packages")
	if !strings.Contains(string(pkg), "Package: foo\n") {
		t.Errorf("Packages не содержит Package: foo\n:\n%s", pkg)
	}
	if !strings.Contains(string(pkg), "Version: 1.0-1") {
		t.Errorf("Packages не содержит Version: %s", pkg)
	}
	// Filename: путь внутри репо (pool/main/f/foo.deb).
	if !strings.Contains(string(pkg), "Filename: pool/main/f/foo.deb\n") {
		t.Errorf("Packages не содержит Filename: %s", pkg)
	}
	// Size: из Meta (длина байт .deb).
	debBytes := readStorage(t, storage, debKey)
	wantSize := fmt.Sprintf("Size: %d\n", len(debBytes))
	if !strings.Contains(string(pkg), wantSize) {
		t.Errorf("Packages не содержит %s: %s", wantSize, pkg)
	}
	// SHA256: hex 64 символа.
	wantSha, _ := buildDeb(t, control)
	sha := sha256.Sum256(debBytes)
	wantShaLine := "SHA256: " + hex.EncodeToString(sha[:]) + "\n"
	if !strings.Contains(string(pkg), wantShaLine) {
		t.Errorf("Packages не содержит %s: %s", wantShaLine, pkg)
	}
	_ = wantSha // suppress unused if buildDeb second return not needed

	// Packages.gz: gzip-сжатая версия Packages.
	pkgGz := readStorage(t, storage, "repo/1/apt/dists/stable/main/binary-amd64/packages.gz")
	gz, err := gzip.NewReader(bytes.NewReader(pkgGz))
	if err != nil {
		t.Fatalf("gzip.NewReader Packages.gz: %v", err)
	}
	unpacked, _ := io.ReadAll(gz)
	if !bytes.Equal(unpacked, pkg) {
		t.Errorf("Packages.gz распакованный не равен Packages: want %q got %q", pkg, unpacked)
	}

	// by-hash/sha256/<sha-of-Packages>: должен существовать и совпадать с Packages.
	pkgSha := sha256.Sum256(pkg)
	byHashKey := "repo/1/apt/dists/stable/main/binary-amd64/by-hash/sha256/" + hex.EncodeToString(pkgSha[:])
	if !bytes.Equal(readStorage(t, storage, byHashKey), pkg) {
		t.Errorf("by-hash/packages не совпадает с packages")
	}

	pkgGzSha := sha256.Sum256(pkgGz)
	byHashGzKey := "repo/1/apt/dists/stable/main/binary-amd64/by-hash/sha256/" + hex.EncodeToString(pkgGzSha[:])
	if !bytes.Equal(readStorage(t, storage, byHashGzKey), pkgGz) {
		t.Errorf("by-hash/packages.gz не совпадает с packages.gz")
	}

	// Release: содержит Date, Suite, Components, Architectures, Codename,
	// Acquire-By-Hash и SHA256-блок с packages и packages.gz.
	release := readStorage(t, storage, "repo/1/apt/dists/stable/release")
	rStr := string(release)
	for _, want := range []string{
		"Suite: stable\n",
		"Components: main\n",
		"Architectures: amd64\n",
		"Codename: stable\n",
		"Acquire-By-Hash: yes\n",
		"SHA256:\n",
		fmt.Sprintf(" %s %8d main/binary-amd64/Packages\n", hex.EncodeToString(pkgSha[:]), len(pkg)),
		fmt.Sprintf(" %s %8d main/binary-amd64/Packages.gz\n", hex.EncodeToString(pkgGzSha[:]), len(pkgGz)),
	} {
		if !strings.Contains(rStr, want) {
			t.Errorf("Release не содержит %q:\n%s", want, rStr)
		}
	}
}

func TestGenerateIndexesMultipleDebs(t *testing.T) {
	moment := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	storage := testutil.NewFakeStorage(testutil.FixedClock(moment))
	repo := domain.Repo{ID: 1, Name: "alice", Ecosystem: "apt"}
	putDeb(t, storage, repo, "pool/main/f/foo.deb", "Package: foo\nVersion: 1.0-1\nArchitecture: amd64\nDescription: foo\n")
	putDeb(t, storage, repo, "pool/main/b/bar.deb", "Package: bar\nVersion: 2.0\nArchitecture: amd64\nDescription: bar\n")
	putDeb(t, storage, repo, "pool/main/b/baz.deb", "Package: baz\nVersion: 3.0\nArchitecture: amd64\nDescription: baz\n")

	g := &Generator{}
	if err := g.GenerateIndexes(context.Background(), repo, storage, nil); err != nil {
		t.Fatalf("GenerateIndexes: %v", err)
	}

	pkg := readStorage(t, storage, "repo/1/apt/dists/stable/main/binary-amd64/packages")
	// По одной stanza на пакет, лексический порядок по пути .deb:
	// bar, baz, foo (pool/main/b/bar < pool/main/b/baz < pool/main/f/foo).
	fooIdx := strings.Index(string(pkg), "Package: foo\n")
	barIdx := strings.Index(string(pkg), "Package: bar\n")
	bazIdx := strings.Index(string(pkg), "Package: baz\n")
	if fooIdx < 0 || barIdx < 0 || bazIdx < 0 {
		t.Fatalf("не все пакеты в Packages:\n%s", pkg)
	}
	if !(barIdx < bazIdx && bazIdx < fooIdx) {
		t.Errorf("порядок пакетов не лексический (bar<baz<foo): bar=%d baz=%d foo=%d", barIdx, bazIdx, fooIdx)
	}
}

func TestGenerateIndexesEmptyRepo(t *testing.T) {
	moment := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	storage := testutil.NewFakeStorage(testutil.FixedClock(moment))
	repo := domain.Repo{ID: 1, Name: "alice", Ecosystem: "apt"}

	g := &Generator{}
	if err := g.GenerateIndexes(context.Background(), repo, storage, nil); err != nil {
		t.Fatalf("GenerateIndexes для пустого репо: %v", err)
	}

	// Пустой Packages (0 байт) + пустой Packages.gz + Release.
	pkg := readStorage(t, storage, "repo/1/apt/dists/stable/main/binary-amd64/packages")
	if len(pkg) != 0 {
		t.Errorf("Packages для пустого репо не пустой: %d байт", len(pkg))
	}
	pkgGz := readStorage(t, storage, "repo/1/apt/dists/stable/main/binary-amd64/packages.gz")
	gz, err := gzip.NewReader(bytes.NewReader(pkgGz))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	unpacked, _ := io.ReadAll(gz)
	if len(unpacked) != 0 {
		t.Errorf("Packages.gz распакованный не пустой: %d байт", len(unpacked))
	}
	// Release существует (не 404 на чтение).
	_ = readStorage(t, storage, "repo/1/apt/dists/stable/release")
}

func TestGenerateIndexesWrongEcosystem(t *testing.T) {
	moment := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	storage := testutil.NewFakeStorage(testutil.FixedClock(moment))
	repo := domain.Repo{ID: 1, Name: "alice", Ecosystem: "rpm-md"}

	g := &Generator{}
	err := g.GenerateIndexes(context.Background(), repo, storage, nil)
	var unsup *domain.UnsupportedError
	if !errors.As(err, &unsup) {
		t.Fatalf("ожидали UnsupportedError, получили %v", err)
	}
}

// TestGenerateIndexesProgressRecords — Progress-вызовы идут по фазам
// и прогрессу; recording-двойник ловит кадры, чтобы убедиться, что
// p.Update вызывается на каждой фазе.
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
	repo := domain.Repo{ID: 1, Name: "alice", Ecosystem: "apt"}
	putDeb(t, storage, repo, "pool/main/f/foo.deb", "Package: foo\nVersion: 1.0\nArchitecture: amd64\nDescription: f\n")

	g := &Generator{}
	rec := &recordingProgress{}
	if err := g.GenerateIndexes(context.Background(), repo, storage, rec); err != nil {
		t.Fatalf("GenerateIndexes: %v", err)
	}
	// Должны быть update'ы фаз enumerate/control/write.
	phases := make(map[string]bool)
	for _, u := range rec.updates {
		phases[strings.SplitN(u, "/", 2)[0]] = true
	}
	for _, want := range []string{"enumerate", "control", "write"} {
		if !phases[want] {
			t.Errorf("фаза %s не отработала в прогрессе: %v", want, rec.updates)
		}
	}
	if !slices.ContainsFunc(rec.logs, func(s string) bool { return strings.Contains(s, "индексы записаны") }) {
		t.Errorf("нет строки завершения в логе: %v", rec.logs)
	}
}

// fakeSigner — port.Signer на настоящем openpgp-ключе (roundtrip через
// go-crypto), но без файлового keys_dir: ключ живёт в памяти. Создаётся
// через openpgp.NewEntity напрямую — генератору метаданных всё равно,
// как ключ получен; проверяем именно формат InRelease/Release.gpg и
// валидность подписи под публичным ключом из PublicKey().
type fakeSigner struct {
	entity *gp.Entity
	cfg    *packet.Config
	pub    []byte
}

func newFakeSigner(t *testing.T) *fakeSigner {
	t.Helper()
	cfg := &packet.Config{
		Algorithm:   packet.PubKeyAlgoEd25519,
		DefaultHash: crypto.SHA256,
	}
	e, err := gp.NewEntity("fake", "", "fake@example", cfg)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	var buf bytes.Buffer
	aw, err := armor.Encode(&buf, "PGP PUBLIC KEY BLOCK", nil)
	if err != nil {
		t.Fatalf("armor encode: %v", err)
	}
	if err := e.Serialize(aw); err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	_ = aw.Close()
	return &fakeSigner{entity: e, cfg: cfg, pub: buf.Bytes()}
}

func (f *fakeSigner) Sign(_ context.Context, input io.Reader) (io.Reader, error) {
	data, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w, err := clearsign.Encode(&buf, f.entity.PrivateKey, f.cfg)
	if err != nil {
		return nil, err
	}
	_, _ = w.Write(data)
	_ = w.Close()
	return &buf, nil
}

func (f *fakeSigner) SignDetached(_ context.Context, input io.Reader) (io.Reader, error) {
	var buf bytes.Buffer
	if err := gp.DetachSign(&buf, f.entity, input, f.cfg); err != nil {
		return nil, err
	}
	return &buf, nil
}

func (f *fakeSigner) PublicKey() ([]byte, error) {
	out := make([]byte, len(f.pub))
	copy(out, f.pub)
	return out, nil
}

func (f *fakeSigner) keyring() gp.EntityList {
	el, err := gp.ReadArmoredKeyRing(bytes.NewReader(f.pub))
	if err != nil {
		panic(err)
	}
	return el
}

func TestGenerateIndexesUnsigned_NoSignatureFiles(t *testing.T) {
	// Без Signer InRelease/Release.gpg НЕ создаются — обратная
	// совместимость с тестами/конфигами без ключа.
	moment := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	storage := testutil.NewFakeStorage(testutil.FixedClock(moment))
	repo := domain.Repo{ID: 1, Name: "alice", Ecosystem: "apt"}
	putDeb(t, storage, repo, "pool/main/f/foo.deb", "Package: foo\nVersion: 1.0\nArchitecture: amd64\nDescription: f\n")

	g := &Generator{}
	if err := g.GenerateIndexes(context.Background(), repo, storage, nil); err != nil {
		t.Fatalf("GenerateIndexes: %v", err)
	}
	for _, key := range []string{
		"repo/1/apt/dists/stable/inrelease",
		"repo/1/apt/dists/stable/release.gpg",
	} {
		if _, err := storage.Get(context.Background(), key); err == nil {
			t.Errorf("без Signer создан %s", key)
		}
	}
}

func TestGenerateIndexesSigned_InReleaseAndReleaseGpg(t *testing.T) {
	moment := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	storage := testutil.NewFakeStorage(testutil.FixedClock(moment))
	repo := domain.Repo{ID: 1, Name: "alice", Ecosystem: "apt"}
	putDeb(t, storage, repo, "pool/main/f/foo.deb", "Package: foo\nVersion: 1.0\nArchitecture: amd64\nDescription: f\n")

	signer := newFakeSigner(t)
	g := &Generator{signer: signer}
	if err := g.GenerateIndexes(context.Background(), repo, storage, nil); err != nil {
		t.Fatalf("GenerateIndexes: %v", err)
	}

	release := readStorage(t, storage, "repo/1/apt/dists/stable/release")
	kring := signer.keyring()

	// InRelease: cleartext-подпись Release; verify под публичным ключом.
	inRel := readStorage(t, storage, "repo/1/apt/dists/stable/inrelease")
	if !strings.Contains(string(inRel), "BEGIN PGP SIGNED MESSAGE") {
		t.Errorf("InRelease не cleartext:\n%s", inRel)
	}
	block, _ := clearsign.Decode(inRel)
	if block == nil {
		t.Fatal("clearsign.Decode InRelease nil")
	}
	want := bytes.ReplaceAll(release, []byte("\n"), []byte("\r\n"))
	if string(block.Bytes) != string(want) {
		t.Errorf("InRelease payload ≠ Release (CRLF-каноникализed):\nwant %q\ngot  %q", want, block.Bytes)
	}
	if _, err := block.VerifySignature(kring, &packet.Config{}); err != nil {
		t.Errorf("InRelease verify: %v", err)
	}

	// Release.gpg: бинарная detached-подпись Release; verify под ключом.
	relGpg := readStorage(t, storage, "repo/1/apt/dists/stable/release.gpg")
	if strings.Contains(string(relGpg), "BEGIN PGP") {
		t.Errorf("Release.gpg должен быть бинарным, не armored")
	}
	if _, err := gp.CheckDetachedSignature(kring, bytes.NewReader(release), bytes.NewReader(relGpg), &packet.Config{}); err != nil {
		t.Errorf("Release.gpg verify: %v", err)
	}

	// Подпись не должна совпадать с подписью ДРУГОГО Release (тампа):
	// CheckDetachedSignature для подменённого payload обязана падать.
	tampered := bytes.Replace(release, []byte("Suite: stable"), []byte("Suite: evil1"), 1)
	if _, err := gp.CheckDetachedSignature(kring, bytes.NewReader(tampered), bytes.NewReader(relGpg), &packet.Config{}); err == nil {
		t.Error("ожидалась ошибка verify для tampered Release")
	}
}

func TestGenerateIndexesSigned_ProgressHasSignPhase(t *testing.T) {
	moment := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	storage := testutil.NewFakeStorage(testutil.FixedClock(moment))
	repo := domain.Repo{ID: 1, Name: "alice", Ecosystem: "apt"}
	putDeb(t, storage, repo, "pool/main/f/foo.deb", "Package: foo\nVersion: 1.0\nArchitecture: amd64\nDescription: f\n")

	g := &Generator{signer: newFakeSigner(t)}
	rec := &recordingProgress{}
	if err := g.GenerateIndexes(context.Background(), repo, storage, rec); err != nil {
		t.Fatalf("GenerateIndexes: %v", err)
	}
	phases := make(map[string]bool)
	for _, u := range rec.updates {
		phases[strings.SplitN(u, "/", 2)[0]] = true
	}
	if !phases["sign"] {
		t.Errorf("фаза sign не отработала: %v", rec.updates)
	}
	if !slices.ContainsFunc(rec.logs, func(s string) bool { return strings.Contains(s, "подписаны") }) {
		t.Errorf("нет строки подписи в логе: %v", rec.logs)
	}
}

// errSignFail — синтетическая ошибка подписчика для error-веток генератора.
var errSignFail = errors.New("synthetic signer failure")

type failSigner struct{}

func (failSigner) Sign(context.Context, io.Reader) (io.Reader, error) { return nil, errSignFail }
func (failSigner) SignDetached(context.Context, io.Reader) (io.Reader, error) {
	return nil, errSignFail
}
func (failSigner) PublicKey() ([]byte, error) { return nil, nil }

// detachFailSigner: Sign ок (настоящем ключе), SignDetached падает —
// чтобы покрыть error-ветку Release.gpg отдельно от InRelease.
type detachFailSigner struct{ inner *fakeSigner }

func (d detachFailSigner) Sign(ctx context.Context, r io.Reader) (io.Reader, error) {
	return d.inner.Sign(ctx, r)
}
func (detachFailSigner) SignDetached(context.Context, io.Reader) (io.Reader, error) {
	return nil, errSignFail
}
func (d detachFailSigner) PublicKey() ([]byte, error) { return d.inner.PublicKey() }

func TestGenerateIndexesSigned_SignerSignErrorFails(t *testing.T) {
	moment := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	storage := testutil.NewFakeStorage(testutil.FixedClock(moment))
	repo := domain.Repo{ID: 1, Name: "alice", Ecosystem: "apt"}
	putDeb(t, storage, repo, "pool/main/f/foo.deb", "Package: foo\nVersion: 1.0\nArchitecture: amd64\nDescription: f\n")

	g := &Generator{signer: failSigner{}}
	err := g.GenerateIndexes(context.Background(), repo, storage, nil)
	if err == nil || !errors.Is(err, errSignFail) {
		t.Fatalf("ожидалась errSignFail из Sign, got %v", err)
	}
}

func TestGenerateIndexesSigned_SignerDetachErrorFails(t *testing.T) {
	moment := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	storage := testutil.NewFakeStorage(testutil.FixedClock(moment))
	repo := domain.Repo{ID: 1, Name: "alice", Ecosystem: "apt"}
	putDeb(t, storage, repo, "pool/main/f/foo.deb", "Package: foo\nVersion: 1.0\nArchitecture: amd64\nDescription: f\n")

	g := &Generator{signer: detachFailSigner{inner: newFakeSigner(t)}}
	err := g.GenerateIndexes(context.Background(), repo, storage, nil)
	if err == nil || !errors.Is(err, errSignFail) {
		t.Fatalf("ожидалась errSignFail из SignDetached, got %v", err)
	}
}

// TestArReaderNegativeSize — отрицательный размер члена ar —
// синтаксическая ошибка заголовка, а не «пустой член»: молчаливый EOF
// рассинхронизировал бы поток, и следующий «заголовок» читался из мусора.
func TestArReaderNegativeSize(t *testing.T) {
	var ar bytes.Buffer
	ar.WriteString("!<arch>\n")
	fmt.Fprintf(&ar, "%-16s%-12d%-6d%-6d%-8o%-10d`\n", "debian-binary/", 0, 0, 0, 0o100644, -5)
	_, err := readControl(bytes.NewReader(ar.Bytes()))
	if err == nil || !strings.Contains(err.Error(), "отрицательный размер") {
		t.Fatalf("ожидали ошибку отрицательного размера члена, получили %v", err)
	}
}

// lieDelta — насколько lyingMetaStorage врёт в Meta.Size.
const lieDelta = 999

// lyingMetaStorage — FakeStorage с завышенным Meta.Size у Get (байты
// тела честные). Проверяет, что генератор не доверяет метаданным.
type lyingMetaStorage struct {
	*testutil.FakeStorage
}

func (l *lyingMetaStorage) Get(ctx context.Context, key string) (port.Object, error) {
	obj, err := l.FakeStorage.Get(ctx, key)
	if err != nil {
		return obj, err
	}
	obj.Size += lieDelta
	return obj, nil
}

// TestGenerateIndexesHonestSize — Size в Packages берётся из фактических
// байт .deb (счётчик tee), а не из Meta.Size хранилища: если метаданные
// солгали, чексумма верна, а size — нет, и apt падает на сверке.
func TestGenerateIndexesHonestSize(t *testing.T) {
	moment := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	storage := testutil.NewFakeStorage(testutil.FixedClock(moment))
	repo := domain.Repo{ID: 1, Name: "alice", Ecosystem: "apt"}
	debKey := putDeb(t, storage, repo, "pool/main/f/foo.deb", "Package: foo\nVersion: 1.0\nArchitecture: amd64\nDescription: f\n")
	debBytes := readStorage(t, storage, debKey)

	g := &Generator{}
	if err := g.GenerateIndexes(context.Background(), repo, &lyingMetaStorage{FakeStorage: storage}, nil); err != nil {
		t.Fatalf("GenerateIndexes: %v", err)
	}
	pkg := string(readStorage(t, storage, "repo/1/apt/dists/stable/main/binary-amd64/packages"))
	if !strings.Contains(pkg, fmt.Sprintf("Size: %d\n", len(debBytes))) {
		t.Errorf("Packages не содержит фактический Size %d:\n%s", len(debBytes), pkg)
	}
	if strings.Contains(pkg, fmt.Sprintf("Size: %d\n", len(debBytes)+lieDelta)) {
		t.Errorf("Packages взял Size из Meta.Size:\n%s", pkg)
	}
}

func TestSetSigner(t *testing.T) {
	g := &Generator{}
	if g.signer != nil {
		t.Fatal("новый Generator уже имеет signer")
	}
	s := newFakeSigner(t)
	g.SetSigner(s)
	if g.signer != s {
		t.Error("SetSigner не сохранил signer")
	}
}

// errListFail — синтетический сбой листинга (недоступный каталог fs /
// битый s3-endpoint; сами носители отдают его через Storage.List).
var errListFail = errors.New("synthetic listing failure")

// failingListStorage — FakeStorage с отказом List: Get/Put честные,
// перечисление падает. Проверяет fail-closed генератора изолированно
// от носителя.
type failingListStorage struct {
	*testutil.FakeStorage
	err error
}

func (f *failingListStorage) List(_ context.Context, _ string) iter.Seq2[port.Meta, error] {
	return func(yield func(port.Meta, error) bool) {
		yield(port.Meta{}, f.err)
	}
}

// TestGenerateIndexesListingErrorKeepsOldIndexes — при ошибке листинга
// генерация падает, прежний индекс остаётся байт-в-байт (fail-closed:
// транзиентный сбой носителя не «опустошает» репо).
func TestGenerateIndexesListingErrorKeepsOldIndexes(t *testing.T) {
	moment := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	storage := testutil.NewFakeStorage(testutil.FixedClock(moment))
	repo := domain.Repo{ID: 1, Name: "alice", Ecosystem: "apt"}
	putDeb(t, storage, repo, "pool/main/f/foo.deb", "Package: foo\nVersion: 1.0\nArchitecture: amd64\nDescription: f\n")

	g := &Generator{}
	if err := g.GenerateIndexes(context.Background(), repo, storage, nil); err != nil {
		t.Fatalf("первая генерация: %v", err)
	}
	const packagesKey = "repo/1/apt/dists/stable/main/binary-amd64/packages"
	before := readStorage(t, storage, packagesKey)

	broken := &failingListStorage{FakeStorage: storage, err: errListFail}
	err := g.GenerateIndexes(context.Background(), repo, broken, nil)
	if err == nil || !errors.Is(err, errListFail) {
		t.Fatalf("ожидали errListFail из листинга, получено %v", err)
	}
	after := readStorage(t, storage, packagesKey)
	if !bytes.Equal(before, after) {
		t.Fatal("ошибка листинга перезаписала валидный Packages (не fail-closed)")
	}
}

// putDebZstd складывает .deb с zstd control.tar (buildDebZstd) под
// префиксом repo/<id>/apt. Возвращает ключ.
func putDebZstd(t *testing.T, storage *testutil.FakeStorage, repo domain.Repo, name, control string) string {
	t.Helper()
	deb := buildDebZstd(t, control)
	key := port.RepoPrefix(repo) + "/" + name
	w, err := storage.Put(context.Background(), key)
	if err != nil {
		t.Fatalf("storage.Put %s: %v", key, err)
	}
	if _, err := w.Write(deb); err != nil {
		t.Fatalf("w.Write %s: %v", key, err)
	}
	if err := w.Commit(context.Background()); err != nil {
		t.Fatalf("w.Commit %s: %v", key, err)
	}
	return key
}

// TestGenerateIndexesZstdControlNoGoroutineLeak — N .deb с zstd
// control.tar: после GenerateIndexes число горутин возвращается к
// базовому. decompressControl обязан отдавать ReadCloser, readControl —
// закрывать: klauspost/compress держит worker-горутины декодера до
// Close, без него — монотонная утечка на каждом .deb каждой регенерации.
func TestGenerateIndexesZstdControlNoGoroutineLeak(t *testing.T) {
	moment := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	storage := testutil.NewFakeStorage(testutil.FixedClock(moment))
	repo := domain.Repo{ID: 1, Name: "alice", Ecosystem: "apt"}
	control := "Package: foo\nVersion: 1.0\nArchitecture: amd64\nDescription: f\n"
	for i := range 8 {
		putDebZstd(t, storage, repo, fmt.Sprintf("pool/main/f/foo%d.deb", i), control)
	}

	base := runtime.NumGoroutine()
	g := &Generator{}
	if err := g.GenerateIndexes(context.Background(), repo, storage, nil); err != nil {
		t.Fatalf("GenerateIndexes: %v", err)
	}
	// Шум рантайма (GC, финализаторы, тестовый фреймворк) допускаем:
	// ждём до 2с возврата к базе с допуском ±2 горутины.
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > base+2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > base+2 {
		t.Fatalf("горутины утекли: база %d, после GenerateIndexes %d", base, n)
	}
}
