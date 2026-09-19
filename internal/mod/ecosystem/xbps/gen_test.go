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

package xbps

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/testutil"
)

// miniProps — props.plist минимального, но валидного пакета xbps.
func miniProps(pkgname, pkgver, arch string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>pkgname</key>
	<string>` + pkgname + `</string>
	<key>pkgver</key>
	<string>` + pkgver + `</string>
	<key>architecture</key>
	<string>` + arch + `</string>
	<key>short_desc</key>
	<string>` + pkgname + ` package</string>
</dict>
</plist>
`
}

// testRsaSigner — port.RsaSigner поверх маленького ключа (1024): тест
// не тянет mod/sign/rsasha256 (mod→mod запрещён depguard'ом), но
// повторяет контракт: длина подписи — модуль ключа, ключ — SPKI-PEM.
type testRsaSigner struct {
	priv   *rsa.PrivateKey
	pubPEM []byte
}

func newTestRsaSigner(t *testing.T) *testRsaSigner {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return &testRsaSigner{
		priv:   priv,
		pubPEM: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}),
	}
}

func (s *testRsaSigner) SignSHA256(_ context.Context, digest []byte) ([]byte, error) {
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("дайджест длиной %d, хочу %d", len(digest), sha256.Size)
	}
	return rsa.SignPKCS1v15(nil, s.priv, crypto.SHA256, digest)
}

func (s *testRsaSigner) PublicKeyPEM() ([]byte, error) {
	out := make([]byte, len(s.pubPEM))
	copy(out, s.pubPEM)
	return out, nil
}

// putXbps складывает zstd-пакет с заданным props.plist в FakeStorage и
// возвращает байты файла (для сверки sha256/размера).
func putXbps(t *testing.T, storage *testutil.FakeStorage, repo domain.Repo, name, propsXML string) []byte {
	t.Helper()
	raw := buildArPkg(t, arMemberSpec{"./props.plist", []byte(propsXML)})
	body := compressPackage(t, "zstd", raw)
	key := port.RepoPrefix(repo) + "/" + name
	w, err := storage.Put(context.Background(), key)
	if err != nil {
		t.Fatalf("storage.Put %s: %v", key, err)
	}
	if _, err := w.Write(body); err != nil {
		t.Fatalf("w.Write %s: %v", key, err)
	}
	if err := w.Commit(context.Background()); err != nil {
		t.Fatalf("w.Commit %s: %v", key, err)
	}
	return body
}

// readKey читает зафиксированный объект из FakeStorage.
func readKey(t *testing.T, storage *testutil.FakeStorage, key string) []byte {
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

// readIndex разворачивает `<arch>-repodata` (парсер 131) и собирает
// записи index.plist (парсер 132) — верификация «генератор → парсер».
func readIndex(t *testing.T, storage *testutil.FakeStorage, key string) []IndexEntry {
	t.Helper()
	raw := readKey(t, storage, key)
	index, closeFn, err := OpenRepoData(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("OpenRepoData %s: %v", key, err)
	}
	var got []IndexEntry
	if err := ParseIndexPlist(index, func(e IndexEntry) error {
		got = append(got, e)
		return nil
	}); err != nil {
		t.Fatalf("ParseIndexPlist %s: %v", key, err)
	}
	if _, err := closeFn(); err != nil {
		t.Fatalf("closeFn %s: %v", key, err)
	}
	return got
}

// entriesByName индексирует записи по pkgname.
func entriesByName(entries []IndexEntry) map[string]IndexEntry {
	out := make(map[string]IndexEntry, len(entries))
	for _, e := range entries {
		out[e.PkgName] = e
	}
	return out
}

// readMeta разворачивает repodata и разбирает index-meta.plist в карту
// «ключ plist → текст значения» (ключ plist — содержимое <key>, не имя
// элемента: struct-теги encoding/xml тут не подходят).
func readMeta(t *testing.T, storage *testutil.FakeStorage, key string) map[string]string {
	t.Helper()
	raw := readKey(t, storage, key)
	index, closeFn, err := OpenRepoData(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("OpenRepoData %s: %v", key, err)
	}
	if _, err := io.Copy(io.Discard, index); err != nil {
		t.Fatalf("чтение index %s: %v", key, err)
	}
	meta, err := closeFn()
	if err != nil {
		t.Fatalf("closeFn %s: %v", key, err)
	}
	return parsePlistDict(t, meta)
}

// parsePlistDict разбирает плоский plist-словарь в карту ключ→значение.
func parsePlistDict(t *testing.T, raw []byte) map[string]string {
	t.Helper()
	dec := xml.NewDecoder(bytes.NewReader(raw))
	out := map[string]string{}
	var key string
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("разбор meta: %v (raw=%q)", err, raw)
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name.Local {
		case "key":
			key = chardata(t, dec)
		case "string", "data", "integer":
			if key != "" {
				out[key] = chardata(t, dec)
				key = ""
			}
		}
	}
}

// chardata читает текст элемента до его закрытия.
func chardata(t *testing.T, dec *xml.Decoder) string {
	t.Helper()
	var b strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			t.Fatalf("char-data: %v", err)
		}
		switch v := tok.(type) {
		case xml.CharData:
			b.Write(v)
		case xml.EndElement:
			return b.String()
		}
	}
}

func newRepo(t *testing.T) (*testutil.FakeStorage, domain.Repo) {
	t.Helper()
	moment := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	storage := testutil.NewFakeStorage(testutil.FixedClock(moment))
	return storage, domain.Repo{ID: 1, Name: "alice", Ecosystem: Name}
}

// TestGenerateIndexesGroupsAndSigns — главный контракт: 2 x86_64 + 1
// noarch + 1 aarch64 → два repodata, noarch в обоих, `.sig2` на каждый
// пакет, подпись верифицируется публичным ключом из index-meta.
func TestGenerateIndexesGroupsAndSigns(t *testing.T) {
	storage, repo := newRepo(t)
	signer := newTestRsaSigner(t)

	type pkgFixture struct {
		name, pkgname, pkgver, arch string
	}
	fixtures := []pkgFixture{
		{"foo-1.0_1.x86_64.xbps", "foo", "foo-1.0_1", "x86_64"},
		{"bar-2.0_1.x86_64.xbps", "bar", "bar-2.0_1", "x86_64"},
		{"python3-pip-24.2_1.noarch.xbps", "python3-pip", "python3-pip-24.2_1", noarchArch},
		{"qux-3.0_1.aarch64.xbps", "qux", "qux-3.0_1", "aarch64"},
	}
	bodies := map[string][]byte{}
	for _, f := range fixtures {
		bodies[f.name] = putXbps(t, storage, repo, f.name, miniProps(f.pkgname, f.pkgver, f.arch))
	}

	g := &Generator{}
	g.SetRsaSigner(signer)
	if err := g.GenerateIndexes(context.Background(), repo, storage, nil); err != nil {
		t.Fatalf("GenerateIndexes: %v", err)
	}

	// Группировка: x86_64 — foo+bar+noarch, aarch64 — qux+noarch.
	x86 := entriesByName(readIndex(t, storage, "repo/1/xbps/x86_64-repodata"))
	aarch := entriesByName(readIndex(t, storage, "repo/1/xbps/aarch64-repodata"))
	if len(x86) != 3 {
		t.Errorf("x86_64: %d записей, хочу 3 (%v)", len(x86), x86)
	}
	if len(aarch) != 2 {
		t.Errorf("aarch64: %d записей, хочу 2 (%v)", len(aarch), aarch)
	}
	for _, archEntries := range []map[string]IndexEntry{x86, aarch} {
		entry, ok := archEntries["python3-pip"]
		if !ok {
			t.Errorf("noarch-пакет отсутствует в группе: %v", archEntries)
			continue
		}
		if entry.Architecture != noarchArch {
			t.Errorf("noarch: architecture = %q", entry.Architecture)
		}
	}

	// index-meta: наш публичный ключ (base64 PEM), размер 1024, маркеры.
	meta := readMeta(t, storage, "repo/1/xbps/x86_64-repodata")
	pub, err := signer.PublicKeyPEM()
	if err != nil {
		t.Fatalf("PublicKeyPEM: %v", err)
	}
	gotPEM, err := base64.StdEncoding.DecodeString(meta["public-key"])
	if err != nil {
		t.Fatalf("декод public-key: %v", err)
	}
	if !bytes.Equal(gotPEM, pub) {
		t.Errorf("public-key не совпал с PublicKeyPEM")
	}
	if meta["public-key-size"] != "1024" {
		t.Errorf("public-key-size = %q, хочу 1024", meta["public-key-size"])
	}
	if meta["signature-by"] != signatureBy || meta["signature-type"] != signatureType {
		t.Errorf("signature-by/type = %q/%q", meta["signature-by"], meta["signature-type"])
	}

	// filename-sha256/размер и подпись каждого пакета.
	for _, f := range fixtures {
		body := bodies[f.name]
		digest := sha256.Sum256(body)
		entry, ok := x86[f.pkgname]
		if f.arch == "aarch64" {
			entry, ok = aarch[f.pkgname]
		}
		if !ok {
			t.Errorf("%s: записи нет в индексе", f.pkgname)
			continue
		}
		if entry.FilenameSHA256 != fmt.Sprintf("%x", digest) {
			t.Errorf("%s: filename-sha256 = %q", f.pkgname, entry.FilenameSHA256)
		}
		if entry.FilenameSize != int64(len(body)) {
			t.Errorf("%s: filename-size = %d, хочу %d", f.pkgname, entry.FilenameSize, len(body))
		}
		sig := readKey(t, storage, "repo/1/xbps/"+f.name+".sig2")
		if err := rsa.VerifyPKCS1v15(&signer.priv.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
			t.Errorf("%s: подпись не верифицируется: %v", f.name, err)
		}
	}
}

// TestGenerateIndexesIdempotent — повторный reindex даёт байт-в-байт те
// же repodata (детерминизм writer'а 140) и те же .sig2 (PKCS#1 v1.5
// детерминирован).
func TestGenerateIndexesIdempotent(t *testing.T) {
	storage, repo := newRepo(t)
	signer := newTestRsaSigner(t)
	putXbps(t, storage, repo, "foo-1.0_1.x86_64.xbps", miniProps("foo", "foo-1.0_1", "x86_64"))
	putXbps(t, storage, repo, "python3-pip-24.2_1.noarch.xbps", miniProps("python3-pip", "python3-pip-24.2_1", noarchArch))

	g := &Generator{rsa: signer}
	if err := g.GenerateIndexes(context.Background(), repo, storage, nil); err != nil {
		t.Fatalf("первый reindex: %v", err)
	}
	firstRepodata := readKey(t, storage, "repo/1/xbps/x86_64-repodata")
	firstSig := readKey(t, storage, "repo/1/xbps/foo-1.0_1.x86_64.xbps.sig2")

	if err := g.GenerateIndexes(context.Background(), repo, storage, nil); err != nil {
		t.Fatalf("второй reindex: %v", err)
	}
	if got := readKey(t, storage, "repo/1/xbps/x86_64-repodata"); !bytes.Equal(got, firstRepodata) {
		t.Error("repodata не детерминирован между reindex")
	}
	if got := readKey(t, storage, "repo/1/xbps/foo-1.0_1.x86_64.xbps.sig2"); !bytes.Equal(got, firstSig) {
		t.Error(".sig2 не детерминирован между reindex")
	}
}

// TestGenerateIndexesFilenameMismatch — имя файла ≠ pkgver.arch.xbps:
// честная ValidationError задачи с именем файла.
func TestGenerateIndexesFilenameMismatch(t *testing.T) {
	storage, repo := newRepo(t)
	putXbps(t, storage, repo, "mismatch-9.9_9.x86_64.xbps", miniProps("foo", "foo-1.0_1", "x86_64"))

	err := (&Generator{}).GenerateIndexes(context.Background(), repo, storage, nil)
	var ve *domain.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("ошибка %v, хочу *domain.ValidationError", err)
	}
	if !strings.Contains(ve.Value, "mismatch") {
		t.Errorf("ValidationError.Value = %q, хочу имя файла", ve.Value)
	}
}

// TestGenerateIndexesBadPackage — битый .xbps (не ar) валит задачу.
func TestGenerateIndexesBadPackage(t *testing.T) {
	storage, repo := newRepo(t)
	key := "repo/1/xbps/foo-1.0_1.x86_64.xbps"
	w, err := storage.Put(context.Background(), key)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := w.Write([]byte("this is not an xbps package")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Commit(context.Background()); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	err = (&Generator{}).GenerateIndexes(context.Background(), repo, storage, nil)
	if !errors.Is(err, ErrBadAr) {
		t.Fatalf("ошибка %v, хочу ErrBadAr", err)
	}
}

// TestGenerateIndexesUnsignedNoSig — без RsaSigner индексы есть, .sig2
// нет, index-meta пуст (деградация образца apk nil-Signer).
func TestGenerateIndexesUnsignedNoSig(t *testing.T) {
	storage, repo := newRepo(t)
	putXbps(t, storage, repo, "foo-1.0_1.x86_64.xbps", miniProps("foo", "foo-1.0_1", "x86_64"))

	if err := (&Generator{}).GenerateIndexes(context.Background(), repo, storage, nil); err != nil {
		t.Fatalf("GenerateIndexes: %v", err)
	}
	if _, err := storage.Get(context.Background(), "repo/1/xbps/foo-1.0_1.x86_64.xbps.sig2"); err == nil {
		t.Error("без RsaSigner создан .sig2")
	}
	meta := readMeta(t, storage, "repo/1/xbps/x86_64-repodata")
	if meta["public-key"] != "" {
		t.Errorf("unsigned meta содержит public-key: %q", meta["public-key"])
	}
}

// TestGenerateIndexesEmptyRepo — пустой (только-noarch невозможен без
// нативных arch) репо: ни repodata, ни ошибки.
func TestGenerateIndexesEmptyRepo(t *testing.T) {
	storage, repo := newRepo(t)
	if err := (&Generator{}).GenerateIndexes(context.Background(), repo, storage, nil); err != nil {
		t.Fatalf("GenerateIndexes пустой репо: %v", err)
	}
	if _, err := storage.Get(context.Background(), "repo/1/xbps/x86_64-repodata"); err == nil {
		t.Error("пустой репо дал repodata")
	}
}

// TestGenerateIndexesOnlyNoarchNoRepodata — только noarch-пакеты: нет
// нативной arch-группы, repodata не генерируется (клиенту непригодно).
func TestGenerateIndexesOnlyNoarchNoRepodata(t *testing.T) {
	storage, repo := newRepo(t)
	putXbps(t, storage, repo, "python3-pip-24.2_1.noarch.xbps", miniProps("python3-pip", "python3-pip-24.2_1", noarchArch))
	if err := (&Generator{}).GenerateIndexes(context.Background(), repo, storage, nil); err != nil {
		t.Fatalf("GenerateIndexes: %v", err)
	}
	if _, err := storage.Get(context.Background(), "repo/1/xbps/noarch-repodata"); err == nil {
		t.Error("сгенерирован noarch-repodata (не существует у Void)")
	}
}

// TestGenerateIndexesWrongEcosystem — чужой ecosystem.
func TestGenerateIndexesWrongEcosystem(t *testing.T) {
	storage, _ := newRepo(t)
	repo := domain.Repo{ID: 1, Name: "alice", Ecosystem: "apt"}
	err := (&Generator{}).GenerateIndexes(context.Background(), repo, storage, nil)
	var unsup *domain.UnsupportedError
	if !errors.As(err, &unsup) {
		t.Fatalf("ошибка %v, хочу UnsupportedError", err)
	}
}

// TestGenerateIndexesContextCanceled — отменённый ctx валит задачу (77).
func TestGenerateIndexesContextCanceled(t *testing.T) {
	storage, repo := newRepo(t)
	putXbps(t, storage, repo, "foo-1.0_1.x86_64.xbps", miniProps("foo", "foo-1.0_1", "x86_64"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (&Generator{}).GenerateIndexes(ctx, repo, storage, nil); err == nil {
		t.Fatal("ожидали ошибку отменённого контекста")
	}
}

// recordingProgress ловит кадры Update.
type recordingProgress struct {
	updates []string
	logs    []string
}

func (r *recordingProgress) Update(phase, current string, processed, total int64) {
	r.updates = append(r.updates, fmt.Sprintf("%s/%s/%d/%d", phase, current, processed, total))
}
func (r *recordingProgress) Log(line string) { r.logs = append(r.logs, line) }

func TestGenerateIndexesProgress(t *testing.T) {
	storage, repo := newRepo(t)
	putXbps(t, storage, repo, "foo-1.0_1.x86_64.xbps", miniProps("foo", "foo-1.0_1", "x86_64"))
	rec := &recordingProgress{}
	g := &Generator{rsa: newTestRsaSigner(t)}
	if err := g.GenerateIndexes(context.Background(), repo, storage, rec); err != nil {
		t.Fatalf("GenerateIndexes: %v", err)
	}
	phases := map[string]bool{}
	for _, u := range rec.updates {
		phases[strings.SplitN(u, "/", 2)[0]] = true
	}
	for _, want := range []string{"enumerate", "read", "index", "sign"} {
		if !phases[want] {
			t.Errorf("фаза %s не отработала: %v", want, rec.updates)
		}
	}
}

func TestValidateObjectPath(t *testing.T) {
	g := &Generator{}
	cases := []struct {
		path string
		want bool
	}{
		{"foo-1.0_1.x86_64.xbps", true},
		{"Mustache-4.1_1.x86_64.xbps", true},
		{"python3-pip-24.2_1.noarch.xbps", true},
		{"x86_64-repodata", false},
		{"foo-1.0_1.x86_64.xbps.sig2", false},
		{"dir/foo.xbps", false},
		{"foo.txt", false},
		{"", false},
	}
	for _, c := range cases {
		err := g.ValidateObjectPath(c.path)
		if got := err == nil; got != c.want {
			t.Errorf("ValidateObjectPath(%q) = %v, want ok=%v", c.path, err, c.want)
		}
	}
}

func TestGeneratorName(t *testing.T) {
	if got := (&Generator{}).Name(); got != Name {
		t.Errorf("Name = %q, want %q", got, Name)
	}
}

// TestGeneratorImplementsRepoAdapter / SetRsaSigner — compile-time
// контракт + внедрение подписчика.
var _ port.RepoAdapter = (*Generator)(nil)

func TestSetRsaSigner(t *testing.T) {
	g := &Generator{}
	if g.rsa != nil {
		t.Fatal("новый Generator уже имеет подписчик")
	}
	g.SetRsaSigner(newTestRsaSigner(t))
	if g.rsa == nil {
		t.Error("SetRsaSigner не сохранил подписчик")
	}
}
