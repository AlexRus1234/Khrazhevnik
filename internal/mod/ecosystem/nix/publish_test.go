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
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"iter"
	"slices"
	"strings"
	"testing"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/testutil"
)

// fakeNarSigner — port.NarSigner с детерминированной «подписью».
// Возвращает sig-строку «fake:<pubkey-b64>:<sig-hex>» (трёхполевой
// формат НЕ влияет на инварианты byte-exact — тесты проверяют
// строку как opaque-значение). Крипто-verify по fingerprint —
// TestResignSignsFingerprint_RealEd25519.
type fakeNarSigner struct {
	name string
	pub  string
}

func newFakeNarSigner() *fakeNarSigner {
	// Детерминированный pubkey-маркер для тестов (не реальный ключ —
	// но формат валиден: 32 байта base64).
	return &fakeNarSigner{name: "fake", pub: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
}

func (f *fakeNarSigner) Sign(msg []byte) string {
	// «подпись» = hex(msg) — детерминирована, проверяем в тестах по
	// формату, а не крипто-verify (реальный verify — выше и в ed25519_test).
	return f.name + ":" + f.pub + ":" + hexEncode(msg)
}
func (f *fakeNarSigner) PubKeyB64() string { return f.pub }
func (f *fakeNarSigner) Name() string      { return f.name }

// ed25519Signer — настоящая ed25519-подпись в nix-формате «name:sig»
// (как mod/sign/ed25519.Signer, но локально: mod→mod depguard запрещает
// пакету nix импортировать sign-модуль даже в тестах).
type ed25519Signer struct {
	name string
	priv ed25519.PrivateKey
}

func (s *ed25519Signer) Sign(msg []byte) string {
	return s.name + ":" + base64.StdEncoding.EncodeToString(ed25519.Sign(s.priv, msg))
}
func (s *ed25519Signer) PubKeyB64() string {
	pub, _ := s.priv.Public().(ed25519.PublicKey)
	return base64.StdEncoding.EncodeToString(pub)
}
func (s *ed25519Signer) Name() string { return s.name }

func hexEncode(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[2*i] = hex[v>>4]
		out[2*i+1] = hex[v&0xf]
	}
	return string(out)
}

// narinfoForTest — валидный narinfo (URL указывает на nar/<52 nix-
// base32 fileHash>.nar.xz); refs — содержимое References-строки (bare-имена,
// как в реальном narinfo; fingerprint восстановит полные пути).
func narinfoForTest(extraSig string, refs ...string) []byte {
	s := "StorePath: /nix/store/" + narHash32 + "-hello-2.12.1\n" +
		"URL: nar/" + narFileHash52 + ".nar.xz\n" +
		"Compression: xz\n" +
		"FileHash: sha256:" + strings.Repeat("0", 64) + "\n" +
		"FileSize: 1024\n" +
		"NarHash: sha256:" + strings.Repeat("0", 64) + "\n" +
		"NarSize: 2048\n"
	if len(refs) > 0 {
		s += "References: " + strings.Join(refs, " ") + "\n"
	} else {
		s += "References: \n"
	}
	s += "Deriver: " + narHash32 + "-hello-2.12.1.drv\n"
	if extraSig != "" {
		s += "Sig: " + extraSig + "\n"
	}
	return []byte(s)
}

// stripSigLines удаляет все строки, начинающиеся с «Sig:», из narinfo
// (для проверки byte-exact-инварианта: non-Sig контент идентичен).
func stripSigLines(content []byte) []byte {
	lines := bytes.Split(content, []byte("\n"))
	var out [][]byte
	for _, l := range lines {
		if !bytes.HasPrefix(l, []byte("Sig:")) {
			out = append(out, l)
		}
	}
	return bytes.Join(out, []byte("\n"))
}

func TestResignNarinfoBytes_ReplacesSig(t *testing.T) {
	orig := narinfoForTest("upstream-1:oldpub:oldsig==", "f0vm1mkfnqrq3hxjcp2wsz5l8h4cgd9y-glibc-2.39")
	n, err := ParseNarinfo(bytes.NewReader(orig))
	if err != nil {
		t.Fatal(err)
	}
	s := newFakeNarSigner()
	out := resignNarinfoBytes(orig, n, s)
	// non-Sig контент байт-точно идентичен.
	if !bytes.Equal(stripSigLines(orig), stripSigLines(out)) {
		t.Errorf("non-Sig контент изменился:\norig-stripped: %q\nout-stripped:  %q",
			stripSigLines(orig), stripSigLines(out))
	}
	// Новая Sig-строка содержит pubkey подписчика и его name.
	outSig := sigLine(out)
	if !strings.HasPrefix(outSig, "Sig: fake:") {
		t.Errorf("Sig-строка %q не начинается с «Sig: fake:»", outSig)
	}
	// Старая Sig-строка исчезла (upstream-1).
	if bytes.Contains(out, []byte("upstream-1")) {
		t.Errorf("старая Sig-строка не заменена: %s", out)
	}
	// Trailing \n сохранён.
	if !bytes.HasSuffix(out, []byte("\n")) {
		t.Errorf("trailing \\n потерян")
	}
}

func TestResignNarinfoBytes_AppendsSigIfAbsent(t *testing.T) {
	orig := narinfoForTest("") // без Sig
	n, err := ParseNarinfo(bytes.NewReader(orig))
	if err != nil {
		t.Fatal(err)
	}
	s := newFakeNarSigner()
	out := resignNarinfoBytes(orig, n, s)
	if !bytes.Equal(stripSigLines(orig), stripSigLines(out)) {
		t.Errorf("non-Sig контент изменился при добавлении Sig")
	}
	if !strings.Contains(sigLine(out), "Sig: fake:") {
		t.Errorf("Sig-строка не добавлена: %s", out)
	}
}

func TestResignNarinfoBytes_DiffIsSigOnly(t *testing.T) {
	// Дифф orig → out строго +Sig/-Sig: вычитаем non-Sig → равны, и
	// ровно одна Sig-строка заменена (origSig ≠ outSig).
	orig := narinfoForTest("upstream-1:oldpub:oldsig==")
	n, err := ParseNarinfo(bytes.NewReader(orig))
	if err != nil {
		t.Fatal(err)
	}
	s := newFakeNarSigner()
	out := resignNarinfoBytes(orig, n, s)
	origSig := sigLine(orig)
	outSig := sigLine(out)
	if origSig == outSig {
		t.Fatalf("Sig не изменилась (ожидали замену)")
	}
	// Число Sig-строк — ровно 1 в каждом.
	if c := bytes.Count(out, []byte("\nSig:")) + boolToInt(strings.HasPrefix(string(out), "Sig:")); c != 1 {
		t.Errorf("число Sig-строк в out = %d, хочу 1", c)
	}
}

func sigLine(content []byte) string {
	for _, l := range bytes.Split(content, []byte("\n")) {
		if bytes.HasPrefix(l, []byte("Sig:")) {
			return string(l)
		}
	}
	return ""
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// TestFingerprint — точный формат подписываемого сообщения
// (libstore PathInfo::fingerprint, сверен с исходниками nix 2.0+):
// «1;StorePath;NarHash;NarSize;Refs», References — ПОЛНЫЕ пути
// storeDir + "/" + bare-имя из файла, отсортированы; пустой
// References — пустая строка после trailing «;».
func TestFingerprint(t *testing.T) {
	storePath := "/nix/store/" + narHash32 + "-hello-2.12.1"
	cases := []struct {
		name string
		n    *Narinfo
		want string
	}{
		{
			"пустой References — пустая строка между «;;»",
			&Narinfo{
				StorePath:  storePath,
				NarHash:    "sha256:" + strings.Repeat("0", 64),
				NarSize:    2048,
				References: nil,
			},
			"1;" + storePath + ";sha256:" + strings.Repeat("0", 64) + ";2048;",
		},
		{
			"References — полные пути, отсортированы",
			&Narinfo{
				StorePath: storePath,
				NarHash:   "sha256:" + strings.Repeat("0", 64),
				NarSize:   2048,
				References: []string{
					"z0vm1mkfnqrq3hxjcp2wsz5l8h4cgd9y-zeta-1.0",
					"f0vm1mkfnqrq3hxjcp2wsz5l8h4cgd9y-glibc-2.39",
				},
			},
			"1;" + storePath + ";sha256:" + strings.Repeat("0", 64) +
				";2048;/nix/store/f0vm1mkfnqrq3hxjcp2wsz5l8h4cgd9y-glibc-2.39," +
				"/nix/store/z0vm1mkfnqrq3hxjcp2wsz5l8h4cgd9y-zeta-1.0",
		},
		{
			"References уже с полным путём — не дублируем префикс",
			&Narinfo{
				StorePath:  storePath,
				NarHash:    "sha256:" + strings.Repeat("0", 64),
				NarSize:    2048,
				References: []string{storePath},
			},
			"1;" + storePath + ";sha256:" + strings.Repeat("0", 64) + ";2048;/nix/store/" + narHash32 + "-hello-2.12.1",
		},
	}
	for _, tc := range cases {
		if got := fingerprint(tc.n); got != tc.want {
			t.Errorf("%s: fingerprint = %q, хочу %q", tc.name, got, tc.want)
		}
	}
}

// TestResignSignsFingerprint_RealEd25519 — сессия 33, задача 2:
// Signer подписывает именно fingerprint (не строки файла), и тест
// вручную верифицирует подпись ed25519 по собранному fingerprint.
// Ключ детерминированный (NewKeyFromSeed) — expected-подпись тест
// строит сам из fingerprint независимо от resign-кода.
func TestResignSignsFingerprint_RealEd25519(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i * 7)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("приватный ключ без ed25519.PublicKey")
	}
	signer := &ed25519Signer{name: "testkey", priv: priv}

	orig := narinfoForTest("upstream-1:old==", "f0vm1mkfnqrq3hxjcp2wsz5l8h4cgd9y-glibc-2.39")
	n, err := ParseNarinfo(bytes.NewReader(orig))
	if err != nil {
		t.Fatal(err)
	}
	out := resignNarinfoBytes(orig, n, signer)

	// Expected-подпись строим сами: fingerprint → ed25519.Sign.
	fp := fingerprint(n)
	wantSig := ed25519.Sign(priv, []byte(fp))
	wantLine := "Sig: testkey:" + base64.StdEncoding.EncodeToString(wantSig)

	got := sigLine(out)
	if got != wantLine {
		t.Fatalf("Sig-строка = %q, хочу %q (подпись не по fingerprint)", got, wantLine)
	}
	// Механизм nix-verify: base64-decode sig → ed25519.Verify(pub, fp).
	parts := strings.SplitN(strings.TrimPrefix(got, "Sig: "), ":", 2)
	if len(parts) != 2 {
		t.Fatalf("sig-строка не name:sig: %q", got)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("signature не base64: %v", err)
	}
	if !ed25519.Verify(pub, []byte(fp), sigBytes) {
		t.Fatal("ed25519.Verify по fingerprint отверг подпись")
	}
	// Tamper-гвард: подпись по строкам файла не совпадает.
	linesMsg := strings.Join([]string{
		"StorePath: /nix/store/" + narHash32 + "-hello-2.12.1",
		"URL: nar/" + narFileHash52 + ".nar.xz",
	}, "\n")
	if bytes.Equal(ed25519.Sign(priv, []byte(linesMsg)), sigBytes) {
		t.Fatal("подпись совпала с подписью по строкам файла — подписывается не fingerprint")
	}
}

// TestResignGoldenByteDiff — golden-тест на байт-дифф (сессия 33,
// задача 2): re-sign golden narinfo; дифф строго ±Sig-строки, non-Sig
// байт-точно; Sig валидируется по fingerprint ключом из testdata.
func TestResignGoldenByteDiff(t *testing.T) {
	golden := mustReadTestdata(t, "narinfo.golden")
	n, err := ParseNarinfo(bytes.NewReader(golden))
	if err != nil {
		t.Fatal(err)
	}
	out := resignNarinfoBytes(golden, n, newFakeNarSigner())

	if !bytes.Equal(stripSigLines(golden), stripSigLines(out)) {
		t.Errorf("non-Sig дифф golden-переподписи:\ngolden: %q\nout:   %q",
			stripSigLines(golden), stripSigLines(out))
	}
	if origSig, outSig := sigLine(golden), sigLine(out); origSig == outSig {
		t.Error("Sig не изменилась")
	}
	if !bytes.HasSuffix(out, []byte("\n")) {
		t.Error("trailing \\n потерян")
	}
}

func TestValidateObjectPath(t *testing.T) {
	g := &Generator{}
	cases := []struct {
		path string
		want bool
	}{
		{narHash32 + ".narinfo", true},
		{"nar/" + narFileHash52 + ".nar.xz", true},
		{"nar/" + narFileHash52 + ".nar", true},
		{"foo.narinfo", false},                      // не хеш
		{"nar/foo.nar.xz", false},                   // не хеш
		{"sub/" + narHash32 + ".narinfo", false},    // не в корне
		{"nar/" + narFileHash52 + ".nar.gz", false}, // неверный суффикс
		// hex с 'e' — не nix-base32 (реальные nix-хеши иного алфавита).
		{"0123456789abcdef0123456789abcdef.narinfo", false},
		{"nar/0123456789abcdef0123456789abcdef0123456789abcdef01234567.nar.xz", false},
		// 32-символьный nar — хеш store path, а не fileHash.
		{"nar/" + narHash32 + ".nar.xz", false},
		{"nar/" + narHash32 + ".nar", false},
		// другой валидный nix-base32 хеш.
		{"0123456789abcdfghijklmnpqrsvwxyz.narinfo", true},
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

// TestGenerateIndexes_OversizedNarinfoFails — narinfo крупнее 16KiB
// отклоняется (ErrNarinfoTooLarge): чтение идёт через LimitReader ДО
// ReadAll, гигантский вход не должен попадать в память целиком.
func TestGenerateIndexes_OversizedNarinfoFails(t *testing.T) {
	moment := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	storage := testutil.NewFakeStorage(testutil.FixedClock(moment))
	repo := domain.Repo{ID: 1, Name: "alice", Ecosystem: Name}
	// narinfoForTest (~250 байт) + набивка до > 16KiB.
	big := string(narinfoForTest("")) + strings.Repeat("Filler: x\n", (maxNarinfoSize/10)+64)
	key := putNarinfo(t, storage, repo, narHash32, big)

	g := &Generator{nar: newFakeNarSigner()}
	err := g.GenerateIndexes(context.Background(), repo, storage, nil)
	if !errors.Is(err, ErrNarinfoTooLarge) {
		t.Fatalf("ожидали ErrNarinfoTooLarge, получили %v", err)
	}
	// Оригинал не тронут (переподпись не состоялась).
	out := readStorage(t, storage, key)
	if !bytes.Equal([]byte(big), out) {
		t.Errorf("oversized narinfo был изменён")
	}
}

func TestGeneratorName(t *testing.T) {
	g := &Generator{}
	if g.Name() != Name {
		t.Errorf("Name = %q, want %q", g.Name(), Name)
	}
}

// putNarinfo складывает narinfo-байты в FakeStorage.
func putNarinfo(t *testing.T, storage *testutil.FakeStorage, repo domain.Repo, hash, content string) string {
	t.Helper()
	key := port.RepoPrefix(repo) + "/" + hash + ".narinfo"
	w, err := storage.Put(context.Background(), key)
	if err != nil {
		t.Fatalf("storage.Put %s: %v", key, err)
	}
	if _, err := w.Write([]byte(content)); err != nil {
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

func TestGenerateIndexes_ResignsNarinfo(t *testing.T) {
	moment := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	storage := testutil.NewFakeStorage(testutil.FixedClock(moment))
	repo := domain.Repo{ID: 1, Name: "alice", Ecosystem: Name}
	origContent := string(narinfoForTest("upstream-1:oldpub:oldsig=="))
	key := putNarinfo(t, storage, repo, narHash32, origContent)

	g := &Generator{nar: newFakeNarSigner()}
	if err := g.GenerateIndexes(context.Background(), repo, storage, nil); err != nil {
		t.Fatalf("GenerateIndexes: %v", err)
	}
	out := readStorage(t, storage, key)
	// non-Sig байт-точно.
	if !bytes.Equal(stripSigLines([]byte(origContent)), stripSigLines(out)) {
		t.Errorf("non-Sig контент изменился после reindex")
	}
	// Sig заменена на «fake:...».
	if !strings.Contains(sigLine(out), "Sig: fake:") {
		t.Errorf("Sig не переподписана: %s", sigLine(out))
	}
}

func TestGenerateIndexes_InvalidNarinfoFails(t *testing.T) {
	moment := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	storage := testutil.NewFakeStorage(testutil.FixedClock(moment))
	repo := domain.Repo{ID: 1, Name: "alice", Ecosystem: Name}
	// narinfo без валидного URL (WantNar → "") → ошибка.
	putNarinfo(t, storage, repo, narHash32,
		"StorePath: /nix/store/"+narHash32+"-foo\nCompression: xz\n")

	g := &Generator{nar: newFakeNarSigner()}
	err := g.GenerateIndexes(context.Background(), repo, storage, nil)
	if !errors.Is(err, ErrBadNarinfo) {
		t.Fatalf("ожидали ErrBadNarinfo, got %v", err)
	}
}

func TestGenerateIndexes_NoSignerIsNoop(t *testing.T) {
	moment := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	storage := testutil.NewFakeStorage(testutil.FixedClock(moment))
	repo := domain.Repo{ID: 1, Name: "alice", Ecosystem: Name}
	orig := string(narinfoForTest("upstream-1:pub:old=="))
	key := putNarinfo(t, storage, repo, narHash32, orig)

	g := &Generator{} // nar == nil
	if err := g.GenerateIndexes(context.Background(), repo, storage, nil); err != nil {
		t.Fatalf("GenerateIndexes без Signer: %v", err)
	}
	// narinfo не изменён.
	out := readStorage(t, storage, key)
	if string(out) != orig {
		t.Errorf("narinfo изменён без Signer")
	}
}

func TestGenerateIndexes_WrongEcosystem(t *testing.T) {
	moment := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	storage := testutil.NewFakeStorage(testutil.FixedClock(moment))
	repo := domain.Repo{ID: 1, Name: "alice", Ecosystem: "apt"}
	g := &Generator{nar: newFakeNarSigner()}
	err := g.GenerateIndexes(context.Background(), repo, storage, nil)
	var unsup *domain.UnsupportedError
	if !errors.As(err, &unsup) {
		t.Fatalf("ожидали UnsupportedError, получили %v", err)
	}
}

func TestGenerateIndexes_ContextCanceled(t *testing.T) {
	moment := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	storage := testutil.NewFakeStorage(testutil.FixedClock(moment))
	repo := domain.Repo{ID: 1, Name: "alice", Ecosystem: Name}
	putNarinfo(t, storage, repo, narHash32, string(narinfoForTest("up:old:pub:sig==")))
	g := &Generator{nar: newFakeNarSigner()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := g.GenerateIndexes(ctx, repo, storage, nil); err == nil {
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

func TestGenerateIndexes_Progress(t *testing.T) {
	moment := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	storage := testutil.NewFakeStorage(testutil.FixedClock(moment))
	repo := domain.Repo{ID: 1, Name: "alice", Ecosystem: Name}
	putNarinfo(t, storage, repo, narHash32, string(narinfoForTest("up:old:p:s==")))
	g := &Generator{nar: newFakeNarSigner()}
	rec := &recordingProgress{}
	if err := g.GenerateIndexes(context.Background(), repo, storage, rec); err != nil {
		t.Fatalf("GenerateIndexes: %v", err)
	}
	phases := map[string]bool{}
	for _, u := range rec.updates {
		phases[strings.SplitN(u, "/", 2)[0]] = true
	}
	for _, want := range []string{"enumerate", "resign"} {
		if !phases[want] {
			t.Errorf("фаза %s не отработала: %v", want, rec.updates)
		}
	}
	if !slices.ContainsFunc(rec.logs, func(s string) bool { return strings.Contains(s, "переподписаны") }) {
		t.Errorf("нет строки завершения: %v", rec.logs)
	}
}

func TestSetNarSigner(t *testing.T) {
	g := &Generator{}
	if g.nar != nil {
		t.Fatal("новый Generator уже имеет nar signer")
	}
	s := newFakeNarSigner()
	g.SetNarSigner(s)
	if g.nar == nil {
		t.Error("SetNarSigner не сохранил nar signer")
	}
}

// errListFail — синтетический сбой листинга носителя (см. Storage.List
// контракт: терминальная ошибка вместо пустого обхода).
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

// TestGenerateIndexes_ListingErrorFails — ошибка листинга не выглядит
// как «переподписывать нечего»: генерация падает, narinfo не тронуты.
func TestGenerateIndexes_ListingErrorFails(t *testing.T) {
	moment := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	storage := testutil.NewFakeStorage(testutil.FixedClock(moment))
	repo := domain.Repo{ID: 1, Name: "alice", Ecosystem: Name}
	key := putNarinfo(t, storage, repo, narHash32, string(narinfoForTest("up:old:p:s==")))

	broken := &failingListStorage{FakeStorage: storage, err: errListFail}
	g := &Generator{nar: newFakeNarSigner()}
	err := g.GenerateIndexes(context.Background(), repo, broken, nil)
	if err == nil || !errors.Is(err, errListFail) {
		t.Fatalf("ожидали errListFail из листинга, получено %v", err)
	}
	obj, err := storage.Get(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	defer obj.Body.Close()
	body, _ := io.ReadAll(obj.Body)
	if !bytes.Contains(body, []byte("Sig: up:old:p:s==")) {
		t.Fatal("сбой листинга изменил narinfo")
	}
}
