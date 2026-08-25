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

package openpgp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	gp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// newSigner — хелпер: Signer в свежем t.TempDir().
func newSigner(t *testing.T, passphrase []byte) *Signer {
	t.Helper()
	s, err := New(t.TempDir(), passphrase)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// keyring собирает EntityList из публичной части Signer (через
// PublicKey + ReadArmoredKeyRing — проверяет, что отданный ключ
// валиден для verify).
func keyring(t *testing.T, s *Signer) gp.EntityList {
	t.Helper()
	pub, err := s.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	el, err := gp.ReadArmoredKeyRing(bytes.NewReader(pub))
	if err != nil {
		t.Fatalf("ReadArmoredKeyRing: %v", err)
	}
	if len(el) == 0 {
		t.Fatal("пустой keyring из PublicKey")
	}
	return el
}

func TestNew_GeneratesKeyFiles(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	priv := filepath.Join(dir, privateKeyFile)
	pub := filepath.Join(dir, publicKeyFile)
	for _, p := range []string{priv, pub} {
		info, err := os.Stat(p)
		if err != nil {
			t.Errorf("файл %s не создан: %v", p, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("файл %s пуст", p)
		}
		// 0600 реален только на POSIX; на Windows chmod но-op.
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Errorf("файл %s: perms %o, хочу 0600", p, info.Mode().Perm())
		}
	}
	if s.Fingerprint() == "" {
		t.Error("Fingerprint пуст")
	}
}

func TestNew_ReloadSameFingerprint(t *testing.T) {
	dir := t.TempDir()
	s1, err := New(dir, nil)
	if err != nil {
		t.Fatalf("New #1: %v", err)
	}
	fp1 := s1.Fingerprint()
	s2, err := New(dir, nil)
	if err != nil {
		t.Fatalf("New #2: %v", err)
	}
	if fp1 != s2.Fingerprint() {
		t.Errorf("fingerprint differs после reload: %q != %q", fp1, s2.Fingerprint())
	}
	if s1.KeyID() != s2.KeyID() {
		t.Errorf("keyid differs после reload")
	}
}

func TestNew_EmptyKeysDir(t *testing.T) {
	if _, err := New("", nil); err == nil {
		t.Fatal("ожидалась ошибка при пустом keys_dir")
	}
}

func TestNew_KeysDirIsFileFails(t *testing.T) {
	// keysDir указывает на обычный файл — MkdirAll не может создать
	// каталог поверх файла → ошибка.
	file := filepath.Join(t.TempDir(), "iamfile")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(file, nil); err == nil {
		t.Fatal("ожидалась ошибка MkdirAll поверх файла")
	}
}

func TestSign_CleartextRoundtrip(t *testing.T) {
	s := newSigner(t, nil)
	kring := keyring(t, s)
	msg := []byte("Date: now\nSuite: stable\nSHA256:\n abc 100 main/binary-amd64/Packages\n")

	out, err := s.Sign(context.Background(), bytes.NewReader(msg))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	signed, err := io.ReadAll(out)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(signed), "BEGIN PGP SIGNED MESSAGE") {
		t.Errorf("подпись не cleartext:\n%s", signed)
	}
	block, _ := clearsign.Decode(signed)
	if block == nil {
		t.Fatalf("clearsign.Decode вернул nil")
	}
	// OpenPGP cleartext каноникализует переводы строк в \r\n
	// (SigTypeText) — это норма; сравниваем с CRLF-версией msg.
	want := bytes.ReplaceAll(msg, []byte("\n"), []byte("\r\n"))
	if string(block.Bytes) != string(want) {
		t.Errorf("cleartext payload изменён:\nwant %q\ngot  %q", want, block.Bytes)
	}
	if signer, err := block.VerifySignature(kring, &packet.Config{}); err != nil {
		t.Errorf("VerifySignature: %v", err)
	} else if signer == nil {
		t.Error("signer nil после verify")
	}
}

func TestSign_TamperInvalid(t *testing.T) {
	s := newSigner(t, nil)
	kring := keyring(t, s)
	out, err := s.Sign(context.Background(), strings.NewReader("Release: original\n"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	signed, _ := io.ReadAll(out)
	// Подменим payload внутри cleartext-блока: найдём строку и
	// заменим первый байт. Сигнатура должна разъехаться.
	tampered := bytes.Replace(signed, []byte("original"), []byte("Xriginal1"), 1)
	if bytes.Equal(tampered, signed) {
		t.Fatal("tamper не сработал")
	}
	block, _ := clearsign.Decode(tampered)
	if block == nil {
		t.Fatal("clearsign.Decode вернул nil для tampered")
	}
	if _, err := block.VerifySignature(kring, &packet.Config{}); err == nil {
		t.Error("ожидалась ошибка verify для tampered payload")
	}
}

func TestSignDetached_Roundtrip(t *testing.T) {
	s := newSigner(t, nil)
	kring := keyring(t, s)
	msg := []byte("Release: detached\nSHA256:\n abc 10 x\n")

	sigR, err := s.SignDetached(context.Background(), bytes.NewReader(msg))
	if err != nil {
		t.Fatalf("SignDetached: %v", err)
	}
	sig, err := io.ReadAll(sigR)
	if err != nil {
		t.Fatalf("read sig: %v", err)
	}
	if strings.Contains(string(sig), "BEGIN PGP") {
		t.Errorf("Release.gpg должен быть бинарным, не armored:\n%s", sig)
	}
	if _, err := gp.CheckDetachedSignature(kring, bytes.NewReader(msg), bytes.NewReader(sig), &packet.Config{}); err != nil {
		t.Errorf("CheckDetachedSignature: %v", err)
	}
}

func TestSignDetached_TamperInvalid(t *testing.T) {
	s := newSigner(t, nil)
	kring := keyring(t, s)
	sigR, err := s.SignDetached(context.Background(), strings.NewReader("Release: ok\n"))
	if err != nil {
		t.Fatalf("SignDetached: %v", err)
	}
	sig, _ := io.ReadAll(sigR)
	// Подмена сообщения: та же сигнатура, другой payload.
	if _, err := gp.CheckDetachedSignature(kring, strings.NewReader("Release: EVIL\n"), bytes.NewReader(sig), &packet.Config{}); err == nil {
		t.Error("ожидалась ошибка verify для tampered detached")
	}
	// Подмена сигнатуры.
	bad := append([]byte{}, sig...)
	bad[0] ^= 0xff
	if _, err := gp.CheckDetachedSignature(kring, strings.NewReader("Release: ok\n"), bytes.NewReader(bad), &packet.Config{}); err == nil {
		t.Error("ожидалась ошибка verify для битой сигнатуры")
	}
}

func TestPassphrase_EncryptedKeyRoundtrip(t *testing.T) {
	dir := t.TempDir()
	pass := []byte("correct horse battery staple")
	s1, err := New(dir, pass)
	if err != nil {
		t.Fatalf("New с passphrase: %v", err)
	}
	// private.asc на диске зашифрован — перезагрузка с правильной
	// passphrase должна дать тот же ключ и рабочую подпись.
	s2, err := New(dir, pass)
	if err != nil {
		t.Fatalf("reload с passphrase: %v", err)
	}
	if s1.Fingerprint() != s2.Fingerprint() {
		t.Errorf("fingerprint differs после reload с passphrase")
	}
	out, err := s2.Sign(context.Background(), strings.NewReader("Release: signed\n"))
	if err != nil {
		t.Fatalf("Sign после reload: %v", err)
	}
	signed, _ := io.ReadAll(out)
	block, _ := clearsign.Decode(signed)
	if block == nil {
		t.Fatal("clearsign.Decode nil")
	}
	if _, err := block.VerifySignature(keyring(t, s2), &packet.Config{}); err != nil {
		t.Errorf("verify после reload: %v", err)
	}
}

func TestPassphrase_WrongFails(t *testing.T) {
	dir := t.TempDir()
	if _, err := New(dir, []byte("right-pass")); err != nil {
		t.Fatalf("New #1: %v", err)
	}
	_, err := New(dir, []byte("wrong-pass"))
	if err == nil {
		t.Fatal("ожидалась ошибка при неверной passphrase")
	}
	if !strings.Contains(err.Error(), "passphrase") && !strings.Contains(err.Error(), "расшифровк") {
		t.Errorf("ошибка не про passphrase: %v", err)
	}
}

func TestPassphrase_EncryptedButEmptyFails(t *testing.T) {
	dir := t.TempDir()
	if _, err := New(dir, []byte("secret")); err != nil {
		t.Fatalf("New с passphrase: %v", err)
	}
	_, err := New(dir, nil)
	if err == nil {
		t.Fatal("ожидалась ошибка: зашифрован, а passphrase пуста")
	}
}

func TestPassphrase_EmptyOnUnencryptedOK(t *testing.T) {
	dir := t.TempDir()
	if _, err := New(dir, nil); err != nil {
		t.Fatalf("New без passphrase: %v", err)
	}
	// reload без passphrase на незашифрованном ключе — норма.
	if _, err := New(dir, nil); err != nil {
		t.Fatalf("reload без passphrase: %v", err)
	}
}

func TestPublicKey_ArmoredBlock(t *testing.T) {
	s := newSigner(t, nil)
	pub, err := s.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if !strings.Contains(string(pub), "BEGIN PGP PUBLIC KEY BLOCK") {
		t.Errorf("публичный ключ не armored:\n%s", pub)
	}
	// PublicKey возвращает копию — мутация не портит кеш.
	pub[0] = 'X'
	pub2, _ := s.PublicKey()
	if pub2[0] == 'X' {
		t.Error("PublicKey не делает копию")
	}
}

func TestLoad_CorruptFileFails(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, privateKeyFile), []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := New(dir, nil)
	if err == nil {
		t.Fatal("ожидалась ошибка для битого private.asc")
	}
}

// failingReader всегда возвращает ошибку чтения — для error-веток
// Sign (io.ReadAll) и SignDetached (DetachSign читает input).
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errSynthetic }

var errSynthetic = errors.New("synthetic read error")

func TestSign_ReaderError(t *testing.T) {
	s := newSigner(t, nil)
	if _, err := s.Sign(context.Background(), failingReader{}); err == nil {
		t.Fatal("ожидалась ошибка Sign при падающем reader")
	}
}

func TestSignDetached_ReaderError(t *testing.T) {
	s := newSigner(t, nil)
	if _, err := s.SignDetached(context.Background(), failingReader{}); err == nil {
		t.Fatal("ожидалась ошибка SignDetached при падающем reader")
	}
}

// failingWriter падает, когда суммарный объём записей превышает cap.
// С cap=0 первый же Write (заголовок armor/clearsign) падает → ошибка
// Encode. С cap>>заголовка тело или футер спотыкаются → Write/Close err.
type failingWriter struct {
	cap int
	n   int
}

func (w *failingWriter) Write(p []byte) (int, error) {
	w.n += len(p)
	if w.n > w.cap {
		return 0, errSynthetic
	}
	return len(p), nil
}

func TestArmorWrite_EncodeError(t *testing.T) {
	// cap=0: armor.Encode пишет заголовок в w → сразу падает.
	if err := armorWrite(&failingWriter{cap: 0}, "PGP PUBLIC KEY BLOCK", func(io.Writer) error {
		return nil
	}); err == nil {
		t.Fatal("ожидалась ошибка armorWrite при падающем writer (Encode)")
	}
}

func TestArmorWrite_WriteBodyError(t *testing.T) {
	// cap велико для заголовка, но write-func возвращает errSynthetic.
	if err := armorWrite(&failingWriter{cap: 1 << 20}, "PGP PUBLIC KEY BLOCK", func(io.Writer) error {
		return errSynthetic
	}); err == nil || !errors.Is(err, errSynthetic) {
		t.Fatalf("ожидалась errSynthetic из write-func, got %v", err)
	}
}

func TestWriteArmored_OpenFileFails(t *testing.T) {
	// path под обычным файлом (не каталогом) — OpenFile не может создать.
	blocker := filepath.Join(t.TempDir(), "iamfile")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(blocker, "out.asc")
	if err := writeArmored(badPath, "PGP PUBLIC KEY BLOCK", func(io.Writer) error { return nil }); err == nil {
		t.Fatal("ожидалась ошибка writeArmored OpenFile под файлом")
	}
}

func TestWriteKeyFiles_PrivateBlockedFails(t *testing.T) {
	s := newSigner(t, nil)
	// keysDir — обычный файл: writeKeyFiles соберёт privPath = file/asc,
	// writeArmored для private.asc упадёт в OpenFile (not a dir).
	blocker := filepath.Join(t.TempDir(), "iamfile")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeKeyFiles(blocker, s.entity, nil, s.cfg); err == nil {
		t.Fatal("ожидалась ошибка writeKeyFiles при блокере-keysDir")
	}
}

func TestNew_PublicAscIsDirFails(t *testing.T) {
	// keysDir валиден, но public.asc — каталог: private.asc пишется,
	// затем writeArmored(public.asc) падает в OpenFile → writeKeyFiles
	// возвращает ошибку → New падает на ветке fresh-write.
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, publicKeyFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dir, nil); err == nil {
		t.Fatal("ожидалась ошибка New когда public.asc — каталог")
	}
}

func TestSignCleartext_EncodeError(t *testing.T) {
	s := newSigner(t, nil)
	// failingWriter cap=0: clearsign.Encode пишет заголовок → падает.
	if err := s.signCleartext(&failingWriter{cap: 0}, []byte("msg")); err == nil {
		t.Fatal("ожидалась ошибка signCleartext при падающем writer (Encode)")
	}
}

func TestSignCleartext_BodyWriteError(t *testing.T) {
	s := newSigner(t, nil)
	// cap=1: заголовок (несколько байт) успевает, тело Write спотыкается.
	if err := s.signCleartext(&failingWriter{cap: 1}, []byte("payload-long-enough")); err == nil {
		t.Fatal("ожидалась ошибка signCleartext при падающем body-write")
	}
}
