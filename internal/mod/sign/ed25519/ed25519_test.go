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

package ed25519

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"khrazhevnik/internal/core/domain"
)

func TestNew_GeneratesKey(t *testing.T) {
	s, err := New("cache.example.org-1")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s.Name() == "" {
		t.Error("Name пуст")
	}
	if s.PubKeyB64() == "" {
		t.Error("PubKeyB64 пуст")
	}
	// Два вызова New дают разные ключи (рандомность).
	s2, _ := New("cache.example.org-1")
	if s.PubKeyB64() == s2.PubKeyB64() {
		t.Error("два New дали одинаковый pubkey — рандом не работает")
	}
}

func TestNew_NameValidation(t *testing.T) {
	if _, err := New(""); err == nil {
		t.Error("пустое имя принято")
	}
	if _, err := New("bad:name"); err == nil {
		t.Error("имя с ':' принято")
	}
}

func TestFromKey_InvalidLength(t *testing.T) {
	if _, err := FromKey("k", ed25519.PrivateKey(make([]byte, 10))); err == nil {
		t.Error("принят ключ неверной длины")
	}
	if _, err := FromKey("", ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))); err == nil {
		t.Error("принято пустое имя")
	}
}

func TestSignVerify_Roundtrip(t *testing.T) {
	s, err := New("hydra.example.org")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	msg := []byte("1;/nix/store/abc...-foo-1.0;sha256:...;1234;/nix/store/def...-bar")
	sigLine := s.Sign(msg)

	parts := strings.SplitN(sigLine, ":", 2)
	if len(parts) != 2 {
		t.Fatalf("sig-строка не из 2 полей: %q", sigLine)
	}
	if parts[0] != "hydra.example.org" {
		t.Errorf("name в sig = %q, хочу hydra.example.org", parts[0])
	}
	// signature — base64 64 байт ed25519 (88 символов с padding).
	sigBytes, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("signature не base64: %v", err)
	}
	if len(sigBytes) != ed25519.SignatureSize {
		t.Errorf("signature = %d байт, хочу %d", len(sigBytes), ed25519.SignatureSize)
	}

	ok, err := Verify(s.PubKey(), msg, sigLine)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Error("Verify вернул false для валидной подписи")
	}
}

func TestVerify_TamperMsg(t *testing.T) {
	s, _ := New("k")
	sigLine := s.Sign([]byte("original"))
	ok, err := Verify(s.PubKey(), []byte("tampered"), sigLine)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Error("Verify вернул true для tampered msg")
	}
}

func TestVerify_TamperSig(t *testing.T) {
	s, _ := New("k")
	sigLine := s.Sign([]byte("msg"))
	// Перевернём байт декодированной сигнатуры и пере-кодируем: base64
	// остаётся валидной формы, но подпись реально иная.
	parts := strings.SplitN(sigLine, ":", 2)
	sigBytes, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	sigBytes[0] ^= 0xff
	bad := parts[0] + ":" + base64.StdEncoding.EncodeToString(sigBytes)
	ok, err := Verify(s.PubKey(), []byte("msg"), bad)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Error("Verify вернул true для битой signature")
	}
}

func TestVerify_WrongKey(t *testing.T) {
	s1, _ := New("k1")
	s2, _ := New("k2")
	msg := []byte("msg")
	sigLine := s1.Sign(msg)
	// Подпись s1 под pubkey s1: чужой pubkey s2 её не валидирует
	// (nix-клиент проверяет парой из trusted-public-keys).
	ok, err := Verify(s2.PubKey(), msg, sigLine)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Error("Verify вернул true под чужим pubkey")
	}
	// Имя в sig-строке обязано совпасть с именем ключа из конфига
	// (local-keys.cc verifyDetached: несовпадение keyName = невалид).
	ok, err = VerifyWithPubKey(s1.PubKey(), msg, sigLine, "k2")
	if err != nil {
		t.Fatalf("VerifyWithPubKey: %v", err)
	}
	if ok {
		t.Error("VerifyWithPubKey вернул true для чужого имени ключа")
	}
	// С ожидаемым k1 — ok.
	ok, err = VerifyWithPubKey(s1.PubKey(), msg, sigLine, "k1")
	if err != nil {
		t.Fatalf("VerifyWithPubKey: %v", err)
	}
	if !ok {
		t.Error("VerifyWithPubKey вернул false для своего имени ключа")
	}
}

func TestVerify_Malformed(t *testing.T) {
	s, _ := New("k")
	pub := s.PubKey()
	cases := []string{
		"onlyonefield",
		// 3 поля «name:pubkey:sig» — формат, который nix не парсит
		// (local-keys.cc: ровно одно «:»).
		"three:fields:here",
		"k:not-base64!",
		"k:tooshort",
	}
	for _, c := range cases {
		if _, err := Verify(pub, []byte("msg"), c); err == nil {
			t.Errorf("ожидалась ошибка для малформата %q", c)
		}
	}
}

func TestSign_DeterministicPerKey(t *testing.T) {
	// Из одного seed — одинаковые подписи (ed25519 детерминирован).
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	s1, _ := FromKey("k", priv)
	s2, _ := FromKey("k", priv)
	msg := []byte("same")
	if s1.Sign(msg) != s2.Sign(msg) {
		t.Error("подписи из одного ключа различаются")
	}
}

func TestLoadOrGenerate_PersistsAcrossCalls(t *testing.T) {
	dir := t.TempDir()
	s1, err := LoadOrGenerate("khrazhevnik", dir)
	if err != nil {
		t.Fatalf("LoadOrGenerate (first): %v", err)
	}
	// Файл создан с правами 0600.
	info, err := os.Stat(filepath.Join(dir, narKeyFile))
	if err != nil {
		t.Fatalf("ключевой файл не создан: %v", err)
	}
	// 0600 — только на POSIX; на Windows chmod no-op.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("права ключевого файла = %o, хочу 0600", info.Mode().Perm())
	}
	// Второй вызов — загружает тот же ключ (fingerprint стабилен).
	s2, err := LoadOrGenerate("khrazhevnik", dir)
	if err != nil {
		t.Fatalf("LoadOrGenerate (second): %v", err)
	}
	if s1.PubKeyB64() != s2.PubKeyB64() {
		t.Fatalf("pubkey изменился между вызовами: %s vs %s", s1.PubKeyB64(), s2.PubKeyB64())
	}
	// Подпись s1 валидируется ключом s2 (тот же ключ, pubkey стабилен
	// между рестартами — инвариант LoadOrGenerate).
	msg := []byte("1;/nix/store/x-foo;sha256:y;1;")
	ok, err := VerifyWithPubKey(s2.PubKey(), msg, s1.Sign(msg), s2.Name())
	if err != nil || !ok {
		t.Errorf("подпись s1 не валидируется ключом s2: ok=%v err=%v", ok, err)
	}
}

func TestLoadOrGenerate_NameValidation(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrGenerate("", dir); err == nil {
		t.Error("пустое имя принято")
	}
	if _, err := LoadOrGenerate("bad:name", dir); err == nil {
		t.Error("имя с ':' принято")
	}
	if _, err := LoadOrGenerate("k", ""); err == nil {
		t.Error("пустой keys_dir принят")
	}
}

func TestLoadOrGenerate_CorruptedFile(t *testing.T) {
	dir := t.TempDir()
	// Запишем файл неверной длины — загрузка упадёт.
	if err := os.WriteFile(filepath.Join(dir, narKeyFile), []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadOrGenerate("k", dir)
	if err == nil {
		t.Fatal("битый ключевой файл загружен без ошибки")
	}
	// Битый ключ — KeyMaterialError: wire валит старт, не деградирует
	// (сессия 40).
	var km *domain.KeyMaterialError
	if !errors.As(err, &km) {
		t.Errorf("битый nar-ключ: хочу KeyMaterialError, got %T: %v", err, err)
	}
}

// TestLoadOrGenerate_TruncatedKeyFails — 64 байта мусора проходят
// size-проверку, но не деривируют публичную часть: ловим на старте,
// а не первым невалидным narinfo.
func TestLoadOrGenerate_TruncatedKeyFails(t *testing.T) {
	dir := t.TempDir()
	garbage := make([]byte, ed25519.PrivateKeySize)
	for i := range garbage {
		garbage[i] = byte(i) + 1 // ненулевые байты — не валидный ключ
	}
	if err := os.WriteFile(filepath.Join(dir, narKeyFile), garbage, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadOrGenerate("k", dir)
	if err == nil {
		t.Fatal("мусорные 64 байта приняты как ключ")
	}
}

// TestLoadOrGenerate_ParallelSameKey — параллельные LoadOrGenerate на
// одном keys_dir (первый старт): один pubkey у всех, тихий fork
// инстансных narinfo-ключей исключён (сессия 40).
func TestLoadOrGenerate_ParallelSameKey(t *testing.T) {
	dir := t.TempDir()
	const concurrency = 4
	pubs := make([]string, concurrency)
	errs := make([]error, concurrency)
	var wg sync.WaitGroup
	for i := range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := LoadOrGenerate("khrazhevnik", dir)
			if err != nil {
				errs[i] = err
				return
			}
			pubs[i] = s.PubKeyB64()
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("LoadOrGenerate #%d: %v", i, err)
		}
	}
	for i := 1; i < concurrency; i++ {
		if pubs[i] != pubs[0] {
			t.Errorf("pubkey #%d != #0: fork инстансных narinfo-ключей", i)
		}
	}
}

// Compile-time: Signer удовлетворяет port.NarSigner.
func TestSignerImplementsNarSigner(t *testing.T) {
	var _ interface {
		Sign(msg []byte) string
		PubKeyB64() string
		Name() string
	} = (*Signer)(nil)
	// подавим unused-base64-warning, если предыдущие тести не трогают.
	_ = base64.StdEncoding
}
