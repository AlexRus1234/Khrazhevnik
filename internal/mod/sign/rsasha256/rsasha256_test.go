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

package rsasha256

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"khrazhevnik/internal/core/domain"
)

// parsePublicPEM разбирает SPKI-PEM, который отдаёт Signer.PublicKeyPEM,
// и валидирует формат (`PUBLIC KEY` + *rsa.PublicKey).
func parsePublicPEM(t *testing.T, pemBytes []byte) *rsa.PublicKey {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatalf("PublicKeyPEM: не PEM")
	}
	if block.Type != "PUBLIC KEY" {
		t.Fatalf("PublicKeyPEM: тип блока %q, хочу PUBLIC KEY", block.Type)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("PublicKeyPEM: ParsePKIXPublicKey: %v", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("PublicKeyPEM: публичный ключ %T, хочу *rsa.PublicKey", pub)
	}
	return rsaPub
}

func TestSignSHA256_Roundtrip(t *testing.T) {
	s, err := LoadOrGenerate(t.TempDir(), 1024)
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}
	msg := []byte("<package><name>0ad</name></package>")
	digest := sha256.Sum256(msg)
	sig, err := s.SignSHA256(context.Background(), digest[:])
	if err != nil {
		t.Fatalf("SignSHA256: %v", err)
	}
	// Формат .sig2: сырая подпись PKCS#1 v1.5 длиной модуля (128 для 1024).
	if len(sig) != 128 {
		t.Fatalf("подпись = %d байт, хочу 128", len(sig))
	}
	pubPEM, err := s.PublicKeyPEM()
	if err != nil {
		t.Fatalf("PublicKeyPEM: %v", err)
	}
	pub := parsePublicPEM(t, pubPEM)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("VerifyPKCS1v15: %v", err)
	}
}

func TestSignSHA256_TamperedDigestFails(t *testing.T) {
	s, err := LoadOrGenerate(t.TempDir(), 1024)
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}
	digest := sha256.Sum256([]byte("original"))
	sig, err := s.SignSHA256(context.Background(), digest[:])
	if err != nil {
		t.Fatalf("SignSHA256: %v", err)
	}
	other := sha256.Sum256([]byte("tampered"))
	pub := parsePublicPEM(t, mustPEM(t, s))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, other[:], sig); err == nil {
		t.Error("подпись прошла верификацию под чужой дайджест")
	}
}

func mustPEM(t *testing.T, s *Signer) []byte {
	t.Helper()
	p, err := s.PublicKeyPEM()
	if err != nil {
		t.Fatalf("PublicKeyPEM: %v", err)
	}
	return p
}

func TestSignSHA256_DigestLength(t *testing.T) {
	s, err := LoadOrGenerate(t.TempDir(), 1024)
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}
	for _, n := range []int{0, 1, 31, 33, 64} {
		if _, err := s.SignSHA256(context.Background(), make([]byte, n)); err == nil {
			t.Errorf("дайджест длиной %d принят", n)
		}
	}
}

// voidLegacyDigestInfoPrefix — SHA-1-DigestInfo легаси-подписи `.sig`,
// байты сняты с живой подписи Void (находки 2026-10-01, приложение А):
// `openssl pkeyutl -verifyrecover` даёт `302d300906052b0e03021a05000420` +
// 32 байта sha256(пакета). Литерал в тесте намеренно: константа пакета в
// сверке была бы тавтологией, а живой образец ловит и чужую OID, и
// неверные длины DigestInfo.
const voidLegacyDigestInfoPrefix = "\x30\x2d\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x20"

// recoverPKCS1 снимает PKCS#1 v1.5 padding с сырой подписи публичным
// ключом: EM = 0x00 || 0x01 || 0xFF…FF || 0x00 || T → T. Это
// `openssl pkeyutl -verifyrecover` без openssl.
func recoverPKCS1(t *testing.T, pub *rsa.PublicKey, sig []byte) []byte {
	t.Helper()
	if len(sig) != pub.Size() {
		t.Fatalf("подпись %d байт, хочу %d (модуль ключа)", len(sig), pub.Size())
	}
	em := make([]byte, pub.Size())
	new(big.Int).Exp(new(big.Int).SetBytes(sig), big.NewInt(int64(pub.E)), pub.N).FillBytes(em)
	if em[0] != 0x00 || em[1] != 0x01 {
		t.Fatalf("EM без PKCS#1 v1.5-заголовка: % x", em[:2])
	}
	i := 2
	for i < len(em) && em[i] == 0xff {
		i++
	}
	if i < 10 || i >= len(em) || em[i] != 0x00 {
		t.Fatalf("EM без разделителя 0x00: % x", em)
	}
	return em[i+1:]
}

// TestSignSHA256SHA1DigestInfo_VerifyRecover — контракт легаси-подписи:
// расшифрованная публичным ключом подпись = SHA-1-DigestInfo + переданный
// SHA-256-дайджест, и это ДРУГИЕ байты, чем у `.sig2`.
func TestSignSHA256SHA1DigestInfo_VerifyRecover(t *testing.T) {
	s, err := LoadOrGenerate(t.TempDir(), 1024)
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}
	digest := sha256.Sum256([]byte("Mustache-4.1_1.x86_64.xbps"))
	pub := parsePublicPEM(t, mustPEM(t, s))

	sig, err := s.SignSHA256SHA1DigestInfo(context.Background(), digest[:])
	if err != nil {
		t.Fatalf("SignSHA256SHA1DigestInfo: %v", err)
	}
	if len(sig) != 128 {
		t.Fatalf("подпись = %d байт, хочу 128 (модуль 1024)", len(sig))
	}
	want := append([]byte(voidLegacyDigestInfoPrefix), digest[:]...)
	if got := recoverPKCS1(t, pub, sig); !bytes.Equal(got, want) {
		t.Errorf("verifyrecover = % x\nхочу           % x", got, want)
	}
	// `.sig` — не `.sig2`: обёртка другая, байты обязаны отличаться.
	sig2, err := s.SignSHA256(context.Background(), digest[:])
	if err != nil {
		t.Fatalf("SignSHA256: %v", err)
	}
	if bytes.Equal(sig, sig2) {
		t.Error("`.sig` совпал с `.sig2` — DigestInfo не добавлен")
	}
	// Следствие формата (не ошибка): SHA-256-верификация на `.sig` падает —
	// ровно поэтому живой xbps и не проверяет `.sig` как sha256-подпись.
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err == nil {
		t.Error("`.sig` прошёл sha256-верификацию: обёртка не SHA-1-DigestInfo")
	}
}

func TestSignSHA256SHA1DigestInfo_DigestLength(t *testing.T) {
	s, err := LoadOrGenerate(t.TempDir(), 1024)
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}
	// 20 — длина SHA-1-дайджеста: для контракта она тоже неверна, тело
	// DigestInfo всегда SHA-256 (32 байта).
	for _, n := range []int{0, 1, 20, 31, 33, 64} {
		if _, err := s.SignSHA256SHA1DigestInfo(context.Background(), make([]byte, n)); err == nil {
			t.Errorf("дайджест длиной %d принят", n)
		}
	}
}

func TestPublicKeyPEM_CopyAndFormat(t *testing.T) {
	s, err := LoadOrGenerate(t.TempDir(), 1024)
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}
	a, err := s.PublicKeyPEM()
	if err != nil {
		t.Fatalf("PublicKeyPEM: %v", err)
	}
	b, err := s.PublicKeyPEM()
	if err != nil {
		t.Fatalf("PublicKeyPEM: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("PublicKeyPEM вернул разные байты для одного ключа")
	}
	// Копия: мутация результата не портит кеш.
	a[0] ^= 0xff
	c, _ := s.PublicKeyPEM()
	if !bytes.Equal(b, c) {
		t.Fatal("PublicKeyPEM отдал внутренний буфер (мутация протекла)")
	}
	parsePublicPEM(t, b)
}

func TestLoadOrGenerate_PersistsAcrossCalls(t *testing.T) {
	dir := t.TempDir()
	s1, err := LoadOrGenerate(dir, 1024)
	if err != nil {
		t.Fatalf("LoadOrGenerate (first): %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, rsaKeyFile))
	if err != nil {
		t.Fatalf("ключевой файл не создан: %v", err)
	}
	// 0600 — только на POSIX; на Windows chmod no-op.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("права ключевого файла = %o, хочу 0600", info.Mode().Perm())
	}
	// Приватный ключ — PKCS#1 PEM (`RSA PRIVATE KEY`), парсится x509.
	raw, err := os.ReadFile(filepath.Join(dir, rsaKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		t.Fatalf("приватный ключ: тип блока %v, хочу RSA PRIVATE KEY", block)
	}
	if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		t.Fatalf("приватный ключ не разбирается как PKCS#1: %v", err)
	}
	// Второй вызов — тот же ключ (стабильность между рестартами).
	s2, err := LoadOrGenerate(dir, 1024)
	if err != nil {
		t.Fatalf("LoadOrGenerate (second): %v", err)
	}
	if !bytes.Equal(mustPEM(t, s1), mustPEM(t, s2)) {
		t.Fatal("публичный ключ изменился между вызовами")
	}
	// Подпись s1 валидируется ключом s2 (тот же ключ).
	digest := sha256.Sum256([]byte("pkg"))
	sig, err := s1.SignSHA256(context.Background(), digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := rsa.VerifyPKCS1v15(parsePublicPEM(t, mustPEM(t, s2)), crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("подпись s1 не валидируется s2: %v", err)
	}
}

func TestLoadOrGenerate_InvalidArgs(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrGenerate("", 1024); err == nil {
		t.Error("пустой keys_dir принят")
	}
	// Generate(0) → ошибка, не паника и не «ключ неизвестной длины».
	if _, err := LoadOrGenerate(dir, 0); err == nil {
		t.Error("bits=0 принят")
	}
	if _, err := LoadOrGenerate(dir, -1); err == nil {
		t.Error("bits<0 принят")
	}
}

func TestLoadOrGenerate_CorruptedFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, rsaKeyFile), []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadOrGenerate(dir, 1024)
	if err == nil {
		t.Fatal("битый ключевой файл загружен без ошибки")
	}
	// Битый ключ — KeyMaterialError: wire валит старт, не деградирует.
	var km *domain.KeyMaterialError
	if !errors.As(err, &km) {
		t.Errorf("битый xbps-ключ: хочу KeyMaterialError, got %T: %v", err, err)
	}
}

func TestLoadOrGenerate_PublicKeyInPrivateSlot(t *testing.T) {
	dir := t.TempDir()
	// Публичный SPKI-PEM в файле приватного ключа: корректный PEM, но не
	// PKCS#1 PRIVATE KEY — обязан быть KeyMaterialError, а не тихая
	// подстановка чужого ключа.
	s, err := LoadOrGenerate(dir, 1024)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, _ := s.PublicKeyPEM()
	if err := os.WriteFile(filepath.Join(dir, rsaKeyFile), pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = LoadOrGenerate(dir, 1024)
	if err == nil {
		t.Fatal("публичный ключ принят как приватный")
	}
	var km *domain.KeyMaterialError
	if !errors.As(err, &km) {
		t.Errorf("публичный вместо приватного: хочу KeyMaterialError, got %T: %v", err, err)
	}
}

func TestLoadOrGenerate_ParallelSameKey(t *testing.T) {
	dir := t.TempDir()
	const concurrency = 4
	pubs := make([][]byte, concurrency)
	errs := make([]error, concurrency)
	var wg sync.WaitGroup
	for i := range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := LoadOrGenerate(dir, 1024)
			if err != nil {
				errs[i] = err
				return
			}
			pubs[i], errs[i] = s.PublicKeyPEM()
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("LoadOrGenerate #%d: %v", i, err)
		}
	}
	for i := 1; i < concurrency; i++ {
		if !bytes.Equal(pubs[i], pubs[0]) {
			t.Errorf("pubkey #%d != #0: fork инстансных xbps-ключей", i)
		}
	}
}

// Compile-time: Signer удовлетворяет port.RsaSigner.
func TestSignerImplementsRsaSigner(t *testing.T) {
	var _ interface {
		SignSHA256(ctx context.Context, digest []byte) ([]byte, error)
		SignSHA256SHA1DigestInfo(ctx context.Context, digest []byte) ([]byte, error)
		PublicKeyPEM() ([]byte, error)
	} = (*Signer)(nil)
}
