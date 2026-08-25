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
	"strings"
	"testing"
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
	msg := []byte("narinfo: /nix/store/abc...-foo-1.0\nRefer: ...")
	sigLine := s.Sign(msg)

	parts := strings.SplitN(sigLine, ":", 3)
	if len(parts) != 3 {
		t.Fatalf("sig-строка не из 3 полей: %q", sigLine)
	}
	if parts[0] != "hydra.example.org" {
		t.Errorf("name в sig = %q, хочу hydra.example.org", parts[0])
	}
	if parts[1] != s.PubKeyB64() {
		t.Errorf("pubkey в sig не совпадает с PubKeyB64")
	}

	ok, err := Verify(msg, sigLine)
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
	ok, err := Verify([]byte("tampered"), sigLine)
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
	parts := strings.SplitN(sigLine, ":", 3)
	sigBytes, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	sigBytes[0] ^= 0xff
	bad := parts[0] + ":" + parts[1] + ":" + base64.StdEncoding.EncodeToString(sigBytes)
	ok, err := Verify([]byte("msg"), bad)
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
	sigLine := s1.Sign([]byte("msg"))
	// Подпись s1, проверяем — ok. Подпись s1 проверяется под pubkey
	// s1 (внутри sig-строки), так что Verify пройдёт. Чтобы проверить
	// «чужой pubkey», используем VerifyWithPubKey с ожидаемым s2.
	ok, err := VerifyWithPubKey([]byte("msg"), sigLine, s2.PubKeyB64())
	if err != nil {
		t.Fatalf("VerifyWithPubKey: %v", err)
	}
	if ok {
		t.Error("VerifyWithPubKey вернул true для чужого pubkey")
	}
	// С ожидаемым s1 — ok.
	ok, err = VerifyWithPubKey([]byte("msg"), sigLine, s1.PubKeyB64())
	if err != nil {
		t.Fatalf("VerifyWithPubKey: %v", err)
	}
	if !ok {
		t.Error("VerifyWithPubKey вернул false для своего pubkey")
	}
}

func TestVerify_Malformed(t *testing.T) {
	s, _ := New("k")
	goodPub := s.PubKeyB64()
	cases := []string{
		"onlyonefield",
		"two:fields",
		"k:not-base64!:abc",
		"k:" + strings.Repeat("A", 44) + ":tooshort",
		// валидный pubkey, но signature-поле — не base64.
		"k:" + goodPub + ":!!not-base64!!",
	}
	for _, c := range cases {
		if _, err := Verify([]byte("msg"), c); err == nil {
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
