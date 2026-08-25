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

// Пакет ed25519 — подпись narinfo-строк в формате nix-бинарного кеша:
// «name:pubkey:signature», где pubkey и signature — base64 (nix
// использует raw ed25519 + base64, не OpenPGP). Задел под генератор
// nix-индексов (сессия 16): здесь только примитивы подписи и формат
// sig-строки, roundtrip-тесты. Интеграция в publish/nix-генератор —
// сессия 16; здесь модуль НЕ реализует port.Signer (тот заточен под
// OpenPGP/cleartext apt) — у nix своя, более простая модель подписи.
//
// Ключ — ed25519 из stdlib (crypto/ed25519), без зависимостей.

package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Signer — ed25519 ключ инстанса для nix narinfo-подписи. PubKey —
// base64 публичной части; Name — метка подписи (nix идентифицирует
// подписи по имени ключа в sig-строке). Иммутабелен после New.
type Signer struct {
	name   string
	priv   ed25519.PrivateKey
	pub    ed25519.PublicKey
	pubB64 string
}

// New генерирует свежую пару ed25519 с именем name (используется в
// sig-строке как префикс). Имя не может быть пустым и не должно
// содержать двоеточий (разделитель формата).
func New(name string) (*Signer, error) {
	if name == "" {
		return nil, errors.New("ed25519: пустое имя ключа")
	}
	if strings.ContainsAny(name, ":") {
		return nil, fmt.Errorf("ed25519: имя ключа %q содержит ':'", name)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ed25519: генерация ключа: %w", err)
	}
	return &Signer{
		name:   name,
		priv:   priv,
		pub:    pub,
		pubB64: base64.StdEncoding.EncodeToString(pub),
	}, nil
}

// FromKey восстанавливает Signer из готовой приватной части (тесты,
// детерминированные ключи). Имя — как в New.
func FromKey(name string, priv ed25519.PrivateKey) (*Signer, error) {
	if name == "" {
		return nil, errors.New("ed25519: пустое имя ключа")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("ed25519: приватный ключ длиной %d, хочу %d", len(priv), ed25519.PrivateKeySize)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("ed25519: приватный ключ не содержит ed25519.PublicKey")
	}
	return &Signer{name: name, priv: priv, pub: pub, pubB64: base64.StdEncoding.EncodeToString(pub)}, nil
}

// Sign подписывает msg и возвращает sig-строку nix:
// «name:pubkey:signature» (pubkey и signature — base64 raw байт).
// msg — canonical narinfo-строка без завершающего перевода строки
// (nix подписывает именно байты сообщения).
func (s *Signer) Sign(msg []byte) string {
	sig := ed25519.Sign(s.priv, msg)
	return s.name + ":" + s.pubB64 + ":" + base64.StdEncoding.EncodeToString(sig)
}

// PubKeyB64 возвращает base64 публичной части (для публикации в
// nix-метаданных binary-cacha, чтобы клиенты знали, кем подписано).
func (s *Signer) PubKeyB64() string { return s.pubB64 }

// Name возвращает метку ключа.
func (s *Signer) Name() string { return s.name }

// Verify проверяет sig-строку формата «name:pubkey:signature» против
// msg: base64-декодирует pubkey и signature, сверяет ed25519.Verify.
// Имя в sig-строке игнорируется (pubkey однозначно определяет ключ);
// оно нужно только людям и nix-клиентам для человекочитаемых ошибок.
// Возвращает (true, nil) для валидной подписи, (false, nil) для
// невалидной (несовпадение), (false, err) для малформированной строки.
func Verify(msg []byte, sigLine string) (bool, error) {
	parts := strings.SplitN(sigLine, ":", 3)
	if len(parts) != 3 {
		return false, fmt.Errorf("ed25519: sig-строка должна быть name:pubkey:signature, получено %d полей", len(parts))
	}
	pub, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return false, fmt.Errorf("ed25519: pubkey base64: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return false, fmt.Errorf("ed25519: pubkey длиной %d, хочу %d", len(pub), ed25519.PublicKeySize)
	}
	sig, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return false, fmt.Errorf("ed25519: signature base64: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return false, fmt.Errorf("ed25519: signature длиной %d, хочу %d", len(sig), ed25519.SignatureSize)
	}
	return ed25519.Verify(pub, msg, sig), nil
}

// VerifyWithPubKey проверяет sig-строку, требуя совпадения pubkey в
// строке с ожидаемым wantPubB64. nix-клиенты доверяют pubkey из
// конфига (trusted-public-keys), поэтому сверка ожидаемого pubkey
// обязательна — иначе sig-строка с чужим pubkey прошла бы Verify,
// если подпись просто валидна под этим чужим ключом.
func VerifyWithPubKey(msg []byte, sigLine, wantPubB64 string) (bool, error) {
	parts := strings.SplitN(sigLine, ":", 3)
	if len(parts) != 3 {
		return false, fmt.Errorf("ed25519: sig-строка должна быть name:pubkey:signature")
	}
	if parts[1] != wantPubB64 {
		return false, nil
	}
	return Verify(msg, sigLine)
}
