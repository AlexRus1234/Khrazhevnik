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
// «name:signature», где signature — base64 raw байт (nix использует
// detached ed25519 + base64, не OpenPGP; см. libutil local-keys.cc
// SecretKey::signDetached). Подписывается fingerprint «1;StorePath;
// NarHash;NarSize;Refs» (libstore PathInfo::fingerprint), не байты
// файла. Задел под генератор nix-индексов (сессия 16): здесь только
// примитивы подписи и формат sig-строки, roundtrip-тесты. Интеграция в
// publish/nix-генератор — сессия 16; здесь модуль НЕ реализует
// port.Signer (тот заточен под OpenPGP/cleartext apt) — у nix своя,
// более простая модель подписи.
//
// Ключ — ed25519 из stdlib (crypto/ed25519), без зависимостей.

package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"khrazhevnik/internal/core/config"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/core/registry"
)

// narSignerName — метка ключа nix в sig-строке («khrazhevnik:sig»).
// Клиенты добавляют «khrazhevnik:<pubkey-b64>» в trusted-public-keys.
// KISS v1: один ключ инстанса на все nix-репо (как у openpgp).
const narSignerName = "khrazhevnik"

// narKeyFile — имя файла приватного ключа ed25519 в keys_dir (рядом с
// private.asc openpgp). Сырые 64 байта, права 0600.
const narKeyFile = "nix-ed25519.key"

func init() {
	// Compile-time регистрация фабрики nar-подписчика в реестре: wire
	// (cmd) находит по имени «ed25519» и вызывает с cfg.Signing. Ключ
	// персистится в keys_dir/nix-ed25519.key (0600): первый старт —
	// генерация, повторные — загрузка (fingerprint стабилен, чтобы
	// trusted-public-keys клиентов не протухали между рестартами).
	registry.RegisterNarSigner(narSignerKind, func(cfg config.Signing) (port.NarSigner, error) {
		return LoadOrGenerate(narSignerName, cfg.KeysDir)
	})
}

// narSignerKind — имя регистрации в реестре.
const narSignerKind = "ed25519"

// Compile-time: Signer реализует port.NarSigner (Sign/PubKeyB64/Name).
var _ port.NarSigner = (*Signer)(nil)

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
// «name:signature» (signature — base64 raw байт ed25519). msg —
// fingerprint «1;StorePath;NarHash;NarSize;Refs», который подписывает
// сам nix (libstore PathInfo::fingerprint), а не байты файла.
func (s *Signer) Sign(msg []byte) string {
	sig := ed25519.Sign(s.priv, msg)
	return s.name + ":" + base64.StdEncoding.EncodeToString(sig)
}

// PubKeyB64 возвращает base64 публичной части (для публикации в
// nix-метаданных binary-cacha, чтобы клиенты знали, кем подписано).
func (s *Signer) PubKeyB64() string { return s.pubB64 }

// PubKey возвращает raw публичную часть ed25519 (32 байта) — для
// Verify, которому нужен ключ из trusted-public-keys, а не из sig-
// строки (в 2-полевом nix-формате pubkey в Sig: не живёт).
func (s *Signer) PubKey() ed25519.PublicKey { return s.pub }

// Name возвращает метку ключа.
func (s *Signer) Name() string { return s.name }

// Verify проверяет sig-строку формата «name:signature» против msg
// с ожидаемым pub (nix-клиент знает pubkey из trusted-public-keys;
// в 2-полевой sig-строке pubkey не живёт): base64-декодирует
// signature, сверяет ed25519.Verify. Возвращает (true, nil) для
// валидной подписи, (false, nil) для невалидной (несовпадение),
// (false, err) для малформированной строки.
func Verify(pub ed25519.PublicKey, msg []byte, sigLine string) (bool, error) {
	if len(pub) != ed25519.PublicKeySize {
		return false, fmt.Errorf("ed25519: pubkey длиной %d, хочу %d", len(pub), ed25519.PublicKeySize)
	}
	parts := strings.SplitN(sigLine, ":", 2)
	if len(parts) != 2 {
		return false, fmt.Errorf("ed25519: sig-строка должна быть name:signature, получено %d полей", len(parts))
	}
	sig, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return false, fmt.Errorf("ed25519: signature base64: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return false, fmt.Errorf("ed25519: signature длиной %d, хочу %d", len(sig), ed25519.SignatureSize)
	}
	return ed25519.Verify(pub, msg, sig), nil
}

// VerifyWithPubKey проверяет sig-строку, требуя совпадения имени ключа
// в строке с ожидаемым wantName и подписи под pub. nix-клиенты
// доверяют паре «имя:pubkey» из конфига (trusted-public-keys) и
// сверяют имя в sig-строке с именем ключа (local-keys.cc
// verifyDetached: keyName обязана совпасть) — иначе sig-строка с
// чужим именем прошла бы Verify, если подпись просто валидна под
// чужим ключом.
func VerifyWithPubKey(pub ed25519.PublicKey, msg []byte, sigLine, wantName string) (bool, error) {
	parts := strings.SplitN(sigLine, ":", 2)
	if len(parts) != 2 {
		return false, fmt.Errorf("ed25519: sig-строка должна быть name:signature")
	}
	if parts[0] != wantName {
		return false, nil
	}
	return Verify(pub, msg, sigLine)
}

// LoadOrGenerate готовит narinfo-ключ инстанса в keysDir. Первый старт:
// генерация ed25519, экспорт сырого приватного ключа (64 байта) в
// keysDir/nix-ed25519.key (0600). Повторный старт: загрузка 64 байт и
// восстановление Signer'а. Стабильность pubkey между рестартами —
// инвариант: клиенты доверяют pubkey в trusted-public-keys, смена ключа
// инвалидировала бы все ранее подписанные narinfo. keysDir создаётся
// с 0700 (как у openpgp).
func LoadOrGenerate(name, keysDir string) (*Signer, error) {
	if name == "" {
		return nil, errors.New("ed25519: пустое имя ключа")
	}
	if strings.ContainsAny(name, ":") {
		return nil, fmt.Errorf("ed25519: имя ключа %q содержит ':'", name)
	}
	if keysDir == "" {
		return nil, errors.New("ed25519: пустой keys_dir")
	}
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		return nil, fmt.Errorf("ed25519: keys_dir %s: %w", keysDir, err)
	}
	path := filepath.Join(keysDir, narKeyFile)
	if f, err := os.Open(path); err == nil {
		priv, rerr := io.ReadAll(f)
		_ = f.Close()
		if rerr != nil {
			return nil, fmt.Errorf("ed25519: чтение %s: %w", path, rerr)
		}
		if len(priv) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("ed25519: %s: размер %d, хочу %d", path, len(priv), ed25519.PrivateKeySize)
		}
		return FromKey(name, ed25519.PrivateKey(priv))
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("ed25519: open %s: %w", path, err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ed25519: генерация ключа: %w", err)
	}
	if err := os.WriteFile(path, priv, 0o600); err != nil {
		return nil, fmt.Errorf("ed25519: запись %s: %w", path, err)
	}
	return &Signer{
		name:   name,
		priv:   priv,
		pub:    pub,
		pubB64: base64.StdEncoding.EncodeToString(pub),
	}, nil
}
