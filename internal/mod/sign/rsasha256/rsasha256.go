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

// Пакет rsasha256 реализует port.RsaSigner для личных xbps-репозиториев
// (Void Linux): detached-подпись каждого пакета <pkg>.sig2 — сырые байты
// RSA PKCS#1 v1.5 поверх SHA-256-дайджеста файла (формат verifysig.c
// xbps-rindex). Ключ инстанса — RSA-4096, PKCS#1 PEM (`RSA PRIVATE KEY`,
// формат PEM_read_RSAPrivateKey xbps-rindex); публичная часть — SPKI-PEM
// (`PUBLIC KEY`, PEM_write_bio_RSA_PUBKEY) для index-meta.plist и ручки
// раздачи. Один ключ на инстанс, живёт в signing.keys_dir (KISS v1,
// прецедент ed25519.go). Passphrase НЕ поддерживается (KISS; в отличие
// от openpgp). Только stdlib: crypto/rsa + crypto/x509 + encoding/pem.
//
// Ключ персистится в keys_dir/xbps-rsa.key (0600): первый старт —
// генерация, повторные — загрузка (смена ключа молча инвалидировала бы
// все ранее выданные .sig2 — прецедент ed25519).

package rsasha256

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"khrazhevnik/internal/core/config"
	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/core/registry"
)

// rsaSignerKind — имя регистрации в реестре.
const rsaSignerKind = "rsasha256"

// rsaKeyFile — имя файла приватного ключа RSA в keys_dir (рядом с
// private.asc openpgp и nix-ed25519.key). PKCS#1 PEM, права 0600.
const rsaKeyFile = "xbps-rsa.key"

// defaultBits — длина ключа инстанса xbps (RSA-4096). Генерация —
// секунды на первом старте, допустимо (KISS v1).
const defaultBits = 4096

// minBits — нижняя граница длины ключа: PKCS#1 v1.5 поверх SHA-256
// требует запаса под padding, меньше 512 бит бессмысленно (и rsa-
// генератор stdlib отвергает такие значения).
const minBits = 512

func init() {
	// Compile-time регистрация фабрики xbps-подписчика в реестре: wire
	// (cmd) находит по имени «rsasha256» и вызывает с cfg.Signing.
	// Ключ персистится в keys_dir/xbps-rsa.key (0600).
	registry.RegisterRsaSigner(rsaSignerKind, func(cfg config.Signing) (port.RsaSigner, error) {
		return LoadOrGenerate(cfg.KeysDir, defaultBits)
	})
}

// Compile-time: Signer реализует port.RsaSigner (SignSHA256/PublicKeyPEM).
var _ port.RsaSigner = (*Signer)(nil)

// Signer — RSA-ключ инстанса для xbps .sig2-подписи. Иммутабелен после
// LoadOrGenerate/New: priv не мутируется, pubPEM — кешированный SPKI.
// Методы безопасны к конкурентным вызовам на чтение.
type Signer struct {
	priv   *rsa.PrivateKey
	pubPEM []byte
}

// LoadOrGenerate готовит xbps-RSA-ключ инстанса в keysDir. Первый старт:
// генерация bits-битного ключа, атомарная фиксация PKCS#1 PEM БЕЗ
// перезаписи существующего (link(2): два процесса на общем keys_dir дают
// одного победителя, проигравший грузит его ключ). Повторный старт:
// загрузка PEM, разбор PKCS#1, Validate — битый/чужой файл ловится здесь
// (KeyMaterialError), а не первым невалидным .sig2. Стабильность ключа
// между рестартами — инвариант: клиенты доверяют публичному ключу,
// смена ключа инвалидировала бы все ранее подписанные .sig2. keysDir
// создаётся с 0700 (как у openpgp/ed25519).
func LoadOrGenerate(keysDir string, bits int) (*Signer, error) {
	if keysDir == "" {
		return nil, errors.New("rsasha256: пустой keys_dir")
	}
	if bits < minBits {
		return nil, fmt.Errorf("rsasha256: некорректная длина ключа %d, минимум %d", bits, minBits)
	}
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		return nil, fmt.Errorf("rsasha256: keys_dir %s: %w", keysDir, err)
	}
	path := filepath.Join(keysDir, rsaKeyFile)
	f, err := os.Open(path)
	if err == nil {
		data, rerr := io.ReadAll(f)
		_ = f.Close()
		if rerr != nil {
			return nil, &domain.KeyMaterialError{What: "xbps-rsa-ключ", Path: path, Err: rerr}
		}
		return parsePrivateKey(data, path)
	}
	if !errors.Is(err, os.ErrNotExist) {
		// Ошибка открытия НЕ «файла нет» (права, I/O) — ключи есть, но
		// не читаются: жёсткая KeyMaterialError, не тихая регенерация.
		return nil, &domain.KeyMaterialError{What: "xbps-rsa-ключ", Path: path, Err: err}
	}
	priv, gerr := rsa.GenerateKey(rand.Reader, bits)
	if gerr != nil {
		return nil, fmt.Errorf("rsasha256: генерация ключа: %w", gerr)
	}
	if werr := writeKeyAtomic(path, encodePrivateKey(priv)); werr != nil {
		if errors.Is(werr, os.ErrExist) {
			// Гонка первого старта: соседний процесс зафиксировал ключ
			// раньше — его ключ канонический, грузим его.
			return LoadOrGenerate(keysDir, bits)
		}
		return nil, fmt.Errorf("rsasha256: запись %s: %w", path, werr)
	}
	return newSigner(priv)
}

// parsePrivateKey разбирает PKCS#1 PEM приватного ключа и валидирует его.
// Неверный тип блока, битый DER или невалидные параметры — KeyMaterialError
// (старт обязан упасть, а не молча регенерировать ключ).
func parsePrivateKey(data []byte, path string) (*Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, &domain.KeyMaterialError{
			What:   "xbps-rsa-ключ",
			Path:   path,
			Reason: "не PKCS#1 PEM «RSA PRIVATE KEY» (битый файл?)",
		}
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, &domain.KeyMaterialError{What: "xbps-rsa-ключ", Path: path, Reason: "разбор PKCS#1", Err: err}
	}
	if err := priv.Validate(); err != nil {
		return nil, &domain.KeyMaterialError{What: "xbps-rsa-ключ", Path: path, Reason: "ключ невалиден", Err: err}
	}
	return newSigner(priv)
}

// newSigner собирает Signer и кеширует SPKI-PEM публичного ключа.
func newSigner(priv *rsa.PrivateKey) (*Signer, error) {
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("rsasha256: маршалинг публичного ключа: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return &Signer{priv: priv, pubPEM: pubPEM}, nil
}

// encodePrivateKey сериализует приватный ключ в PKCS#1 PEM
// (`RSA PRIVATE KEY`) — формат, который читает xbps-rindex.
func encodePrivateKey(priv *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
}

// SignSHA256 подписывает дайджест SHA-256 содержимого файла и возвращает
// сырые байты подписи PKCS#1 v1.5 (512 для ключа 4096) — формат .sig2
// xbps. digest обязан быть ровно 32 байта; иначе ошибка (не паника и не
// усечение, которое дало бы валидную-по-форме, но неверную подпись).
func (s *Signer) SignSHA256(_ context.Context, digest []byte) ([]byte, error) {
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("rsasha256: дайджест длиной %d, хочу %d", len(digest), sha256.Size)
	}
	sig, err := rsa.SignPKCS1v15(nil, s.priv, crypto.SHA256, digest)
	if err != nil {
		return nil, fmt.Errorf("rsasha256: подпись: %w", err)
	}
	return sig, nil
}

// PublicKeyPEM возвращает SPKI-PEM публичного ключа (`PUBLIC KEY`) —
// для index-meta.plist и ручки раздачи /repo/<name>/xbps-key (сессия
// 142). Возвращается копия: вызывающий волен мутировать.
func (s *Signer) PublicKeyPEM() ([]byte, error) {
	out := make([]byte, len(s.pubPEM))
	copy(out, s.pubPEM)
	return out, nil
}

// writeKeyAtomic фиксирует PEM приватного ключа атомарно: tmp → fsync →
// close → link(2) без перезаписи цели → fsync каталога (образец
// ed25519.writeKeyAtomic). Крэш посреди записи не оставляет
// битый-но-существующий файл (регенерации не будет — файл есть). Права
// tmp 0600 (os.CreateTemp) переносятся link'ом.
func writeKeyAtomic(path string, pemBytes []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	writeErr := writeAll(tmp, pemBytes)
	if writeErr == nil {
		writeErr = tmp.Sync()
	}
	closeErr := tmp.Close()
	if writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		_ = os.Remove(tmpPath)
		return writeErr
	}
	if err := os.Link(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	_ = os.Remove(tmpPath)
	return fsyncDir(filepath.Dir(path))
}

// writeAll — io.Writer с полным вычитом (os.File.Write может записать
// меньше p; контракт io.Writer обязывает цикл).
func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}
