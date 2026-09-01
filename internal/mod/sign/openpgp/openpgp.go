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

// Пакет openpgp реализует port.Signer для apt-подобных личных репозиториев:
// InRelease (cleartext) + Release.gpg (detached, бинарный) одним ключом
// инстанса. Ключ ed25519 (OpenPGP, RFC 9580) генерируется на первом
// старте в signing.keys_dir/private.asc (0600) + public.asc; при
// повторных запусках — загружается. Опциональная passphrase защищает
// приватный ключ на диске (S2K, AES-256); неверная passphrase падает
// на DecryptPrivateKeys — это и есть проверка при загрузке.
//
// v1 — один ключ инстанса на все репо (KISS, docs/ARCHITECTURE.md §7).
// Per-repo ключи и per-repo signed=false — не-цели v1 (см. docs).
//
// Имя пакета совпадает с каталогом; библиотека go-crypto алиасится как
// gp, чтобы не тенять собственное имя пакета openpgp.

package openpgp

import (
	"bytes"
	"context"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	gp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"khrazhevnik/internal/core/config"
	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/core/registry"
)

// UID ключа инстанса — фиксирован (KISS): имя + email без комментария.
const (
	uidName  = "Khrazhevnik"
	uidEmail = "repo@localhost"

	privateKeyFile = "private.asc"
	publicKeyFile  = "public.asc"
)

// signerConfig — параметры OpenPGP: ed25519 (подпись) + SHA256 (хеш
// подписи). ed25519 выбирает и x25519 encryption-сабки автоматически
// (NewEntity), но он не используется для подписи метаданных — лишний,
// однако выкидывать его из ключа нельзя без ручной сборки пакетов;
// оставляем как есть (apt игнорирует encryption-сабки при проверке
// подписи Release). clock (если не nil) становится источником меток
// времени подписей (packet.Config.Now) — правило «время только через
// port.Clock»; иначе go-crypto берёт time.Now (тесты без часов).
func signerConfig(clock port.Clock) *packet.Config {
	cfg := &packet.Config{
		Algorithm:     packet.PubKeyAlgoEd25519,
		DefaultHash:   crypto.SHA256,
		DefaultCipher: packet.CipherAES256,
	}
	if clock != nil {
		cfg.Time = clock.Now
	}
	return cfg
}

func init() {
	// Compile-time регистрация фабрики подписчика в реестре: wire
	// (cmd) находит по имени «openpgp» и вызывает с cfg.Signing и
	// системными часами.
	registry.RegisterSigner(signerName, func(cfg config.Signing, clock port.Clock) (port.Signer, error) {
		return New(cfg.KeysDir, []byte(cfg.Passphrase), clock)
	})
}

const signerName = "openpgp"

// Signer — port.Signer через локальный OpenPGP-ключ инстанса.
// Один экземпляр на процесс; ключ грузится/генерируется в New.
// Методы безопасны к конкурентным вызовам только на чтение (Sign/
// SignDetached не мутируют состояние); генерация и загрузка идут
// исключительно в New, после чего entity и pubArmor иммутабельны.
type Signer struct {
	entity   *gp.Entity
	pubArmor []byte
	cfg      *packet.Config
}

// Compile-time: Signer реализует port.Signer.
var _ port.Signer = (*Signer)(nil)

// New готовит ключ инстанса в keysDir. Первый старт: генерация ed25519,
// экспорт private.asc (0600) + public.asc (0600) через эксклюзивный
// O_EXCL-захват (два процесса на общем keys_dir не плодят разные
// ключи — проигравший грузит ключ победителя), опциональное
// шифрование приватного ключа passphrase. Повторный старт: загрузка
// private.asc, расшифровка passphrase (если зашифрован) — неверная
// passphrase падает здесь. keysDir создаётся с 0700. clock — источник
// меток времени подписей и сабков (nil → системное время пакета).
func New(keysDir string, passphrase []byte, clock port.Clock) (*Signer, error) {
	if keysDir == "" {
		return nil, errors.New("openpgp: пустой keys_dir")
	}
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		return nil, fmt.Errorf("openpgp: keys_dir %s: %w", keysDir, err)
	}
	cfg := signerConfig(clock)
	privPath := filepath.Join(keysDir, privateKeyFile)

	entity, fresh, err := loadOrGenerate(privPath, passphrase, cfg)
	if err != nil {
		return nil, err
	}
	if fresh {
		if err := writeKeyFiles(keysDir, entity, passphrase, cfg); err != nil {
			if !errors.Is(err, os.ErrExist) {
				return nil, err
			}
			// Гонка первого старта: соседний процесс создал private.asc
			// раньше — его ключ канонический. Перечитываем и грузим его;
			// наш свежесгенерированный выкидываем (ещё ничего не подписывал).
			// public.asc не пишем: победитель уже записал, pubArmor для
			// runtime строится в памяти из entity.
			entity, fresh, err = loadOrGenerate(privPath, passphrase, cfg)
			if err != nil {
				return nil, err
			}
			if fresh {
				return nil, fmt.Errorf("openpgp: %s исчез сразу после гонки keygen", privPath)
			}
		}
	}
	// armorPublicKey пишет в bytes.Buffer — ошибиться не может, поэтому
	// без error-возврата; защитные ветки armorWrite покрыты прямым тестом
	// с failing-writer.
	pubArmor := armorPublicKey(entity)
	return &Signer{entity: entity, pubArmor: pubArmor, cfg: cfg}, nil
}

// loadOrGenerate возвращает entity: либо загруженный из privPath
// (fresh=false), либо свежесгенерированный (fresh=true). Отсутствие
// private.asc — единственный сигнал к генерации (os.ErrNotExist);
// прочие ошибки открытия (права, I/O) — KeyMaterialError, не повод
// молча перегенерировать ключ. Загрузка зашифрованного ключа
// расшифровывается passphrase; пустая passphrase для зашифрованного
// ключа и битый/публичный armored — тоже KeyMaterialError: ключи
// ЕСТЬ, но не читаются, старт обязан упасть, а не деградировать в
// «репо без подписи».
func loadOrGenerate(privPath string, passphrase []byte, cfg *packet.Config) (*gp.Entity, bool, error) {
	f, err := os.Open(privPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			e, gerr := generateEntity(cfg)
			if gerr != nil {
				return nil, false, fmt.Errorf("openpgp: генерация ключа: %w", gerr)
			}
			return e, true, nil
		}
		return nil, false, &domain.KeyMaterialError{What: "ключ подписи", Path: privPath, Err: err}
	}
	defer f.Close()
	entity, rerr := readPrivateEntity(f, passphrase)
	if rerr != nil {
		return nil, false, fmt.Errorf("%w", rerr)
	}
	return entity, false, nil
}

// readPrivateEntity разбирает armored keyring из r и валидирует его
// как ПРИВАТНЫЙ ключ инстанса: публичный ключ, скопированный поверх
// private.asc, «успешно» парсится, но взрывается при первом Sign
// глубоко в go-crypto — отгораживаемся понятной ошибкой на старте.
func readPrivateEntity(r io.Reader, passphrase []byte) (*gp.Entity, error) {
	el, err := gp.ReadArmoredKeyRing(r)
	if err != nil {
		return nil, &domain.KeyMaterialError{What: "ключ подписи", Reason: "битый armored (крэш посреди записи?)", Err: err}
	}
	if len(el) == 0 || el[0] == nil {
		return nil, &domain.KeyMaterialError{What: "ключ подписи", Reason: "armored не содержит ключа"}
	}
	entity := el[0]
	if entity.PrivateKey == nil {
		return nil, &domain.KeyMaterialError{
			What:   "ключ подписи",
			Reason: "не содержит приватного ключа (это публичный ключ?)",
		}
	}
	if privateKeysEncrypted(entity) {
		if len(passphrase) == 0 {
			return nil, &domain.KeyMaterialError{What: "ключ подписи", Reason: "ключ зашифрован, а passphrase пуста"}
		}
		if err := entity.DecryptPrivateKeys(passphrase); err != nil {
			return nil, &domain.KeyMaterialError{What: "ключ подписи", Reason: "расшифровка (неверная passphrase?)", Err: err}
		}
	}
	return entity, nil
}

// generateEntity создаёт ed25519 Entity с UID инстанса.
func generateEntity(cfg *packet.Config) (*gp.Entity, error) {
	return gp.NewEntity(uidName, "", uidEmail, cfg)
}

// privateKeysEncrypted сообщает, есть ли зашифрованные приватные
// компоненты (primary или сабки). Без early-return: проверяем все,
// чтобы сабки-ветка была покрываема (EncryptPrivateKeys шифрует и
// primary, и сабки — на reload оба Encrypted). DecryptPrivateKeys
// падает на пустой passphrase только если ключи реально зашифрованы —
// явная проверка выше даёт понятную ошибку вместо невнятной из пакета.
func privateKeysEncrypted(e *gp.Entity) bool {
	encrypted := false
	if e.PrivateKey != nil && e.PrivateKey.Encrypted {
		encrypted = true
	}
	for _, sk := range e.Subkeys {
		if sk.PrivateKey != nil && sk.PrivateKey.Encrypted {
			encrypted = true
		}
	}
	return encrypted
}

// writeKeyFiles сериализует приватный (опц. зашифрованный passphrase)
// и публичный ключи в keysDir с правами 0600. private.asc пишется
// первым и ЭКСКЛЮЗИВНО (O_CREATE|O_EXCL): при гонке двух процессов на
// первом старте проигравший получает ErrExist, перечитывает файл
// победителя и грузит ЕГО ключ — тихий fork инстансных ключей
// исключён (аудит 2026-08-30). При сбое до public.asc повторный старт
// перегенерирует.
//
// Для passphrase: шифруем приватные ключи в памяти, пишем зашифрованный
// private.asc (SerializePrivateWithoutSigning — reSign=true упал бы
// на зашифрованном ключе, т.к. SignUserId нечем подписывать), затем
// расшифровываем обратно — в runtime Signer держит расшифрованный
// ключ для подписи. Селф-сигнатуры от NewEntity уже валидны, reSign
// не нужен.
func writeKeyFiles(keysDir string, entity *gp.Entity, passphrase []byte, cfg *packet.Config) error {
	if len(passphrase) > 0 {
		if err := entity.EncryptPrivateKeys(passphrase, cfg); err != nil {
			return fmt.Errorf("openpgp: шифрование приватного ключа: %w", err)
		}
	}
	privPath := filepath.Join(keysDir, privateKeyFile)
	err := writeArmored(privPath, gp.PrivateKeyType, func(w io.Writer) error {
		return entity.SerializePrivateWithoutSigning(w, cfg)
	}, true)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			// Гонка первого старта: другой процесс успел создать
			// private.asc — его ключ канонический, наш выкидываем.
			return err
		}
		return fmt.Errorf("openpgp: запись %s: %w", privPath, err)
	}
	if len(passphrase) > 0 {
		if err := entity.DecryptPrivateKeys(passphrase); err != nil {
			return fmt.Errorf("openpgp: расшифровка после записи: %w", err)
		}
	}
	pubPath := filepath.Join(keysDir, publicKeyFile)
	if err := writeArmored(pubPath, gp.PublicKeyType, func(w io.Writer) error {
		return entity.Serialize(w)
	}, false); err != nil {
		return fmt.Errorf("openpgp: запись %s: %w", pubPath, err)
	}
	return nil
}

// writeArmored атомарно создаёт файл 0600: tmp-файл в том же каталоге
// → armor-тело → fsync → close → фиксация → fsync каталога (по образцу
// fs-storage fs.go Commit). Крэш посреди записи оставляет на диске
// ЛИБО старый файл, ЛИБО полный новый — «битый private.asc, который
// навсегда валит ReadArmoredKeyRing» исключён. exclusive=true —
// фиксация без перезаписи существующей цели (link(2) атомарен и падает
// с EEXIST, если цель уже есть): первый keygen двух процессов на общем
// keys_dir даёт ровно одного победителя. Не-excl (public.asc)
// перезаписывается rename поверх.
func writeArmored(path, blockType string, encode func(io.Writer) error, exclusive bool) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	writeErr := armorWrite(tmp, blockType, encode)
	if writeErr == nil {
		writeErr = tmp.Sync() // rename без fsync переживает не всякий крэш
	}
	closeErr := tmp.Close()
	if writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		// tmp не виден под целевым именем — очистка мусора best-effort,
		// битой цели оставить не может.
		_ = os.Remove(tmpPath)
		return writeErr
	}
	if exclusive {
		// link(2) — единственный stdlib-способ атомарного «создать, если
		// нет»: права tmp (0600) сохраняются, окно между проверкой и
		// фиксацией отсутствует. Windows: CreateHardLink = ERROR_ALREADY_EXISTS.
		if err := os.Link(tmpPath, path); err != nil {
			_ = os.Remove(tmpPath)
			return err
		}
		_ = os.Remove(tmpPath)
		return fsyncDir(filepath.Dir(path))
	}
	if err := renameReplace(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return fsyncDir(filepath.Dir(path))
}

// armorWrite эмитит armored block в w: открывает armor-encoder,
// вызывает write для тела, закрывает encoder. Общий путь для файла
// (writeArmored) и памяти (armorPublicKey). Ошибки armor.Encode и
// write (Serialize) и Close пробрасываются — все три пишут в w, так
// что failing-writer в тестах покрывает их разом.
func armorWrite(w io.Writer, blockType string, write func(io.Writer) error) error {
	aw, err := armor.Encode(w, blockType, nil)
	if err != nil {
		return err
	}
	if err := write(aw); err != nil {
		_ = aw.Close()
		return err
	}
	return aw.Close()
}

// armorPublicKey возвращает armored PGP PUBLIC KEY BLOCK в памяти —
// кешируется в Signer.pubArmor для отдачи через PublicKey(). Пишет в
// bytes.Buffer, который не ошибается, поэтому error-возврата нет;
// защитные ветки armorWrite покрыты прямым тестом с failing-writer.
func armorPublicKey(entity *gp.Entity) []byte {
	var buf bytes.Buffer
	_ = armorWrite(&buf, gp.PublicKeyType, func(w io.Writer) error {
		return entity.Serialize(w)
	})
	return buf.Bytes()
}

// Sign возвращает cleartext-подпись input (формат InRelease apt):
// «-----BEGIN PGP SIGNED MESSAGE----- ... -----END PGP SIGNATURE-----».
// Input вычитывается полностью — cleartext требует полного сообщения
// до dash-escape и эмиссии подписи.
func (s *Signer) Sign(_ context.Context, input io.Reader) (io.Reader, error) {
	data, err := io.ReadAll(input)
	if err != nil {
		return nil, fmt.Errorf("openpgp.Sign: чтение input: %w", err)
	}
	var buf bytes.Buffer
	if err := s.signCleartext(&buf, data); err != nil {
		return nil, fmt.Errorf("openpgp.Sign: %w", err)
	}
	return bytes.NewReader(buf.Bytes()), nil
}

// signCleartext пишет cleartext-подпись data в w. Вынесено из Sign,
// чтобы failing-writer в тестах покрывал error-ветки clearsign.Encode
// (заголовок в w), Write (dash-escape тело) и Close (эмиссия подписи).
func (s *Signer) signCleartext(w io.Writer, data []byte) error {
	cw, err := clearsign.Encode(w, s.entity.PrivateKey, s.cfg)
	if err != nil {
		return err
	}
	if _, err := cw.Write(data); err != nil {
		_ = cw.Close()
		return err
	}
	return cw.Close()
}

// SignDetached возвращает бинарную detached-подпись input (формат
// Release.gpg apt: бинарный OpenPGP-пакет, не armored). Потоковая —
// input уходит в подписант напрямую.
func (s *Signer) SignDetached(_ context.Context, input io.Reader) (io.Reader, error) {
	var buf bytes.Buffer
	if err := gp.DetachSign(&buf, s.entity, input, s.cfg); err != nil {
		return nil, fmt.Errorf("openpgp.SignDetached: %w", err)
	}
	return bytes.NewReader(buf.Bytes()), nil
}

// PublicKey возвращает кешированный armored публичный ключ (копия
// bytes — вызывающий волен мутировать).
func (s *Signer) PublicKey() ([]byte, error) {
	out := make([]byte, len(s.pubArmor))
	copy(out, s.pubArmor)
	return out, nil
}

// Fingerprint — hex отпечаток primary key; служебный метод для
// тестов (проверка стабильности ключа между запусками). Не входит
// в port.Signer — только у конкретного типа.
func (s *Signer) Fingerprint() string {
	return hex.EncodeToString(s.entity.PrimaryKey.Fingerprint)
}

// KeyID — 64-битный ID primary key (lower bits of fingerprint).
// Служебный, для логов/аудита.
func (s *Signer) KeyID() uint64 {
	return s.entity.PrimaryKey.KeyId
}
