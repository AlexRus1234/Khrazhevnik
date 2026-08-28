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

// Package fs — posix-хранилище поверх os-файлов (port.Storage). Ключи —
// пути от корня; запись идёт в tmp/<uuid> и становится видимой только
// атомарным rename на Commit. Единая точка path-traversal —
// domain.ValidateKey до любого обращения к диску.
package fs

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"iter"
	"os"
	"path/filepath"
	"strings"

	"khrazhevnik/internal/core/config"
	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/core/registry"
)

// tmpDir — каталог незавершённых загрузок внутри корня; в List не
// виден и не пересекается с валидными ключами (объекты кладутся в
// cache/… или repo/…).
const tmpDir = "tmp"

// init регистрирует фабрику в compile-time реестре.
func init() {
	registry.RegisterStorage(config.DriverFS, func(cfg config.Storage) (port.Storage, error) {
		return New(cfg.FS.Path, cryptoRand{})
	})
}

// Storage — файловое хранилище с корнем root.
type Storage struct {
	root string
	rand port.Rand
}

// New создаёт корень и tmp-каталог; rand именует временные файлы.
func New(root string, rand port.Rand) (*Storage, error) {
	if root == "" {
		return nil, fmt.Errorf("fs: пустой корень хранилища")
	}
	if err := os.MkdirAll(filepath.Join(root, tmpDir), 0o755); err != nil {
		return nil, fmt.Errorf("fs: создание корня %s: %w", root, err)
	}
	return &Storage{root: root, rand: rand}, nil
}

// Get возвращает ридер поверх зафиксированных байтов. Каталог (место
// вложенных ключей) объектом не считается.
func (s *Storage) Get(ctx context.Context, key string) (port.Object, error) {
	path, err := s.objectPath(ctx, key)
	if err != nil {
		return port.Object{}, err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return port.Object{}, mapPathError(err, key)
	}
	if st.IsDir() {
		return port.Object{}, &domain.NotFoundError{What: "объект", Key: key}
	}
	f, err := os.Open(path)
	if err != nil {
		return port.Object{}, mapPathError(err, key)
	}
	st, err = f.Stat()
	if err != nil {
		_ = f.Close()
		return port.Object{}, fmt.Errorf("fs: чтение метаданных %s: %w", path, err)
	}
	return port.Object{
		Meta: metaFrom(key, st),
		Body: f,
	}, nil
}

// Stat возвращает метаданные объекта (Lstat — без следования symlink).
func (s *Storage) Stat(ctx context.Context, key string) (port.Meta, error) {
	path, err := s.objectPath(ctx, key)
	if err != nil {
		return port.Meta{}, err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return port.Meta{}, mapPathError(err, key)
	}
	if st.IsDir() {
		return port.Meta{}, &domain.NotFoundError{What: "объект", Key: key}
	}
	return metaFrom(key, st), nil
}

// Put открывает транзакционную запись во временный файл.
func (s *Storage) Put(ctx context.Context, key string) (port.Writer, error) {
	if _, err := s.objectPath(ctx, key); err != nil {
		return nil, err
	}
	uuid, err := s.rand.UUID4()
	if err != nil {
		return nil, fmt.Errorf("fs: генерация имени временного файла: %w", err)
	}
	tmpPath := filepath.Join(s.root, tmpDir, uuid)
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("fs: создание временного файла: %w", err)
	}
	return &writer{storage: s, key: key, tmpPath: tmpPath, file: f}, nil
}

// Delete удаляет объект; пустые каталоги не трогает.
func (s *Storage) Delete(ctx context.Context, key string) error {
	path, err := s.objectPath(ctx, key)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return mapPathError(err, key)
	}
	return nil
}

// List лениво обходит объекты с префиксом prefix в лексическом порядке
// WalkDir (детерминированный DFS); tmp-каталог служебный и не виден.
// Ошибка обхода (недоступный каталог, пропавший корень, отмена ctx) —
// терминальная: один (Meta{}, err), обход прекращается — потребитель
// не должен путать сбой носителя с «объектов нет».
func (s *Storage) List(ctx context.Context, prefix string) iter.Seq2[port.Meta, error] {
	return func(yield func(port.Meta, error) bool) {
		if !validPrefix(prefix) {
			return
		}
		_ = filepath.WalkDir(s.root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				yield(port.Meta{}, fmt.Errorf("fs: обход %s: %w", path, err))
				return fs.SkipAll
			}
			if ctx.Err() != nil {
				yield(port.Meta{}, ctx.Err())
				return fs.SkipAll
			}
			key, ok := s.keyOf(path)
			if !ok {
				return nil // сам корень
			}
			if d.IsDir() {
				if key == tmpDir {
					return fs.SkipDir
				}
				// отсечение поддеревьев мимо префикса
				if !strings.HasPrefix(prefix, key) && !strings.HasPrefix(key, prefix) {
					return fs.SkipDir
				}
				return nil
			}
			if strings.HasPrefix(key, prefix) && d.Type().IsRegular() {
				info, err := d.Info()
				if err != nil {
					// файл исчез между ReadDir и Info — листинг неполон
					yield(port.Meta{}, fmt.Errorf("fs: метаданные %s: %w", path, err))
					return fs.SkipAll
				}
				if !yield(metaFrom(key, info), nil) || ctx.Err() != nil {
					return fs.SkipAll
				}
			}
			return nil
		})
	}
}

// objectPath — проверка ключа (единая точка traversal) и перевод в
// абсолютный путь. Namespace tmp/ — внутренний (незавершённые
// загрузки) и извне недоступен.
func (s *Storage) objectPath(ctx context.Context, key string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if key == tmpDir || strings.HasPrefix(key, tmpDir+"/") {
		return "", &domain.InvalidKeyError{
			Key:     key,
			Reasons: []error{errors.New("зарезервированный namespace tmp/")},
		}
	}
	if err := domain.ValidateKey(key); err != nil {
		return "", err
	}
	return filepath.Join(s.root, filepath.FromSlash(key)), nil
}

// keyOf — обратный перевод пути обхода в ключ; false для корня.
func (s *Storage) keyOf(path string) (string, bool) {
	if path == s.root {
		return "", false
	}
	rel, err := filepath.Rel(s.root, path)
	if err != nil {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

// validPrefix — мягкая проверка префикса List: хвостовой «/» легален
// («cache/apt/»), остальное — правила ключей.
func validPrefix(prefix string) bool {
	trimmed := strings.TrimSuffix(prefix, "/")
	if trimmed == "" {
		return true
	}
	return domain.ValidateKey(trimmed) == nil
}

// metaFrom — Meta из FileInfo (fs не знает ETag/ContentType).
func metaFrom(key string, st os.FileInfo) port.Meta {
	return port.Meta{Key: key, Size: st.Size(), ModTime: st.ModTime()}
}

// mapPathError переводит ошибки носителя: отсутствующий файл — NotFound.
func mapPathError(err error, key string) error {
	if os.IsNotExist(err) {
		return &domain.NotFoundError{What: "объект", Key: key}
	}
	return err
}

// writer — транзакционная запись: tmp-файл → rename при Commit.
type writer struct {
	storage *Storage
	key     string
	tmpPath string
	file    *os.File
	done    bool
}

// Write реализует io.Writer.
func (w *writer) Write(p []byte) (int, error) {
	if w.done {
		return 0, fmt.Errorf("fs: запись после завершения Writer для %q", w.key)
	}
	return w.file.Write(p)
}

// Commit делает объект видимым: close → mkdir → rename → fsync каталога.
func (w *writer) Commit(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if w.done {
		return fmt.Errorf("fs: повторный Commit для %q", w.key)
	}
	w.done = true
	if err := w.file.Close(); err != nil {
		return fmt.Errorf("fs: закрытие временного файла: %w", err)
	}
	final := filepath.Join(w.storage.root, filepath.FromSlash(w.key))
	if err := os.MkdirAll(filepath.Dir(final), 0o755); err != nil {
		return fmt.Errorf("fs: создание каталога объекта: %w", err)
	}
	if err := renameReplace(w.tmpPath, final); err != nil {
		_ = os.Remove(w.tmpPath)
		return fmt.Errorf("fs: фиксация %q: %w", w.key, err)
	}
	// rename устойчив к выключению питания только после fsync каталога
	if err := fsyncDir(filepath.Dir(final)); err != nil {
		return fmt.Errorf("fs: fsync каталога %q: %w", w.key, err)
	}
	return nil
}

// Abort отбрасывает запись и временный файл.
func (w *writer) Abort(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if w.done {
		return fmt.Errorf("fs: повторный Abort для %q", w.key)
	}
	w.done = true
	if err := w.file.Close(); err != nil {
		return fmt.Errorf("fs: закрытие временного файла: %w", err)
	}
	if err := os.Remove(w.tmpPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("fs: удаление временного файла: %w", err)
	}
	return nil
}

// cryptoRand — port.Rand поверх crypto/rand (как uuidRand в wire).
type cryptoRand struct{}

// UUID4 генерирует канонический UUID v4.
func (cryptoRand) UUID4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("fs: чтение crypto/rand: %w", err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

// Int64 возвращает неотрицательное псевдослучайное число в [0, max):
// 8 байт crypto/rand как uint64. fs-хранилище использует rand только
// для tmp-имён (UUID4); Int64 добавлен ради реализации port.Rand,
// расширенного в сессии 11 (джиттер планировщика зеркал).
func (cryptoRand) Int64(max int64) int64 {
	if max <= 0 {
		return 0
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	n := int64(b[0])<<56 | int64(b[1])<<48 | int64(b[2])<<40 | int64(b[3])<<32 |
		int64(b[4])<<24 | int64(b[5])<<16 | int64(b[6])<<8 | int64(b[7])
	if n < 0 {
		n = -n
	}
	return n % max
}
