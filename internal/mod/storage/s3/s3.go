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

// Package s3 — S3-совместимое хранилище (port.Storage). Put спулирует
// байты в локальный каталог (storage.s3.spool_dir); Commit — PutObject
// (атомарный в S3: объект либо виден целиком, либо нет), Abort —
// удаление спула. Объекты крупнее порога multipart'ятся minio-go
// (single-PUT cap S3 — 5 GiB < cache.max_object_size): стартовый sweep
// (спул + incomplete multipart) убирает мусор после краха. Единая точка
// path-traversal — domain.ValidateKey до любого обращения к S3;
// namespace tmp/ зарезервирован (как в fs) для единообразия контракта.
package s3

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"math"
	"mime"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"khrazhevnik/internal/core/config"
	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/core/registry"
)

// tmpPrefix — зарезервированный namespace (незавершённые загрузки fs
// живут там; s3 спулит в spool_dir, но ключ tmp/ отвергается ради
// единого контракта хранилища — клиент не может им воспользоваться).
const tmpPrefix = "tmp"

// init регистрирует фабрику в compile-time реестре.
func init() {
	registry.RegisterStorage(config.DriverS3, func(cfg config.Storage) (port.Storage, error) {
		return New(cfg.S3, cryptoRand{})
	})
}

// Storage — S3-хранилище поверх *minio.Client. Спул-каталог хранит
// незавершённые тела до атомарного PutObject.
type Storage struct {
	client   *minio.Client
	bucket   string
	spoolDir string
	rand     port.Rand
}

// New создаёт клиент S3 и спул-каталог; rand именует спул-файлы.
// На старте спул подметается: живых writers не бывает (один процесс на
// spool_dir), все остатки — тела погибших при крэше upload'ов.
// Endpoint с «https://» → Secure=true (TLS), иначе http; схема
// отсекается — minio.New принимает host[:port] без схемы.
func New(cfg config.S3Storage, rand port.Rand) (*Storage, error) {
	endpoint, secure, ok := splitEndpoint(cfg.Endpoint)
	if !ok {
		return nil, fmt.Errorf("s3: пустой endpoint")
	}
	lookup := minio.BucketLookupAuto
	if cfg.PathStyle {
		lookup = minio.BucketLookupPath
	}
	cli, err := minio.New(endpoint, &minio.Options{
		Creds:        credentials.NewStaticV4(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		Secure:       secure,
		Region:       cfg.Region,
		BucketLookup: lookup,
	})
	if err != nil {
		return nil, fmt.Errorf("s3: клиент %s: %w", endpoint, err)
	}
	if cfg.SpoolDir == "" {
		return nil, fmt.Errorf("s3: пустой spool_dir")
	}
	if err := os.MkdirAll(cfg.SpoolDir, 0o755); err != nil {
		return nil, fmt.Errorf("s3: создание спула %s: %w", cfg.SpoolDir, err)
	}
	if err := sweepSpool(cfg.SpoolDir); err != nil {
		return nil, err
	}
	// Баундированный контекст: зависший endpoint не должен блокировать
	// старт дольше таймаута — это та же «деградация без s3».
	sweepCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sweepMultipart(sweepCtx, cli, cfg.Bucket)
	return &Storage{client: cli, bucket: cfg.Bucket, spoolDir: cfg.SpoolDir, rand: rand}, nil
}

// sweepSpool удаляет осиротевшие спул-файлы после крэша/убийства
// процесса (аудит, fs durability: s3-спул симметричен fs tmp/).
// Сбой удаления — ошибка старта: недокачки копились бы вечно, а
// замусоренный спул — проблема носителя, которую нужно показать.
func sweepSpool(spoolDir string) error {
	entries, err := os.ReadDir(spoolDir)
	if err != nil {
		return fmt.Errorf("s3: чтение спула %s: %w", spoolDir, err)
	}
	for _, e := range entries {
		p := filepath.Join(spoolDir, e.Name())
		if err := os.RemoveAll(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("s3: удаление осиротевшего спула %s: %w", p, err)
		}
	}
	return nil
}

// sweepMultipart абортит incomplete multipart-загрузки в нашем
// пространстве ключей: крах процесса посреди multipart (SIGKILL)
// оставляет осколки навсегда — minio-go абортит их только при возврате
// ошибки, не при гибели процесса. Листинг не по всему bucket (""), а
// перечислением корней StorageKey (порт Target: cache/<eco>/… —
// прокси/зеркало, repo/<id>/… — личные репо): bucket бывает общим
// с соседними инстансами (прод, storage-db.md), их идущие загрузки
// вне наших корней наш рестарт не трогает. Новый корневой namespace
// StorageKey — добавить сюда. Фильтр возраста осколков не нужен:
// sweep выполняется до поднятия слушателей нашего процесса, легитимных
// multipart-загрузок в этот момент нет (v1-граница — один инстанс на
// корни cache//repo/). Ошибки логируются и не валят старт: деградация
// «без s3» хуже мусора.
func sweepMultipart(ctx context.Context, cli *minio.Client, bucket string) {
	log := slog.Default().With("bucket", bucket)
	// Прямой AbortMultipartUpload по известному info.UploadID (Core-метод):
	// RemoveIncompleteUpload внутри перелистывал бы uploads — лишний
	// List-раунд на каждую сироту.
	core := minio.Core{Client: cli}
	for _, root := range []string{"cache/", "repo/"} {
		for info := range cli.ListIncompleteUploads(ctx, bucket, root, true) {
			if info.Err != nil {
				log.Warn("s3: sweep multipart: листинг осколков", "prefix", root, "err", info.Err)
				continue
			}
			if err := core.AbortMultipartUpload(ctx, bucket, info.Key, info.UploadID); err != nil {
				log.Warn("s3: sweep multipart: аборт осколка", "key", info.Key, "err", err)
			}
		}
	}
}

// Get возвращает ридер поверх зафиксированных байтов. S3 GetObject —
// один запрос; Meta берётся из Stat объекта (хранящиеся ETag/size/
// content-type из PutObject).
func (s *Storage) Get(ctx context.Context, key string) (port.Object, error) {
	if err := s.checkKey(ctx, key); err != nil {
		return port.Object{}, err
	}
	obj, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return port.Object{}, mapS3Error(err, key)
	}
	info, err := obj.Stat()
	if err != nil {
		_ = obj.Close()
		return port.Object{}, mapS3Error(err, key)
	}
	return port.Object{Meta: metaFrom(key, info), Body: obj}, nil
}

// Stat возвращает метаданные объекта (HEAD).
func (s *Storage) Stat(ctx context.Context, key string) (port.Meta, error) {
	if err := s.checkKey(ctx, key); err != nil {
		return port.Meta{}, err
	}
	info, err := s.client.StatObject(ctx, s.bucket, key, minio.StatObjectOptions{})
	if err != nil {
		return port.Meta{}, mapS3Error(err, key)
	}
	return metaFrom(key, info), nil
}

// Put открывает транзакционную запись: байты спулируются в локальный
// файл, Commit — одиночный PutObject. ContentType назначается по
// расширению ключа (best-effort: контракт Writer не передаёт upstream
// content-type; версии etag/modtime mutable-объектов живут в ObjectIndex).
func (s *Storage) Put(ctx context.Context, key string) (port.Writer, error) {
	if err := s.checkKey(ctx, key); err != nil {
		return nil, err
	}
	uuid, err := s.rand.UUID4()
	if err != nil {
		return nil, fmt.Errorf("s3: генерация имени спула: %w", err)
	}
	spoolPath := filepath.Join(s.spoolDir, uuid)
	f, err := os.OpenFile(spoolPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, spoolUnavailable(fmt.Errorf("s3: создание спула: %w", err))
	}
	return &writer{
		storage:     s,
		key:         key,
		spoolPath:   spoolPath,
		file:        f,
		contentType: contentTypeFor(key),
	}, nil
}

// Delete удаляет объект; отсутствующий — NotFound. S3 RemoveObject
// идемпотентен (нет ошибки на отсутствующий ключ), поэтому предшествующий
// Stat отличает отсутствие от успеха.
func (s *Storage) Delete(ctx context.Context, key string) error {
	if err := s.checkKey(ctx, key); err != nil {
		return err
	}
	if _, err := s.client.StatObject(ctx, s.bucket, key, minio.StatObjectOptions{}); err != nil {
		return mapS3Error(err, key)
	}
	if err := s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{}); err != nil {
		return mapS3Error(err, key)
	}
	return nil
}

// List лениво обходит объекты с префиксом prefix; порядок —
// лексикографический по ключу (S3 ListObjectsV2 отдаёт именно его).
// ctx отменяет обход (minio iter уважает ctx). Ошибка листинга —
// терминальная: один (Meta{}, err), как у fs — потребитель отличает
// сбой носителя от «объектов нет».
func (s *Storage) List(ctx context.Context, prefix string) iter.Seq2[port.Meta, error] {
	return func(yield func(port.Meta, error) bool) {
		if !validPrefix(prefix) {
			return
		}
		for info := range s.client.ListObjectsIter(ctx, s.bucket, minio.ListObjectsOptions{
			Prefix:    prefix,
			Recursive: true,
		}) {
			if info.Err != nil {
				yield(port.Meta{}, fmt.Errorf("s3: листинг %s: %w", prefix, info.Err))
				return
			}
			if ctx.Err() != nil {
				yield(port.Meta{}, ctx.Err())
				return
			}
			if !yield(metaFrom(info.Key, info), nil) || ctx.Err() != nil {
				return
			}
		}
	}
}

// checkKey — проверка ключа (единая точка traversal) и контекста.
func (s *Storage) checkKey(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if key == tmpPrefix || strings.HasPrefix(key, tmpPrefix+"/") {
		return &domain.InvalidKeyError{
			Key:     key,
			Reasons: []error{errors.New("зарезервированный namespace tmp/")},
		}
	}
	return domain.ValidateKey(key)
}

// validPrefix — мягкая проверка префикса List: хвостовой «/» легален.
func validPrefix(prefix string) bool {
	trimmed := strings.TrimSuffix(prefix, "/")
	if trimmed == "" {
		return true
	}
	return domain.ValidateKey(trimmed) == nil
}

// metaFrom — Meta из ObjectInfo: S3 знает ETag (md5 объекта), content-
// type, modtime, size (богаче fs, где ETag/content-type пусты).
func metaFrom(key string, info minio.ObjectInfo) port.Meta {
	mtime := info.LastModified
	if mtime.IsZero() {
		mtime = time.Time{}
	}
	return port.Meta{
		Key:         key,
		Size:        info.Size,
		ETag:        info.ETag,
		ContentType: info.ContentType,
		ModTime:     mtime,
	}
}

// mapS3Error переводит ошибки носителя: NoSuchKey/NoSuchBucket — NotFound
// объекта; всё остальное — недоступность хранилища: и сеть без S3-ответа
// (endpoint недоступен, по образцу authStoreError), и ответы S3 с кодом
// ошибки (AccessDenied, SignatureDoesNotMatch, InternalError, SlowDown,
// …) — это сбои НАШЕГО хранилища, на публичном порту они отдавались как
// 502 «виноват upstream» (сессии 50, 60).
func mapS3Error(err error, key string) error {
	if err == nil {
		return nil
	}
	resp := minio.ToErrorResponse(err)
	switch resp.Code {
	case minio.NoSuchKey, minio.NoSuchBucket:
		return &domain.NotFoundError{What: "объект", Key: key}
	case "":
		return &domain.UnavailableError{What: "хранилище", Reason: "S3 недоступен", Err: err}
	}
	return &domain.UnavailableError{What: "хранилище", Reason: "S3-ответ " + resp.Code, Err: err}
}

// spoolUnavailable — сбой локального спула (диск кончился, каталог
// пропал) — недоступность хранилища, а не upstream: иначе сырая
// OS-ошибка уходила бы в 502 (сессия 60).
func spoolUnavailable(err error) error {
	return &domain.UnavailableError{What: "хранилище", Reason: "сбой спула", Err: err}
}

// splitEndpoint разбирает endpoint конфига: «https://host[:port]» →
// (host[:port], true, true); «http://host» → (host, false, true); bare
// «host[:port]» → (host, false, true). Пусто → (_, _, false).
func splitEndpoint(endpoint string) (host string, secure, ok bool) {
	if endpoint == "" {
		return "", false, false
	}
	switch {
	case strings.HasPrefix(endpoint, "https://"):
		return strings.TrimPrefix(endpoint, "https://"), true, true
	case strings.HasPrefix(endpoint, "http://"):
		return strings.TrimPrefix(endpoint, "http://"), false, true
	default:
		return endpoint, false, true
	}
}

// contentTypeFor — best-effort Content-Type по расширению ключа:
// stdlib mime-таблица (.gz, .zst, .xz, …), иначе application/octet-stream.
func contentTypeFor(key string) string {
	if ct := mime.TypeByExtension(filepath.Ext(key)); ct != "" {
		return ct
	}
	return "application/octet-stream"
}

// writer — транзакционная запись: спул-файл → одиночный PutObject при
// Commit. failed фиксирует сбой Write (диск кончился): последующий
// Commit отклоняется, вызывающий обязан Abort.
type writer struct {
	storage     *Storage
	key         string
	spoolPath   string
	file        *os.File
	contentType string
	failed      bool
	writeErr    error
	done        bool
}

// Write реализует io.Writer.
func (w *writer) Write(p []byte) (int, error) {
	if w.done {
		return 0, fmt.Errorf("s3: запись после завершения Writer для %q", w.key)
	}
	n, err := w.file.Write(p)
	if err != nil {
		w.failed = true
		w.writeErr = err
		// движок не заворачивает UnavailableError в UpstreamError —
		// ENOSPC при копировании тела дойдёт до клиента как 503
		return n, spoolUnavailable(fmt.Errorf("s3: запись спула %q: %w", w.key, err))
	}
	return n, err
}

// Commit делает объект видимым: close → stat размера → PutObject →
// удаление спула. PutObject атомарен в S3 (нет partial-объектов).
func (w *writer) Commit(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if w.done {
		return fmt.Errorf("s3: повторный Commit для %q", w.key)
	}
	w.done = true
	if w.failed {
		_ = w.file.Close()
		_ = os.Remove(w.spoolPath)
		return spoolUnavailable(fmt.Errorf("s3: фиксация %q после сбоя записи: %w", w.key, w.writeErr))
	}
	if err := w.file.Close(); err != nil {
		_ = os.Remove(w.spoolPath)
		return spoolUnavailable(fmt.Errorf("s3: закрытие спула: %w", err))
	}
	st, err := os.Stat(w.spoolPath)
	if err != nil {
		_ = os.Remove(w.spoolPath)
		return spoolUnavailable(fmt.Errorf("s3: размер спула %q: %w", w.key, err))
	}
	f, err := os.Open(w.spoolPath)
	if err != nil {
		_ = os.Remove(w.spoolPath)
		return spoolUnavailable(fmt.Errorf("s3: чтение спула: %w", err))
	}
	defer func() { _ = f.Close(); _ = os.Remove(w.spoolPath) }()
	if _, err := w.storage.client.PutObject(ctx, w.storage.bucket, w.key, f, st.Size(),
		minio.PutObjectOptions{ContentType: w.contentType, DisableMultipart: false}); err != nil {
		return fmt.Errorf("s3: фиксация %q: %w", w.key, mapS3Error(err, w.key))
	}
	return nil
}

// Abort отбрасывает запись и спул-файл. Выполняется даже при
// отменённом ctx: проверка отмены утекала бы спул и fd при обрыве
// клиента посреди Put (аудит, fs durability). Close-ошибка не
// маскирует cleanup и наоборот: Remove выполняется всегда, ошибки
// собираются в join.
func (w *writer) Abort(_ context.Context) error {
	if w.done {
		return fmt.Errorf("s3: повторный Abort для %q", w.key)
	}
	w.done = true
	var closeErr error
	if err := w.file.Close(); err != nil {
		closeErr = fmt.Errorf("s3: закрытие спула: %w", err)
	}
	var rmErr error
	if err := os.Remove(w.spoolPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		rmErr = fmt.Errorf("s3: удаление спула: %w", err)
	}
	return errors.Join(closeErr, rmErr)
}

// Убеждаемся, что *os.File через io.ReadSeeker удовлетворяет io.Reader,
// требуемому PutObject (компилятор поймает несовпадение).
var _ io.Reader = (*os.File)(nil)

// cryptoRand — port.Rand поверх crypto/rand (как uuidRand в wire и
// cryptoRand в fs; дублируется ради запрета mod→mod). read вынесен
// в поле по образцу sleep в db/sqlite: тест clamp'а MinInt64 вводит
// детерминированные байты вместо патча crypto/rand; nil = crypto/rand.
type cryptoRand struct {
	read func([]byte) (int, error)
}

// fill читает байты через инъекцию или crypto/rand.
func (r cryptoRand) fill(b []byte) error {
	f := r.read
	if f == nil {
		f = rand.Read
	}
	if _, err := f(b); err != nil {
		return fmt.Errorf("s3: чтение crypto/rand: %w", err)
	}
	return nil
}

// UUID4 генерирует канонический UUID v4.
func (r cryptoRand) UUID4() (string, error) {
	var b [16]byte
	if err := r.fill(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

// Int64 возвращает неотрицательное псевдослучайное число в [0, max).
// s3-хранилище использует rand только для имён спула (UUID4); Int64
// добавлен ради полноты port.Rand (расширен в сессии 11).
func (r cryptoRand) Int64(max int64) int64 {
	if max <= 0 {
		return 0
	}
	var b [8]byte
	if err := r.fill(b[:]); err != nil {
		return 0
	}
	n := int64(b[0])<<56 | int64(b[1])<<48 | int64(b[2])<<40 | int64(b[3])<<32 |
		int64(b[4])<<24 | int64(b[5])<<16 | int64(b[6])<<8 | int64(b[7])
	// clamp перед abs: -MinInt64 в дополнительном коде == MinInt64 — без
	// зажима модульная арифметика дала бы отрицательный результат
	// (ревю 2026-09-03, twin fs.go; урок сессии 77 — фикс класса, не точки).
	if n < 0 {
		if n == math.MinInt64 {
			n = math.MaxInt64
		} else {
			n = -n
		}
	}
	return n % max
}
