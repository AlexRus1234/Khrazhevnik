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

// Генератор apt-индексов личного репозитория (port.RepoAdapter).
// Обходит repo/<id>/apt/pool/.../*.deb, одним проходом читает control-
// stanza и считает SHA256 каждого .deb, собирает
// dists/stable/main/binary-amd64/Packages (+.gz) и dists/stable/Release
// (Date/Suite/Components/Architectures/SHA256). Подпись InRelease/
// Release.gpg — сессия 15; атомарный swap — 17.
//
// Формат .deb: ar-архив из трёх членов — debian-binary, control.tar.*,
// data.tar.*. ar — 60-байтный заголовок + контент, выровненный по 2
// байта; чтение streaming, без decode всего архива в память.
// control.tar.* — gzip/zstd-компресс; внутри tar-потока лежит ./control
// (deb822 stanza), его и парсим. data.tar.* НЕ распаковываем —
// экономим байты и время, SHA256 считаем по сырому ar-потоку.

package apt

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/core/registry"
)

// Параметры генерируемого репо v1. Жёстко заданы (KISS): один suite,
// одна компонента, одна архитектура. Мульти-компонента/арх — сессия 16.
//
// Имена файлов-индексов в storage — lowercase: domain.ValidateKey
// пропускает только [a-z0-9/._-], и apt-адаптер кеша (apt.go:Resolve)
// делает то же для cache/* (strings.ToLower(upstreamPath)). Личные
// репо следуют той же конвенции: клиенты apt-get просят /Packages/
// /Release/... (заглавные), публичный роутер :29202 лоуэркейсит
// запрос перед lookup'ом — совпадение ключей гарантировано.
const (
	repoDist       = "stable"
	suite          = "stable"
	repoComponent  = "main"
	repoArch       = "amd64"
	repoDateFormat = "Mon, 02 Jan 2006 15:04:05 MST"
)

// Pool-суффиксы, которые apt-репо принимает на upload (ValidateObjectPath).
var allowedPoolSuffixes = []string{
	".deb", ".udeb", ".ddeb", ".dsc",
	".orig.tar.gz", ".orig.tar.xz", ".orig.tar.zst", ".orig.tar.bz2",
	".debian.tar.gz", ".debian.tar.xz", ".debian.tar.zst", ".debian.tar.bz2",
}

func init() {
	// Регистрация repo-адаптера в compile-time реестре: имя совпадает
	// с именем экосистемы (apt). Фабрика без параметров: генератору
	// нужен только Storage, который приходит в GenerateIndexes.
	registry.RegisterRepoAdapter(Name, func() (port.RepoAdapter, error) {
		return &Generator{}, nil
	})
}

// Generator реализует port.RepoAdapter для apt-репо.
type Generator struct{}

// Name — имя экосистемы, совпадает с Adapter.Name.
func (g *Generator) Name() string { return Name }

// ValidateObjectPath принимает только pool/* с известным суффиксом;
// dists/* — генерируется, клиенту туда соваться нельзя. Возвращает
// *domain.ValidationError для маппинга в 400.
func (g *Generator) ValidateObjectPath(p string) error {
	if !strings.HasPrefix(p, "pool/") {
		return &domain.ValidationError{What: "путь apt-репо", Value: p, Reason: "должен начинаться с pool/"}
	}
	for _, suf := range allowedPoolSuffixes {
		if strings.HasSuffix(p, suf) {
			return nil
		}
	}
	return &domain.ValidationError{What: "путь apt-репо", Value: p, Reason: "неизвестное расширение (ожидалось .deb/.udeb/.ddeb/.dsc/.tar.*-src)"}
}

// GenerateIndexes обходит пул .deb, читает control из каждого, собирает
// Packages (+.gz) и Release. Атомарность v1: запись ключей по одному
// после полной генерации staging в памяти (окно рассинхрона ~секунды;
// полный atomic-swap — сессия 17). Прогресс — обработанные пакеты.
//
//nolint:gocyclo // enumerate → control → write — одна линейная последовательность
func (g *Generator) GenerateIndexes(ctx context.Context, repo domain.Repo, storage port.Storage, p port.RepoProgress) error {
	if p == nil {
		p = noopRepoProgress{}
	}
	if repo.Ecosystem != Name {
		return &domain.UnsupportedError{What: "apt.gen", Why: "экосистема " + repo.Ecosystem + " ≠ apt"}
	}
	prefix := port.RepoPrefix(repo)
	poolPrefix := prefix + "/pool/"

	// Фаза 1: enumerate .deb-ов.
	p.Update("enumerate", repo.Name, 0, 0)
	debKeys, err := collectDebs(ctx, storage, poolPrefix)
	if err != nil {
		return fmt.Errorf("apt.gen: enumerate: %w", err)
	}
	p.Log(fmt.Sprintf("apt.gen: найдено %d .deb в %s", len(debKeys), poolPrefix))

	// Фаза 2: чтение control + SHA256 из каждого .deb (один проход),
	// сборка Packages в памяти.
	p.Update("control", repo.Name, 0, int64(len(debKeys)))
	packages := &bytes.Buffer{}
	packages.Grow(64 * 1024)
	for i, key := range debKeys {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := appendPackagesEntry(ctx, storage, key, packages); err != nil {
			return fmt.Errorf("apt.gen: %s: %w", key, err)
		}
		p.Update("control", repo.Name, int64(i+1), int64(len(debKeys)))
	}

	// Фаза 3: запись packages + packages.gz + by-hash + release.
	// Путь к индексам в storage — lowercase (см. комментарий к repoDist):
	// repo/<id>/apt/dists/stable/main/binary-amd64/{packages,packages.gz}.
	p.Update("write", repo.Name, 0, 4)
	packagesBytes := packages.Bytes()
	packagesGz := gzipBytes(packagesBytes)
	indexDir := prefix + "/dists/" + repoDist + "/" + repoComponent + "/binary-" + repoArch
	if err := writeAtomic(ctx, storage, indexDir+"/packages", packagesBytes); err != nil {
		return fmt.Errorf("apt.gen: packages: %w", err)
	}
	p.Update("write", repo.Name, 1, 4)
	if err := writeAtomic(ctx, storage, indexDir+"/packages.gz", packagesGz); err != nil {
		return fmt.Errorf("apt.gen: packages.gz: %w", err)
	}
	p.Update("write", repo.Name, 2, 4)
	if err := writeByHash(ctx, storage, indexDir, packagesBytes); err != nil {
		return fmt.Errorf("apt.gen: by-hash packages: %w", err)
	}
	if err := writeByHash(ctx, storage, indexDir, packagesGz); err != nil {
		return fmt.Errorf("apt.gen: by-hash packages.gz: %w", err)
	}
	p.Update("write", repo.Name, 3, 4)
	release := buildRelease(repo, packagesBytes, packagesGz)
	if err := writeAtomic(ctx, storage, prefix+"/dists/"+repoDist+"/release", release); err != nil {
		return fmt.Errorf("apt.gen: release: %w", err)
	}
	p.Update("write", repo.Name, 4, 4)
	p.Log("apt.gen: индексы записаны")
	return nil
}

// collectDebs возвращает лексически отсортированный список ключей
// .deb/.udeb/.ddeb в pool-префиксе. Storage.List отдаёт метаданные, мы
// фильтруем по суффиксу.
func collectDebs(ctx context.Context, storage port.Storage, poolPrefix string) ([]string, error) {
	var out []string
	for meta := range storage.List(ctx, poolPrefix) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		name := meta.Key
		if strings.HasSuffix(name, ".deb") || strings.HasSuffix(name, ".udeb") || strings.HasSuffix(name, ".ddeb") {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

// appendPackagesEntry читает .deb одним проходом (control-stanza +
// SHA256 всего файла) и дописывает запись Packages в buf. Обязательные
// поля, которых нет в control: Filename (путь от корня репо), Size (из
// Storage.Meta), SHA256 (посчитан по байтам .deb).
func appendPackagesEntry(ctx context.Context, storage port.Storage, debKey string, buf *bytes.Buffer) error {
	obj, err := storage.Get(ctx, debKey)
	if err != nil {
		return err
	}
	defer obj.Body.Close()
	h := sha256.New()
	tee := io.TeeReader(obj.Body, h)
	stanza, err := readControl(tee)
	if err != nil {
		return err
	}
	// Докачиваем остаток .deb (data.tar.*) через tee, чтобы SHA256
	// был посчитан по всему файлу: readControl остановился после
	// control.tar.*, но в .deb ещё data.tar.*.
	if _, err := io.Copy(io.Discard, tee); err != nil {
		return fmt.Errorf("apt.deb: дочтение .deb: %w", err)
	}
	sha := hex.EncodeToString(h.Sum(nil))
	// Filename: путь от корня apt-секции репо (без repo/<id>/apt/).
	filename := debKey
	if idx := strings.Index(debKey, "/apt/"); idx >= 0 {
		filename = debKey[idx+len("/apt/"):]
	}
	stanza.Set("Filename", filename)
	stanza.Set("Size", strconv.FormatInt(obj.Meta.Size, 10))
	stanza.Set("SHA256", sha)
	writeStanza(buf, stanza)
	buf.WriteByte('\n')
	return nil
}

// writeStanza пишет deb822-запись в buf: «Field: value\n» для каждого
// поля в порядке ключей; multiline-значения — продолжения с ведущим
// пробелом (формат deb822, dpkg-fold: пустая строка-продолжение → « .»).
func writeStanza(buf *bytes.Buffer, s *Stanza) {
	for _, k := range s.Keys() {
		v := s.Get(k)
		if !strings.Contains(v, "\n") {
			fmt.Fprintf(buf, "%s: %s\n", k, v)
			continue
		}
		lines := strings.Split(v, "\n")
		fmt.Fprintf(buf, "%s: %s\n", k, lines[0])
		for _, l := range lines[1:] {
			if l == "" {
				buf.WriteString(" .\n")
				continue
			}
			buf.WriteString(" ")
			buf.WriteString(l)
			buf.WriteByte('\n')
		}
	}
}

// buildRelease собирает Release-stanza: Date/Suite/Components/
// Architectures + SHA256-блок для Packages и Packages.gz (по строке
// на файл: hash size path). Date — текущее время генерации (UTC,
// формат apt). Пути в SHA256-блоке — канонические apt (с заглавной
// P): apt-get читает Release и запрашивает файлы по этим путям;
// публичный роутер :29202 лоуэркейсит запрос при lookup'е в Storage.
func buildRelease(_ domain.Repo, packages, packagesGz []byte) []byte {
	now := time.Now().UTC()
	var b bytes.Buffer
	b.Grow(2048)
	fmt.Fprintf(&b, "Date: %s\n", now.Format(repoDateFormat))
	fmt.Fprintf(&b, "Suite: %s\n", suite)
	fmt.Fprintf(&b, "Components: %s\n", repoComponent)
	fmt.Fprintf(&b, "Architectures: %s\n", repoArch)
	fmt.Fprintf(&b, "Codename: %s\n", repoDist)
	b.WriteString("Acquire-By-Hash: yes\n")
	b.WriteString("SHA256:\n")
	pkgPath := repoComponent + "/binary-" + repoArch + "/Packages"
	pkgGzPath := pkgPath + ".gz"
	appendShaLine(&b, packages, pkgPath)
	appendShaLine(&b, packagesGz, pkgGzPath)
	return b.Bytes()
}

// appendShaLine пишет одну строку SHA256-блока Release:
// « <hash> <size(8)> <rel-path>».
func appendShaLine(b *bytes.Buffer, content []byte, relPath string) {
	h := sha256.Sum256(content)
	fmt.Fprintf(b, " %s %8d %s\n", hex.EncodeToString(h[:]), len(content), relPath)
}

// writeAtomic пишет байты в storage через Put+Commit; на ошибке Abort.
// fs делает tmp+rename (атомарно); s3 — одиночный PUT (атомарно).
func writeAtomic(ctx context.Context, storage port.Storage, key string, content []byte) error {
	if err := domain.ValidateKey(key); err != nil {
		return err
	}
	w, err := storage.Put(ctx, key)
	if err != nil {
		return err
	}
	if _, err := w.Write(content); err != nil {
		_ = w.Abort(context.Background())
		return err
	}
	if err := w.Commit(ctx); err != nil {
		_ = w.Abort(context.Background())
		return err
	}
	return nil
}

// writeByHash пишет копию content в by-hash/sha256/<hash> для поддержки
// content-addressed индексов apt (Acquire-By-Hash: yes в Release).
// indexDir — каталог индексов (dists/<dist>/<comp>/binary-<arch>),
// в нём создаётся подкаталог by-hash/sha256/.
func writeByHash(ctx context.Context, storage port.Storage, indexDir string, content []byte) error {
	h := sha256.Sum256(content)
	hash := hex.EncodeToString(h[:])
	key := indexDir + "/by-hash/sha256/" + hash
	return writeAtomic(ctx, storage, key, content)
}

// gzipBytes возвращает gzip-сжатую копию content (один writer, flush на
// конце). Используется для Packages.gz.
func gzipBytes(content []byte) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write(content)
	_ = gz.Close()
	return buf.Bytes()
}

// noopRepoProgress — заглушка, чтобы GenerateIndexes можно было звать
// без репортёра (из тестов).
type noopRepoProgress struct{}

func (noopRepoProgress) Update(string, string, int64, int64) {}
func (noopRepoProgress) Log(string)                          {}

// readControl извлекает control-stanza из .deb одним проходом по
// ar-архиву: маг → первый член control.tar.* → распаковка (gzip/zstd)
// → tar → ./control → первая stanza. r — источник байт .deb; чтобы
// посчитать SHA256, вызывающий tee'ит r через хешер (readControl
// читает ровно столько байт, сколько нужно для control, и не больше).
func readControl(r io.Reader) (*Stanza, error) {
	ar := newArReader(r)
	for {
		hdr, body, err := ar.next()
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("apt.deb: control.tar.* не найден в .deb")
		}
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(hdr.Name, "control.tar.") {
			// Пропускаем содержимое члена, чтобы дойти до следующего
			// заголовка (debian-binary, data.tar.* — мимо).
			if _, err := io.Copy(io.Discard, body); err != nil {
				return nil, fmt.Errorf("apt.deb: пропуск %s: %w", hdr.Name, err)
			}
			continue
		}
		dr, err := decompressControl(body)
		if err != nil {
			return nil, err
		}
		return readControlTar(dr)
	}
}

// readControlTar читает tar-архив control-секции, находит ./control
// (или control) и парсит первую stanza. Возвращает её; игнорирует
// остальные файлы (postinst, prerm и т.п.).
func readControlTar(r io.Reader) (*Stanza, error) {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("apt.deb: control.tar не содержит ./control")
		}
		if err != nil {
			return nil, fmt.Errorf("apt.deb: tar: %w", err)
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		if name != "control" {
			continue
		}
		// Парсим через существующий stanza-парсер: он толерантен к
		// CRLF и не требует завершающего \n\n.
		var first *Stanza
		for s, ferr := range Stanzas(tr) {
			if ferr != nil {
				return nil, fmt.Errorf("apt.deb: parse control: %w", ferr)
			}
			first = s
			break
		}
		if first == nil {
			return nil, fmt.Errorf("apt.deb: пустой control")
		}
		return first, nil
	}
}

// decompressControl распознаёт формат по сигнатуре и возвращает
// распакованный поток. Поддерживаются gzip (1f 8b) и zstd (28 b5 2f fd);
// xz не поддерживается — в whitelist нет xz-либы (мини-читатель
// достаточно покрывает .deb с gz/zstd-компрессией, что генерируют
// dpkg-deb и наши фикстуры).
func decompressControl(r io.Reader) (io.Reader, error) {
	br := bufio.NewReader(r)
	peek, err := br.Peek(4)
	if err != nil && err != io.EOF {
		return nil, err
	}
	switch {
	case len(peek) >= 2 && peek[0] == 0x1f && peek[1] == 0x8b:
		gz, gzErr := gzip.NewReader(br)
		if gzErr != nil {
			return nil, fmt.Errorf("apt.deb: gzip: %w", gzErr)
		}
		return gz, nil
	case len(peek) >= 4 && peek[0] == 0x28 && peek[1] == 0xb5 && peek[2] == 0x2f && peek[3] == 0xfd:
		zr, gzErr := zstd.NewReader(br)
		if gzErr != nil {
			return nil, fmt.Errorf("apt.deb: zstd: %w", gzErr)
		}
		return zr, nil
	}
	// Несжатый tar — редкость, но поддержим (контроль-секция
	// маленькая, peek достаточен).
	return br, nil
}

// newArReader создаёт читатель ar-архива поверх r. ar-формат: 8-байтный
// маг «!<arch>\n», затем 60-байтные заголовки членов + контент,
// выровненный по 2 байтам (нечётный размер → один байт-паддинг).
func newArReader(r io.Reader) *arReader {
	return &arReader{r: bufio.NewReader(r)}
}

// arReader — streaming ar-чтец. Не грузит архив в память: отдаёт
// содержимое члена через LimitedReader над внутренним bufio.Reader.
type arReader struct {
	r       *bufio.Reader
	readHdr bool
	curSize int64
	off     int64
}

// arHeader — заголовок члена ar.
type arHeader struct {
	Name string
	Size int64
}

// next возвращает следующий член ar-архива. Первый вызов читает маг.
// Возвращает (header, body, err); err == io.EOF — архив исчерпан.
func (a *arReader) next() (arHeader, io.Reader, error) {
	if !a.readHdr {
		magic := make([]byte, 8)
		if _, err := io.ReadFull(a.r, magic); err != nil {
			return arHeader{}, nil, err
		}
		if string(magic) != "!<arch>\n" {
			return arHeader{}, nil, fmt.Errorf("apt.deb: неверный ar-magic %q", magic)
		}
		a.readHdr = true
	}
	// Пропускаем остаток прошлого члена (если не вычитали полностью)
	// и один байт паддинга для нечётного размера.
	if a.curSize > 0 && a.off < a.curSize {
		if _, err := io.CopyN(io.Discard, a.r, a.curSize-a.off); err != nil {
			return arHeader{}, nil, err
		}
	}
	if a.curSize > 0 && a.curSize%2 == 1 {
		if _, err := a.r.ReadByte(); err != nil {
			return arHeader{}, nil, err
		}
	}
	a.off = 0
	hdrBuf := make([]byte, 60)
	if _, err := io.ReadFull(a.r, hdrBuf); err != nil {
		return arHeader{}, nil, err
	}
	hdr := arHeader{Name: strings.TrimSpace(string(hdrBuf[0:16]))}
	sizeStr := strings.TrimSpace(string(hdrBuf[48:58]))
	size, err := strconv.ParseInt(sizeStr, 10, 64)
	if err != nil {
		return arHeader{}, nil, fmt.Errorf("apt.deb: неверный размер члена %q: %w", hdr.Name, err)
	}
	hdr.Size = size
	a.curSize = size
	return hdr, &arMemberReader{ar: a, limit: size}, nil
}

// arMemberReader — io.Reader над arReader, ограниченный размером члена.
// Чтение за пределами limit возвращает io.EOF; curSize/off обновляются
// в arReader для последующего skip-члена в next().
type arMemberReader struct {
	ar    *arReader
	limit int64
}

func (m *arMemberReader) Read(p []byte) (int, error) {
	if m.limit <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > m.limit {
		p = p[:m.limit]
	}
	n, err := m.ar.r.Read(p)
	m.limit -= int64(n)
	m.ar.off += int64(n)
	return n, err
}
