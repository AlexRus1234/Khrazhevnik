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

// Генератор apk-индексов личного репозитория (port.RepoAdapter): обходит
// repo/<id>/apk/<arch>/<файл>.apk, читает .PKGINFO каждого (pkginfo.go) и
// считает sha1, собирает по одному APKINDEX.tar.gz на архитектуру
// (gzip+tar с файлом APKINDEX в формате «K:V») + APKINDEX.tar.gz.sig
// (подпись Signer'ом из сессии 15).
//
// Раскладка — по URL-контракту apk-tools (живая проба сессии 192, скрипты
// и логи — в постамбуле): клиент запрашивает индекс строго по
// <repo-url>/<своя-арх>/APKINDEX.tar.gz (плоского режима нет ни в 2.14.6,
// ни в 3.0.7), а пакет — по <repo-url>/<A-записи>/<basename(F:)>, причём
// каталог из поля F: игнорируется целиком: путь каталога берётся из arch
// записи (= architecture .PKGINFO), имя файла — из basename(F:). Поэтому
// пакет обязан лежать в каталоге своей архитектуры (ValidateObjectPath),
// .PKGINFO-архитектура пакета = каталог = каталог индекса.
// Пакеты arch=noarch попадают в КАЖДЫЙ arch-индекс: клиент читает только
// индекс своей архитектуры, а файл тянет из <repo>/noarch/ — без инъекции
// такой пакет клиенту не виден (факт пробы: запись A:noarch в x86_64-индексе
// принята, запрос ушёл за /noarch/<файл>).
//
// Атомарность v1 — перезапись ключей после полной генерации staging в
// памяти (окно рассинхрона ~секунды; полный atomic-swap — сессия 17).
//
// Ключи в storage — lowercase (domain.ValidateKey): <arch>/apkindex.tar.gz,
// <arch>/apkindex.tar.gz.sig. apk fetch'ит APKINDEX.tar.gz (имя —
// каноническое uppercase в URL, но публичный роутер :29202 лоуэркейсит
// запрос перед lookup'ом, поэтому storage-ключ lowercase). Старый индекс в
// корне репо больше не пишется; уже лежащий — не удаляется (чистка — вне
// скоупа, см. docs/func/ru/ecosystems/apk.md).

package apk

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"sort"
	"strings"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/core/registry"
)

func init() {
	// Регистрация repo-адаптера в compile-time реестре: имя совпадает
	// с именем экосистемы (apk). Signer внедряется через SetSigner.
	registry.RegisterRepoAdapter(Name, func() (port.RepoAdapter, error) {
		return &Generator{}, nil
	})
}

// Generator реализует port.RepoAdapter для apk-репо.
type Generator struct {
	signer port.Signer

	// decompressLimit — потолок разжатого .apk (0 = прод-дефолт
	// maxDecompressedApk). Поле только для тестов: прод-инстанс
	// собирается реестром без параметров; уменьшенный кап не ослабляет
	// контракт бомб-тестов — проверяется та же ветка limitedReader-отказа.
	decompressLimit int64
}

// decompressCap возвращает эффективный лимит декомпрессии.
func (g *Generator) decompressCap() int64 {
	if g.decompressLimit > 0 {
		return g.decompressLimit
	}
	return maxDecompressedApk
}

// SetSigner внедряет подписчик: после APKINDEX.tar.gz генератор эмитит
// APKINDEX.tar.gz.sig (detached). nil — репо не подписывается.
func (g *Generator) SetSigner(s port.Signer) { g.signer = s }

// Name — имя экосистемы, совпадает с Adapter.Name.
func (g *Generator) Name() string { return Name }

// ValidateObjectPath принимает только <архитектура>/<файл>.apk: каталог
// обязан быть один и совпадать с architecture .PKGINFO пакета (проверить
// это по пути нельзя — генератор пропускает несоответствия с логом).
// Клиент apk строит URL пакета как <repo-url>/<A:>/<basename(F:)>, поэтому
// пакет вне каталога своей архитектуры (в корне репо или с лишним уровнем
// вложенности) клиенту недоступен. APKINDEX.tar.gz — генерируется, клиенту
// туда соваться нельзя.
func (g *Generator) ValidateObjectPath(p string) error {
	if !strings.HasSuffix(p, ".apk") {
		return &domain.ValidationError{What: "путь apk-репо", Value: p, Reason: "неизвестное расширение (ожидалось .apk)"}
	}
	dir, file, ok := splitArchDir(p)
	if !ok || dir == "" || file == "" {
		return &domain.ValidationError{What: "путь apk-репо", Value: p, Reason: "пакет кладётся в каталог своей архитектуры: <arch>/<файл>.apk"}
	}
	return nil
}

// splitArchDir делит путь пакета на каталог архитектуры и имя файла:
// ровно один сегмент каталога («x86_64/foo-1.0-r0.apk»). ok=false — путь
// без каталога («foo.apk» в корне репо) или с вложенностью глубже одного
// уровня («a/b/foo.apk»): оба клиенту недоступны, каталог он не угадает
// (в URL идёт arch записи, а имя — basename файла).
func splitArchDir(p string) (dir, file string, ok bool) {
	idx := strings.LastIndexByte(p, '/')
	if idx < 0 {
		return "", p, false
	}
	dir, file = p[:idx], p[idx+1:]
	if strings.Contains(dir, "/") {
		return dir, file, false
	}
	return dir, file, true
}

// ObjectFamily — port.FamilyResolver: семейство версий apk-объекта —
// имя пакета из basename файла: <имя>-<версия>-r<релиз>.apk. Граница
// «имя-версия» — эвристика ROADMAP: версия — первый сегмент (после
// деления по «-»), начинающийся с цифры, всё до него — семейство.
// Реальные имена Alpine с дефисами и цифрами держатся именно так:
// py3-pip-25.1.1-r0 → py3-pip, libnl3-3.11.0-r0 → libnl3,
// ca-certificates-20250605-r0 → ca-certificates. Генерируемые
// APKINDEX.tar.gz (+ .sig) и ключи (khrazhevnik.rsa.pub) — ok=false.
func (g *Generator) ObjectFamily(p string) (string, bool) {
	name := baseName(p)
	if !strings.HasSuffix(name, ".apk") {
		return "", false
	}
	return pkgFamily(strings.TrimSuffix(name, ".apk"))
}

// baseName — последний сегмент пути. Не path.Base: разделитель ключей
// Storage всегда «/» независимо от ОС.
func baseName(p string) string {
	if idx := strings.LastIndexByte(p, '/'); idx >= 0 {
		return p[idx+1:]
	}
	return p
}

// pkgFamily — имя пакета из имени файла без расширения: часть до первого
// сегмента, начинающегося с цифры (граница «имя-версия»), сегменты — по
// «-». Пакет без границы версии — ok=false.
func pkgFamily(stem string) (string, bool) {
	segs := strings.Split(stem, "-")
	for i := 1; i < len(segs); i++ {
		if segs[i] == "" || !isASCIIDigit(segs[i][0]) {
			continue
		}
		return strings.Join(segs[:i], "-"), true
	}
	return "", false
}

// isASCIIDigit — цифра ASCII-диапазона: версия пакета всегда начинается
// с «0»–«9», unicode-цифры в именах пакетов не встречаются.
func isASCIIDigit(b byte) bool { return b >= '0' && b <= '9' }

// archNoarch — значение architecture .PKGINFO у пакетов, не привязанных к
// архитектуре. Файл такого пакета клиент любой архитектуры тянет из
// <repo>/noarch/, а запись обязана лежать в КАЖДОМ arch-индексе: клиент
// читает индекс только своей архитектуры (проба сессии 192).
const archNoarch = "noarch"

// GenerateIndexes обходит .apk, читает .PKGINFO, собирает по APKINDEX.tar.gz
// на архитектуру (+ .sig при Signer). Прогресс — обработанные пакеты.
//
//nolint:gocyclo // enumerate → pkginfo → group → write → sign — линейная
func (g *Generator) GenerateIndexes(ctx context.Context, repo domain.Repo, storage port.Storage, p port.RepoProgress) error {
	if p == nil {
		p = noopRepoProgress{}
	}
	if repo.Ecosystem != Name {
		return &domain.UnsupportedError{What: "apk.gen", Why: "экосистема " + repo.Ecosystem + " ≠ apk"}
	}
	prefix := port.RepoPrefix(repo)

	// Фаза 1: enumerate .apk под prefix.
	p.Update("enumerate", repo.Name, 0, 0)
	apkKeys, err := collectApks(ctx, storage, prefix)
	if err != nil {
		return fmt.Errorf("apk.gen: enumerate: %w", err)
	}
	p.Log(fmt.Sprintf("apk.gen: найдено %d .apk в %s", len(apkKeys), prefix))

	// Фаза 2: чтение .PKGINFO + sha1 каждого .apk, группировка записей по
	// architecture из .PKGINFO. Каталог пакета обязан совпасть с ней:
	// ValidateObjectPath держит только форму пути (значение архитектуры по
	// пути не узнать), а пакет в чужом каталоге клиенту недоступен — в
	// индекс он не пишется, факт идёт в лог.
	p.Update("pkginfo", repo.Name, 0, int64(len(apkKeys)))
	groups := make(map[string]*bytes.Buffer)
	var archs []string
	skipped := 0
	for i, key := range apkKeys {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		entry, err := readIndexEntry(ctx, storage, key, prefix, g.decompressCap())
		if err != nil {
			return fmt.Errorf("apk.gen: %s: %w", key, err)
		}
		if entry.arch == "" || entry.dir != entry.arch {
			skipped++
			p.Log(fmt.Sprintf("apk.gen: пропущен %s: каталог %q ≠ architecture %q (.PKGINFO)", key, entry.dir, entry.arch))
		} else {
			buf, ok := groups[entry.arch]
			if !ok {
				buf = &bytes.Buffer{}
				groups[entry.arch] = buf
				archs = append(archs, entry.arch)
			}
			buf.Write(entry.text)
		}
		p.Update("pkginfo", repo.Name, int64(i+1), int64(len(apkKeys)))
	}
	// Детерминизм: обход map в Go рандомный, порядок записи индексов — по
	// алфавиту архитектур.
	sort.Strings(archs)
	if skipped > 0 {
		p.Log(fmt.Sprintf("apk.gen: пропущено пакетов вне каталога своей архитектуры: %d", skipped))
	}

	// Фаза 3: APKINDEX.tar.gz на архитектуру (+ опц. .sig). Ключи — lowercase.
	p.Update("write", repo.Name, 0, int64(len(archs)))
	noarch := groups[archNoarch]
	for i, arch := range archs {
		var text bytes.Buffer
		text.Write(groups[arch].Bytes())
		if arch != archNoarch && noarch != nil {
			// noarch-запись — в каждый arch-индекс: клиент читает только
			// индекс своей архитектуры, а файл тянет из <repo>/noarch/.
			text.Write(noarch.Bytes())
		}
		indexGz, err := buildAPKINDEXTarGz(text.Bytes())
		if err != nil {
			return fmt.Errorf("apk.gen: сборка APKINDEX.tar.gz (%s): %w", arch, err)
		}
		indexKey := prefix + "/" + arch + "/apkindex.tar.gz"
		if err := writeAtomic(ctx, storage, indexKey, indexGz); err != nil {
			return fmt.Errorf("apk.gen: APKINDEX.tar.gz (%s): %w", arch, err)
		}
		if g.signer != nil {
			p.Update("sign", repo.Name, int64(i), int64(len(archs)))
			sigR, err := g.signer.SignDetached(ctx, bytes.NewReader(indexGz))
			if err != nil {
				return fmt.Errorf("apk.gen: APKINDEX.tar.gz.sig (%s): %w", arch, err)
			}
			sig, err := io.ReadAll(sigR)
			if err != nil {
				return fmt.Errorf("apk.gen: APKINDEX.tar.gz.sig (%s): чтение: %w", arch, err)
			}
			if err := writeAtomic(ctx, storage, indexKey+".sig", sig); err != nil {
				return fmt.Errorf("apk.gen: APKINDEX.tar.gz.sig (%s): %w", arch, err)
			}
			p.Update("sign", repo.Name, int64(i+1), int64(len(archs)))
		}
		p.Update("write", repo.Name, int64(i+1), int64(len(archs)))
	}
	p.Log(fmt.Sprintf("apk.gen: индексы записаны (%d архитектур)", len(archs)))
	return nil
}

// collectApks возвращает лексически отсортированный список .apk под
// prefix. Ошибка листинга — ошибка генерации (иначе пустой обход записал
// бы ПУСТОЙ APKINDEX поверх валидного).
func collectApks(ctx context.Context, storage port.Storage, prefix string) ([]string, error) {
	var out []string
	listPrefix := prefix + "/"
	for meta, err := range storage.List(ctx, listPrefix) {
		if err != nil {
			return nil, fmt.Errorf("листинг %s: %w", listPrefix, err)
		}
		if strings.HasSuffix(meta.Key, ".apk") {
			out = append(out, meta.Key)
		}
	}
	sort.Strings(out)
	return out, nil
}

// indexEntry — одна запись индекса: архитектура пакета (.PKGINFO; она же
// его каталог и каталог индекса), каталог фактического ключа и готовый
// K:V-текст записи.
type indexEntry struct {
	arch string
	dir  string
	text []byte
}

// readIndexEntry читает .apk одним проходом (.PKGINFO + sha1 всего файла)
// и рендерит запись APKINDEX (K:V-формат). F: — путь .apk от корня репо
// (каталог + имя файла): клиент берёт из поля только basename, но поле
// обязано совпадать с фактическим путём выдачи, иначе индекс лжёт.
func readIndexEntry(ctx context.Context, storage port.Storage, apkKey, prefix string, decompressLimit int64) (indexEntry, error) {
	obj, err := storage.Get(ctx, apkKey)
	if err != nil {
		return indexEntry{}, err
	}
	defer obj.Body.Close()
	h := sha1.New()
	cr := &countReader{r: obj.Body}
	tee := io.TeeReader(cr, h)
	pi, err := readPkgInfoFromPackage(ctx, tee, decompressLimit)
	if err != nil {
		return indexEntry{}, err
	}
	// Докачиваем остаток .apk через tee, чтобы sha1 был посчитан по
	// всему файлу: readPkgInfoFromPackage остановился после .PKGINFO.
	if _, err := io.Copy(io.Discard, tee); err != nil {
		return indexEntry{}, fmt.Errorf("apk.apk: дочтение .apk: %w", err)
	}
	checksum := "Q1" + base64.StdEncoding.EncodeToString(h.Sum(nil))
	filepath := strings.TrimPrefix(apkKey, prefix+"/")
	dir, _, _ := splitArchDir(filepath)
	// Размер — фактические байты через tee, не obj.Meta.Size: метаданные
	// носителя могут солгать, и apk упадёт на сверке размера.
	var buf bytes.Buffer
	writeAPKINDEXEntry(&buf, pi, checksum, filepath, cr.n)
	return indexEntry{arch: pi.Arch, dir: dir, text: buf.Bytes()}, nil
}

// countReader считает прочитанные байты: источник размера индексных
// записей (фактическое тело объекта, не метаданные хранилища).
type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// writeAPKINDEXEntry пишет одну запись в APKINDEX-текст: K:V-строки,
// разделитель записей — пустая строка. Поля — подмножество, нужное apk
// update и roundtrip-парсеру ParseAPKINDEX (F:/P:/V:). C — sha1-чекcумма
// .apk (Q1 = sha1, apk v2 convention); S — размер файла; I — установлен.
// D:/p:/i: — зависимости (depends/provides/install_if, space-joined,
// как их пишет apk-tools): без них `apk add` не может резолвить
// зависимости пакета из личного репо.
func writeAPKINDEXEntry(buf *bytes.Buffer, pi *PkgInfo, checksum, filepath string, csize int64) {
	fmt.Fprintf(buf, "C:%s\n", checksum)
	fmt.Fprintf(buf, "P:%s\n", pi.Name)
	fmt.Fprintf(buf, "V:%s\n", pi.Version)
	if pi.Arch != "" {
		fmt.Fprintf(buf, "A:%s\n", pi.Arch)
	}
	if pi.Desc != "" {
		fmt.Fprintf(buf, "T:%s\n", pi.Desc)
	}
	if pi.URL != "" {
		fmt.Fprintf(buf, "U:%s\n", pi.URL)
	}
	if len(pi.License) > 0 {
		fmt.Fprintf(buf, "L:%s\n", strings.Join(pi.License, " "))
	}
	fmt.Fprintf(buf, "S:%d\n", csize)
	if pi.Size != 0 {
		fmt.Fprintf(buf, "I:%d\n", pi.Size)
	}
	if pi.Origin != "" {
		fmt.Fprintf(buf, "o:%s\n", pi.Origin)
	}
	if pi.Maintainer != "" {
		fmt.Fprintf(buf, "m:%s\n", pi.Maintainer)
	}
	if pi.BuildDate != 0 {
		fmt.Fprintf(buf, "t:%d\n", pi.BuildDate)
	}
	if len(pi.Depends) > 0 {
		fmt.Fprintf(buf, "D:%s\n", strings.Join(pi.Depends, " "))
	}
	if len(pi.Provides) > 0 {
		fmt.Fprintf(buf, "p:%s\n", strings.Join(pi.Provides, " "))
	}
	if len(pi.InstallIf) > 0 {
		fmt.Fprintf(buf, "i:%s\n", strings.Join(pi.InstallIf, " "))
	}
	fmt.Fprintf(buf, "F:%s\n", filepath)
	buf.WriteByte('\n') // разделитель записей
}

// buildAPKINDEXTarGz собирает tar с одним файлом «APKINDEX» (содержимое —
// indexText), затем gzip-сжимает. Возвращает байты APKINDEX.tar.gz.
func buildAPKINDEXTarGz(indexText []byte) ([]byte, error) {
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	if err := tw.WriteHeader(&tar.Header{
		Name: "APKINDEX", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(indexText)),
	}); err != nil {
		return nil, fmt.Errorf("apk.apkindex: tar header: %w", err)
	}
	if _, err := tw.Write(indexText); err != nil {
		return nil, fmt.Errorf("apk.apkindex: tar write: %w", err)
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("apk.apkindex: tar close: %w", err)
	}
	var gzBuf bytes.Buffer
	gz := gzip.NewWriter(&gzBuf)
	if _, err := gz.Write(tarBuf.Bytes()); err != nil {
		return nil, fmt.Errorf("apk.apkindex: gzip write: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("apk.apkindex: gzip close: %w", err)
	}
	return gzBuf.Bytes(), nil
}

// writeAtomic пишет байты в storage через Put+Commit; на ошибке Abort.
// Дубликат из apt/rpmmmd/pacman.gen: mod→mod запрещён depguard'ом.
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

// noopRepoProgress — заглушка. Дубликат из apt/rpmmmd/pacman.gen.
type noopRepoProgress struct{}

func (noopRepoProgress) Update(string, string, int64, int64) {}
func (noopRepoProgress) Log(string)                          {}
