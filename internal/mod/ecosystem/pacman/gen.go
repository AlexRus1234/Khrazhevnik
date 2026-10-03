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

// Генератор pacman-индексов личного репозитория (port.RepoAdapter):
// обходит repo/<id>/pacman/**/*.pkg.tar.zst, читает .PKGINFO
// каждого (pkginfo.go) и считает SHA256, собирает <repo.Name>.db
// (tar.zst с <name>-<ver>-<arch>/desc-записями) + <repo.Name>.db.sig
// (подпись Signer'ом из сессии 15). Атомарность v1 — перезапись ключей
// после полной генерации staging в памяти (окно рассинхрона ~секунды;
// полный atomic-swap — сессия 17). Подпись .db.sig — detached через
// port.Signer. Legacy .xz/.gz-пакеты не принимаются: в whitelist
// зависимостей нет xz/gz-декодера — ValidateObjectPath отвергает их
// честной ValidationError, а не падением на регенерации.
//
// Ключи в storage — lowercase (domain.ValidateKey): <repo.Name>.db,
// <repo.Name>.db.sig. pacman fetch'ит <repo>.db (имя remote = имя репо);
// публичный роутер :29202 лоуэркейсит запрос перед lookup'ом.

package pacman

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/klauspost/compress/zstd"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/core/registry"
)

func init() {
	// Регистрация repo-адаптера в compile-time реестре: имя совпадает
	// с именем экосистемы (pacman). Signer внедряется через SetSigner
	// (wire type-assert'ит к port.SignerInjector) — nil = .db.sig не
	// эмитится.
	registry.RegisterRepoAdapter(Name, func() (port.RepoAdapter, error) {
		return &Generator{}, nil
	})
}

// Generator реализует port.RepoAdapter для pacman-репо.
type Generator struct {
	signer port.Signer

	// decompressLimit — потолок разжатого .pkg.tar.zst (0 = прод-дефолт
	// maxDecompressed). Поле только для тестов: прод-инстанс собирается
	// реестром без параметров; уменьшенный кап не ослабляет контракт
	// бомб-тестов — проверяется та же ветка limitedReader-отказа.
	decompressLimit int64
}

// decompressCap возвращает эффективный лимит декомпрессии.
func (g *Generator) decompressCap() int64 {
	if g.decompressLimit > 0 {
		return g.decompressLimit
	}
	return maxDecompressed
}

// SetSigner внедряет подписчик: после .db генератор эмитит .db.sig
// (detached, бинарный). nil — репо не подписывается.
func (g *Generator) SetSigner(s port.Signer) { g.signer = s }

// Name — имя экосистемы, совпадает с Adapter.Name.
func (g *Generator) Name() string { return Name }

// ValidateObjectPath принимает только .pkg.tar.zst где угодно под
// корнем репо; .db/.files/.sig — генерируются, клиенту туда соваться
// нельзя. Legacy .pkg.tar.xz/.gz отвергаются с внятной причиной: парсер
// .PKGINFO читает пакет только через zstd (xz/gz-декодера нет в
// whitelist зависимостей), и один загруженный legacy-пакет иначе валил
// бы GenerateIndexes целиком — индексы протухали для всего репо.
func (g *Generator) ValidateObjectPath(p string) error {
	if strings.HasSuffix(p, ".pkg.tar.zst") {
		return nil
	}
	for _, suf := range []string{".pkg.tar.xz", ".pkg.tar.gz"} {
		if strings.HasSuffix(p, suf) {
			return &domain.ValidationError{What: "путь pacman-репо", Value: p, Reason: "xz/gz не поддерживается: нет декодера в whitelist зависимостей (переупакуйте в .pkg.tar.zst)"}
		}
	}
	return &domain.ValidationError{What: "путь pacman-репо", Value: p, Reason: "неизвестное расширение (ожидалось .pkg.tar.zst)"}
}

// ObjectFamily — port.FamilyResolver: семейство версий pacman-объекта —
// имя пакета из basename файла: <имя>-<версия>-<релиз>-<арх>.pkg.tar.zst.
// Граница «имя-версия» — эвристика ROADMAP: версия — первый сегмент
// (после деления по «-»), начинающийся с цифры, всё до него — семейство.
// Реальные имена Arch с дефисами и цифрами держатся именно так:
// python-pysocks-1.7.1-1-any → python-pysocks, gcc-libs-14.2.1-1-x86_64 →
// gcc-libs. Генерируемые объекты (.db, .files, .db.sig) и legacy
// .pkg.tar.xz/.gz (парсер их не умеет, на upload отвергаются) — ok=false.
func (g *Generator) ObjectFamily(p string) (string, bool) { return pacmanFamily(p) }

// CacheObjectFamily — port.CacheFamilyResolver: то же семейство для
// объекта кеш-прокси. Вход — upstream-путь Arch-зеркала
// (Target.UpstreamPath: «/core/os/x86_64/htop-3.3.0-2-x86_64.pkg.tar.zst»),
// а не путь внутри личного репо: разбор общий (pacmanFamily) — смотрит
// только basename.
func (g *Generator) CacheObjectFamily(upstreamPath string) (string, bool) {
	return pacmanFamily(upstreamPath)
}

// pacmanFamily — общая логика ObjectFamily и CacheObjectFamily: имя
// пакета из basename файла; .db/.files/.db.sig — ok=false.
func pacmanFamily(p string) (string, bool) {
	name := baseName(p)
	if !strings.HasSuffix(name, ".pkg.tar.zst") {
		return "", false
	}
	return pkgFamily(strings.TrimSuffix(name, ".pkg.tar.zst"))
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

// GenerateIndexes обходит .pkg.tar.*, читает .PKGINFO, собирает .db
// (tar.zst) + .db.sig (при Signer). Прогресс — обработанные пакеты.
//
//nolint:gocyclo // enumerate → pkginfo → write → sign — линейная
func (g *Generator) GenerateIndexes(ctx context.Context, repo domain.Repo, storage port.Storage, p port.RepoProgress) error {
	if p == nil {
		p = noopRepoProgress{}
	}
	if repo.Ecosystem != Name {
		return &domain.UnsupportedError{What: "pacman.gen", Why: "экосистема " + repo.Ecosystem + " ≠ pacman"}
	}
	prefix := port.RepoPrefix(repo)

	// Фаза 1: enumerate .pkg.tar.zst под prefix.
	p.Update("enumerate", repo.Name, 0, 0)
	pkgKeys, err := collectPkgTar(ctx, storage, prefix)
	if err != nil {
		return fmt.Errorf("pacman.gen: enumerate: %w", err)
	}
	p.Log(fmt.Sprintf("pacman.gen: найдено %d .pkg.tar.zst в %s", len(pkgKeys), prefix))

	// Фаза 2: чтение .PKGINFO + SHA256 каждого пакета, сборка desc-записей.
	p.Update("pkginfo", repo.Name, 0, int64(len(pkgKeys)))
	descs := make([]descEntry, 0, len(pkgKeys))
	for i, key := range pkgKeys {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		de, err := buildDescEntry(ctx, storage, key, g.decompressCap())
		if err != nil {
			return fmt.Errorf("pacman.gen: %s: %w", key, err)
		}
		descs = append(descs, de)
		p.Update("pkginfo", repo.Name, int64(i+1), int64(len(pkgKeys)))
	}
	// Фаза 2.5: дедуп по имени пакета — в .db не более одной записи на
	// %NAME% (детали и «почему» — в dedupeDescs). Storage не чистится:
	// несколько версий одного пакета — штатное состояние (retention/пины).
	before := len(descs)
	descs = dedupeDescs(descs, p)
	p.Log(fmt.Sprintf("pacman.gen: дедуп по имени: отброшено %d из %d записей", before-len(descs), before))
	// Лексический порядок desc-записей в .db (как repo-add).
	sort.Slice(descs, func(i, j int) bool { return descs[i].dir < descs[j].dir })

	// Фаза 3: сборка .db (tar.zst) + запись + (опц.) .db.sig.
	p.Update("write", repo.Name, 0, 2)
	dbBytes, err := buildDBTarZst(descs)
	if err != nil {
		return fmt.Errorf("pacman.gen: сборка .db: %w", err)
	}
	dbKey := prefix + "/" + repo.Name + ".db"
	if err := writeAtomic(ctx, storage, dbKey, dbBytes); err != nil {
		return fmt.Errorf("pacman.gen: .db: %w", err)
	}
	p.Update("write", repo.Name, 1, 2)

	if g.signer != nil {
		p.Update("sign", repo.Name, 0, 1)
		sigR, err := g.signer.SignDetached(ctx, bytes.NewReader(dbBytes))
		if err != nil {
			return fmt.Errorf("pacman.gen: .db.sig: %w", err)
		}
		sig, err := io.ReadAll(sigR)
		if err != nil {
			return fmt.Errorf("pacman.gen: .db.sig: чтение: %w", err)
		}
		if err := writeAtomic(ctx, storage, dbKey+".sig", sig); err != nil {
			return fmt.Errorf("pacman.gen: .db.sig: %w", err)
		}
		p.Update("sign", repo.Name, 1, 1)
		p.Log("pacman.gen: .db подписан")
	}
	p.Update("write", repo.Name, 2, 2)
	p.Log("pacman.gen: индексы записаны")
	return nil
}

// descEntry — одна desc-запись для .db: каталог в tar (<name>-<version>,
// без арх-суффикса — сессия 181), текст desc-файла и ключ дедупа —
// %NAME%/%VERSION% из .PKGINFO. По каталогу группировать нельзя: в нём
// склеены имя и версия, а разделитель «-» встречается в обоих (см.
// ObjectFamily).
type descEntry struct {
	dir     string
	desc    string
	name    string
	version string
}

// dedupeDescs оставляет по одной записи на имя пакета: из нескольких
// версий в .db попадает новейшая по alpm_pkg_vercmp (ComparePkgVer),
// прочие отбрасываются — но остаются в storage (retention/пины).
//
// Почему: клиент (libalpm, be_sync.c load_pkg_for_entry) переиспользует
// alpm_pkg первой записи с тем же %NAME% — вторая запись переписывает
// %FILENAME%/чексуммы, а %VERSION% остаётся от первой, и pacman падает
// «database is inconsistent: version mismatch on package …»: пакет не
// ставится ни `-S`, ни `-Sy`. Эталон upstream (`repo-add`) ведёт себя так
// же — запись замещается по имени пакета.
//
// Иммутабельность: входной срез не правится, собирается новый. Порядок
// записей (и, значит, лог) детерминирован: вход отсортирован по ключам
// storage (collectPkgTar), выбор — функцией сравнения, а не map.
func dedupeDescs(descs []descEntry, p port.RepoProgress) []descEntry {
	out := make([]descEntry, 0, len(descs))
	byName := make(map[string]int, len(descs))
	for _, de := range descs {
		idx, seen := byName[de.name]
		if !seen {
			byName[de.name] = len(out)
			out = append(out, de)
			continue
		}
		kept := out[idx]
		if ComparePkgVer(de.version, kept.version) > 0 {
			out[idx] = de
			p.Log(fmt.Sprintf("pacman.gen: дедуп: %s: %s → %s", de.name, kept.version, de.version))
			continue
		}
		p.Log(fmt.Sprintf("pacman.gen: дедуп: %s: отброшена %s (в индексе %s)", de.name, de.version, kept.version))
	}
	return out
}

// collectPkgTar возвращает лексически отсортированный список
// .pkg.tar.zst под prefix. Фильтр — только .zst: upload-ветка больше
// его не пропускает (см. ValidateObjectPath), но старые объекты могли
// осесть в хранилище до ужесточения — генератор их молча пропускает,
// вместо того чтобы падать на недекодируемом пакете.
func collectPkgTar(ctx context.Context, storage port.Storage, prefix string) ([]string, error) {
	var out []string
	listPrefix := prefix + "/"
	for meta, err := range storage.List(ctx, listPrefix) {
		if err != nil {
			return nil, fmt.Errorf("листинг %s: %w", listPrefix, err)
		}
		if strings.HasSuffix(meta.Key, ".pkg.tar.zst") {
			out = append(out, meta.Key)
		}
	}
	sort.Strings(out)
	return out, nil
}

// buildDescEntry читает .pkg.tar.* одним проходом (.PKGINFO + SHA256
// всего файла) и собирает desc-запись. %FILENAME% — basename .pkg.tar.*;
// %CSIZE% — фактический размер файла (счётчик tee); %SHA256SUM% — sha256
// файла; %ISIZE% — size из .PKGINFO. Каталог в .db: <pkgname>-<pkgver>-<arch>.
func buildDescEntry(ctx context.Context, storage port.Storage, pkgKey string, decompressLimit int64) (descEntry, error) {
	obj, err := storage.Get(ctx, pkgKey)
	if err != nil {
		return descEntry{}, err
	}
	defer obj.Body.Close()
	h := sha256.New()
	cr := &countReader{r: obj.Body}
	tee := io.TeeReader(cr, h)
	pi, err := readPkgInfoFromPackage(ctx, tee, decompressLimit)
	if err != nil {
		return descEntry{}, err
	}
	// Докачиваем остаток .pkg.tar.* через tee, чтобы SHA256 был посчитан
	// по всему файлу: readPkgInfoFromPackage остановился после .PKGINFO,
	// но в .pkg.tar.* ещё список файлов (data-секция tar).
	if _, err := io.Copy(io.Discard, tee); err != nil {
		return descEntry{}, fmt.Errorf("pacman.pkg: дочтение .pkg.tar: %w", err)
	}
	sha := hex.EncodeToString(h.Sum(nil))
	filename := pkgKey
	if idx := strings.LastIndexByte(pkgKey, '/'); idx >= 0 {
		filename = pkgKey[idx+1:]
	}
	// Каталог записи в .db — `<name>-<version>` без арх-суффикса: pacman
	// сверяет имя каталога с %NAME%/%VERSION% из desc и падает с
	// "name/version mismatch", если к ним приклеена архитектура. Архитектура
	// пакета живёт внутри desc в %ARCH% (buildDescText) — суффикс был
	// дублированием, а не носителем информации.
	dir := pi.Name + "-" + pi.Version
	// Размер — фактические байты через tee, не obj.Meta.Size: метаданные
	// носителя могут солгать, и pacman упадёт на сверке размера.
	desc := buildDescText(pi, filename, cr.n, sha)
	return descEntry{dir: dir, desc: desc, name: pi.Name, version: pi.Version}, nil
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

// buildDescText собирает текст desc-файла в pacman-формате: поля
// %FIELD%\nvalue\n\n (как repo-add), многозначные — по одному значению
// на строку. Поля — подмножество, нужное pacman -Sy и roundtrip-парсеру
// ParseDB (%FILENAME%/%NAME%/%VERSION%). %DEPENDS%/%PROVIDES%/
// %CONFLICTS% — из .PKGINFO: без них `pacman -S` не может резолвить
// зависимости пакета из личного репо.
func buildDescText(pi *PkgInfo, filename string, csize int64, sha string) string {
	var b strings.Builder
	writeDescField(&b, "FILENAME", filename)
	writeDescField(&b, "NAME", pi.Name)
	writeDescField(&b, "VERSION", pi.Version)
	if pi.Desc != "" {
		writeDescField(&b, "DESC", pi.Desc)
	}
	if pi.URL != "" {
		writeDescField(&b, "URL", pi.URL)
	}
	if len(pi.License) > 0 {
		writeDescField(&b, "LICENSE", strings.Join(pi.License, "\n"))
	}
	if pi.Arch != "" {
		writeDescField(&b, "ARCH", pi.Arch)
	}
	if pi.BuildDate != 0 {
		writeDescField(&b, "BUILDDATE", fmt.Sprintf("%d", pi.BuildDate))
	}
	if pi.Packager != "" {
		writeDescField(&b, "PACKAGER", pi.Packager)
	}
	writeDescField(&b, "CSIZE", fmt.Sprintf("%d", csize))
	if pi.Size != 0 {
		writeDescField(&b, "ISIZE", fmt.Sprintf("%d", pi.Size))
	}
	writeDescField(&b, "SHA256SUM", sha)
	if len(pi.Conflicts) > 0 {
		writeDescField(&b, "CONFLICTS", strings.Join(pi.Conflicts, "\n"))
	}
	if len(pi.Provides) > 0 {
		writeDescField(&b, "PROVIDES", strings.Join(pi.Provides, "\n"))
	}
	if len(pi.Depends) > 0 {
		writeDescField(&b, "DEPENDS", strings.Join(pi.Depends, "\n"))
	}
	return b.String()
}

// writeDescField пишет «%FIELD%\nvalue\n\n» в builder (формат desc).
func writeDescField(b *strings.Builder, field, value string) {
	fmt.Fprintf(b, "%%%s%%\n%s\n\n", field, value)
}

// buildDBTarZst собирает tar из desc-записей (каталог + desc-файл на
// каждую), затем zstd-сжимает. Порядок desc — лексический (вызывающий
// отсортировал). Возвращает байты .db.
func buildDBTarZst(descs []descEntry) ([]byte, error) {
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	for _, de := range descs {
		// каталог <dir>/
		dirName := de.dir + "/"
		if err := tw.WriteHeader(&tar.Header{
			Name:     dirName,
			Typeflag: tar.TypeDir,
			Mode:     0o755,
		}); err != nil {
			return nil, fmt.Errorf("pacman.db: dir %s: %w", dirName, err)
		}
		// desc-файл <dir>/desc
		content := []byte(de.desc)
		if err := tw.WriteHeader(&tar.Header{
			Name:     dirName + "desc",
			Typeflag: tar.TypeReg,
			Mode:     0o644,
			Size:     int64(len(content)),
		}); err != nil {
			return nil, fmt.Errorf("pacman.db: desc %s: %w", dirName, err)
		}
		if _, err := tw.Write(content); err != nil {
			return nil, fmt.Errorf("pacman.db: write desc %s: %w", dirName, err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("pacman.db: tar close: %w", err)
	}
	// zstd-сжатие tar'а.
	var zstBuf bytes.Buffer
	zw, err := zstd.NewWriter(&zstBuf)
	if err != nil {
		return nil, fmt.Errorf("pacman.db: zstd writer: %w", err)
	}
	if _, err := zw.Write(tarBuf.Bytes()); err != nil {
		_ = zw.Close()
		return nil, fmt.Errorf("pacman.db: zstd write: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("pacman.db: zstd close: %w", err)
	}
	return zstBuf.Bytes(), nil
}

// writeAtomic пишет байты в storage через Put+Commit; на ошибке Abort.
// Дубликат из apt/rpmmmd.gen: mod→mod запрещён depguard'ом.
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

// noopRepoProgress — заглушка, чтобы GenerateIndexes можно было звать
// без репортёра (из тестов). Дубликат из apt/rpmmmd.gen.
type noopRepoProgress struct{}

func (noopRepoProgress) Update(string, string, int64, int64) {}
func (noopRepoProgress) Log(string)                          {}
