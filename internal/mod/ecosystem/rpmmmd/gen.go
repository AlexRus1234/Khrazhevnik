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

// Генератор rpm-md-индексов личного репозитория (port.RepoAdapter):
// обходит repo/<id>/rpm-md/**/*.rpm (кроме repodata/), читает RPM-заголовок
// каждого и считает SHA256, собирает repodata/primary.xml.gz + repodata/
// repomd.xml (с чексуммами и размерами) + repodata/repomd.xml.asc (подпись
// Signer'ом из сессии 15). Атомарность v1 — перезапись ключей после полной
// генерации staging в памяти (окно рассинхрона ~секунды; полный atomic-swap
// — сессия 17). Подпись repomd.xml.asc — detached через port.Signer.
//
// Ключи в storage — lowercase (репо-пути лоуэркейсятся сознательно:
// repodata-пути lowercase по конвенции rpm-md, сам домен допускает
// регистр с сессии 19): repodata/primary.xml.gz, repodata/repomd.xml,
// repodata/repomd.xml.asc. dnf/zypper просят repomd.xml (lowercase
// клиентских путей нет — dnf кодирует baseurl+«/repodata/repomd.xml»),
// публичный роутер :29202 лоуэркейсит запрос перед lookup'ом.

package rpmmmd

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/core/registry"
)

// Параметры генерируемого репо v1 (KISS): один репозиторий целиком,
// без деления на media. Имя каталога индексов — «repodata» (как у
// createrepo_c); пакеты лежат где угодно под корнем репо (кроме repodata/).
const repodataDir = "repodata"

func init() {
	// Регистрация repo-адаптера в compile-time реестре: имя совпадает
	// с именем экосистемы (rpm-md). Фабрика без параметров: генератору
	// нужен только Storage, который приходит в GenerateIndexes. Signer
	// внедряется после сборки через SetSigner (wire type-assert'ит к
	// port.SignerInjector) — nil = repomd.xml.asc не эмитится.
	registry.RegisterRepoAdapter(Name, func() (port.RepoAdapter, error) {
		return &Generator{}, nil
	})
}

// Generator реализует port.RepoAdapter для rpm-md-репо. Внедряемый
// через port.SignerInjector подписчик включает эмиссию repomd.xml.asc
// после repomd.xml; nil = репо не подписывается (сессия 15). Clock —
// источник времени для revision/timestamp в repomd.xml
// (port.ClockInjector, wire); nil — фолбэк systemClock (тесты без wire).
type Generator struct {
	signer port.Signer
	clock  port.Clock
}

// SetSigner внедряет подписчик метаданных: после repomd.xml генератор
// эмитит repomd.xml.asc (detached, бинарный — как Release.gpg у apt).
// nil — репо не подписывается. Вызывается из wire (type-assert к
// port.SignerInjector).
func (g *Generator) SetSigner(s port.Signer) { g.signer = s }

// SetClock внедряет источник времени для revision/timestamp repomd.
// Вызывается из wire (type-assert к port.ClockInjector).
func (g *Generator) SetClock(c port.Clock) { g.clock = c }

// now — время генерации: внедрённый Clock, без него systemClock
// (нулевое значение Generator в тестах остаётся рабочим).
func (g *Generator) now() time.Time {
	if g.clock != nil {
		return g.clock.Now()
	}
	return systemClock{}.Now()
}

// systemClock — port.Clock поверх time.Now (фолбэк как в движках;
// тесты подменяют через SetClock/testutil).
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// Name — имя экосистемы, совпадает с Adapter.Name.
func (g *Generator) Name() string { return Name }

// ValidateObjectPath принимает .rpm/.drpm (включая .src.rpm как
// частный случай .rpm) где угодно под корнем репо, кроме repodata/
// (там живут индексы — генерируются, клиенту туда соваться нельзя).
// Возвращает *domain.ValidationError для маппинга в 400.
func (g *Generator) ValidateObjectPath(p string) error {
	if strings.HasPrefix(p, repodataDir+"/") {
		return &domain.ValidationError{What: "путь rpm-md-репо", Value: p, Reason: "repodata/ — генерируется, upload туда запрещён"}
	}
	switch {
	case strings.HasSuffix(p, ".rpm"), strings.HasSuffix(p, ".drpm"):
		return nil
	}
	return &domain.ValidationError{What: "путь rpm-md-репо", Value: p, Reason: "неизвестное расширение (ожидалось .rpm/.drpm/.src.rpm)"}
}

// GenerateIndexes обходит .rpm, читает заголовки, собирает primary.xml.gz
// и repomd.xml (+ repomd.xml.asc при Signer). Прогресс — обработанные
// пакеты. Атомарность v1: запись ключей по одному после полной генерации
// staging в памяти (окно рассинхрона ~секунды; полный atomic-swap — 17).
//
//nolint:gocyclo // enumerate → header → write → sign — линейная последовательность
func (g *Generator) GenerateIndexes(ctx context.Context, repo domain.Repo, storage port.Storage, p port.RepoProgress) error {
	if p == nil {
		p = noopRepoProgress{}
	}
	if repo.Ecosystem != Name {
		return &domain.UnsupportedError{What: "rpm-md.gen", Why: "экосистема " + repo.Ecosystem + " ≠ rpm-md"}
	}
	prefix := port.RepoPrefix(repo)

	// Фаза 1: enumerate .rpm (все, кроме repodata/).
	p.Update("enumerate", repo.Name, 0, 0)
	rpmKeys, err := collectRpms(ctx, storage, prefix)
	if err != nil {
		return fmt.Errorf("rpm-md.gen: enumerate: %w", err)
	}
	p.Log(fmt.Sprintf("rpm-md.gen: найдено %d .rpm в %s", len(rpmKeys), prefix))

	// Фаза 2: чтение заголовка + SHA256 каждого .rpm одним проходом,
	// сборка primary.xml в памяти.
	p.Update("header", repo.Name, 0, int64(len(rpmKeys)))
	var primary bytes.Buffer
	primary.Grow(64 * 1024)
	fmt.Fprintf(&primary, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	fmt.Fprintf(&primary, "<metadata xmlns=\"http://linux.duke.edu/metadata/common\" "+
		"xmlns:rpm=\"http://linux.duke.edu/metadata/rpm\" packages=\"%d\">\n", len(rpmKeys))
	for i, key := range rpmKeys {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := appendPrimaryEntry(ctx, storage, key, prefix, &primary); err != nil {
			return fmt.Errorf("rpm-md.gen: %s: %w", key, err)
		}
		p.Update("header", repo.Name, int64(i+1), int64(len(rpmKeys)))
	}
	primary.WriteString("</metadata>\n")

	// Фаза 3: primary.xml.gz + repomd.xml (+ .asc). Ключи — lowercase.
	p.Update("write", repo.Name, 0, 2)
	primaryBytes := primary.Bytes()
	primaryGz := gzipBytes(primaryBytes)
	repodataPrefix := prefix + "/" + repodataDir
	if err := writeAtomic(ctx, storage, repodataPrefix+"/primary.xml.gz", primaryGz); err != nil {
		return fmt.Errorf("rpm-md.gen: primary.xml.gz: %w", err)
	}
	p.Update("write", repo.Name, 1, 2)
	repomd := buildRepomd(g.now().UTC(), primaryBytes, primaryGz)
	if err := writeAtomic(ctx, storage, repodataPrefix+"/repomd.xml", repomd); err != nil {
		return fmt.Errorf("rpm-md.gen: repomd.xml: %w", err)
	}
	p.Update("write", repo.Name, 2, 2)

	// Фаза 4 (опц.): подпись repomd.xml → repomd.xml.asc (detached,
	// бинарный — как Release.gpg apt). Подписывается ровно тот байтовый
	// состав repomd.xml, что записан выше (инвариант: метаданные
	// подписываются как есть, без переписывания).
	if g.signer != nil {
		p.Update("sign", repo.Name, 0, 1)
		sigR, err := g.signer.SignDetached(ctx, bytes.NewReader(repomd))
		if err != nil {
			return fmt.Errorf("rpm-md.gen: repomd.xml.asc: %w", err)
		}
		sig, err := io.ReadAll(sigR)
		if err != nil {
			return fmt.Errorf("rpm-md.gen: repomd.xml.asc: чтение: %w", err)
		}
		if err := writeAtomic(ctx, storage, repodataPrefix+"/repomd.xml.asc", sig); err != nil {
			return fmt.Errorf("rpm-md.gen: repomd.xml.asc: %w", err)
		}
		p.Update("sign", repo.Name, 1, 1)
		p.Log("rpm-md.gen: repomd.xml подписан")
	}
	p.Log("rpm-md.gen: индексы записаны")
	return nil
}

// collectRpms возвращает лексически отсортированный список ключей .rpm
// под prefix, исключая repodata/ (там живут индексы). Storage.List отдаёт
// метаданные, фильтруем по суффиксу и префиксу repodata/. Ошибка листинга
// — ошибка генерации (иначе пустой обход записал бы ПУСТОЙ primary.xml
// поверх валидного).
func collectRpms(ctx context.Context, storage port.Storage, prefix string) ([]string, error) {
	var out []string
	listPrefix := prefix + "/"
	for meta, err := range storage.List(ctx, listPrefix) {
		if err != nil {
			return nil, fmt.Errorf("листинг %s: %w", listPrefix, err)
		}
		name := meta.Key
		// отсекаем ключи под repodata/ — это индексы, не пакеты.
		rel := strings.TrimPrefix(name, listPrefix)
		if strings.HasPrefix(rel, repodataDir+"/") {
			continue
		}
		if strings.HasSuffix(rel, ".rpm") || strings.HasSuffix(rel, ".drpm") {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

// appendPrimaryEntry читает .rpm одним проходом (RPM-заголовок + SHA256
// всего файла) и дописывает <package>-запись в primary.xml. location
// href — путь относительно корня репо (без repo/<id>/rpm-md/).
func appendPrimaryEntry(ctx context.Context, storage port.Storage, rpmKey, prefix string, buf *bytes.Buffer) error {
	obj, err := storage.Get(ctx, rpmKey)
	if err != nil {
		return err
	}
	defer obj.Body.Close()
	h := sha256.New()
	cr := &countReader{r: obj.Body}
	tee := io.TeeReader(cr, h)
	hdr, err := ParseRPMHeader(tee)
	if err != nil {
		return err
	}
	// Докачиваем остаток .rpm (payload) через tee, чтобы SHA256 был
	// посчитан по всему файлу: ParseRPMHeader остановился после main
	// header, но в .rpm ещё payload (cpio).
	if _, err := io.Copy(io.Discard, tee); err != nil {
		return fmt.Errorf("rpm-md.rpm: дочтение .rpm: %w", err)
	}
	sha := hex.EncodeToString(h.Sum(nil))
	href := strings.TrimPrefix(rpmKey, prefix+"/")
	// Размер — фактические байты через tee, не obj.Meta.Size: если
	// метаданные носителя солгали, чексумма верна, а size — нет, и
	// клиентский dnf падает бы на сверке.
	writePrimaryPackage(buf, hdr, sha, href, cr.n, obj.Meta.ModTime)
	return nil
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

// writePrimaryPackage пишет одну <package>-запись в buf. Минимальный
// набор тегов, которые читают dnf/zypper: name, arch, version(epoch/
// ver/rel), checksum (sha256 файла), summary, description, url, time
// (file mtime + buildtime), size (package=size файла, installed=SIZE),
// location href, rpm:license; зависимости — rpm:sourcerpm, rpm:requires,
// rpm:provides (entry с name; flags/ver/rel из отдельных тегов RPM
// не читаем — dnf резолвит и без них, а без зависимостей вовсе
// `dnf install` не может резолвить из личного репо). Текст — xmlEscape,
// атрибуты — escapeAttr.
func writePrimaryPackage(buf *bytes.Buffer, h *RPMHeader, sha, href string, pkgSize int64, mtime time.Time) {
	buf.WriteString("\t<package type=\"rpm\">\n")
	fmt.Fprintf(buf, "\t\t<name>%s</name>\n", xmlEscape(h.Name))
	fmt.Fprintf(buf, "\t\t<arch>%s</arch>\n", xmlEscape(h.Arch))
	fmt.Fprintf(buf, "\t\t<version epoch=\"%d\" ver=\"%s\" rel=\"%s\"/>\n", h.Epoch, escapeAttr(h.Version), escapeAttr(h.Release))
	fmt.Fprintf(buf, "\t\t<checksum type=\"sha256\">%s</checksum>\n", sha)
	fmt.Fprintf(buf, "\t\t<summary>%s</summary>\n", xmlEscape(h.Summary))
	fmt.Fprintf(buf, "\t\t<description>%s</description>\n", xmlEscape(h.Description))
	if h.URL != "" {
		fmt.Fprintf(buf, "\t\t<url>%s</url>\n", xmlEscape(h.URL))
	}
	fmt.Fprintf(buf, "\t\t<time file=\"%d\" build=\"%d\"/>\n", mtime.Unix(), h.BuildTime)
	fmt.Fprintf(buf, "\t\t<size package=\"%d\" installed=\"%d\" archive=\"%d\"/>\n", pkgSize, h.Size, pkgSize)
	fmt.Fprintf(buf, "\t\t<location href=\"%s\"/>\n", escapeAttr(href))
	buf.WriteString("\t\t<format>\n")
	if h.License != "" {
		fmt.Fprintf(buf, "\t\t\t<rpm:license>%s</rpm:license>\n", xmlEscape(h.License))
	}
	if h.SourceRPM != "" {
		fmt.Fprintf(buf, "\t\t\t<rpm:sourcerpm>%s</rpm:sourcerpm>\n", xmlEscape(h.SourceRPM))
	}
	if len(h.Requires) > 0 {
		buf.WriteString("\t\t\t<rpm:requires>\n")
		for _, dep := range h.Requires {
			fmt.Fprintf(buf, "\t\t\t\t<rpm:entry name=\"%s\"/>\n", escapeAttr(dep))
		}
		buf.WriteString("\t\t\t</rpm:requires>\n")
	}
	if len(h.Provides) > 0 {
		buf.WriteString("\t\t\t<rpm:provides>\n")
		for _, prov := range h.Provides {
			fmt.Fprintf(buf, "\t\t\t\t<rpm:entry name=\"%s\"/>\n", escapeAttr(prov))
		}
		buf.WriteString("\t\t\t</rpm:provides>\n")
	}
	buf.WriteString("\t\t</format>\n")
	buf.WriteString("\t</package>\n")
}

// buildRepomd собирает repomd.xml: revision (timestamp), один data
// type="primary" с checksum/open-checksum (sha256), size/open-size,
// location href, timestamp. checksum — sha256 сжатого primary.xml.gz;
// open-checksum — sha256 несжатого primary.xml. now — время генерации
// (Clock вызывающего).
func buildRepomd(now time.Time, primary, primaryGz []byte) []byte {
	var b bytes.Buffer
	b.Grow(2048)
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	b.WriteString("<repomd xmlns=\"http://linux.duke.edu/metadata/repo\">\n")
	fmt.Fprintf(&b, "\t<revision>%d</revision>\n", now.Unix())
	b.WriteString("\t<data type=\"primary\">\n")
	fmt.Fprintf(&b, "\t\t<checksum type=\"sha256\">%s</checksum>\n", sha256Hex(primaryGz))
	fmt.Fprintf(&b, "\t\t<open-checksum type=\"sha256\">%s</open-checksum>\n", sha256Hex(primary))
	fmt.Fprintf(&b, "\t\t<location href=\"repodata/primary.xml.gz\"/>\n")
	fmt.Fprintf(&b, "\t\t<timestamp>%d</timestamp>\n", now.Unix())
	fmt.Fprintf(&b, "\t\t<size>%d</size>\n", len(primaryGz))
	fmt.Fprintf(&b, "\t\t<open-size>%d</open-size>\n", len(primary))
	b.WriteString("\t</data>\n")
	b.WriteString("</repomd>\n")
	return b.Bytes()
}

// sha256Hex возвращает hex(sha256(data)).
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// xmlEscape экранирует текстовые узлы XML (&, <, >); для атрибутов
// используйте escapeAttr — текстовый эскейп не трогает кавычку.
func xmlEscape(s string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

// escapeAttr экранирует значение XML-атрибута. Значения приходят из
// заголовка .rpm — сборщик может вписать туда кавычку, и голая кавычка
// прорвала бы атрибут primary.xml. xml.EscapeText покрывает &<> и сам
// превращает «"» в &#34;; канонизируем оба варианта в именованный
// &quot; (та же семантика, diff'ы индексов читаемее).
func escapeAttr(s string) string {
	escaped := xmlEscape(s)
	escaped = strings.ReplaceAll(escaped, `"`, "&quot;")
	return strings.ReplaceAll(escaped, "&#34;", "&quot;")
}

// writeAtomic пишет байты в storage через Put+Commit; на ошибке Abort.
// fs делает tmp+rename (атомарно); s3 — одиночный PUT (атомарно).
// Дубликат из apt.gen: mod→mod запрещён depguard'ом, держим адаптеры
// самодостаточными.
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

// gzipBytes возвращает gzip-сжатую копию content. Дубликат из apt.gen.
func gzipBytes(content []byte) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write(content)
	_ = gz.Close()
	return buf.Bytes()
}

// noopRepoProgress — заглушка, чтобы GenerateIndexes можно было звать
// без репортёра (из тестов). Дубликат из apt.gen.
type noopRepoProgress struct{}

func (noopRepoProgress) Update(string, string, int64, int64) {}
func (noopRepoProgress) Log(string)                          {}
