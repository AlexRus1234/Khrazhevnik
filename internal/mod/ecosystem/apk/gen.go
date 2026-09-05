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
// repo/<id>/apk/**/*.apk, читает .PKGINFO каждого (pkginfo.go) и считает
// sha1, собирает APKINDEX.tar.gz (gzip+tar с файлом APKINDEX в формате
// «K:V») + APKINDEX.tar.gz.sig (подпись Signer'ом из сессии 15).
// Атомарность v1 — перезапись ключей после полной генерации staging в
// памяти (окно рассинхрона ~секунды; полный atomic-swap — сессия 17).
//
// Ключи в storage — lowercase (domain.ValidateKey): apkindex.tar.gz,
// apkindex.tar.gz.sig. apk fetch'ит APKINDEX.tar.gz (имя — каноническое
// uppercase в URL, но публичный роутер :29202 лоуэркейсит запрос перед
// lookup'ом, поэтому storage-ключ lowercase).

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
}

// SetSigner внедряет подписчик: после APKINDEX.tar.gz генератор эмитит
// APKINDEX.tar.gz.sig (detached). nil — репо не подписывается.
func (g *Generator) SetSigner(s port.Signer) { g.signer = s }

// Name — имя экосистемы, совпадает с Adapter.Name.
func (g *Generator) Name() string { return Name }

// ValidateObjectPath принимает .apk где угодно под корнем репо;
// APKINDEX.tar.gz — генерируется, клиенту туда соваться нельзя.
func (g *Generator) ValidateObjectPath(p string) error {
	if strings.HasSuffix(p, ".apk") {
		return nil
	}
	return &domain.ValidationError{What: "путь apk-репо", Value: p, Reason: "неизвестное расширение (ожидалось .apk)"}
}

// GenerateIndexes обходит .apk, читает .PKGINFO, собирает APKINDEX.tar.gz
// (+ .sig при Signer). Прогресс — обработанные пакеты.
//
//nolint:gocyclo // enumerate → pkginfo → write → sign — линейная
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

	// Фаза 2: чтение .PKGINFO + sha1 каждого .apk, сборка APKINDEX-текста.
	p.Update("pkginfo", repo.Name, 0, int64(len(apkKeys)))
	var indexText bytes.Buffer
	for i, key := range apkKeys {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := appendIndexEntry(ctx, storage, key, prefix, &indexText); err != nil {
			return fmt.Errorf("apk.gen: %s: %w", key, err)
		}
		p.Update("pkginfo", repo.Name, int64(i+1), int64(len(apkKeys)))
	}

	// Фаза 3: APKINDEX.tar.gz (gzip+tar с файлом «APKINDEX») + запись
	// (+ опц. .sig). Ключи — lowercase.
	p.Update("write", repo.Name, 0, 2)
	indexGz, err := buildAPKINDEXTarGz(indexText.Bytes())
	if err != nil {
		return fmt.Errorf("apk.gen: сборка APKINDEX.tar.gz: %w", err)
	}
	indexKey := prefix + "/apkindex.tar.gz"
	if err := writeAtomic(ctx, storage, indexKey, indexGz); err != nil {
		return fmt.Errorf("apk.gen: APKINDEX.tar.gz: %w", err)
	}
	p.Update("write", repo.Name, 1, 2)

	if g.signer != nil {
		p.Update("sign", repo.Name, 0, 1)
		sigR, err := g.signer.SignDetached(ctx, bytes.NewReader(indexGz))
		if err != nil {
			return fmt.Errorf("apk.gen: APKINDEX.tar.gz.sig: %w", err)
		}
		sig, err := io.ReadAll(sigR)
		if err != nil {
			return fmt.Errorf("apk.gen: APKINDEX.tar.gz.sig: чтение: %w", err)
		}
		if err := writeAtomic(ctx, storage, indexKey+".sig", sig); err != nil {
			return fmt.Errorf("apk.gen: APKINDEX.tar.gz.sig: %w", err)
		}
		p.Update("sign", repo.Name, 1, 1)
		p.Log("apk.gen: APKINDEX подписан")
	}
	p.Update("write", repo.Name, 2, 2)
	p.Log("apk.gen: индексы записаны")
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

// appendIndexEntry читает .apk одним проходом (.PKGINFO + sha1 всего
// файла) и дописывает запись в APKINDEX-текст (K:V-формат). F: — путь
// .apk относительно корня репо (apk кладёт полный относительный путь).
func appendIndexEntry(ctx context.Context, storage port.Storage, apkKey, prefix string, buf *bytes.Buffer) error {
	obj, err := storage.Get(ctx, apkKey)
	if err != nil {
		return err
	}
	defer obj.Body.Close()
	h := sha1.New()
	cr := &countReader{r: obj.Body}
	tee := io.TeeReader(cr, h)
	pi, err := readPkgInfoFromPackage(ctx, tee)
	if err != nil {
		return err
	}
	// Докачиваем остаток .apk через tee, чтобы sha1 был посчитан по
	// всему файлу: readPkgInfoFromPackage остановился после .PKGINFO.
	if _, err := io.Copy(io.Discard, tee); err != nil {
		return fmt.Errorf("apk.apk: дочтение .apk: %w", err)
	}
	checksum := "Q1" + base64.StdEncoding.EncodeToString(h.Sum(nil))
	filepath := strings.TrimPrefix(apkKey, prefix+"/")
	// Размер — фактические байты через tee, не obj.Meta.Size: метаданные
	// носителя могут солгать, и apk упадёт на сверке размера.
	writeAPKINDEXEntry(buf, pi, checksum, filepath, cr.n)
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
