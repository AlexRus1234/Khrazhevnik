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

// Генератор личного xbps-репозитория (port.RepoAdapter) — функциональный
// аналог `xbps-rindex --add --sign --sign-pkg`. Лэйаут плоский, как
// upstream Void: repo/<id>/xbps/ содержит только пакеты `<pkgver>.<arch>.xbps`
// (upload клиента, publish лоуэркейсит путь) и генерируемые артефакты
// `<arch>-repodata` (zstd+tar: index.plist / index-meta.plist / stage.plist)
// плюс detached-подписи `<pkgver>.<arch>.xbps.sig2` и `.sig` (сессии 139/191).
//
// Группировка: индекс строится отдельно по каждой нативной архитектуре;
// noarch-пакет входит в КАЖДУЮ arch-группу — клиент ищет пакет в
// repodata своей native-arch. Если в репо нет ни одного нативного пакета
// (только noarch), arch-групп нет и repodata не генерируется: клиенту
// такая раздача всё равно непригодна (Void не имеет noarch-индекса).
//
// Подпись: каждый .xbps получает ОБЕ detached-подписи — `.sig2` (RSA
// PKCS#1 v1.5/SHA-256 по дайджесту тела) и легаси `.sig` (тот же дайджест
// в SHA-1-DigestInfo; ровно её запрашивает живой клиент); публичный ключ
// инстанса встраивается в index-meta.plist (TOFU-импорт клиентом). Без
// RsaSigner (wire не слинковал модуль или подписчик выключен) репо
// деградирует как apk без Signer: repodata генерируется, index-meta пуст,
// подписи не эмитятся.
//
// Атомарность v1 — перезапись ключей после полной генерации в памяти
// (окно рассинхрона ~секунды, образец apk/gen.go). Отмена ctx
// проверяется на каждом пакете (сессия 77).

package xbps

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/klauspost/compress/zstd"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/core/registry"
)

const (
	// pkgSuffix — расширение пакета; единственный объект, который
	// клиент вправе загрузить в личный xbps-репо.
	pkgSuffix = ".xbps"
	// sig2Suffix — штатная detached-подпись xbps: RSA PKCS#1 v1.5/SHA-256
	// по дайджесту пакета (формат xbps-rindex).
	sig2Suffix = ".sig2"
	// sigSuffix — легаси-подпись Void: та же RSA-подпись, но с
	// SHA-1-DigestInfo вокруг SHA-256-дайджеста. Живой клиент
	// (`signature-type: rsa`) просит именно `.sig` — без него установка
	// падает на 404, хотя `.sig2` лежит рядом.
	sigSuffix = ".sig"
	// repodataSuffix — суффикс генерируемого индекса архитектуры
	// (`<arch>-repodata`).
	repodataSuffix = "-repodata"
	// noarchArch — архитектура архитектурно-независимых пакетов; такие
	// записи дублируются в каждую нативную arch-группу.
	noarchArch = "noarch"
	// signatureBy — значение поля index-meta.plist: идентификатор
	// генератора. Константа v1 (KISS, без конфиг-ручки).
	signatureBy = "Khrazhevnik"
	// signatureType — тип подписи index-meta.plist (RSA PKCS#1 v1.5).
	signatureType = "rsa"
)

func init() {
	// Регистрация repo-адаптера в compile-time реестре: имя совпадает
	// с именем экосистемы (xbps). RsaSigner внедряется через wire
	// (port.RsaSignerInjector).
	registry.RegisterRepoAdapter(Name, func() (port.RepoAdapter, error) {
		return &Generator{}, nil
	})
}

// Generator реализует port.RepoAdapter для личных xbps-репо.
type Generator struct {
	rsa port.RsaSigner
}

// Compile-time: Generator умеет принимать xbps-подписчик (wire).
var _ port.RsaSignerInjector = (*Generator)(nil)

// SetRsaSigner внедряет xbps-подписчик: после repodata генератор
// эмитит `<pkgver>.<arch>.xbps.sig2` и `.sig` (detached) и встраивает
// публичный ключ в index-meta.plist. nil — индексы без ключа, подписей нет.
func (g *Generator) SetRsaSigner(s port.RsaSigner) { g.rsa = s }

// Name — имя экосистемы, совпадает с Adapter.Name.
func (g *Generator) Name() string { return Name }

// ValidateObjectPath принимает только плоские `*.xbps` без каталогов:
// лэйаут Void плоский (нет pool/dists). Генерируемые `<arch>-repodata`
// и подписи (`.sig2`/`.sig`) клиенту закрыты — равно как и любые
// вложенные пути (`foo/bar.xbps` не .xbps-объект в корне). Тот же
// суффикс-барьер закрывает и `.sig` — отдельной ветки ему не нужно.
func (g *Generator) ValidateObjectPath(p string) error {
	if p == "" {
		return &domain.ValidationError{What: "путь xbps-репо", Value: p, Reason: "пустой"}
	}
	if strings.ContainsRune(p, '/') {
		return &domain.ValidationError{What: "путь xbps-репо", Value: p, Reason: "плоский лэйаут: каталоги не поддерживаются"}
	}
	if !strings.HasSuffix(p, pkgSuffix) {
		return &domain.ValidationError{What: "путь xbps-репо", Value: p, Reason: "неизвестное расширение (ожидалось .xbps)"}
	}
	return nil
}

// ObjectFamily — port.FamilyResolver: семейство версий xbps-объекта —
// имя пакета из pkgver. Разбор не дублируем: переиспользуем SplitPkgver
// (сессия 133) — тот же разбор, что у Enumerate и генератора. Имя файла —
// <pkgver>.<arch>.xbps, и арх-хвост срезается ДО разбора: SplitPkgver
// строг к ревизии (`_N`) и на «x86_64»/«noarch» в хвосте вернул бы
// ValidationError (ревизией оказалась бы часть «64» или «1.noarch»).
// Лэйаут Void плоский (ValidateObjectPath отвергает каталоги), поэтому
// путь и есть имя файла. Архитектура — последний точечный сегмент
// (точек в именах архитектур Void нет), без него имя неканонично —
// ok=false. Мусорный pkgver — тоже ok=false: версию ретеншн не тронет,
// а падать на одном битом объекте не должен. Генерируемые
// `<arch>-repodata` и подписи (`.sig2`/`.sig`) — ok=false. Регистр имени
// сохраняем: Mustache и Gifsicle в Void реальны.
func (g *Generator) ObjectFamily(p string) (string, bool) { return xbpsFamily(p) }

// CacheObjectFamily — port.CacheFamilyResolver: то же семейство для
// объекта кеш-прокси. Вход — upstream-путь Void-зеркала
// (Target.UpstreamPath: «/Mustache-4.1_1.x86_64.xbps»), а не путь внутри
// личного репо: лэйаут Void плоский и на upstream (файл в корне remote),
// поэтому разбор общий (xbpsFamily) — отличается только нормализация
// ведущего «/».
func (g *Generator) CacheObjectFamily(upstreamPath string) (string, bool) {
	return xbpsFamily(upstreamPath)
}

// xbpsFamily — общая логика ObjectFamily и CacheObjectFamily: ведущий «/»
// срезается (upstream-пути кеша идут с ним, пути внутри личного репо —
// без), дальше имя пакета из pkgver до последней точки.
func xbpsFamily(p string) (string, bool) {
	p = strings.TrimPrefix(p, "/")
	if !strings.HasSuffix(p, pkgSuffix) {
		return "", false
	}
	stem := strings.TrimSuffix(p, pkgSuffix)
	dot := strings.LastIndexByte(stem, '.')
	if dot <= 0 {
		return "", false
	}
	pkgName, _, err := SplitPkgver(stem[:dot])
	if err != nil {
		return "", false
	}
	return pkgName, true
}

// pkgRecord — разобранный пакет: ключ storage, поля props.plist,
// SHA-256 всего тела и его размер (последние два пишутся в индекс как
// filename-sha256/filename-size).
type pkgRecord struct {
	key    string
	props  Props
	digest []byte
	size   int64
}

// GenerateIndexes обходит `.xbps`, читает props.plist каждого, собирает
// `<arch>-repodata` (noarch — в каждую группу) и подписи `.sig2`+`.sig`
// на каждый пакет. Прогресс — фазы enumerate/read/index/sign.
//
//nolint:gocyclo // enumerate → read → index → sign — линейные фазы
func (g *Generator) GenerateIndexes(ctx context.Context, repo domain.Repo, storage port.Storage, p port.RepoProgress) error {
	if p == nil {
		p = noopRepoProgress{}
	}
	if repo.Ecosystem != Name {
		return &domain.UnsupportedError{What: "xbps.gen", Why: "экосистема " + repo.Ecosystem + " ≠ xbps"}
	}
	prefix := port.RepoPrefix(repo)

	// Фаза 1: enumerate плоских .xbps под prefix.
	p.Update("enumerate", repo.Name, 0, 0)
	pkgKeys, err := collectPackages(ctx, storage, prefix)
	if err != nil {
		return fmt.Errorf("xbps.gen: enumerate: %w", err)
	}
	p.Log(fmt.Sprintf("xbps.gen: найдено %d .xbps в %s", len(pkgKeys), prefix))

	// Фаза 2: props.plist + sha256/размер каждого пакета.
	p.Update("read", repo.Name, 0, int64(len(pkgKeys)))
	records := make([]pkgRecord, 0, len(pkgKeys))
	for i, key := range pkgKeys {
		if err := ctx.Err(); err != nil {
			return err
		}
		rec, err := readPackage(ctx, storage, key)
		if err != nil {
			return fmt.Errorf("xbps.gen: %s: %w", key, err)
		}
		records = append(records, rec)
		p.Update("read", repo.Name, int64(i+1), int64(len(pkgKeys)))
	}

	// index-meta.plist одинаков для всех архитектур (ключ инстанса).
	metaXML, err := g.buildMetaPlist()
	if err != nil {
		return err
	}

	// Фаза 2.5: дедуп по имени пакета — в index.plist не более одной записи
	// на PkgName (детали и «почему» — в dedupeRecords). Storage не чистится:
	// несколько версий одного пакета — штатное состояние (retention/пины),
	// поэтому фаза 4 подписывает ВСЕ найденные пакеты, а не только те, что
	// остались в индексе: файл лежит в storage, и подпись к нему нужна.
	before := len(records)
	indexRecords := dedupeRecords(records, p)
	p.Log(fmt.Sprintf("xbps.gen: дедуп по имени: отброшено %d из %d записей", before-len(indexRecords), before))

	// Фаза 3: per-arch repodata.
	groups := groupByArch(indexRecords)
	archs := sortedArchs(groups)
	p.Update("index", repo.Name, 0, int64(len(archs)))
	for i, arch := range archs {
		if err := ctx.Err(); err != nil {
			return err
		}
		indexXML, err := renderIndex(groups[arch])
		if err != nil {
			return fmt.Errorf("xbps.gen: %s: index.plist: %w", arch, err)
		}
		repodata, err := buildRepodata(indexXML, metaXML)
		if err != nil {
			return fmt.Errorf("xbps.gen: %s: repodata: %w", arch, err)
		}
		key := prefix + "/" + strings.ToLower(arch) + repodataSuffix
		if err := writeAtomic(ctx, storage, key, repodata); err != nil {
			return fmt.Errorf("xbps.gen: %s: запись: %w", key, err)
		}
		p.Update("index", repo.Name, int64(i+1), int64(len(archs)))
		p.Log(fmt.Sprintf("xbps.gen: %s записан (%d записей)", key, len(groups[arch])))
	}

	// Фаза 4: подписи на каждый пакет (дайджест уже посчитан при чтении):
	// `.sig2` (PKCS#1 v1.5/SHA-256, формат xbps-rindex) и легаси `.sig`
	// (тот же дайджест в SHA-1-DigestInfo — её просит живой клиент).
	// Два вызова подписчика на пакет: дайджест один, обёртки разные.
	if g.rsa != nil {
		p.Update("sign", repo.Name, 0, int64(len(records)))
		for i, rec := range records {
			if err := ctx.Err(); err != nil {
				return err
			}
			sig2, err := g.rsa.SignSHA256(ctx, rec.digest)
			if err != nil {
				return fmt.Errorf("xbps.gen: %s: подпись: %w", rec.key, err)
			}
			if err := writeAtomic(ctx, storage, rec.key+sig2Suffix, sig2); err != nil {
				return fmt.Errorf("xbps.gen: %s%s: %w", rec.key, sig2Suffix, err)
			}
			sig, err := g.rsa.SignSHA256SHA1DigestInfo(ctx, rec.digest)
			if err != nil {
				return fmt.Errorf("xbps.gen: %s: подпись %s: %w", rec.key, sigSuffix, err)
			}
			if err := writeAtomic(ctx, storage, rec.key+sigSuffix, sig); err != nil {
				return fmt.Errorf("xbps.gen: %s%s: %w", rec.key, sigSuffix, err)
			}
			p.Update("sign", repo.Name, int64(i+1), int64(len(records)))
		}
		p.Log("xbps.gen: пакеты подписаны (.sig2 и .sig)")
	}
	p.Log("xbps.gen: индексы записаны")
	return nil
}

// collectPackages возвращает лексически отсортированный список плоских
// `.xbps` под prefix (вложенные ключи скипаются: лэйаут плоский, а
// uploaded-пути publish и так лоуэркейсит). Ошибка листинга — ошибка
// генерации (иначе пустой обход записал бы ПУСТОЙ индекс поверх
// валидного, fail-closed образца apk).
func collectPackages(ctx context.Context, storage port.Storage, prefix string) ([]string, error) {
	var out []string
	listPrefix := prefix + "/"
	for meta, err := range storage.List(ctx, listPrefix) {
		if err != nil {
			return nil, fmt.Errorf("листинг %s: %w", listPrefix, err)
		}
		rest := strings.TrimPrefix(meta.Key, listPrefix)
		if strings.ContainsRune(rest, '/') {
			continue
		}
		if strings.HasSuffix(rest, pkgSuffix) {
			out = append(out, meta.Key)
		}
	}
	sort.Strings(out)
	return out, nil
}

// readPackage читает props.plist одного .xbps и попутно считает SHA-256
// и размер всего тела: пакет проходит через tee один раз. F: — имя
// файла без каталогов, обязано совпасть с Filename(pkgver, arch) (133);
// upload лоуэркейсит путь, поэтому сверка регистронезависима.
func readPackage(ctx context.Context, storage port.Storage, key string) (pkgRecord, error) {
	obj, err := storage.Get(ctx, key)
	if err != nil {
		return pkgRecord{}, err
	}
	defer obj.Body.Close()
	h := sha256.New()
	counter := &byteCounter{r: obj.Body}
	tee := io.TeeReader(counter, h)
	props, err := OpenPackage(tee)
	if err != nil {
		return pkgRecord{}, err
	}
	// Дочитываем остаток .xbps через tee, чтобы sha256/размер были по
	// всему файлу: OpenPackage остановился после props.plist.
	if _, err := io.Copy(io.Discard, tee); err != nil {
		return pkgRecord{}, fmt.Errorf("дочтение .xbps: %w", err)
	}
	base := key
	if idx := strings.LastIndexByte(base, '/'); idx >= 0 {
		base = base[idx+1:]
	}
	want := Filename(props.PkgVer, props.Architecture)
	if !strings.EqualFold(base, want) {
		return pkgRecord{}, &domain.ValidationError{
			What:   "имя файла пакета",
			Value:  base,
			Reason: fmt.Sprintf("не совпадает с pkgver.arch %q", want),
		}
	}
	return pkgRecord{key: key, props: props, digest: h.Sum(nil), size: counter.n}, nil
}

// dedupeRecords оставляет по одной записи на PkgName: из нескольких версий
// в index.plist попадает новейшая по CompareXbpsVer, прочие отбрасываются —
// но остаются в storage (retention/пины) и подписываются как обычно.
//
// Почему: index.plist — словарь pkgname → поля, и клиент (proplib/libxbps)
// вставляет записи по ключу: вторая запись с тем же именем молча перекрывает
// первую, а какую именно версию он в итоге видит — решает порядок ключей в
// XML, то есть лексический порядок ключей storage, а не порядок версий.
// Живая проба 2026-10-01: репо с `lxc-loc-7.0.9_1` и `lxc-loc-7.0.10_1`
// клиент показал как `7.0.9_1` (`xbps-query -R`), то есть СТАРУЮ версию, и
// транзакция пошла ставить именно её. Эталон upstream (`xbps-rindex`,
// bin/xbps-rindex/index-add.c) сравнивает версии через xbps_cmpver и держит
// в индексе ровно одну запись на имя — повторяем его порядок.
//
// Иммутабельность: входной срез не правится, собирается новый. Порядок
// записей (и, значит, лог) детерминирован: вход отсортирован по ключам
// storage (collectPackages), выбор — функцией сравнения, а не map.
func dedupeRecords(records []pkgRecord, p port.RepoProgress) []pkgRecord {
	out := make([]pkgRecord, 0, len(records))
	byName := make(map[string]int, len(records))
	for _, rec := range records {
		name := rec.props.PkgName
		idx, seen := byName[name]
		if !seen {
			byName[name] = len(out)
			out = append(out, rec)
			continue
		}
		kept := out[idx]
		if CompareXbpsVer(rec.props.PkgVer, kept.props.PkgVer) > 0 {
			out[idx] = rec
			p.Log(fmt.Sprintf("xbps.gen: дедуп: %s: %s → %s", name, kept.props.PkgVer, rec.props.PkgVer))
			continue
		}
		p.Log(fmt.Sprintf("xbps.gen: дедуп: %s: отброшена %s (в индексе %s)", name, rec.props.PkgVer, kept.props.PkgVer))
	}
	return out
}

// groupByArch раскладывает пакеты по нативным архитектурам; noarch
// дублируется в каждую группу (клиент ищет пакет в repodata своей
// архитектуры). Набор нативных архитектур определяется самими
// пакетами: у личного репо нет внешнего списка arch.
func groupByArch(records []pkgRecord) map[string][]IndexOut {
	groups := map[string][]IndexOut{}
	native := map[string]struct{}{}
	for _, r := range records {
		if r.props.Architecture != noarchArch {
			native[r.props.Architecture] = struct{}{}
		}
	}
	for _, r := range records {
		entry := IndexOut{
			Props:          r.props,
			FilenameSHA256: hex.EncodeToString(r.digest),
			FilenameSize:   r.size,
		}
		if r.props.Architecture == noarchArch {
			for arch := range native {
				groups[arch] = append(groups[arch], entry)
			}
			continue
		}
		groups[r.props.Architecture] = append(groups[r.props.Architecture], entry)
	}
	return groups
}

// sortedArchs — детерминированный порядок генерации групп.
func sortedArchs(groups map[string][]IndexOut) []string {
	archs := make([]string, 0, len(groups))
	for arch := range groups {
		archs = append(archs, arch)
	}
	sort.Strings(archs)
	return archs
}

// renderIndex собирает index.plist группы: writer сессии 140 сам
// сортирует записи и опускает пустые поля (детерминизм байт-в-байт).
func renderIndex(entries []IndexOut) ([]byte, error) {
	var buf bytes.Buffer
	if err := WriteIndexPlist(&buf, entries); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// buildMetaPlist собирает index-meta.plist. С подписчиком — публичный
// ключ (base64-PEM data-элемент), его размер и маркеры generator/signature;
// без подписчика — пустой словарь (деградация без ключа, образец apk
// nil-Signer: repodata есть, ключа и подписей нет).
func (g *Generator) buildMetaPlist() ([]byte, error) {
	var buf bytes.Buffer
	if _, err := io.WriteString(&buf, xml.Header+plistDoctype); err != nil {
		return nil, fmt.Errorf("xbps.gen: index-meta: пролог: %w", err)
	}
	enc := xml.NewEncoder(&buf)
	enc.Indent("\t", "")
	if err := enc.EncodeToken(xml.StartElement{
		Name: xml.Name{Local: "plist"},
		Attr: []xml.Attr{{Name: xml.Name{Local: "version"}, Value: "1.0"}},
	}); err != nil {
		return nil, fmt.Errorf("xbps.gen: index-meta: <plist>: %w", err)
	}
	if err := startElem(enc, "dict"); err != nil {
		return nil, fmt.Errorf("xbps.gen: index-meta: <dict>: %w", err)
	}
	if g.rsa != nil {
		pub, err := g.rsa.PublicKeyPEM()
		if err != nil {
			return nil, fmt.Errorf("xbps.gen: index-meta: публичный ключ: %w", err)
		}
		bits, err := publicKeyBits(pub)
		if err != nil {
			return nil, fmt.Errorf("xbps.gen: index-meta: %w", err)
		}
		if err := writeDataField(enc, "public-key", pub); err != nil {
			return nil, fmt.Errorf("xbps.gen: index-meta: public-key: %w", err)
		}
		if err := writeIntField(enc, "public-key-size", int64(bits)); err != nil {
			return nil, fmt.Errorf("xbps.gen: index-meta: public-key-size: %w", err)
		}
		if err := writeStringField(enc, "signature-by", signatureBy); err != nil {
			return nil, fmt.Errorf("xbps.gen: index-meta: signature-by: %w", err)
		}
		if err := writeStringField(enc, "signature-type", signatureType); err != nil {
			return nil, fmt.Errorf("xbps.gen: index-meta: signature-type: %w", err)
		}
	}
	if err := endElem(enc, "dict"); err != nil {
		return nil, fmt.Errorf("xbps.gen: index-meta: </dict>: %w", err)
	}
	if err := endElem(enc, "plist"); err != nil {
		return nil, fmt.Errorf("xbps.gen: index-meta: </plist>: %w", err)
	}
	if err := enc.Flush(); err != nil {
		return nil, fmt.Errorf("xbps.gen: index-meta: сброс буфера: %w", err)
	}
	return buf.Bytes(), nil
}

// writeDataField пишет <key>key</key><data>base64(val)</data>: формат
// public-key index-meta.plist (proplib data-элемент).
func writeDataField(enc *xml.Encoder, key string, val []byte) error {
	if err := writeKey(enc, key); err != nil {
		return err
	}
	if err := startElem(enc, "data"); err != nil {
		return err
	}
	if err := enc.EncodeToken(xml.CharData(base64.StdEncoding.EncodeToString(val))); err != nil {
		return err
	}
	return endElem(enc, "data")
}

// publicKeyBits возвращает длину модуля RSA-ключа из SPKI-PEM. Ошибка —
// битый/чужой ключевой материал: генерация честно падает, а не пишет
// индекс с неполным meta.
func publicKeyBits(pemBytes []byte) (int, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return 0, fmt.Errorf("публичный ключ: не PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return 0, fmt.Errorf("публичный ключ: разбор SPKI: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return 0, fmt.Errorf("публичный ключ: %T, ожидался *rsa.PublicKey", pub)
	}
	return rsaPub.N.BitLen(), nil
}

// buildRepodata собирает контейнер `<arch>-repodata`: zstd(level 9)
// поверх pax-tar из index.plist, index-meta.plist и пустой stage.plist
// (канонический порядок libxbps, парсер 131 строг к первым двум).
func buildRepodata(indexXML, metaXML []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(9)))
	if err != nil {
		return nil, fmt.Errorf("zstd: %w", err)
	}
	tw := tar.NewWriter(zw)
	entries := []struct {
		name string
		data []byte
	}{
		{indexName, indexXML},
		{metaName, metaXML},
		{stageName, nil},
	}
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name: e.name, Typeflag: tar.TypeReg, Mode: 0o644,
			Size: int64(len(e.data)), Format: tar.FormatPAX,
		}); err != nil {
			return nil, fmt.Errorf("tar %s: %w", e.name, err)
		}
		if len(e.data) > 0 {
			if _, err := tw.Write(e.data); err != nil {
				return nil, fmt.Errorf("tar %s: %w", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("tar close: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("zstd close: %w", err)
	}
	return buf.Bytes(), nil
}

// writeAtomic пишет байты в storage через Put+Commit; на ошибке Abort.
// Дубликат из apt/rpmmmd/pacman/apk.gen: mod→mod запрещён depguard'ом.
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

// byteCounter считает прочитанные байты: источник filename-size
// (фактическое тело объекта, не метаданные хранилища).
type byteCounter struct {
	r io.Reader
	n int64
}

func (c *byteCounter) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// noopRepoProgress — заглушка. Дубликат из apt/rpmmmd/pacman/apk.gen.
type noopRepoProgress struct{}

func (noopRepoProgress) Update(string, string, int64, int64) {}
func (noopRepoProgress) Log(string)                          {}
