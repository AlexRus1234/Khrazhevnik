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

// Package rpmmmd — адаптер экосистемы rpm-md (Fedora/RHEL/openSUSE и
// прочие dnf/zypper-репозитории): маппинг путей публичного порта
// /rpm/<remote>/<остальной-путь> на upstream и классификация объектов
// по изменчивости. Один адаптер обслуживает и dnf, и Zypper — формат
// общий (repomd). Кеш RemoteStore с инвалидацией по TTL 30с (KISS):
// новые remotes подхватываются без рестарта. Streaming-парсер
// repomd.xml живёт в parse.go (переиспользуется зеркалом, сессия 11).
//
// Имя экосистемы в реестре и StorageKey — «rpm-md» (дефис — каноническая
// форма, конфиг нормализует rpm_md → rpm-md); префикс публичного пути —
// «/rpm/» (короткий, как пишут в .repo-файлах).
package rpmmmd

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"khrazhevnik/internal/core/config"
	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
	"khrazhevnik/internal/core/registry"
)

// Name — каноническое имя экосистемы (реестр, StorageKey, Remote.Ecosystem).
const Name = "rpm-md"

// URLPrefix — префикс путей публичного порта («/rpm/…»). Короче имени:
// dnf/zypper-пользователи пишут baseurl=http://host/rpm/<remote>, и
// «rpm-md» в URL был бы чужим.
const URLPrefix = "rpm"

// Периоды кеширования/ревалидации. remoteCacheTTL — TTL кеша RemoteStore
// (новые/изменённые remotes подхватываются без рестарта); TTL индексов
// mutable объектов задаётся здесь, а не в конфиге — инвариант экосистемы
// (repomd/primary меняются вместе, подписи обязаны ревалидироваться).
const (
	remoteCacheTTL    = 30 * time.Second
	mutableIndexTTL   = 5 * time.Minute
	mutableUnknownTTL = 1 * time.Minute

	// maxDecompressedRpmMd — лимит на разжатый primary.xml.gz-поток
	// (zip-bomb guard, та же константа-семантика, что apt/pacman/apk —
	// сессии 34/54; злонамеренный upstream крутит CPU/bandwidth, но не
	// процесс).
	maxDecompressedRpmMd = int64(1 << 30) // 1 GiB
)

// remoteReloadTimeout — шапка на DB-вызов reloadLocked под write-lock'ом:
// зависший каталог не держит hot-path дольше шапки. Дубль константы в
// каждом пакете легален — mod→mod импорты запрещены depguard'ом (по
// образцу writeAtomic сессии 40).
const remoteReloadTimeout = 5 * time.Second

func init() {
	registry.RegisterEcosystem(Name, func(_ config.Ecosystem, deps registry.EcosystemDeps) (port.Ecosystem, error) {
		return New(deps.Remotes, deps.Clock)
	})
}

// Adapter реализует port.Ecosystem для rpm-md.
type Adapter struct {
	remotes port.RemoteStore
	clock   port.Clock
	rules   []compiledRule
	sums    *checksumIndex

	mu            sync.RWMutex
	remoteCache   map[string]remoteEntry
	cacheLoaded   time.Time
	reloadTimeout time.Duration
}

// remoteEntry — кеш одной записи RemoteStore по имени: remote и момент
// обновления. err кешируется тоже (БД легла — не долбим её каждым
// запросом, пока TTL не вышел).
type remoteEntry struct {
	remote domain.Remote
	err    error
}

// New создаёт адаптер: remotes — источник upstream-конфигураций, clock —
// время для инвалидации кеша remotes. Правила классификации компилируются
// один раз.
func New(remotes port.RemoteStore, clock port.Clock) (*Adapter, error) {
	if remotes == nil {
		return nil, fmt.Errorf("rpm-md: RemoteStore обязателен")
	}
	if clock == nil {
		return nil, fmt.Errorf("rpm-md: Clock обязателен")
	}
	return &Adapter{
		remotes:       remotes,
		clock:         clock,
		rules:         compileRules(),
		sums:          newChecksumIndex(),
		remoteCache:   map[string]remoteEntry{},
		reloadTimeout: remoteReloadTimeout,
	}, nil
}

// Name возвращает имя экосистемы.
func (a *Adapter) Name() string { return Name }

// URLPrefix возвращает префикс путей публичного порта («rpm»). Короче
// имени: dnf/zygger-пользователи пишут baseurl=http://host/rpm/<remote>,
// и «rpm-md» в URL был бы чужим. Роутер ищет экосистему по префиксу.
func (a *Adapter) URLPrefix() string { return URLPrefix }

// Resolve переводит /rpm/<remote-name>/<остальной-путь> в Target.
// false — путь не принадлежит rpm-md или remote неизвестен/выключен.
// Кеш remotes обновляется по TTL 30с: перезапуск не нужен для вновь
// добавленных upstream'ов. UpstreamURL/UpstreamPath сохраняют оригинальный
// регистр (byte-exact к upstream); StorageKey лоуэркейсит путь
// сознательно: домен допускает регистр с сессии 19 (case-чувствительность
// закрыта отдельно в apt), но repodata-пути lowercase по конвенции
// формата, case-риск upstream признан низким. Checksum заполняется чексуммой из
// repomd.xml (если Enumerate уже разбирал его): движок кеша сверяет
// скачанные repodata с корневым индексом; без sync — честная деградация
// к Content-Length.
func (a *Adapter) Resolve(ecosystemPath string) (port.Target, bool) {
	prefix := "/" + URLPrefix + "/"
	if !strings.HasPrefix(ecosystemPath, prefix) {
		return port.Target{}, false
	}
	name, upstreamPath, ok := splitRemotePath(strings.TrimPrefix(ecosystemPath, prefix))
	if !ok {
		return port.Target{}, false
	}
	remote, err := a.lookupRemote(name)
	if err != nil {
		return port.Target{}, false
	}
	if !remote.Enabled {
		return port.Target{}, false
	}
	base := strings.TrimRight(remote.BaseURL, "/")
	target := port.Target{
		UpstreamURL:  base + upstreamPath,
		UpstreamPath: upstreamPath,
		StorageKey:   "cache/" + Name + "/" + strconv.FormatInt(remote.ID, 10) + strings.ToLower(upstreamPath),
	}
	if sum, ok := a.sums.lookup(remote.ID, upstreamPath); ok {
		target.Checksum = sum
	}
	return target, true
}

// Classify делит объекты rpm-md по изменчивости. Пакеты (.rpm/.drpm/.src.rpm)
// и repodata-файлы с хешем в имени — immutable (content-addressed);
// repomd.xml и его подписи, repodata без хеша — mutable{TTL 5m}; всё
// прочее (media.1/products и т.п.) — conservative mutable{TTL 1m}
// (безопасный дефолт: короткий TTL ограничивает отдачу протухших данных).
// Пустой путь — ошибка валидации (не передаётся в движок).
func (a *Adapter) Classify(upstreamPath string) (domain.Class, error) {
	if upstreamPath == "" {
		return domain.Class{}, &domain.ValidationError{What: "путь upstream", Value: upstreamPath, Reason: "пустой"}
	}
	path := strings.TrimPrefix(upstreamPath, "/")
	for _, r := range a.rules {
		if r.re.MatchString(path) {
			return r.class, nil
		}
	}
	return domain.Mutable(mutableUnknownTTL), nil
}

// Enumerate обходит repomd.xml → primary.xml[.gz] и собирает upstream-пути
// пакетов (location-href каждого <package>). Remote.Include для rpm-md не
// используется: репо — единое целое по repomd. Метаданные качаются через
// meta (движок кеша — singleflight/TTL/метрики). primary.xml может быть
// сжат (gzip) — расширение .gz автоматически распаковывается.
//
// Побочный эффект — наполнение таблицы чексумм remote из repomd.xml
// (checksum каждого <data>): после успешного Enumerate прокси-ветка
// сверяет скачанные repodata с корневым индексом. Чексуммы пакетов из
// primary.xml не собираются: парсер primary извлекает только location
// (v1 — чексуммы пакетов rpm-md не верифицируются, задокументировано).
func (a *Adapter) Enumerate(ctx context.Context, remote domain.Remote, meta port.MetaFetcher) ([]string, error) {
	if meta == nil {
		return nil, fmt.Errorf("rpm-md: Enumerate: MetaFetcher обязателен")
	}
	sums, href, err := a.parseRepomd(ctx, meta, remote.Name)
	if err != nil {
		return nil, err
	}
	// repomd разобран целиком — его знания о repodata валидны, даже
	// если primary дальше не качнулся.
	a.sums.replace(remote.ID, sums)
	// Честная ошибка для сжатий вне whitelist — до fetch'а: sync
	// падает с причиной «формат не поддерживается», а не с общим
	// «parse primary» на бинарном потоке.
	if err := unsupportedPrimaryErr(href); err != nil {
		return nil, err
	}
	body, err := meta.Fetch(ctx, "/"+URLPrefix+"/"+remote.Name+"/"+href)
	if err != nil {
		return nil, fmt.Errorf("rpm-md: primary %s: %w", href, err)
	}
	defer body.Close()
	r, err := unwrapGzIfNeeded(body, href)
	if err != nil {
		return nil, err
	}
	defer func() {
		if c, ok := r.(io.Closer); ok {
			_ = c.Close()
		}
	}()
	var paths []string
	for pkgHref, perr := range ParsePrimary(r) {
		if perr != nil {
			return nil, fmt.Errorf("rpm-md: parse primary: %w", perr)
		}
		if pkgHref == "" {
			continue
		}
		paths = append(paths, "/"+pkgHref)
	}
	return paths, nil
}

// parseRepomd fetch'ит repomd.xml и возвращает чексуммы repodata-файлов
// (checksum каждого <data> по его location — алгоритм из атрибута type)
// и location-href элемента <data type="primary">. primary — обязательный
// элемент rpm-md; его отсутствие — ошибка перечисления.
func (a *Adapter) parseRepomd(ctx context.Context, meta port.MetaFetcher, remoteName string) (map[string]port.Checksum, string, error) {
	body, err := meta.Fetch(ctx, "/"+URLPrefix+"/"+remoteName+"/repodata/repomd.xml")
	if err != nil {
		return nil, "", fmt.Errorf("rpm-md: repomd.xml: %w", err)
	}
	defer body.Close()
	sums := map[string]port.Checksum{}
	primary := ""
	for el, ferr := range ParseRepomd(body) {
		if ferr != nil {
			return nil, "", fmt.Errorf("rpm-md: parse repomd: %w", ferr)
		}
		if el.LocationHref == "" {
			continue
		}
		if sum, ok := hexChecksum(el.ChecksumType, el.Checksum); ok {
			sums["/"+el.LocationHref] = sum
		}
		if el.Type == "primary" && primary == "" {
			primary = el.LocationHref
		}
	}
	if primary == "" {
		return nil, "", fmt.Errorf("rpm-md: repomd без <data type=\"primary\">")
	}
	return sums, primary, nil
}

// unsupportedPrimaryErr — честная ошибка для сжатий primary.xml,
// которые Хражевник не распаковывает: .zck (zchunk, Fedora), .zst,
// .xz, .bz2. Поддержаны несжатый и .gz (unwrapGzIfNeeded). nil —
// формат нам известен или неизвестен парсеру (пусть скажет своё).
func unsupportedPrimaryErr(href string) error {
	unsupported := map[string]string{
		".zck": "zchunk — декодера нет в whitelist зависимостей",
		".zst": "zstd — декомпрессия primary не поддерживается",
		".xz":  "xz — декодера нет в whitelist зависимостей",
		".bz2": "bzip2 — декомпрессия primary не поддерживается",
	}
	for suffix, reason := range unsupported {
		if strings.HasSuffix(href, suffix) {
			return &domain.UnsupportedError{
				What: "enumerate",
				Why:  fmt.Sprintf("rpm-md: primary %s в неподдерживаемом формате (%s), возьмите .gz-вариант", href, reason),
			}
		}
	}
	return nil
}

// unwrapGzIfNeeded оборачивает body в gzip.Reader, если имя файла
// заканчивается на .gz; иначе отдаёт как есть. Имя берётся из href,
// потому что Content-Type у репозиториев часто absent или «text/plain».
// Поток ограничен maxDecompressedRpmMd (паттерн apt/pacman/apk):
// gzip-бомба вместо primary.xml.gz валит sync одного remote с
// ErrDecompressTooLarge, а не крутит декомпрессию вечно.
func unwrapGzIfNeeded(body io.Reader, href string) (io.Reader, error) {
	if !strings.HasSuffix(href, ".gz") {
		return body, nil
	}
	gz, err := gzip.NewReader(body)
	if err != nil {
		return nil, fmt.Errorf("rpm-md: unpack primary.xml.gz: %w", err)
	}
	return &limitedReader{r: gz, limit: maxDecompressedRpmMd}, nil
}

// ErrDecompressTooLarge — разжатый primary.xml.gz превысил лимит
// (zip-bomb guard). Сравнение через errors.Is.
var ErrDecompressTooLarge = errors.New("rpm-md: декомпрессия превысила лимит")

// limitedReader — обёртка, считающая байты и возвращающая
// ErrDecompressTooLarge при превышении лимита (паттерн apt/pacman/apk):
// лимит проверяется в процессе чтения, а не после полного буфера.
type limitedReader struct {
	r     io.Reader
	n     int64
	limit int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n >= l.limit {
		return 0, ErrDecompressTooLarge
	}
	n, err := l.r.Read(p)
	l.n += int64(n)
	if l.n > l.limit {
		return n, ErrDecompressTooLarge
	}
	return n, err
}

// lookupRemote возвращает Remote по имени из кеша; при истечении TTL
// перечитывает весь список remotes (KISS: remotes обычно единицы).
// Reload выполняется под write-lock'ом — простота двойной проверки без
// свапа снапшота; ограничение — таймаут DB-вызова (5s): зависшая БД
// задерживает hot-path лишь на шапку, а не навсегда. Вынос reload
// наружу со свапом — пост-v1: требует ревизии консистентности кеша
// между RLock/Lock-фазами.
func (a *Adapter) lookupRemote(name string) (domain.Remote, error) {
	now := a.clock.Now()
	a.mu.RLock()
	if now.Sub(a.cacheLoaded) < remoteCacheTTL {
		if e, ok := a.remoteCache[name]; ok {
			a.mu.RUnlock()
			return e.remote, e.err
		}
	}
	a.mu.RUnlock()

	a.mu.Lock()
	defer a.mu.Unlock()
	if now.Sub(a.cacheLoaded) >= remoteCacheTTL {
		// TTL истёк — перечитываем remotes. Двойная проверка после
		// захвата write-lock: конкурент мог уже обновить кеш. Шапка на
		// DB-вызов (см. выше); ошибка по таймауту не отличима от прочих
		// — «старый кеш лучше пустого» ниже обрабатывает её так же.
		ctx, cancel := context.WithTimeout(context.Background(), a.reloadTimeout)
		defer cancel()
		if err := a.reloadLocked(ctx); err != nil {
			// старый кеш лучше пустого: отдаём то, что есть
			if e, ok := a.remoteCache[name]; ok {
				return e.remote, e.err
			}
			return domain.Remote{}, err
		}
	}
	if e, ok := a.remoteCache[name]; ok {
		return e.remote, e.err
	}
	return domain.Remote{}, &domain.NotFoundError{What: "remote", Key: name}
}

// reloadLocked перечитывает Remotes из хранилища. mu уже захвачена на запись.
func (a *Adapter) reloadLocked(ctx context.Context) error {
	remotes, err := a.remotes.Remotes(ctx)
	a.cacheLoaded = a.clock.Now()
	if err != nil {
		return err
	}
	cache := make(map[string]remoteEntry, len(remotes))
	for _, r := range remotes {
		cache[r.Name] = remoteEntry{remote: r}
	}
	a.remoteCache = cache
	return nil
}

// splitRemotePath делит «<name>/<остальной-путь>» на имя remote и
// upstream-путь (с ведущим «/»). ok=false для traversal-попыток и
// пустого имени. Дубликат из apt — mod→mod запрещён depguard'ом,
// держать адаптеры самодостаточными.
func splitRemotePath(rest string) (name, upstreamPath string, ok bool) {
	idx := strings.IndexByte(rest, '/')
	switch {
	case idx < 0:
		name, upstreamPath = rest, "/"
	default:
		name, upstreamPath = rest[:idx], rest[idx:]
	}
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "\\/\x00") {
		return "", "", false
	}
	return name, upstreamPath, true
}

// compiledRule — скомпилированное правило классификации: регекс из
// glob/regex + класс.
type compiledRule struct {
	re    *regexp.Regexp
	class domain.Class
	name  string
}

// rawRule — данные правила до компиляции. glob непуст — паттерн
// переводится через globToRegex; regex непуст — используется как
// сырой регекс (для правил, неудобных как glob: хеш в имени).
type rawRule struct {
	glob  string
	regex string
	class domain.Class
}

// classifyRules — таблица классификации rpm-md как данные. Порядок —
// от специфичного к общему; первый матч выигрывает.
func classifyRules() []rawRule {
	immutable := domain.Immutable()
	mutable := domain.Mutable(mutableIndexTTL)
	return []rawRule{
		// Immutable: RPM пакеты (бинарные, delta, source) —
		// content-addressed по NEVRA в имени файла.
		{"**/*.rpm", "", immutable},
		{"**/*.drpm", "", immutable},
		// *.src.rpm матчится **/*.rpm, но оставим явное правило для
		// документирования и теста (порядок — выше repodata).
		{"**/*.src.rpm", "", immutable},
		// repomd.xml — корневой индекс репозитория (меняется при каждом
		// publish'е). Подписи (asc/key) — mutable тоже: отдаются
		// byte-exact, но ревалидируются вместе с индексом.
		{"**/repodata/repomd.xml", "", mutable},
		{"**/repodata/repomd.xml.asc", "", mutable},
		{"**/repodata/repomd.xml.key", "", mutable},
		// repodata с хешом-чексуммой в имени файла — content-addressed
		// (createrepo_c с zchunk/hash): <sha>-primary.xml.gz и т.п.
		// Хеш — 8+ hex-цифр в basename; безопасный порог: 8 подряд
		// hex-знаков в обычных именах не встречаются. Префикс каталогов
		// опционален — на случай вложенного repodata/ (редко, но
		// консистентно с glob-правилами **/repodata/…).
		{"", `^(?:.*/)?repodata/[^/]*[0-9a-f]{8,}[^/]*$`, immutable},
		// Прочие repodata-файлы без хеша (primary.xml.gz, filelists.xml.*,
		// other.xml.*, *-UPDATE_INFO.xml, *.sqlite.bz2, *zck) — mutable:
		// индексы перегенерируются при каждом обновлении репо.
		{"**/repodata/*", "", mutable},
	}
}

// compileRules компилирует правила один раз в New.
func compileRules() []compiledRule {
	raw := classifyRules()
	out := make([]compiledRule, len(raw))
	for i, r := range raw {
		var re *regexp.Regexp
		switch {
		case r.regex != "":
			re = regexp.MustCompile(r.regex)
			out[i] = compiledRule{re: re, class: r.class, name: r.regex}
		default:
			re = globToRegex(r.glob)
			out[i] = compiledRule{re: re, class: r.class, name: r.glob}
		}
	}
	return out
}

// globToRegex переводит glob в регекс: **/ → опциональный префикс
// каталогов, * → сегмент без /, ? → один байт без /. Literals эскейпятся.
// Дубликат из apt: mod→mod запрещён, адаптеры самодостаточны.
func globToRegex(glob string) *regexp.Regexp {
	var b strings.Builder
	b.WriteByte('^')
	for i := 0; i < len(glob); {
		c := glob[i]
		switch {
		case c == '*' && i+1 < len(glob) && glob[i+1] == '*':
			if i+2 < len(glob) && glob[i+2] == '/' {
				// "**/" — любой префикс каталогов (включая пустой)
				b.WriteString(`(?:.*/)?`)
				i += 3
			} else {
				b.WriteString(".*")
				i += 2
			}
		case c == '*':
			b.WriteString(`[^/]*`)
			i++
		case c == '?':
			b.WriteString(`[^/]`)
			i++
		default:
			if strings.IndexByte(`\.+*?()|[]{}^$`, c) >= 0 {
				b.WriteByte('\\')
			}
			b.WriteByte(c)
			i++
		}
	}
	b.WriteByte('$')
	return regexp.MustCompile(b.String())
}
