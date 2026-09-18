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

// Enumerate зеркала xbps: по include-архитектурам (у Void нет корневого
// индекса архов, перечислить «вообще все» нельзя — пустой Include
// ValidationError) разбирает `<arch>-repodata` и собирает пути пакетов
// `<pkgver>.<arch>.xbps` + их подписей `.sig2`. Имя файла в индексе
// отсутствует — путь достраивается Filename() (libxbps строит имя так
// же). noarch-пакеты входят в каждый arch-индекс, поэтому пути
// дедуплицируются seen-картой. `<arch>-repodata` в список НЕ входит:
// это mutable-объект, его кеширует движок через MetaFetcher (образец
// apk: APKINDEX не в Enumerate).
//
// Побочный эффект — наполнение таблицы чексумм remote из поля
// filename-sha256: после успешного sync прокси-ветка (Resolve) сверяет
// скачанные .xbps с индексом; `.sig2` и кривой/отсутствующий sha256 —
// честная деградация к Content-Length, не ошибка.

package xbps

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
)

// checksumIndex — потокобезопасная таблица «remote-id → upstream-путь →
// чексумма». Запись — полная замена по remote: Enumerate перечитывает
// индексы целиком, прежние знания устаревать не должны. Дубль
// apk/checksum.go — mod→mod импорты запрещены depguard'ом, адаптеры
// самодостаточны.
type checksumIndex struct {
	mu   sync.RWMutex
	byID map[int64]map[string]port.Checksum
}

// newChecksumIndex создаёт пустую таблицу.
func newChecksumIndex() *checksumIndex {
	return &checksumIndex{byID: map[int64]map[string]port.Checksum{}}
}

// replace целиком заменяет знания о remote id.
func (c *checksumIndex) replace(id int64, sums map[string]port.Checksum) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.byID[id] = sums
}

// lookup возвращает чексумму upstream-пути (с ведущим «/») remote.
func (c *checksumIndex) lookup(id int64, upstreamPath string) (port.Checksum, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	sums, ok := c.byID[id]
	if !ok {
		return port.Checksum{}, false
	}
	sum, ok := sums[upstreamPath]
	return sum, ok
}

// Enumerate обходит `<arch>-repodata` каждой include-архитектуры и
// собирает upstream-пути пакетов и их подписей `.sig2`. Remote.Include
// для xbps — список архитектур (например, «x86_64», «aarch64»);
// индекс лежит по пути «<arch>-repodata» в корне репозитория. Пустой
// Include — ошибка: xbps не имеет корневого индекса архитектур.
// Метаданные качаются через meta (движок кеша — singleflight/TTL/метрики).
func (a *Adapter) Enumerate(ctx context.Context, remote domain.Remote, meta port.MetaFetcher) ([]string, error) {
	if meta == nil {
		return nil, fmt.Errorf("xbps: Enumerate: MetaFetcher обязателен")
	}
	archs, err := parseXbpsInclude(remote.Include)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	sums := make(map[string]port.Checksum)
	var paths []string
	for _, arch := range archs {
		got, err := a.enumerateArch(ctx, meta, remote.Name, arch, seen, sums)
		if err != nil {
			return nil, fmt.Errorf("xbps: enumerate %s: %w", arch, err)
		}
		for _, p := range got {
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			paths = append(paths, p)
		}
	}
	// Только после полного прохода: частичный sync не должен оставлять
	// таблицу, «знающую» меньше, чем прежняя.
	a.sums.replace(remote.ID, sums)
	return paths, nil
}

// parseXbpsInclude разбирает Remote.Include на список архитектур. Формат
// элемента — просто имя архитектуры («x86_64», «aarch64»). Пустой
// Include — ошибка: xbps требует явного перечисления архитектур.
func parseXbpsInclude(include []string) ([]string, error) {
	if len(include) == 0 {
		return nil, &domain.ValidationError{
			What: "include", Value: "", Reason: "xbps sync: укажите архитектуры (например [\"x86_64\"])",
		}
	}
	var out []string
	for _, item := range include {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.ContainsAny(item, " \x00/") {
			return nil, &domain.ValidationError{What: "include", Value: item, Reason: "архитектура содержит недопустимые символы"}
		}
		out = append(out, item)
	}
	if len(out) == 0 {
		return nil, &domain.ValidationError{What: "include", Value: "", Reason: "нет валидных архитектур"}
	}
	return out, nil
}

// enumerateArch fetch'ит `<arch>-repodata`, разбирает index.plist и
// возвращает пути пакетов и их `.sig2` (вторым проходом). Записи без
// pkgver/architecture скипаются: имя файла без них не построить.
// Чексумма из filename-sha256 кладётся в sums (SHA256-валидация —
// невалидная строка остаётся без чексуммы).
func (a *Adapter) enumerateArch(ctx context.Context, meta port.MetaFetcher, remoteName, arch string, seen map[string]struct{}, sums map[string]port.Checksum) ([]string, error) {
	indexEcoPath := "/" + Name + "/" + remoteName + "/" + arch + "-repodata"
	body, err := meta.Fetch(ctx, indexEcoPath)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	index, closeFn, err := OpenRepoData(body)
	if err != nil {
		return nil, err
	}
	var pkgs []string
	parseErr := ParseIndexPlist(index, func(entry IndexEntry) error {
		if entry.PkgVer == "" || entry.Architecture == "" {
			return nil
		}
		p := "/" + Filename(entry.PkgVer, entry.Architecture)
		if _, ok := seen[p]; !ok {
			if sum, ok := sha256Checksum(entry.FilenameSHA256); ok {
				sums[p] = sum
			}
		}
		pkgs = append(pkgs, p)
		return nil
	})
	// closeFn обязателен к вызову и при ошибке парсинга: владеет zstd-
	// декодером (горутины). meta-байты не нужны — Enumerate работает с
	// index.plist.
	if _, cerr := closeFn(); cerr != nil && parseErr == nil {
		return nil, fmt.Errorf("xbps: repodata %s: %w", arch, cerr)
	}
	if parseErr != nil {
		return nil, fmt.Errorf("xbps: parse %s-repodata: %w", arch, parseErr)
	}
	// Второй проход: подпись `.sig2` рядом с каждым пакетом. Дедуп —
	// на уровне Enumerate.
	out := make([]string, 0, len(pkgs)*2)
	out = append(out, pkgs...)
	for _, p := range pkgs {
		out = append(out, p+".sig2")
	}
	return out, nil
}

// sha256Checksum валидирует поле filename-sha256 (64 hex-символа) и
// переводит его в Checksum. Невалидная строка/длина — «чексуммы нет»:
// деградация к Content-Length лучше ложного mismatch. Регистр
// нормализуется к lowercase (сверка и так регистронезависима).
func sha256Checksum(val string) (port.Checksum, bool) {
	if len(val) != 64 {
		return port.Checksum{}, false
	}
	for i := 0; i < len(val); i++ {
		c := val[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			continue
		}
		return port.Checksum{}, false
	}
	return port.Checksum{Algo: "sha256", Hex: strings.ToLower(val)}, true
}
