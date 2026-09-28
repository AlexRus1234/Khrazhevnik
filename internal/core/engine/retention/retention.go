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

// Package retention — авто-очистка старых версий пакетов в личных
// репозиториях (волна «Ретеншн-политики»). Отдельный компонент рядом с
// publish/storagegc: движок publish не расширяется — его зона это
// HTTP-транзакция upload, а чистка идёт по расписанию/команде админа.
// Горютин жизненного цикла у движка нет (прецедент storagegc): воркеры и
// админ-задачи зовут Apply синхронно, reindex после удаления — забота
// вызывающего (движок отдаёт счётчики, а не генерирует индексы).
//
// Консервативность важнее полноты: ложное срабатывание удаляет живой
// объект, а неполнота закрывается следующим проходом. Удаляется только
// то, что НЕ защищено ни одной из трёх независимых защит (решение
// владельца 2026-09-25):
//
//	(а) топ-N семейства по ModTime (дате загрузки) — «свежие»;
//	(б) обращение к версии новее now−MaxAgeDays;
//	(в) пин (repo_pins).
//
// Семейства резолвит адаптер экосистемы (port.FamilyResolver) — движок не
// знает форматов имён; упорядочивание версий — по ModTime, НЕ по разбору
// версий: версированным апстримам важна «свежесть загрузки», а не
// семантика номера.
package retention

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
)

// deleteConcurrency — потолок одновременных удалений (образец delSem
// кеша и storagegc): проход не должен выметать носитель всплеском.
const deleteConcurrency = 4

// Result — итоги одного прохода. Счётчики защит диагностические: версия
// попадает ровно в один из них (первая сработавшая защита), а жива она
// при любой из трёх — защиты складываются по ИЛИ. Duration — время
// прохода (для гистограммы метрик, сессия 171), измеряется часами
// движка — образец storagegc.Result.
type Result struct {
	DryRun            bool
	Duration          time.Duration
	Families          int64
	ObjectsScanned    int64
	Candidates        int64
	Deleted           int64
	FailedDeletes     int64
	BytesFreed        int64
	ProtectedByMin    int64
	ProtectedByAccess int64
	ProtectedByPin    int64
}

// version — объект семейства в рамках прохода: ключ, размер и дата
// загрузки (ModTime носителя).
type version struct {
	key     string
	size    int64
	modTime time.Time
}

// Engine — один проход по объектам репозитория. Новый проход — вызов
// Apply; состояние прохода локально, между вызовами не переносится.
type Engine struct {
	storage  port.Storage
	repos    port.RepoStore
	access   port.AccessStore
	adapters map[string]port.RepoAdapter
	pins     port.PinStore
	clock    port.Clock
	sem      chan struct{}

	// OnApply — хук после каждого прохода (nil-safe), наполнение —
	// в сессии 171 (метрики); ошибка прохода передаётся как есть.
	OnApply func(res Result, err error)
}

// New собирает движок ретеншна. adapters — карта адаптеров экосистем из
// wire (как у движка publish): семейства резолвит адаптер репозитория,
// отсутствие резолвера — честная ошибка прохода, а не молчаливый no-op.
// repos — каталог личных репо (нужен вызывающим сторонам прохода: движок
// держит его тем же набором, что publish/storagegc, без собственного
// доступа к БД).
func New(storage port.Storage, repos port.RepoStore, access port.AccessStore, adapters map[string]port.RepoAdapter, pins port.PinStore, clock port.Clock) *Engine {
	return &Engine{
		storage:  storage,
		repos:    repos,
		access:   access,
		adapters: adapters,
		pins:     pins,
		clock:    clock,
		sem:      make(chan struct{}, deleteConcurrency),
	}
}

// Apply — один проход по объектам репозитория. dryRun считает кандидатов,
// ничего не удаляя (ревизия перед чисткой). Политика выключена —
// no-op без ошибки (текущее поведение: репо растёт в пределах квоты).
// Возвращаемая ошибка — сбой прохода (листинг, каталог, отмена), а не
// «нечего удалять»; частично выполненные удаления остаются выполненными.
func (e *Engine) Apply(ctx context.Context, repo domain.Repo, dryRun bool) (Result, error) {
	res := Result{DryRun: dryRun}
	start := e.clock.Now()
	err := e.apply(ctx, &res, repo, dryRun)
	res.Duration = e.clock.Now().Sub(start)
	if e.OnApply != nil {
		e.OnApply(res, err)
	}
	return res, err
}

// ApplyAndReindex — проход Apply и, если что-то удалено, перегенерация
// индексов тем же адаптером экосистемы (единственная точка генерации —
// port.RepoAdapter.GenerateIndexes; прецедент publish.Engine.Reindex).
// Порядок «сначала удаления, затем индексы» — из планирования волны:
// индекс, собранный по ещё живым жертвам, ссылался бы на объекты,
// исчезающие через мгновение. Окно рассогласования («индекс ссылается
// на удалённое») живёт до конца reindex — цена KISS, принята при
// планировании. Dry-run индексы не трогает по построению: удалений в
// нём нет (Deleted == 0 — единственный триггер reindex). Сбой reindex
// удаления не откатывает (они уже сделаны): ошибка возвращается вместе
// с их счётчиками — вызывающий решает, эскалировать ли.
func (e *Engine) ApplyAndReindex(ctx context.Context, repo domain.Repo, dryRun bool) (Result, error) {
	res, err := e.Apply(ctx, repo, dryRun)
	if err != nil {
		return res, err
	}
	if res.Deleted == 0 {
		return res, nil
	}
	if err := e.reindex(ctx, repo); err != nil {
		return res, err
	}
	return res, nil
}

// reindex — генерация индексов репо. Прогресс — noop: проход фоновый
// (задачи TaskRegistry у него нет, репортёра тоже). Адаптер после
// успешного Apply заведомо есть (его требовал резолвер семейств), но
// ошибка лукапа не глушится: «перегенерировать нечем» должно быть
// видно вызывающему.
func (e *Engine) reindex(ctx context.Context, repo domain.Repo) error {
	adapter, err := e.adapterFor(repo)
	if err != nil {
		return err
	}
	return adapter.GenerateIndexes(ctx, repo, e.storage, noopProgress{})
}

// noopProgress — заглушка прогресса фонового reindex (прецедент
// publish.noopProgress).
type noopProgress struct{}

func (noopProgress) Update(string, string, int64, int64) {}
func (noopProgress) Log(string)                          {}

// apply — тело прохода: резолвер → листинг с группировкой по семействам →
// разбор каждого семейства защитами.
func (e *Engine) apply(ctx context.Context, res *Result, repo domain.Repo, dryRun bool) error {
	if !repo.Retention.Enabled() {
		return nil
	}
	resolver, err := e.familyResolver(repo)
	if err != nil {
		return err
	}
	pinned, err := e.pins.Pins(ctx, repo.ID)
	if err != nil {
		return fmt.Errorf("retention: пины репозитория %d: %w", repo.ID, err)
	}
	pinSet := make(map[string]struct{}, len(pinned))
	for _, k := range pinned {
		pinSet[k] = struct{}{}
	}
	prefix := port.RepoPrefix(repo) + "/"
	families := make(map[string][]version)
	var order []string
	for meta, lerr := range e.storage.List(ctx, prefix) {
		if lerr != nil {
			return fmt.Errorf("retention: листинг %s: %w", prefix, lerr)
		}
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		res.ObjectsScanned++
		// Резолвер получает путь ВНУТРИ репо (тот же, что у
		// ValidateObjectPath); ok=false — индексы, подписи, служебные
		// файлы: ретеншн их не трогает (живут генерацией/подписью).
		family, ok := resolver.ObjectFamily(strings.TrimPrefix(meta.Key, prefix))
		if !ok {
			continue
		}
		if _, seen := families[family]; !seen {
			order = append(order, family)
		}
		families[family] = append(families[family], version{key: meta.Key, size: meta.Size, modTime: meta.ModTime})
	}
	now := e.clock.Now()
	for _, family := range order {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		res.Families++
		if err := e.sweepFamily(ctx, res, repo, families[family], pinSet, now, dryRun); err != nil {
			return err
		}
	}
	return nil
}

// adapterFor — адаптер экосистемы репо. Отсутствующий адаптер — честный
// UnsupportedError, а не «объектов нет»: движок не знает, что чистить
// (ни семейств, ни генератора индексов), и молчаливый no-op скрыл бы,
// что политика не работает вовсе.
func (e *Engine) adapterFor(repo domain.Repo) (port.RepoAdapter, error) {
	adapter, ok := e.adapters[repo.Ecosystem]
	if !ok || adapter == nil {
		return nil, &domain.UnsupportedError{
			What: "retention",
			Why:  "нет адаптера экосистемы " + repo.Ecosystem,
		}
	}
	return adapter, nil
}

// familyResolver достаёт резолвер семейств у адаптера экосистемы.
// Отсутствие резолвера — тот же UnsupportedError: у nix семейств нет
// (content-addressed — старых версий одного пути не бывает).
func (e *Engine) familyResolver(repo domain.Repo) (port.FamilyResolver, error) {
	adapter, err := e.adapterFor(repo)
	if err != nil {
		return nil, err
	}
	resolver, ok := adapter.(port.FamilyResolver)
	if !ok {
		return nil, &domain.UnsupportedError{
			What: "retention",
			Why:  "экосистема " + repo.Ecosystem + " не резолвит семейства (nix — content-addressed)",
		}
	}
	return resolver, nil
}

// sweepFamily разбирает одно семейство: топ-N защищён, остальных решают
// обращения и пины. Возвращает ошибку только если состояние обращений
// прочесть нельзя: гадать о давности и удалять «наугад» запрещено —
// fail-closed, как у листинга.
func (e *Engine) sweepFamily(ctx context.Context, res *Result, repo domain.Repo, versions []version, pins map[string]struct{}, now time.Time, dryRun bool) error {
	// Свежие — последние по ModTime; тай-брейк по ключу делает топ-N
	// детерминированным при совпадении времени (пакетный upload).
	slices.SortFunc(versions, func(a, b version) int {
		if c := b.modTime.Compare(a.modTime); c != 0 {
			return c
		}
		return strings.Compare(a.key, b.key)
	})
	top := repo.Retention.MinVersions
	if top > len(versions) {
		top = len(versions)
	}
	// Максимум возраста: MaxAgeDays == 0 — ограничения нет (только keep-N),
	// отрицательный отсекает валидация политики.
	cutoff := time.Time{}
	if repo.Retention.MaxAgeDays > 0 {
		cutoff = now.Add(-time.Duration(repo.Retention.MaxAgeDays) * 24 * time.Hour)
	}
	for i, v := range versions {
		if i < top {
			res.ProtectedByMin++
			continue
		}
		lastAccess := v.modTime // бутстрап: нет строки обращений — дата загрузки
		var nf *domain.NotFoundError
		entry, err := e.access.AccessEntry(ctx, domain.AccessScopeRepo, v.key)
		switch {
		case err == nil:
			lastAccess = entry.LastAccess
		case errors.As(err, &nf):
			// Обращений не было — считаем от даты загрузки.
		default:
			return fmt.Errorf("retention: обращение к %s: %w", v.key, err)
		}
		if !cutoff.IsZero() && !lastAccess.Before(cutoff) {
			res.ProtectedByAccess++
			continue
		}
		if _, ok := pins[v.key]; ok {
			res.ProtectedByPin++
			continue
		}
		res.Candidates++
		if dryRun {
			continue
		}
		e.deleteKey(ctx, v.key, v.size, res)
	}
	return nil
}

// deleteKey удаляет одну версию. NotFound — «уже нет» (гонка с другим
// удалением или с самим собой после сбоя), не сбой; прочие ошибки копятся
// в FailedDeletes, проход продолжается (следующий запуск доберёт).
// Семафор живёт на движке: параллельные проходы делят потолок удалений.
func (e *Engine) deleteKey(ctx context.Context, key string, size int64, res *Result) {
	e.sem <- struct{}{}
	defer func() { <-e.sem }()
	if err := e.storage.Delete(ctx, key); err != nil {
		var nf *domain.NotFoundError
		if errors.As(err, &nf) {
			return
		}
		res.FailedDeletes++
		return
	}
	res.Deleted++
	res.BytesFreed += size
}
