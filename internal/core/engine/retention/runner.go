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

package retention

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"khrazhevnik/internal/core/port"
)

// Runner — периодический проход ретеншна по всем репозиториям с
// включённой политикой. Отдельный тип, а не метод Engine: у Apply нет
// ни горутин, ни состояния между вызовами (зови его синхронно —
// прецедент Sweeper), жизненный цикл есть только у периодического
// цикла. Ручной запуск одного репо (API сессии 173) зовёт
// Engine.ApplyAndReindex напрямую и Runner'а не касается.
//
// Зачем периодический проход вообще: TTL-защита (MaxAgeDays) стареет
// сама по себе — версия, живая при последней загрузке, через месяц
// мертва, и без прохода её никто не удалит: post-upload-триггер при
// планировании волны отклонён (upload→reindex и так фоновая задача —
// вкладывать вторую в её хвост значит удвоить очередь и риск 409).
type Runner struct {
	engine   *Engine
	repos    port.RepoStore
	interval time.Duration

	// OnError — сбой тик-прохода целиком (недоступен список репо,
	// отменён контекст); ошибки отдельных репо идут в OnPass — проход
	// их переживает (nil-safe, как OnApply).
	OnError func(error)
	// OnPass — итог прохода по одному репо (nil-safe), наполнение —
	// лог/метрики в wire.
	OnPass func(repoName string, res Result, err error)

	// mu охраняет cancel/done — поля жизненного цикла Run/Stop.
	mu     sync.Mutex
	cancel context.CancelFunc // nil до Run и после Stop
	done   chan struct{}      // закрытие = горутина-тикер вышла
}

// NewRunner собирает периодический проход. interval — период тика
// (конфиг retention.interval); Run поднимает цикл только при interval > 0.
func NewRunner(e *Engine, repos port.RepoStore, interval time.Duration) *Runner {
	return &Runner{engine: e, repos: repos, interval: interval}
}

// RunOnce — один проход: Repos(ctx) → по каждому репо с включённой
// политикой ApplyAndReindex, последовательно. Последовательно, а не
// параллельно: проходы делят семафор удалений движка, а параллельный
// reindex нескольких репо ничего не выигрывает и штормит носитель.
//
// Ошибка одного репо не стопает остальные (сбой nix-репо не должен
// оставлять без чистки apt-репо): она уходит в OnPass и в агрегат
// возвращённой ошибки. Между репо — проверка ctx: отмена гасит проход
// на границе репо (удалённое остаётся удалённым, остаток подберёт
// следующий проход; прецедент Apply). Порядок «сначала удаления, затем
// reindex» — внутри ApplyAndReindex.
func (r *Runner) RunOnce(ctx context.Context) error {
	repos, err := r.repos.Repos(ctx)
	if err != nil {
		return fmt.Errorf("retention: список репозиториев: %w", err)
	}
	var errs []error
	for _, repo := range repos {
		if cerr := ctx.Err(); cerr != nil {
			return errors.Join(append(errs, cerr)...)
		}
		if !repo.Retention.Enabled() {
			continue // политика не включена — репо живёт как раньше
		}
		res, err := r.engine.ApplyAndReindex(ctx, repo, false)
		if r.OnPass != nil {
			r.OnPass(repo.Name, res, err)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("ретеншн репо %s: %w", repo.Name, err))
		}
	}
	return errors.Join(errs...)
}

// Run запускает горутину-тикер: раз в interval — RunOnce. Пауза —
// time.Ticker, а не port.Clock: момент снятия показаний времени не
// важен (прецедент statskeeper). Тик-проход идёт в контексте
// WithoutCancel: отмену shutdown'а посреди удалений проход переживает
// до конца — брошенный на половине проход оставил бы индексы
// несоответствующими хранилищу, а следующим проходом это не чинится
// мгновенно. Ошибки идут в OnError, цикл продолжает тикать.
//
// interval <= 0 — цикл не поднимается (легальное «выключено» и защита
// от паники time.NewTicker; основной гейт — wire).
func (r *Runner) Run(ctx context.Context) {
	if r.interval <= 0 {
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	r.mu.Lock()
	r.cancel = cancel
	r.done = make(chan struct{})
	done := r.done
	r.mu.Unlock()
	go func() {
		defer close(done)
		ticker := time.NewTicker(r.interval)
		defer ticker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				if err := r.RunOnce(context.WithoutCancel(runCtx)); err != nil && r.OnError != nil {
					r.OnError(err)
				}
			}
		}
	}()
}

// Stop гасит тикер и дожидается выхода горутины. Финального прохода
// НЕТ (в отличие от statskeeper: тот флашит накопленное, потеря
// которого невосстановима). Проход на выходе вместо этого был бы
// удалением объектов в момент останова сервера — ровно то, чего от
// ретеншна на shutdown не ждут; пропущенный тик добирает следующий
// старт. Повторный Stop — идемпотентен.
func (r *Runner) Stop(ctx context.Context) error {
	r.mu.Lock()
	cancel, done := r.cancel, r.done
	r.cancel, r.done = nil, nil
	r.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
