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

package eviction

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/port"
)

// Runner — периодический проход eviction по всем proxy-remote с
// включённой политикой. Отдельный тип, а не метод Engine (образец
// retention.Runner, сессия 171): у Apply нет ни горутин, ни состояния
// между вызовами — жизненный цикл есть только у периодического цикла, а
// ручной запуск (API сессии 202) зовёт Apply/Preview напрямую и Runner'а
// не касается.
//
// Зачем периодический проход вообще: давность обращения (MaxAgeDays)
// стареет сама по себе — версия, живая при последней загрузке, через
// полгода мертва, и без прохода её никто не удалит: post-download-триггер
// отклонён при планировании волны (чистка в горячем пути загрузки —
// вторая очередь и лишний риск 409 строке выдачи, та же логика, что у
// ретеншна).
type Runner struct {
	engine   *Engine
	remotes  port.RemoteStore
	interval time.Duration

	// OnError — сбой тик-прохода целиком (недоступен список remote,
	// отменён контекст); ошибки отдельных remote идут в OnPass — проход
	// их переживает (nil-safe, как OnApply).
	OnError func(error)
	// OnPass — итог прохода по одному remote (nil-safe), наполнение —
	// лог/метрики в wire.
	OnPass func(remoteName string, res Result, err error)

	// mu охраняет cancel/done — поля жизненного цикла Run/Stop.
	mu     sync.Mutex
	cancel context.CancelFunc // nil до Run и после Stop
	done   chan struct{}      // закрытие = горутина-тикер вышла
}

// NewRunner собирает периодический проход. interval — период тика
// (конфиг eviction.interval); Run поднимает цикл только при interval > 0.
func NewRunner(e *Engine, remotes port.RemoteStore, interval time.Duration) *Runner {
	return &Runner{engine: e, remotes: remotes, interval: interval}
}

// RunOnce — один проход: Remotes(ctx) → по каждому proxy-remote с
// включённой политикой Apply (без reindex — у кеша его нет). Фильтры до
// Apply, а не внутри движка, чтобы выключенный/зеркальный remote не
// тратил листинг хранилища: зеркало это полная копия upstream, и churn
// «скачал → удалил → скачал» конфликтует с resume-diff sync.
//
// Последовательно, а не параллельно: проходы делят семафор удалений
// движка, а параллельный листинг нескольких remote штормит носитель без
// выигрыша (прецедент retention.Runner). Ошибка одного remote не стопает
// остальные (сбой nix-remote не должен оставлять без чистки apt): она
// уходит в OnPass и в агрегат возвращённой ошибки. Между remote —
// проверка ctx.Err(): отмена гасит проход на границе, удалённое остаётся
// удалённым, остаток подберёт следующий проход (прецедент Apply).
func (r *Runner) RunOnce(ctx context.Context) error {
	remotes, err := r.remotes.Remotes(ctx)
	if err != nil {
		return fmt.Errorf("eviction: список remote: %w", err)
	}
	var errs []error
	for _, remote := range remotes {
		if cerr := ctx.Err(); cerr != nil {
			return errors.Join(append(errs, cerr)...)
		}
		if remote.Mode != domain.ModeProxy || !remote.Enabled {
			continue // зеркало/выключенный remote — не кандидат на чистку
		}
		if !r.engine.Policy(remote).Enabled() {
			continue // политика не включена — кеш remote растёт как раньше
		}
		res, err := r.engine.Apply(ctx, remote, false)
		if r.OnPass != nil {
			r.OnPass(remote.Name, res, err)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("eviction remote %s: %w", remote.Name, err))
		}
	}
	return errors.Join(errs...)
}

// Run запускает горутину-тикер: раз в interval — RunOnce. Пауза —
// time.Ticker, а не port.Clock: момент снятия показаний времени не важен
// (прецедент retention.Runner/statskeeper). Тик-проход идёт в контексте
// WithoutCancel: отмену shutdown'а посреди удалений проход переживает до
// конца — брошенный на половине проход оставил бы часть семейств
// неразобранной, а частично удалённое следующим проходом добирается лишь
// целиком (прецедент retention). Ошибки идут в OnError, цикл продолжает
// тикать.
//
// interval <= 0 — цикл не поднимается (легальное «выключено» и защита от
// паники time.NewTicker; основной гейт — wire).
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

// Stop гасит тикер и дожидается выхода горутины. Финального прохода НЕТ
// (в отличие от statskeeper: тот флашит накопленное, потеря которого
// невосстановима). Проход на выходе был бы удалением объектов в момент
// останова сервера — ровно то, чего от чистки кеша на shutdown не ждут;
// пропущенный тик добирает следующий старт. Повторный Stop идемпотентен.
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
