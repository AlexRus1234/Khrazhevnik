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

package web

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// newTestServer — сервер на ephemeral-портах сdiscard-логгером.
func newTestServer(wait func(ctx context.Context) error) *Server {
	return &Server{
		PublicAddr:    "127.0.0.1:0",
		PublicHandler: BuildPublicRouter(Deps{Version: "test"}),
		AdminAddr:     "127.0.0.1:0",
		AdminHandler:  BuildAdminRouter(Deps{Version: "test"}),
		Log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		WaitTasks:     wait,
	}
}

// waitHealthy опрашивает healthz, пока сервер не ответит (или таймаут).
func waitHealthy(t *testing.T, addr func() string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + addr() + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("healthz на %s не ответил за 3с", addr())
}

func TestServerRunAndGracefulShutdown(t *testing.T) {
	s := newTestServer(nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	waitHealthy(t, func() string { pub, _ := s.Addrs(); return pub })
	waitHealthy(t, func() string { _, admin := s.Addrs(); return admin })

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("сервер завершился с ошибкой: %v", err)
		}
	case <-time.After(httpShutdownTimeout + time.Second):
		t.Fatal("сервер не завершился после отмены контекста")
	}
}

func TestServerWaitTasksHook(t *testing.T) {
	tasksDone := make(chan struct{})
	s := newTestServer(func(context.Context) error {
		close(tasksDone)
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	waitHealthy(t, func() string { pub, _ := s.Addrs(); return pub })
	cancel()

	select {
	case <-tasksDone:
	case <-time.After(2 * time.Second):
		t.Fatal("хук WaitTasks не вызван после остановки HTTP")
	}
	if err := <-done; err != nil {
		t.Fatalf("сервер завершился с ошибкой: %v", err)
	}
}

func TestServerListenerFailure(t *testing.T) {
	s := newTestServer(nil)
	s.AdminAddr = "no-port" // net.Listen падает сразу

	if err := s.Run(context.Background()); err == nil {
		t.Fatal("ожидалась ошибка бинда некорректного адреса")
	}
}

// TestServerWaitTasksAfterShutdownTimeout — HTTP-фаза каскада
// свалилась (висящий запрос на публичном слушателе без WriteTimeout →
// Shutdown вернёт DeadlineExceeded), а фаза задач всё равно
// выполнена: стадии каскада не зависят друг от друга (аудит
// 2026-08-30, сессия 35). Раньше return-на-ошибке-HTTP рвал каскад,
// и 30s-бюджет задач никогда не наступал.
func TestServerWaitTasksAfterShutdownTimeout(t *testing.T) {
	tasksDone := make(chan struct{})
	s := newTestServer(func(context.Context) error {
		close(tasksDone)
		return nil
	})
	// Короткий HTTP-таймаут: тесту не нужно ждать полные 5s.
	s.shutdownTimeout = 50 * time.Millisecond
	// Публичный хендлер с «висящим» путём: активный запрос живёт
	// дольше HTTP-таймаута — как стрим пакетов в проде.
	hangStarted := make(chan struct{})
	s.PublicHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		select {
		case <-hangStarted:
		default:
			close(hangStarted)
		}
		time.Sleep(2 * time.Second) // >> shutdownTimeout
		w.WriteHeader(http.StatusOK)
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	waitHealthy(t, func() string { pub, _ := s.Addrs(); return pub })
	waitHealthy(t, func() string { _, adm := s.Addrs(); return adm })

	// Висящий клиент: запрос отправлен, ответ не читается — Shutdown
	// не может закрыть соединение с живым запросом и вернёт ошибку.
	go func() {
		pub, _ := s.Addrs()
		conn, err := net.DialTimeout("tcp", pub, 2*time.Second)
		if err != nil {
			t.Errorf("нет соединения к %s: %v", pub, err)
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write([]byte("GET /package.deb HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
			t.Errorf("write: %v", err)
			return
		}
		// соединение держим открытым до конца теста (defer выше)
		time.Sleep(2 * time.Second)
	}()

	// Запрос обязан достигнуть хендлера ДО cancel — иначе Shutdown
	// закроет пустой conn без ошибки и тест потеряет смысл.
	select {
	case <-hangStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("висящий запрос не дошёл до хендлера")
	}

	cancel()
	select {
	case <-tasksDone:
	case <-time.After(2 * time.Second):
		t.Fatal("WaitTasks не вызван: ошибка HTTP-фазы отменила фазу задач")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("ожидалась агрегированная ошибка (HTTP-фаза обязана вернуться)")
		}
		if !strings.Contains(err.Error(), "context deadline exceeded") {
			t.Errorf("ожидалась ошибка HTTP-фазы в агрегате: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("сервер не завершился")
	}
}

// TestServerWaitTasksOnListenerDeath — смерть листенера в рантайме
// (accept error): раньше ветка возвращала ошибку сразу, не дожидаясь
// фоновых задач — sync_jobs зависали в running до следующего старта
// (аудит 2026-08-30, сессия 35).
func TestServerWaitTasksOnListenerDeath(t *testing.T) {
	tasksDone := make(chan struct{})
	s := newTestServer(func(context.Context) error {
		close(tasksDone)
		return nil
	})

	ctx := context.Background()
	done := make(chan error, 1)
	go func() {
		// Свои listener'ы: admin-сокет убиваем снаружи → Serve вернёт
		// accept error → ветка смерти листенера в serve.
		publicLn, err := net.Listen("tcp", s.PublicAddr)
		if err != nil {
			done <- err
			return
		}
		adminLn, err := net.Listen("tcp", s.AdminAddr)
		if err != nil {
			_ = publicLn.Close()
			done <- err
			return
		}
		go func() {
			waitHealthy(t, func() string { pub, _ := s.Addrs(); return pub })
			// Дожидаемся bind'а admin-адреса в Addrs, затем роняем сокет.
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				_, adm := s.Addrs()
				if adm != s.AdminAddr && adm != "" && adm != "127.0.0.1:0" {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			_ = adminLn.Close()
		}()
		done <- s.serve(ctx, publicLn, adminLn)
	}()

	select {
	case <-tasksDone:
	case <-time.After(3 * time.Second):
		t.Fatal("WaitTasks не вызван после смерти листенера")
	}
	err := <-done
	if err == nil {
		t.Fatal("ожидалась accept-ошибка из ветки смерти листенера")
	}
}
