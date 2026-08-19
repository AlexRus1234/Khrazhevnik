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
	"net/http"
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
