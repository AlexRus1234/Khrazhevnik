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
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// Каскад graceful shutdown (docs/ARCHITECTURE.md §2): SIGTERM →
// оба HTTP-слушателя параллельно (5с) → фоновые задачи (30с).
const (
	httpShutdownTimeout = 5 * time.Second
	tasksWaitTimeout    = 30 * time.Second
	readHeaderTimeout   = 10 * time.Second // slowloris-защита
)

// Server — пара слушателей (public/admin) с общим жизненным циклом.
// Порт :0 в адресе выбирает ОС; фактические адреса — через Addrs.
type Server struct {
	PublicAddr    string
	PublicHandler http.Handler
	AdminAddr     string
	AdminHandler  http.Handler
	Log           *slog.Logger

	// WaitTasks — хук ожидания фоновых задач после остановки HTTP
	// (sync-воркеры зеркал, сессия 11); nil — ждать нечего.
	WaitTasks func(ctx context.Context) error

	mu         sync.Mutex
	publicAddr string
	adminAddr  string
}

// Run слушает до отмены ctx; при отмене гаснет каскадом. Сбой одного
// из слушателей останавливает оба и возвращает ошибку.
func (s *Server) Run(ctx context.Context) error {
	log := s.Log
	if log == nil {
		log = slog.Default()
	}

	publicLn, err := net.Listen("tcp", s.PublicAddr)
	if err != nil {
		return fmt.Errorf("web: слушатель public %s: %w", s.PublicAddr, err)
	}
	adminLn, err := net.Listen("tcp", s.AdminAddr)
	if err != nil {
		_ = publicLn.Close()
		return fmt.Errorf("web: слушатель admin %s: %w", s.AdminAddr, err)
	}
	s.mu.Lock()
	s.publicAddr = publicLn.Addr().String()
	s.adminAddr = adminLn.Addr().String()
	s.mu.Unlock()

	publicSrv := &http.Server{Handler: s.PublicHandler, ReadHeaderTimeout: readHeaderTimeout}
	adminSrv := &http.Server{Handler: s.AdminHandler, ReadHeaderTimeout: readHeaderTimeout}

	errCh := make(chan error, 2)
	go func() { errCh <- serveListener("public", publicSrv, publicLn) }()
	go func() { errCh <- serveListener("admin", adminSrv, adminLn) }()

	select {
	case err := <-errCh:
		if cerr := shutdownHTTP(publicSrv, adminSrv); cerr != nil {
			log.Error("web: ошибки остановки слушателей", "err", cerr)
		}
		return err
	case <-ctx.Done():
	}
	if err := shutdownHTTP(publicSrv, adminSrv); err != nil {
		return err
	}
	return s.waitTasks()
}

// Addrs — фактические адреса слушателей (после bind внутри Run;
// до него — исходные значения полей).
func (s *Server) Addrs() (public, admin string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.publicAddr == "" {
		public = s.PublicAddr
	} else {
		public = s.publicAddr
	}
	if s.adminAddr == "" {
		admin = s.AdminAddr
	} else {
		admin = s.adminAddr
	}
	return public, admin
}

// serveListener оборачивает Serve: плановая остановка — не ошибка.
func serveListener(name string, srv *http.Server, ln net.Listener) error {
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("web: слушатель %s: %w", name, err)
	}
	return nil
}

// shutdownHTTP гасит слушатели параллельно с общим таймаутом.
func shutdownHTTP(servers ...*http.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), httpShutdownTimeout)
	defer cancel()

	var wg sync.WaitGroup
	errs := make([]error, len(servers))
	for i, srv := range servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = srv.Shutdown(ctx)
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}

// waitTasks выполняет хук фоновых задач с таймаутом каскада.
func (s *Server) waitTasks() error {
	if s.WaitTasks == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), tasksWaitTimeout)
	defer cancel()
	if err := s.WaitTasks(ctx); err != nil {
		return fmt.Errorf("web: фоновые задачи: %w", err)
	}
	return nil
}
