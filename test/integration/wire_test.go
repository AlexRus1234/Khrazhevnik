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

//go:build integration

package integration

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"khrazhevnik/internal/core/config"
	"khrazhevnik/internal/core/web"
)

// freePort — ephemeral-порт: конфиг справедливо не принимает :0
// (продакшн-адреса обязаны быть явными), поэтому порт берём заранее.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("адрес слушателя %s не TCP", ln.Addr())
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(addr.Port))
}

// waitHealthy опрашивает healthz, пока сервер не ответит.
func waitHealthy(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("healthz на %s не ответил за 3с", url)
}

// TestWireBootShutdown — минимальный TOML (fs-заглушка конфига) →
// конфиг → роутеры → оба слушателя → healthz 200 → отмена контекста →
// чистое завершение за <6с (goleak не подключаем: ждём Run с таймаутом).
func TestWireBootShutdown(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "khrazhevnik.toml")
	tomlCfg := "[server]\n" +
		"public_listen = \"" + freePort(t) + "\"\n" +
		"admin_listen = \"" + freePort(t) + "\"\n\n" +
		"[storage.fs]\n" +
		"path = \"" + filepath.ToSlash(filepath.Join(dir, "store")) + "\"\n\n" +
		"[auth]\n" +
		"jwt_secret = \"integration-secret-integration-secret-0123\"\n"
	if err := os.WriteFile(confPath, []byte(tomlCfg), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(confPath, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := &web.Server{
		PublicAddr:    cfg.Server.PublicListen,
		PublicHandler: web.BuildPublicRouter(web.Deps{Log: log, Version: "test"}),
		AdminAddr:     cfg.Server.AdminListen,
		AdminHandler:  web.BuildAdminRouter(web.Deps{Log: log, Version: "test"}),
		Log:           log,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()

	publicURL := "http://" + cfg.Server.PublicListen + "/healthz"
	adminURL := "http://" + cfg.Server.AdminListen + "/healthz"
	waitHealthy(t, publicURL)
	waitHealthy(t, adminURL)

	// админский корень API отвечает версией (заглушка до сессии 05)
	resp, err := http.Get("http://" + cfg.Server.AdminListen + "/api/v1/")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "khrazhevnik") {
		t.Fatalf("/api/v1/ = %d %s", resp.StatusCode, body)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("сервер завершился с ошибкой: %v", err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("сервер не завершился за 6с после отмены контекста")
	}
}
