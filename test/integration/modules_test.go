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

// Сборка wire с реальными модулями (blank-import'ы — как в
// cmd/khrazhevnik/wire.go): fs-хранилище + sqlite-каталог, сервер
// стартует и пишет аудит. wireApp живёт в package main, поэтому путь
// реестра воспроизводится здесь построчно.

package integration

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "khrazhevnik/internal/mod/db/sqlite"
	_ "khrazhevnik/internal/mod/storage/fs"

	"khrazhevnik/internal/core/config"
	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/registry"
	"khrazhevnik/internal/core/web"
)

func TestWireFsSqliteCatalog(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "khrazhevnik.toml")
	tomlCfg := "[server]\n" +
		"public_listen = \"" + freePort(t) + "\"\n" +
		"admin_listen = \"" + freePort(t) + "\"\n\n" +
		"[storage.fs]\n" +
		"path = \"" + filepath.ToSlash(filepath.Join(dir, "store")) + "\"\n\n" +
		"[database]\n" +
		"dsn = \"" + filepath.ToSlash(filepath.Join(dir, "khrazhevnik.db")) + "\"\n\n" +
		"[auth]\n" +
		"jwt_secret = \"integration-secret\"\n"
	if err := os.WriteFile(confPath, []byte(tomlCfg), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(confPath, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Storage.Driver != config.DriverFS || cfg.Database.Driver != config.DriverSQLite {
		t.Fatalf("конфиг: драйверы %s/%s", cfg.Storage.Driver, cfg.Database.Driver)
	}

	// путь wireApp: фабрики из compile-time реестра
	storageFactory, err := registry.Storage(cfg.Storage.Driver)
	if err != nil {
		t.Fatal(err)
	}
	dbFactory, err := registry.DB(cfg.Database.Driver)
	if err != nil {
		t.Fatal(err)
	}
	storage, err := storageFactory(cfg.Storage)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := dbFactory(cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	if closer, ok := catalog.Audit.(interface{ Close() error }); ok {
		t.Cleanup(func() { _ = closer.Close() })
	}

	ctx := context.Background()

	// хранилище: транзакционная запись видна после Commit
	w, err := storage.Put(ctx, "cache/apt/1/pool/a.deb")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("package-bytes")); err != nil {
		t.Fatal(err)
	}
	if err := w.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	obj, err := storage.Get(ctx, "cache/apt/1/pool/a.deb")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(obj.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := obj.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if string(body) != "package-bytes" || obj.Size != 13 {
		t.Fatalf("Get = %q (%d байт)", body, obj.Size)
	}

	// каталог: миграции уже применены, аудит пишется и читается
	has, err := catalog.Users.HasUsers(ctx)
	if err != nil || has {
		t.Fatalf("HasUsers на чистой БД = %v, %v", has, err)
	}
	entry := domain.AuditEntry{
		At: time.Now().Truncate(time.Second).UTC(), Actor: "system",
		Action: "integration.boot", Object: "server", Result: domain.AuditOK,
	}
	if err := catalog.Audit.Record(ctx, entry); err != nil {
		t.Fatal(err)
	}
	page, err := catalog.Audit.AuditEntries(ctx, 0, 10)
	if err != nil || len(page) != 1 || page[0].Action != entry.Action {
		t.Fatalf("аудит после записи: %+v, %v", page, err)
	}

	// оба слушателя живы
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := &web.Server{
		PublicAddr:    cfg.Server.PublicListen,
		PublicHandler: web.BuildPublicRouter(web.Deps{Log: log, Version: "test"}),
		AdminAddr:     cfg.Server.AdminListen,
		AdminHandler:  web.BuildAdminRouter(web.Deps{Log: log, Version: "test"}),
		Log:           log,
	}
	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.Run(runCtx) }()
	waitHealthy(t, fmt.Sprintf("http://%s/healthz", cfg.Server.PublicListen))
	waitHealthy(t, fmt.Sprintf("http://%s/healthz", cfg.Server.AdminListen))

	// graceful shutdown
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("сервер завершился с ошибкой: %v", err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("сервер не завершился за 6с")
	}
}

// TestWireRejectsUnknownDriver — реестр с реальными модулями даёт
// понятную ошибку на неизвестный драйвер.
func TestWireRejectsUnknownDriver(t *testing.T) {
	if _, err := registry.Storage(config.DriverS3); err == nil {
		t.Fatal("s3 не слинкован, но фабрика нашлась")
	}
	if _, err := registry.DB(config.DriverPostgres); err == nil {
		t.Fatal("postgres не слинкован, но фабрика нашлась")
	}
}
