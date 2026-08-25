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

// Package main — точка входа бинарника khrazhevnik: флаги, конфиг,
// склейка (wire.go), два слушателя и graceful shutdown. Вся логика —
// в internal/core и internal/mod.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"khrazhevnik/internal/core/config"
	"khrazhevnik/internal/core/web"
)

// Version подставляется линкером через -ldflags "-X main.Version=..."
// (для package main Go 1.26 принимает только main.Version).
// Единственная разрешённая package-level переменная (см. AGENTS.md).
var Version = "dev"

// logLevelEnv — уровень логов при старте (debug|info|warn|error).
const logLevelEnv = "KHRZ_LOG_LEVEL"

func main() {
	configPath := flag.String("config", "", "путь к TOML-конфигурации (пусто — defaults+env)")
	showVersion := flag.Bool("version", false, "напечатать версию и выйти")
	// -add-remote — одноразовая bootstrap-команда: пишет upstream в
	// БД и выходит, не поднимая сервер. Админ-API (сессия 09) её заменит.
	addRemote := flag.String("add-remote", "", "записать remote в БД и выйти (формат: <eco>/<name>=<base-url>)")
	flag.Parse()

	if *showVersion {
		fmt.Println("khrazhevnik", Version)
		return
	}

	// os.Exit без висящих defer: контекст сигналов живёт в execute
	// (gocritic exitAfterDefer)
	if err := execute(*configPath, *addRemote); err != nil {
		fmt.Fprintln(os.Stderr, "khrazhevnik:", err)
		os.Exit(1)
	}
}

// execute — run с контекстом сигналов; SIGINT/SIGTERM → отмена →
// каскад HTTP 5с → задачи 30с (docs/ARCHITECTURE.md §2, PID 1).
// addRemoteSpec пуст — обычный запуск сервера; иначе — одноразовая
// bootstrap-команда (см. addremote.go), контекст сигналов ей не нужен.
func execute(configPath, addRemoteSpec string) error {
	if addRemoteSpec != "" {
		return runAddRemote(configPath, addRemoteSpec)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx, configPath)
}

// run — жизненный цикл: конфиг → сборка зависимостей → слушатели.
func run(ctx context.Context, configPath string) error {
	cfg, err := config.Load(configPath, os.Getenv)
	if err != nil {
		return err
	}
	log := newLogger()

	app, err := wireApp(cfg, log)
	if err != nil {
		return err
	}

	srv := &web.Server{
		PublicAddr:    cfg.Server.PublicListen,
		PublicHandler: web.BuildPublicRouter(web.Deps{Log: log, Version: Version, Cache: app.Cache, Ecosystems: app.Ecosystems, Storage: app.Storage, Repos: app.Catalog.Repos}),
		AdminAddr:     cfg.Server.AdminListen,
		AdminHandler: web.BuildAdminRouter(web.Deps{
			Log:            log,
			Version:        Version,
			Auth:           app.Auth,
			SetupToken:     cfg.Auth.SetupToken,
			Cache:          app.Cache,
			Ecosystems:     app.Ecosystems,
			Remotes:        app.Catalog.Remotes,
			Repos:          app.Catalog.Repos,
			Storage:        app.Storage,
			Audit:          app.Catalog.Audit,
			Tasks:          app.Tasks,
			Mirror:         app.Mirror,
			Publish:        app.Publish,
			MetricsHandler: app.MetricsHandler,
			Clock:          app.Clock,
		}),
		Log:       log,
		WaitTasks: app.WaitTasks,
	}
	log.Info("khrazhevnik запущен",
		"version", Version,
		"public", cfg.Server.PublicListen,
		"admin", cfg.Server.AdminListen,
		"storage", cfg.Storage.Driver,
		"database", cfg.Database.Driver,
	)
	return srv.Run(ctx)
}

// newLogger — slog в stderr; уровень из KHRZ_LOG_LEVEL, default info.
func newLogger() *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToUpper(os.Getenv(logLevelEnv)) {
	case "DEBUG":
		level = slog.LevelDebug
	case "WARN", "WARNING":
		level = slog.LevelWarn
	case "ERROR":
		level = slog.LevelError
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}
