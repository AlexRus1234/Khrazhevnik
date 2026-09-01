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
	"net"
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
	trusted, err := cfg.ParsedTrustedProxies()
	if err != nil {
		return err
	}

	srv := &web.Server{
		PublicAddr:    cfg.Server.PublicListen,
		PublicHandler: web.BuildPublicRouter(web.Deps{Log: log, Version: Version, Cache: app.Cache, Ecosystems: app.Ecosystems, Storage: app.Storage, Repos: app.Catalog.Repos, Signer: app.Signer, NarSigner: app.NarSigner}),
		AdminAddr:     cfg.Server.AdminListen,
		AdminHandler: web.BuildAdminRouter(web.Deps{
			Log:              log,
			Version:          Version,
			Auth:             app.Auth,
			SetupToken:       cfg.Auth.SetupToken,
			Cache:            app.Cache,
			Ecosystems:       app.Ecosystems,
			TrustedProxies:   trusted,
			Remotes:          app.Catalog.Remotes,
			Repos:            app.Catalog.Repos,
			Storage:          app.Storage,
			Audit:            app.Catalog.Audit,
			Tasks:            app.Tasks,
			Mirror:           app.Mirror,
			Publish:          app.Publish,
			OnRemotesChanged: app.NotifyRemotesChanged,
			MetricsHandler:   app.MetricsHandler,
			Clock:            app.Clock,
		}),
		Log:       log,
		WaitTasks: app.WaitTasks,
	}
	warnAdminListen(log, cfg.Server.AdminListen)
	log.Info("khrazhevnik запущен",
		"version", Version,
		"public", cfg.Server.PublicListen,
		"admin", cfg.Server.AdminListen,
		"storage", cfg.Storage.Driver,
		"database", cfg.Database.Driver,
	)
	return srv.Run(ctx)
}

// warnAdminListen — админ-API на не-loopback адресе (дефолт :30202 —
// все интерфейсы, аудит 2026-08-27): дефолт не меняем ради контейнерных
// деплоев, но молчать не должны — оператор обязан знать, что админка
// видна снаружи. Некорректный адрес молча пропускается: его отловит
// fail-fast валидация конфига.
func warnAdminListen(log *slog.Logger, addr string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return
	}
	switch {
	case host == "" || host == "0.0.0.0" || host == "::":
		log.Warn("admin-API слушает на всех интерфейсах (дефолт) — убедись, что порт :30202 не торчит наружу", "admin_listen", addr)
	case net.ParseIP(host) != nil && !net.ParseIP(host).IsLoopback():
		log.Warn("admin-API слушает на не-loopback адресе — убедись, что доступ закрыт файрволом/прокси", "admin_listen", addr)
	case net.ParseIP(host) == nil && host != "localhost":
		// именованный хост: loopback только по имени localhost
		log.Warn("admin-API слушает на именованном хосте — убедись, что это не внешний интерфейс", "admin_listen", addr)
	}
}

// newLogger — slog в stderr; уровень из KHRZ_LOG_LEVEL, default info.
// Опечатка в уровне («debuge») не должна молча означать info: warning
// пишет временный логгер, потому что основной хендлер ещё не создан.
func newLogger() *slog.Logger {
	allowed := "debug|info|warn|error"
	raw := os.Getenv(logLevelEnv)
	var level slog.Level
	switch strings.ToUpper(raw) {
	case "DEBUG":
		level = slog.LevelDebug
	case "WARN", "WARNING":
		level = slog.LevelWarn
	case "ERROR":
		level = slog.LevelError
	case "":
		level = slog.LevelInfo
	default:
		level = slog.LevelInfo
		slog.New(slog.NewTextHandler(os.Stderr, nil)).Warn(
			"неизвестный KHRZ_LOG_LEVEL — использую info",
			"value", raw, "allowed", allowed)
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}
