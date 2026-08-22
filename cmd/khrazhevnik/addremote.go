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

// Логика флага -add-remote: одноразовая bootstrap-команда, пишет
// upstream в БД и выходит. Нужна, пока нет админ-API (сессия 09);
// после него флаг удаляется. Конфиг нужен тот же, что у сервера —
// чтобы DSN/драйвер БД брались из единого источника правды.

package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"khrazhevnik/internal/core/config"
	"khrazhevnik/internal/core/domain"
	"khrazhevnik/internal/core/registry"
)

// runAddRemote парсит спецификацию, грузит конфиг, открывает каталог
// БД и записывает remote. Сервер не поднимает. Идемпотентностью не
// обладает: повторный запуск с тем же name — Conflict (как и боевой
// CreateRemote); для обновления будет PUT /api/v1/remotes/<id> (09).
func runAddRemote(configPath, spec string) error {
	eco, name, baseURL, err := parseAddRemoteSpec(spec)
	if err != nil {
		return err
	}
	cfg, err := config.Load(configPath, bootstrapEnv)
	if err != nil {
		return err
	}
	dbFactory, err := registry.DB(cfg.Database.Driver)
	if err != nil {
		return err
	}
	catalog, err := dbFactory(cfg.Database)
	if err != nil {
		return fmt.Errorf("каталог %q: %w", cfg.Database.Driver, err)
	}
	// CatalogSet — набор интерфейсов; Close не в порту (мало кому нужен
	// в рантайме). Адаптеры БД реализуют io.Closer — проверяем
	// type-assertion'ом, как это делает integration/modules_test.go.
	if closer, ok := catalog.Audit.(interface{ Close() error }); ok {
		defer func() { _ = closer.Close() }()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	remote, err := catalog.Remotes.CreateRemote(ctx, domain.Remote{
		Name:      name,
		Ecosystem: eco,
		BaseURL:   baseURL,
		Mode:      domain.ModeProxy,
		Enabled:   true,
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		return fmt.Errorf("запись remote: %w", err)
	}
	fmt.Printf("remote %s/%s (id=%d) записан в каталог %q\n", eco, name, remote.ID, cfg.Database.Driver)
	return nil
}

// bootstrapEnv — env-геттер для -add-remote: реальное окружение, но с
// заглушкой jwt_secret, если его не задали. Bootstrap-команда не
// трогает auth, а config.Load валидирует jwt_secret как сервер; без
// заглушке пользователь обязан был бы задать бесполезный секрет ради
// одной записи в БД. Серверу эту заглушку НЕ подсовываем — только CLI.
func bootstrapEnv(key string) string {
	const jwtKey = "KHRZ_AUTH__JWT_SECRET"
	if key == jwtKey && os.Getenv(jwtKey) == "" {
		return "bootstrap-not-used-by-server"
	}
	return os.Getenv(key)
}

// parseAddRemoteSpec разбирает «<eco>/<name>=<base-url>» на три части
// и валидирует каждую. eco должен быть зарегистрирован в compile-time
// реестре (blank-import в wire.go): иначе бесполезно писать remote,
// который никто не разрезолвит. name — slug без слэшей; base-url —
// http(s)://…
func parseAddRemoteSpec(spec string) (eco, name, baseURL string, err error) {
	eq := strings.IndexByte(spec, '=')
	if eq < 0 {
		return "", "", "", fmt.Errorf("-add-remote: ожидается <eco>/<name>=<base-url>, получено %q", spec)
	}
	left, baseURL := spec[:eq], spec[eq+1:]
	if baseURL == "" {
		return "", "", "", errors.New("-add-remote: пустой base-url")
	}
	slash := strings.IndexByte(left, '/')
	if slash < 0 {
		return "", "", "", fmt.Errorf("-add-remote: ожидается <eco>/<name>, получено %q", left)
	}
	eco, name = left[:slash], left[slash+1:]
	if eco == "" || name == "" {
		return "", "", "", errors.New("-add-remote: eco и name не могут быть пустыми")
	}
	if strings.ContainsAny(name, "/\\\x00") || name == "." || name == ".." {
		return "", "", "", fmt.Errorf("-add-remote: имя remote %q недопустимо (slug без слэшей и «..»)", name)
	}
	// eco должен быть слинкован в бинарник, иначе remote мёртвый груз.
	if _, err := registry.Ecosystem(eco); err != nil {
		return "", "", "", fmt.Errorf("-add-remote: экосистема %q не слинкована (добавьте blank-import в wire.go): %w", eco, err)
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" {
		return "", "", "", fmt.Errorf("-add-remote: base-url %q некорректен", baseURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", "", "", fmt.Errorf("-add-remote: scheme base-url должна быть http или https, получено %q", u.Scheme)
	}
	return eco, name, baseURL, nil
}
