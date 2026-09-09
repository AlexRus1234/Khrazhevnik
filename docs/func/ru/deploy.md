<!--
Хражевник — кеш-прокси и зеркало linux-репозиториев
Copyright (C) 2026 AlexRus1234

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
-->

# Развёртывание

Основная дистрибуция — OCI-образ из scratch под rootless podman
quadlet (или docker compose). Альтернатива — [голый бинарник
(CGO-free, static)](#запуск-из-бинарника-systemd) под systemd или любой
процесс-супервизор. Быстрая установка —
в [quickstart.md](quickstart.md); эта страница — справочник развёртывания.

Контейнер слушает два порта:

| Порт  | Доступ          | Назначение                                      |
|-------|-----------------|-------------------------------------------------|
| 29202 | публичный       | раздача пакетов (`/<eco>/<remote>/<путь>`, `/repo/<name>/*`) + `/healthz` |
| 30202 | 127.0.0.1 only (quadlet) | админ-API `/api/v1`, `/metrics`, веб-админка `/ui` |

Loopback-админка — свойство quadlet-деплоя (`PublishPort=127.0.0.1:...`).
Голый бинарник без конфига слушает оба порта на всех интерфейсах
(со стартовым warn); как закрыть админку снаружи —
[SECURITY.md](../../SECURITY.md).

Rootless: оба порта ≥1024, порты ниже 1024 — через reverse-proxy на
хосте — [reverse-proxy.md](reverse-proxy.md) (Caddy/Traefik/nginx).
Контейнер: `USER 65534:65534`, scratch (только
бинарник + CA-bundle), rootfs read-only (`ReadOnlyRootfs=true` в
quadlet), writable — только volume `/var/lib/khrazhevnik`; PID 1 =
бинарник (сабпроцессов нет, зомби-реапер не нужен), graceful shutdown:
SIGTERM → HTTP 5с → задачи 30с.

## Требования

- podman ≥ 4 (quadlet, `host-gateway` для smoke), rootless-режим;
- systemd --user (для quadlet) либо голый `podman run`;
- каталог данных `/var/lib/khrazhevnik` (sqlite, fs-store, ключи);
- OpenSSL (для генерации JWT-секрета).

## Установка через quadlet

```sh
# 1. Конфиг quadlet в пользовательский путь генератора.
mkdir -p ~/.config/containers/systemd
cp deploy/quadlet/khrazhevnik.container ~/.config/containers/systemd/

# 2. JWT-секрет — как Podman Secret (не светится в env/`systemctl show`).
podman secret create jwt-secret "$(openssl rand -hex 32)"

# 3. Каталог данных; контейнер работает под UID 65534 (nobody).
sudo mkdir -p /var/lib/khrazhevnik
sudo chown 65534:65534 /var/lib/khrazhevnik

# 4. Перезагрузить генератор и стартовать.
systemctl --user daemon-reload
systemctl --user start khrazhevnik.service
systemctl --user status khrazhevnik.service
```

`AutoUpdate=registry` в quadlet включает автообновление образа через
`podman auto-update` (таймер `podman-auto-update.timer`). Для пинов к
конкретной версии замените тег в `Image=` и уберите `AutoUpdate=`.

Проверка: `curl -s http://localhost:29202/healthz` → `ok`;
`curl -s http://127.0.0.1:30202/api/v1/` → JSON с `service: khrazhevnik`.

## Запуск через Docker

Тот же образ поднимается чистым docker — podman и systemd не нужны.
Готовый compose-файл — `deploy/docker-compose.yml` (порты, read-only
rootfs, volume и stop-timeout повторяют quadlet):

```sh
# 1. Конфиг + JWT-секрет в .env (рядом с compose-файлом; в git не коммитить).
cp deploy/docker-compose.yml docker-compose.yml
echo "KHRZ_AUTH__JWT_SECRET=$(openssl rand -hex 32)" > .env

# 2. Каталог данных: контейнер работает под UID 65534 (nobody).
sudo mkdir -p /var/lib/khrazhevnik
sudo chown 65534:65534 /var/lib/khrazhevnik

# 3. Старт.
docker compose up -d
curl -s http://localhost:29202/healthz   # → ok
```

То же одним `docker run` (секрет генерируется при создании контейнера
и живёт до его пересоздания — для стабильных сессий используйте
compose с `.env`):

```sh
docker run -d --name khrazhevnik \
  -p 29202:29202 -p 127.0.0.1:30202:30202 \
  --read-only \
  -v /var/lib/khrazhevnik:/var/lib/khrazhevnik \
  -e KHRZ_AUTH__JWT_SECRET="$(openssl rand -hex 32)" \
  --stop-timeout 40 \
  --restart on-failure \
  git.yadr00.internal/build/khrazhevnik:latest
```

Отличия от quadlet: JWT-секрет передаётся env из `.env` (Podman Secret
недоступен) — значение видно в `docker inspect`, держите `.env` вне
git и backup'ов; для пина версии замените тег на `vX.Y.Z`. Публикация
на 80/443 и TLS — через reverse-proxy
([reverse-proxy.md](reverse-proxy.md)).

## Запуск из бинарника (systemd)

Бинарник статический (`CGO_ENABLED=0`, sqlite — pure Go), рантайм-
зависимостей нет — только каталог данных и env с секретом. Релизные
артефакты `khrazhevnik-<version>-linux-amd64` + `.sha256` публикуются
CI в Releases (Forgejo/GitHub/Codeberg, см. [RELEASE.md](../../RELEASE.md));
для иных платформ — сборка из исходников
([README](../../README.md#сборка-из-исходников)).

```sh
# 1. Скачать артефакт из Release и сверить чексумму.
curl -fLO <url-release>/khrazhevnik-vX.Y.Z-linux-amd64
curl -fLO <url-release>/khrazhevnik-vX.Y.Z-linux-amd64.sha256
sha256sum -c khrazhevnik-vX.Y.Z-linux-amd64.sha256

# 2. Установить бинарник.
sudo install -m 0755 khrazhevnik-vX.Y.Z-linux-amd64 /usr/local/bin/khrazhevnik

# 3. Системный пользователь и каталог данных (sqlite, fs-store, ключи).
sudo useradd --system --user-group --home-dir /var/lib/khrazhevnik --no-create-home khrazhevnik
sudo install -d -o khrazhevnik -g khrazhevnik /var/lib/khrazhevnik

# 4. Env-файл: JWT-секрет и loopback-админка — голый бинарник без
#    конфига слушает :30202 на всех интерфейсах (warn в логе).
sudo install -d -m 0750 /etc/khrazhevnik
sudo sh -c 'umask 077; printf "KHRZ_AUTH__JWT_SECRET=%s\nKHRZ_SERVER__ADMIN_LISTEN=127.0.0.1:30202\n" "$(openssl rand -hex 32)" > /etc/khrazhevnik/khrazhevnik.env'

# 5. Юнит и старт.
sudo cp deploy/systemd/khrazhevnik.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now khrazhevnik
curl -s http://localhost:29202/healthz   # → ok
```

Готовый юнит — `deploy/systemd/khrazhevnik.service`: `TimeoutStopSec=40`
под каскад graceful shutdown (SIGTERM → HTTP 5с → задачи 30с — тот же
запас, что `StopTimeout=40` в quadlet) и hardening
(`ProtectSystem=strict`, writable только `/var/lib/khrazhevnik`,
`NoNewPrivileges`, пустой `CapabilityBoundingSet` — порты ≥1024).
Env-файл читает systemd от root — `0600 root:root` достаточно.
Для TOML-конфига — drop-in:

```sh
sudo systemctl edit khrazhevnik
# [Service]
# ExecStart=
# ExecStart=/usr/local/bin/khrazhevnik -config /etc/khrazhevnik/khrazhevnik.toml
```

Headless-bootstrap без контейнера — тот же флаг `-add-remote` (пишет
remote в БД и выходит; jwt_secret не нужен — CLI подставляет заглушку):

```sh
sudo -u khrazhevnik /usr/local/bin/khrazhevnik -add-remote apt/debian=https://deb.debian.org/debian
```

Другой процесс-супервизор (OpenRC, runit, supervisord) или запуск
вручную: достаточно env `KHRZ_AUTH__JWT_SECRET` и writable-каталога
данных — `khrazhevnik [-config <путь>]`; флаги: `-version`,
`-add-remote`. Дальше — общий для всех способов
[bootstrap](#первый-запуск-bootstrap) и настройка клиентов.

## Первый запуск: bootstrap

Каталог БД пуст → откройте `http://127.0.0.1:30202/ui/` — веб-админка
сама предложит создать первого админа ([ui.md](ui.md)). Те же шаги
через API: создать админа через `/api/v1/setup`, затем добавить
upstream'ы (remotes). Альтернатива для headless — флаг `-add-remote`
(пишет remote в БД без поднятия сервера).

```sh
# 1. Первый админ (один раз, пока таблица users пуста).
curl -s -X POST http://127.0.0.1:30202/api/v1/setup \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<пароль>"}'

# 2. Логин — получаем JWT сессии админки.
TOKEN=$(curl -s -X POST http://127.0.0.1:30202/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<пароль>"}' | jq -r .token)

# 3. Регистрируем upstream (кеш-прокси Debian apt).
curl -s -X POST http://127.0.0.1:30202/api/v1/remotes \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"debian","ecosystem":"apt","base_url":"https://deb.debian.org/debian","mode":"proxy","enabled":true}'
```

То же флагом, без запущенного сервера (CI/init-скрипты):

```sh
podman exec khrazhevnik /khrazhevnik -add-remote apt/debian=https://deb.debian.org/debian
```

Все 5 экосистем включены по умолчанию — отдельное env-включение не
нужно. 404 на `/<eco>/*` означает либо выключенную экосистему
(`KHRZ_ECOSYSTEM__<ИМЯ>__ENABLED=false`), либо remote с таким именем
не зарегистрирован.

## Настройка клиентов на прокси

Хражевник прозрачен: путь после `/<remote-name>/` пробрасывается
upstream'у побайтово, подписи и чексуммы остаются валидны — keyring
клиента не меняется. Примеры (полные страницы с mirror/include — в
[ecosystems/](ecosystems/)):

### apt (Debian/Ubuntu)

`/etc/apt/sources.list.d/khrazhevnik.list`:

```
deb http://<хражевник>:29202/apt/debian stable main
```

### dnf / Zypper (rpm-md)

`/etc/yum.repos.d/khrazhevnik.repo` (dnf) или
`/etc/zypp/repos.d/khrazhevnik.repo` (zypper). URL-префикс rpm-md —
`rpm` (короче имени адаптера `rpm-md`, как пишут в `.repo` baseurl).

```ini
[khrazhevnik-fedora]
name=khrazhevnik proxy of Fedora
baseurl=http://<хражевник>:29202/rpm/fedora/releases/$releasever/Everything/$basearch/os/
enabled=1
gpgcheck=1
```

### pacman / apk / nix

`Server = http://<хражевник>:29202/pacman/<remote>/$repo/os/$arch`,
строка в `/etc/apk/repositories`, `substituters` в `nix.conf` — см.
[ecosystems/pacman.md](ecosystems/pacman.md),
[ecosystems/apk.md](ecosystems/apk.md), [ecosystems/nix.md](ecosystems/nix.md).

## Свой TOML-конфиг (опционально)

По умолчанию контейнер работает на defaults + env (порт, fs, sqlite,
экосистемы — всё из env). Для расширенного конфига смонтируйте TOML и
передайте `-config` через `Exec=` в drop-in quadlet:

```sh
mkdir -p ~/.config/containers/systemd/khrazhevnik.container.d
cat > ~/.config/containers/systemd/khrazhevnik.container.d/10-config.conf << 'EOF'
[Container]
Mount=type=bind,source=/etc/khrazhevnik/khrazhevnik.toml,destination=/etc/khrazhevnik/khrazhevnik.toml,readonly=true
Exec=-config /etc/khrazhevnik/khrazhevnik.toml
EOF
systemctl --user daemon-reload
systemctl --user restart khrazhevnik.service
```

Схема TOML и env (секреты `file://`, все ключи и дефолты) — в
[config.md](config.md); канон для разработчиков — в
[docs/SPECIFICATION.md](../../SPECIFICATION.md#Конфигурация).

> **Строгий разбор TOML.** Неизвестный или опечатанный ключ — ошибка
> запуска с именем ключа и строкой файла, например:
> `неизвестные ключи TOML — опечатка или лишний ключ: "auth.session_tt" (строка 3)`.
> Ранее лишние ключи молча игнорировались: при обновлении с прежних
> версий уберите их из конфига или исправьте опечатки. Env-слой
> (`KHRZ_*`) не изменился.

## Сборка образа локально

```sh
make image                      # нативная платформа, тег dev
make image TAG=v0.1.0           # с версией
make image PLATFORMS=linux/amd64,linux/arm64 TAG=v0.1.0  # multi-arch (нужен qemu-user-static)
make smoke                      # дымовой тест собранного образа
```

## Выбор хранилища и БД

Дефолт (fs + sqlite) — KISS для homelab. Для прода — S3 + postgres/
mariadb: пример quadlet — `deploy/quadlet/khrazhevnik-s3.container`.
Подробности и рекомендации — в [storage-db.md](storage-db.md).
