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
quadlet. Альтернатива — голый бинарник (CGO-free, static) под systemd
или любой процесс-супервизор. Быстрая установка — в
[quickstart.md](quickstart.md); эта страница — справочник развёртывания.

Контейнер слушает два порта:

| Порт  | Доступ          | Назначение                                      |
|-------|-----------------|-------------------------------------------------|
| 29202 | публичный       | раздача пакетов (`/<eco>/<remote>/<путь>`, `/repo/<name>/*`) + `/healthz` |
| 30202 | 127.0.0.1 only  | админ-API `/api/v1`, `/metrics`, веб-админка `/ui` |

Rootless: оба порта ≥1024, порты ниже 1024 — через reverse-proxy
nginx/caddy на хосте. Контейнер: `USER 65534:65534`, scratch (только
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

То же флагом (без сервера — удобно из CI/init-скрипта):

```sh
podman exec khrazhevnik /khrazhevnik -add-remote apt/debian=https://deb.debian.org/debian
```

Адаптер экосистемы должен быть включён (quadlet уже ставит
`KHRZ_ECOSYSTEM__APT__ENABLED=true`); иначе `/apt/*` отдаёт 404.

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
