<!--
Хражевник — кеш-прокси и зеркало linux-репозиториев
Copyright (C) 2026 AlexRus1234

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
-->

**Русский** | [English](README.en.md) |

<div align="center">

<h1>Хражевник</h1>

**Кеш-прокси, зеркало и хостинг linux-репозиториев**

Хражевник представляет собой автономный сервер кеширования и
зеркалирования пакетных репозиториев Linux. Go-бинарник и встроенная
веб-админка (Vue 3) объединены в одном исполняемом файле; хранилище
объектов — локальный каталог или любое S3-совместимое, каталог —
SQLite, PostgreSQL или MariaDB, выбор — TOML-конфигом без пересборки.
Первичная дистрибуция — OCI-контейнер из `scratch` (non-root,
read-only rootfs) под rootless podman quadlet.

[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg?style=flat-square)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8.svg?style=flat-square)](https://go.dev/)
[![Vue](https://img.shields.io/badge/Vue-3-4FC08D.svg?style=flat-square)](https://vuejs.org/)
[![Vite](https://img.shields.io/badge/Vite-7-646CFF.svg?style=flat-square)](https://vite.dev/)
[![Platform](https://img.shields.io/badge/Linux-any-1793D1.svg?style=flat-square)](#быстрый-старт)
[![CI](https://img.shields.io/badge/CI-Forgejo%20Actions-ff7b00.svg?style=flat-square)](.forgejo/workflows/build.yml)

</div>

> **Прозрачность для клиентов.** Метаданные upstream отдаются
> **побайтово** — ни байта переписывания: подписи и чексуммы остаются
> валидными, keyring клиентов не меняется:
>
> ```bash
> # /etc/apt/sources.list.d/khrazhevnik.list
> deb http://<хражевник>:29202/apt/debian stable main
> ```
>
> Хражевник лишь добавляет сверху кеш (пакеты — навсегда, индексы —
> ревалидация по ETag/Last-Modified), фоновые зеркала и личные
> подписанные репозитории пользователей.

---

## Содержание

- [Возможности](#возможности)
- [Быстрый старт](#быстрый-старт)
- [Конфигурация](#конфигурация)
- [Развёртывание и безопасность](#развёртывание-и-безопасность)
- [API и веб-админка](#api-и-веб-админка)
- [Структура проекта](#структура-проекта)
- [Технологический стек](#технологический-стек)
- [Разработка](#разработка)
- [Планы](#планы)
- [Лицензия](#лицензия)

> Расширенная документация по развёртыванию, конфигурации, REST API,
> клиентам экосистем и личным репозиториям приведена в каталоге
> [`docs/func/ru/`](docs/func/ru/quickstart.md). Настоящий файл содержит
> обзор системы и инструкцию по первоначальному запуску.

Проект разработан в соответствии с заранее определённой архитектурой; при
подготовке исходного кода использовался ИИ-ассистент.[^1]

---

## Возможности

### Кеш-прокси

- Прозрачный pull-through для поддерживаемых пакетных менеджеров:
  первый запрос к объекту уходит upstream, ответ складывается в кеш и
  дальше отдаётся локально (`X-Cache: HIT`)
- Классификация объектов по правилам экосистемы: пакеты и
  content-addressed объекты — immutable (навсегда); индексы (`dists/`,
  `repodata/`, `APKINDEX`, `{repo}.db`, narinfo) — mutable с
  conditional revalidate по ETag/Last-Modified и TTL
- `stale-if-error` (опционально) и отрицательное кеширование 404/5xx в
  памяти: upstream-отказ не транслируется клиентам
- Singleflight на ключ: параллельные запросы одного объекта не бьют в
  upstream; лимит размера кешируемого объекта (`cache.max_object_size`)

### Зеркало

- Полная локальная копия upstream-репозитория (`mode = mirror`): фоновый
  sync с worker pool, retry и bandwidth-лимитом (token-bucket)
- Идемпотентный resume: каждый запуск сравнивает перечень upstream с
  имеющимися объектами и докачивает недостающее; прогресс — в каталоге
  (`files=N;bytes=M`), состояние задачи переживает рестарт
- Планировщик per-remote: `sync_interval` ± случайный jitter; ручной
  запуск — через API или веб-админку (409 на дубль, 429 на лимит
  воркеров)
- Include-фильтры: apt — dists и компоненты (`stable`, `stable/main`);
  pacman — `repo/arch`; apk — архитектуры

### Личные репозитории

- Upload пакетов пользователями: стрим прямо в хранилище с обязательным
  `Content-Length` и сверкой байтов на лету (abort чистит `tmp/`)
- RBAC: admin — везде; владелец репо и scoped-токен `repo:<id>:write` —
  upload/delete/reindex/list; чтение публичное без auth
- Квоты `bytes`/`files` на репозиторий, лимит одного объекта,
  перезапись существующего ключа — 409 (`force` — только админ, с
  аудитом)
- Генерация индексов фоновой задачей reindex (apt: `Packages` + `.gz`,
  `by-hash/SHA256/*`, `Release`)
- Подпись ключом инстанса (OpenPGP ed25519): `InRelease` (cleartext) и
  `Release.gpg` (detached); для nix — переподпись narinfo (заменяется
  только поле `Sig`, остальное байт-точно); при недоступном подписчике
  репо работают без подписи
- Публичный ключ — `GET /repo/<name>/key.asc` на публичном порту

### Экосистемы

| Экосистема | Клиенты | URL-префикс | Зеркало |
|---|---|---|---|
| **apt** | Debian, Ubuntu | `/apt/` | да (+ include-фильтр) |
| **rpm-md** | dnf, Zypper | `/rpm/` | да |
| **pacman** | Arch Linux | `/pacman/` | да (+ include-фильтр) |
| **apk** | Alpine Linux | `/apk/` | да (+ include-фильтр) |
| **nix** | binary cache | `/nix/` | нет — только pull-through «по использованию» |

Парсеры метаданных всех экосистем (deb822, repomd/primary XML, tar.zst
`{repo}.db`, `APKINDEX.tar.gz`, narinfo) — streaming, с декомпресс-лимитом
и фаззингом с первого адаптера.

### Интерфейсы и безопасность

- Два слушателя: публика `:29202` (раздача пакетов без auth +
  `/healthz`), админка `:30202` (`/api/v1`, `/metrics`, SPA `/ui`).
  Дефолт `:30202` — все интерфейсы (старт пишет warning в лог);
  loopback обеспечивает quadlet (`PublishPort=127.0.0.1:30202:30202`)
- Веб-админка (Vue 3, русский/английский): дашборд со статистикой кеша и
  живыми задачами, remotes, репозитории с upload/reindex, пользователи и
  scoped-токены, аудит-журнал, публичные ключи с готовыми строками
  клиентов (`signed-by=…`, `rpm --import`, `pacman-key --add`, …)
- Аутентификация: JWT-сессии (bcrypt, rate-limit 10/min на логин,
  отзыв при logout) и scoped API-токены (хранится только sha256,
  показывается один раз); роль и `token_version` сверяются с БД на
  каждом запросе
- Аудит всех мутаций (actor/action/object/result/detail) с keyset-пагинацией
- Метрики Prometheus (`/metrics`, за auth): hits/misses/stale/negative по
  экосистемам, байты от upstream/клиентам, гистограммы длительности и
  размеров объектов
- Единая точка path-traversal для всех путей из запросов

Подробное описание приведено в [`docs/func/ru/`](docs/func/ru/).

---

## Быстрый старт

### Требования

| Компонент | Версия | Назначение |
|---|---|---|
| **podman** | 4+ | Rootless-контейнер, quadlet |
| **systemd --user** | — | Генератор quadlet |
| **OpenSSL** | — | Генерация JWT-секрета |
| **Go** | 1.26+ | Сборка из исходников (опционально) |
| **Node.js** | 22+ | Сборка Web UI (опционально) |

### Установка (контейнер)

```bash
# 1. Quadlet — в пользовательский путь генератора systemd.
mkdir -p ~/.config/containers/systemd
cp deploy/quadlet/khrazhevnik.container ~/.config/containers/systemd/

# 2. JWT-секрет — Podman Secret (не светится в env и `systemctl show`).
podman secret create jwt-secret "$(openssl rand -hex 32)"

# 3. Каталог данных: контейнер работает под UID 65534 (nobody).
sudo mkdir -p /var/lib/khrazhevnik
sudo chown 65534:65534 /var/lib/khrazhevnik

# 4. Старт.
systemctl --user daemon-reload
systemctl --user start khrazhevnik.service
curl -s http://localhost:29202/healthz   # → ok
```

### Bootstrap и первый remote

При пустой таблице `users` веб-админка `http://127.0.0.1:30202/ui/`
сама предложит создать первого админа; далее upstream'ы и личные репо
настраиваются из UI. Те же шаги через API:

```bash
# Первый админ (один раз, пока таблица users пуста).
curl -s -X POST http://127.0.0.1:30202/api/v1/setup \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<пароль>"}'

# Логин → JWT; регистрируем кеш-прокси Debian.
TOKEN=$(curl -s -X POST http://127.0.0.1:30202/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<пароль>"}' | jq -r .token)

curl -s -X POST http://127.0.0.1:30202/api/v1/remotes \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"debian","ecosystem":"apt","base_url":"https://deb.debian.org/debian","mode":"proxy","enabled":true}'
```

Headless-альтернатива для init-скриптов (без поднятия сервера):

```bash
podman exec khrazhevnik /khrazhevnik -add-remote apt/debian=https://deb.debian.org/debian
```

### Настройка клиента

На любой Debian/Ubuntu-машине укажите Хражевник вместо upstream:

```bash
echo 'deb http://<хражевник>:29202/apt/debian stable main' \
  > /etc/apt/sources.list.d/khrazhevnik.list
apt-get update && apt-get install hello
```

Подписи и чексуммы валидны: метаданные upstream отдаются побайтово.
Проверка кеша: повторный запрос к `dists/…/Packages.gz` возвращает
`X-Cache: HIT`. Клиенты dnf/zypper, pacman, apk и nix — в
[`docs/func/ru/ecosystems/`](docs/func/ru/ecosystems/).

### Сборка из исходников

```bash
# Web UI и серверная часть в порядке, используемом CI:
make web-build
make build        # исполняемый файл bin/khrazhevnik
```

CGO не требуется (SQLite — `modernc.org/sqlite`), исполняемый файл
статический. Сборка для рабочей среды (как в CI):

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags="-s -w \
  -X main.Version=1.0.0" \
  -o khrazhevnik ./cmd/khrazhevnik
```

> Для package main линкер принимает только `-X main.Version=…`;
> полный import path (`khrazhevnik/cmd/khrazhevnik.Version`) молча
> не применяется — версия останется `dev` (как в CI и Containerfile).

> Релизные бинарники (`khrazhevnik-<version>-linux-amd64` + `.sha256`) и
> OCI-образ публикуются вручную из CI в Packages и Releases подключённых
> реестров. Для разработки — сборка из исходного кода.

Пошаговое руководство — в [`docs/func/ru/quickstart.md`](docs/func/ru/quickstart.md).

---

## Конфигурация

`khrazhevnik.toml` (флаг `-config`; пустое значение — только
defaults + env):

```toml
[server]
public_listen = ":29202"        # раздача пакетов + /healthz
admin_listen  = ":30202"        # /api/v1, /metrics, /ui

[storage]
driver = "fs"                   # fs | s3
[storage.fs]
path = "/var/lib/khrazhevnik/store"
[storage.s3]
endpoint = "" ; region = "" ; bucket = "" ; path_style = true

[database]
driver = "sqlite"               # sqlite | postgres | mariadb
dsn    = "/var/lib/khrazhevnik/khrazhevnik.db"

[auth]
jwt_secret   = ""               # НЕ в проде-файле: env/file (обязателен)
session_ttl  = "8h"
setup_token  = ""               # опц. защита bootstrap первого админа

[cache]
stale_if_error  = true
max_object_size = "20GiB"
negative_ttl_404 = "5m" ; negative_ttl_5xx = "30s"

[mirror]
workers = 4 ; interval_jitter = "10m"

[publish]
max_object_size    = "1GiB"     # лимит одного загружаемого объекта
default_quota_bytes = "5GiB"    # квота нового репо (0 = без лимита)
default_quota_files = 10000

[signing]
keys_dir = "/var/lib/khrazhevnik/keys"   # ed25519-ключ инстанса
# passphrase = ""              # опц.: env KHRZ_SIGNING__PASSPHRASE

[metrics]
enabled = true

[ecosystem.apt]                 # apt | rpm-md | pacman | apk | nix;
enabled = true                  # секция нужна только для переопределения
```

Слои применения: **defaults → TOML → env**. Env-префикс `KHRZ_`,
сегменты пути — через `__`, верхний регистр: `KHRZ_AUTH__JWT_SECRET`,
`KHRZ_STORAGE__S3__SECRET_ACCESS_KEY`, `KHRZ_ECOSYSTEM__RPM_MD__ENABLED`.
Значения вида `file:///run/secrets/x` (env или TOML) читаются из файла —
поддержка quadlet Secret. Валидация fail-fast со списком всех проблем
сразу. Полная схема — в [`docs/func/ru/config.md`](docs/func/ru/config.md).

---

## Развёртывание и безопасность

Основная дистрибуция — OCI-образ из `scratch`: бинарник + CA-bundle,
`USER 65534:65534`, read-only rootfs, writable — только volume
`/var/lib/khrazhevnik` (SQLite, fs-store, ключи подписи). Бинарник —
PID 1, сабпроцессов нет (OpenPGP in-process), зумби-реапер не нужен;
graceful shutdown: SIGTERM → HTTP 5с → фоновые задачи 30с.

| Порт | Доступ | Назначение |
|---|---|---|
| 29202 | публичный | раздача пакетов (`/<eco>/<remote>/<путь>`, `/repo/<name>/*`), `/healthz` |
| 30202 | все интерфейсы (дефолт; warn при старте — loopback через PublishPort quadlet'а) | админ-API `/api/v1`, `/metrics`, веб-админка `/ui` |

Rootless-режим: оба порта ≥1024; публикация на 80/443 — через
reverse-proxy на хосте. `AutoUpdate=registry` в quadlet включает
автообновление образа через `podman auto-update`. Дефолт (fs + sqlite) —
для homelab; для прода — S3 + postgres/mariadb (пример quadlet —
`deploy/quadlet/khrazhevnik-s3.container`, рекомендации — в
[`docs/func/ru/storage-db.md`](docs/func/ru/storage-db.md)).

Альтернатива контейнеру — голый бинарник под systemd или любым
процесс-супервизором; JWT-секрет передаётся env
`KHRZ_AUTH__JWT_SECRET=file:///run/secrets/jwt-secret`.

Полное руководство по развёртыванию — в
[`docs/func/ru/deploy.md`](docs/func/ru/deploy.md).

---

## API и веб-админка

| Интерфейс | Кратко | Подробности |
|---|---|---|
| **REST API** | `/api/v1`: setup/login, remotes, repos (+objects/perms/reindex), users, api-tokens, tasks, cache/stats, audit; ошибки — `{"error":"snake_case"}` | [`docs/func/ru/api.md`](docs/func/ru/api.md) |
| **Веб-админка** | `/ui/` на админском порту; RU/EN; встроена в бинарник (`go:embed`) | [`docs/func/ru/ui.md`](docs/func/ru/ui.md) |
| **Метрики** | `/metrics` (Prometheus exposition, за auth) | [`docs/func/ru/api.md`](docs/func/ru/api.md) |
| **Личные репо** | upload по токену, reindex, подпись, настройка клиентов | [`docs/func/ru/personal-repos.md`](docs/func/ru/personal-repos.md) |

Аутентификация админ-API: `Authorization: Bearer <jwt>` (браузер) или
scoped API-токен `Bearer khz_...` (CI-скрипты: `admin`,
`repo:<id>:write`).

---

## Структура проекта

```
.
├── cmd/khrazhevnik/          # Точка входа: main.go (~40 строк), wire.go —
│                            # единственная склейка (compile-time реестр)
├── internal/
│   ├── core/
│   │   ├── port/             # Контракты: Storage, Ecosystem, Catalog*, Signer, Clock, Rand, HTTP
│   │   ├── domain/           # Модели + типизированные ошибки (только stdlib)
│   │   ├── config/           # Слои: defaults → TOML → env KHRZ_* (+file://-секреты)
│   │   ├── dbtalk/           # Шим SQL-диалектов каталога (placeholder/upsert)
│   │   ├── engine/           # Usecase-логика: cache, mirror, publish, auth
│   │   ├── registry/         # Compile-time реестр модулей
│   │   └── web/              # chi-роутеры, middleware, TaskRegistry, embed SPA
│   ├── mod/                  # Модули (регистрируются в init()): ecosystem/
│   │                        # {apt, rpmmmd, pacman, apk, nix}, storage/{fs, s3},
│   │                        # db/{sqlite, postgres, mariadb}, sign/{openpgp, ed25519}
│   ├── testutil/             # Общие test doubles (FixedClock, FakeStorage, …)
│   └── contract/             # Контрактные suite каталога/хранилища (integration)
├── migrations/<driver>/      # Embedded goose-миграции (по каталогу на СУБД)
├── web/                      # Vue 3 + Vite + TypeScript SPA (бандл → core/web/assets)
├── deploy/                   # Containerfile (node → golang → scratch) + quadlet/
├── test/                     # integration/ (in-process + binary-smoke), smoke/
├── docs/                     # ARCHITECTURE/SPECIFICATION/TESTING/ROADMAP; func/ru/
└── .forgejo/workflows/       # CI: сборка, тесты, e2e, OCI
```

Бизнес-логика (`core/domain`, `core/engine`) не импортирует `os`,
`syscall`, `net`, `net/http` и конкретные модули — весь ввод-вывод через
интерфейсы `core/port`; ядро и модули не знают друг о друге, склейка —
только в `wire.go`. Правила проверяются линтером `depguard`.

---

## Технологический стек

**Бэкенд:** Go 1.26 · chi v5 · pelletier/go-toml/v2 · modernc.org/sqlite
(без CGO) · jackc/pgx/v5 · go-sql-driver/mysql · pressly/goose/v3 ·
golang-jwt/jwt/v5 · golang.org/x/crypto (bcrypt) · golang.org/x/sync
(singleflight) · golang.org/x/time (rate) · ProtonMail/go-crypto
(OpenPGP) · minio/minio-go/v7 · klauspost/compress (zstd) ·
prometheus/client_golang · `log/slog` · `go:embed`.

**Фронтенд:** Vue 3 (Composition API) · vue-router 4 · Vite 7 ·
TypeScript 5.9 (vue-tsc).

**Инфраструктура и качество:** Forgejo Actions (CI) · golangci-lint
(строгий конфиг, depguard слоёв) · `go vet` / `gofmt` ·
unit- / integration- / binary-smoke-уровни тестов · фаззинг парсеров
чужих форматов · Playwright E2E (опционально) · podman (OCI из scratch,
multi-arch).

---

## Разработка

| Команда | Назначение |
|---|---|
| `make lint` | `golangci-lint run ./...` (строгий конфиг) |
| `make vet` | `go vet ./...` |
| `make test` | `go test ./...` |
| `make test-race` | `go test -race ./...` |
| `make test-integration` | `go test -race -tags integration ./test/integration/...` |
| `make cover` | Отчёт о покрытии |
| `make build` | Сборка `bin/khrazhevnik` |
| `make web-build` | Vite-сборка Web UI в `internal/core/web/assets/` |
| `make web-dev` | Dev-сервер Vite с прокси `/api` на `:30202` |
| `make image` | OCI-образ из `deploy/Containerfile` (`PLATFORMS`, `TAG`) |
| `make smoke` | Дымовой тест живого контейнера (локально, перед релизом) |
| `make clean` | Удалить `bin/`, `coverage/`, восстановить заглушку web-assets |

При новом клонировании репозитория сначала срабатывает заглушка
web-assets (Go-команды собираются без фронтенда); реальный бандл —
`make web-build`. Все тесты прогоняются в CI (Forgejo Actions):
контрактные suite на postgres/mariadb/minio, binary-smoke собранного
артефакта, опциональные `-race` и Playwright E2E.

Документация для разработчиков (порядок чтения перед правками):

1. [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — слои, правила импортов, инварианты движков.
2. [docs/SPECIFICATION.md](docs/SPECIFICATION.md) — требования, REST API, схема БД.
3. [docs/TESTING.md](docs/TESTING.md) — стратегия тестирования.
4. [docs/ROADMAP.md](docs/ROADMAP.md) — план и история этапов.

---

## Планы

Направления развития после релиза v1.0.0 (eviction старых версий и
прочие пост-v1 вопросы — в [docs/ROADMAP.md](docs/ROADMAP.md)).
Приоритет: сначала XBPS и
pkg — их модель «каталог + индекс» повторяет уже решённые задачи;
Flatpak требует новой механики публикации и идёт последним.

Каждая новая экосистема — адаптер `port.Ecosystem`: классификация
объектов (immutable/mutable), парсер метаданных, перечисление для
зеркала, генератор индексов личных репо — без изменений ядра и
контрактов. Критерий приёмки прежний: byte-exact прокси метаданных,
зеркало с resume, личные репо с подписью, фаззинг парсера, реальный
клиент в проверке.

### Void Linux (XBPS)

Репозиторий — каталог вида `current/<arch>/`: пакеты `.xbps` и индекс
`repodata` с подписью `.sig2` (ed25519). Классификация прямая: пакеты
immutable и хранятся навсегда, `repodata` — mutable с ревалидацией по
ETag/Last-Modified. Зеркало — рекурсивная копия каталога; resume и
include-фильтры по архитектурам ложатся на существующую механику
(аналог apk).

Работы по адаптеру: streaming-парсер repodata (собственный архивный
формат с plist-метаданными внутри) — для зеркала, статистики и
детекции неиндексных объектов; генератор repodata для личных репо —
функциональный аналог `xbps-rindex`; подпись `.sig2` — формат,
отличный и от OpenPGP, и от ed25519-ключа инстанса, — отдельный
Signer-адаптер (контракт `port.Signer` это допускает). Void-клиент
доступен в контейнерной матрице distro-test — автоматическая проверка
реальным `xbps-install` возможна наравне с пятью текущими экосистемами.

### pkg (FreeBSD, OpenBSD)

FreeBSD pkg(8): репозиторий — каталог с `meta.conf`, архивами
`packagesite.txz`/`digests.txz` (YAML-метаданные) и пакетами
`.pkg`/`.txz`. Индексы mutable, пакеты immutable; подпись репозитория —
RSA-ключ, публикуемый в конфиге клиента. Для личных репо — генератор
`packagesite`+`digests` и третий формат ключа (RSA) в signing-модуле.

OpenBSD pkg_add(7): общего индексного файла нет — метаданные каждого
пакета лежат внутри него самого, зависимости клиент разрешает сам;
репозиторий — просто каталог `packages/<arch>/`. Для кеш-прокси это
самый простой из возможных случаев: все объекты immutable,
отрицательное кеширование и singleflight работают вовсе без парсера;
зеркало — точная копия каталога.

Ограничение обоих: клиенты не Linux, CI-раннер (Linux-контейнеры) их
не покрывает — приёмочная проверка остаётся ручной по чеклисту
RELEASE.md; VM или отдельный раннер — открытый вопрос.

### Flatpak

Репозиторий Flatpak — хранилище OSTree: подписанный `summary`,
контент-адресованные объекты (sha256, zstd-упаковка), статические
дельты. Инвариант byte-exact выполняется естественным образом: объекты
immutable навсегда, `summary`/`summary.sig` — mutable с ревалидацией;
зеркало — рекурсивная HTTP-копия хранилища.

Личные репо — самая сложная из трёх задач, этап отложен отдельно:
публикация — это создание OSTree-коммитов (`flatpak build-export` +
`build-update-repo`), а не загрузка готовых артефактов; первым этапом
Flatpak ограничится прокси и зеркалом. Подпись — GPG, по формату
совпадает с OpenPGP-адаптером. Открытые вопросы: поведение клиентов при
неполном наборе дельт на зеркале, диапазонные запросы к pack-файлам,
целесообразность GC нессылаемых объектов.

---

## Лицензия

Проект распространяется под лицензией **[GNU Affero General Public License v3.0](LICENSE)**
или более поздней.

```
Хражевник — кеш-прокси и зеркало linux-репозиториев
Copyright (C) 2026  AlexRus1234

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
```

[^1]: Разработка исходного кода выполнялась с использованием ИИ-ассистента в
соответствии с заранее определённой архитектурой проекта; архитектурные решения,
проверка результатов и итоговая интеграция осуществлялись автором.
