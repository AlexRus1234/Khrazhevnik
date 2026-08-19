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

# Спецификация

Скелет; дополняется по мере реализации (REST API — пока placeholder).

## Назначение

Хражевник — кеш-прокси и зеркало linux-репозиториев с личными
репозиториями пользователей. Один Go-бинарник + Vue 3 SPA, основная
дистрибьюция — OCI-контейнер под rootless podman quadlet.

## Три функции

1. **Кеш-прокси** — прозрачный pull-through для поддерживаемых пакетных
   менеджеров: первый запрос к объекту уходит upstream, ответ
   складывается в кеш и дальше отдаётся локально (метаданные —
   побайтово, без переписывания).
2. **Зеркало** — полный локальный копия upstream-репозитория, фоновый
   sync с resume по etag/size.
3. **Личные репо** — upload пакетов пользователями по scoped-токенам,
   генерация и OpenPGP-подпись метаданных.

Поддерживаемые экосистемы v1: apt; rpm-md (dnf + zypper одним
адаптером); pacman; apk; nix.

## Порты

| Порт  | Назначение                                                          |
|-------|---------------------------------------------------------------------|
| 29202 | Публика: раздача пакетов (без auth) + `GET /healthz`. Переопределяется конфигом. |
| 30202 | Админка: `/api/v1` (auth), `/metrics` (Prometheus, за auth), SPA `/ui`. Переопределяется конфигом. |

## Конфигурация

TOML-файл (флаг `-config`, по умолчанию `khrazhevnik.toml`; пустое
значение — только defaults+env) + env-слой. Слои: **defaults → TOML →
env**. Пакет `internal/core/config`.

```toml
[server]
public_listen = ":29202"
admin_listen = ":30202"

[storage]
driver = "fs"                    # fs | s3
[storage.fs]
path = "/var/lib/khrazhevnik/store"
[storage.s3]
endpoint = "" ; region = "" ; bucket = "" ; path_style = true
access_key_id = "" ; secret_access_key = ""

[database]
driver = "sqlite"                # sqlite | postgres | mariadb
dsn = "/var/lib/khrazhevnik/khrazhevnik.db"

[auth]
jwt_secret = ""                  # НЕ в файле проде: env/file
session_ttl = "8h"
setup_token = ""

[cache]
mutable_ttl = "5m" ; stale_if_error = true
max_object_size = "20GiB"
negative_ttl_404 = "5m" ; negative_ttl_5xx = "30s"

[mirror]
workers = 4 ; interval_jitter = "10m"

[signing]
keys_dir = "/var/lib/khrazhevnik/keys"

[metrics]
enabled = true

[ecosystem.apt]                  # enabled = true + специфичные поля; аналогично
[ecosystem.rpm-md]               # rpm-md (или rpm_md), pacman, apk, nix
```

- Env: префикс `KHRZ_`, сегменты пути через `__` (двойное
  подчёркивание), верхний регистр, дефисы — подчёркиваниями:
  `KHRZ_SERVER__PUBLIC_LISTEN`, `KHRZ_STORAGE__S3__SECRET_ACCESS_KEY`,
  `KHRZ_AUTH__JWT_SECRET`, `KHRZ_CACHE__NEGATIVE_TTL_404`. Пустое
  значение env трактуется как «не задано».
- Записи `[ecosystem.<имя>]`: env может включать известные экосистемы
  (`apt`, `rpm-md`, `pacman`, `apk`, `nix`) и без упоминания в TOML:
  `KHRZ_ECOSYSTEM__RPM_MD__ENABLED=true`. В TOML ключи `rpm_md` и
  `"rpm-md"` эквивалентны (нормализация `_` → `-`).
- Значения вида `file:///run/secrets/x` (env или TOML) — читается
  содержимое файла, пробелы/переводы строк обрезаются (quadlet Secret).
- Duration-поля — строки `time.ParseDuration` (`"8h"`), размеры —
  `"20GiB"`/`"512MiB"`/`"1024"` (байты).
- Валидация fail-fast, список **всех** проблем сразу: `jwt_secret`
  непуст (env обязателен), драйверы из допустимых, duration/порты
  валидны, для выбранного драйвера обязательны его поля (у s3 —
  endpoint/region/bucket/ключи).
- Уровень логов — env `KHRZ_LOG_LEVEL` (`debug|info|warn|error`,
  default `info`), читается при старте.

## REST API (placeholder)

Детальные роуты и схемы ответов фиксируются по мере реализации.

- Публичный :29202 — пути экосистем (`/apt/...`, `/dnf/...`, ...),
  `GET /healthz`.
- Админ :30202 — `POST /api/v1/setup` (первый админ, только при пустой
  таблице users), `POST /api/v1/login`, управление remotes/repos/
  sync-задачами/токенами/пользователями, аудит, `GET /metrics`,
  SPA `/ui`.

## БД

Таблицы (миграция 0001, goose): `users`, `api_tokens`, `repos`,
`repo_perms`, `remotes`, `sync_jobs`, `audit_log`, `object_index`
(etag/expires mutable-объектов кеша). `schema_migrations` — служебная
таблица goose.

| Таблица        | Назначение                                        |
|----------------|---------------------------------------------------|
| `users`        | учётки админки (bcrypt, token_version)            |
| `api_tokens`   | scoped-токены (только sha256)                     |
| `repos`        | личные репозитории                                |
| `repo_perms`   | права на личные репо                              |
| `remotes`      | upstream'ы (зеркала/прокси)                       |
| `sync_jobs`    | sync-задачи зеркал (состояние, resume-данные)     |
| `audit_log`    | аудит мутаций (actor/action/object/result/detail) |
| `object_index` | etag/expires mutable-объектов кеша                |

Драйверы — плагин через TOML:

- sqlite: modernc (CGO-free), WAL, busy_timeout=5000, foreign_keys=ON,
  пул не 1 (мы сервер), retry при SQLITE_BUSY.
- postgres: jackc/pgx/v5/stdlib. mariadb: go-sql-driver/mysql.
- SQL переносимый: диалект-шим для placeholder и upsert;
  диалект-специфичные миграции — свои каталоги `migrations/<driver>/`.
