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
- Записи `[ecosystem.<имя>]`: все 5 экосистем v1 (`apt`, `rpm-md`,
  `pacman`, `apk`, `nix`) включены в дефолтном конфиге (M2 — все
  экосистемы); секция в TOML нужна только чтобы переопределить
  (`enabled = false`) или задать специфичные поля. Env может включить
  известную экосистему и без упоминания в TOML:
  `KHRZ_ECOSYSTEM__RPM_MD__ENABLED=true`. В TOML ключи `rpm_md` и
  `"rpm-md"` эквивалентны (нормализация `_` → `-`). Сборка без
  blank-import'а нужного адаптера падает на старте с понятной ошибкой
  реестра.
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

## REST API

Админ-API (порт :30202) под корнем `/api/v1`. Аутентификация — JWT-
сессии (`Authorization: Bearer <jwt>`) или scoped API-токены
(`Bearer khz_...`); role/`token_version` сверяются с БД на каждом
запросе. Все ошибки — `{"error":"snake_case_code"}`; фронт маппит
в i18n (сессия 18). Мутации (не-GET) автоматом пишутся в аудит-лог
через `AuditMiddleware`: actor из auth-контекста, action из
`WithAuditAction` (или выводится из метода+пути), result по коду
ответа, detail из `WithAuditDetail`.

### Авторизация и bootstrap

| Метод | Путь                       | Auth        | Код | Назначение                          |
|-------|----------------------------|-------------|-----|-------------------------------------|
| POST  | `/api/v1/setup`            | — (пустая БД), `X-Setup-Token` | 201/403 | Первый админ |
| POST  | `/api/v1/auth/login`       | —           | 200/401 | Выдача JWT; rate-limit 10/min      |
| POST  | `/api/v1/auth/logout`      | session     | 204 | Отзыв JWT в процессе                |

### Управление upstream'ами

| Метод | Путь                       | Auth        | Код | Назначение                          |
|-------|----------------------------|-------------|-----|-------------------------------------|
| GET   | `/api/v1/remotes`          | admin       | 200 | Список remotes                      |
| POST  | `/api/v1/remotes`          | admin       | 201/400 | Создание remote                 |
| PATCH | `/api/v1/remotes/{id}`     | admin       | 200/404 | Обновление remote               |
| DELETE| `/api/v1/remotes/{id}`     | admin       | 204/404 | Удаление remote                 |
| POST  | `/api/v1/remotes/{id}/sync`| admin       | 202/409/429 | Запуск sync-задачи; 409 — дубль (kind,label), 429 — лимит воркеров |

Поля remote: `name` (slug, [a-z0-9._-]), `ecosystem` (`apt`, `rpm-md`,
…), `base_url` (http(s)://), `mode` (`proxy`|`mirror`), `enabled`
(bool), `sync_interval` (duration, 0 — только вручную), `include`
(массив строк: для apt — dists с опциональной компонентой, «stable»
или «stable/main»; для rpm-md/nix — не используется).

### Фоновые задачи

| Метод | Путь                       | Auth        | Код | Назначение                          |
|-------|----------------------------|-------------|-----|-------------------------------------|
| GET   | `/api/v1/tasks`            | admin       | 200 | Снимки всех задач (активные первыми)|
| GET   | `/api/v1/tasks/{id}`       | admin       | 200/404 | Снимок одной задачи            |

Снимок задачи: `{id, kind, label, state, phase, current, processed,
total, percent, speed_bps, logs, error, started_at, finished_at}`.
`logs` — последние 50 строк кольцевого буфера. TaskRegistry —
in-memory, не персистится; персистентное состояние sync-задач
(`sync_jobs`: state, last_run_at, cursor с прогрессом `files=N;bytes=M`)
пишут сами воркеры зеркал (сессия 11): одна sync_job на remote,
`cursor` кодирует прогресс, `state` ∈ pending|running|succeeded|failed.

### Учётные записи и токены

| Метод | Путь                                      | Auth   | Код | Назначение              |
|-------|-------------------------------------------|--------|-----|-------------------------|
| GET   | `/api/v1/users`                           | admin  | 200 | Список пользователей    |
| POST  | `/api/v1/users`                           | admin  | 201 | Создание пользователя   |
| DELETE| `/api/v1/users/{id}`                      | admin  | 204 | Удаление пользователя   |
| POST  | `/api/v1/users/{id}/api-tokens`           | admin  | 201 | Выпуск scoped-токена    |
| GET   | `/api/v1/users/{id}/api-tokens`           | admin  | 200 | Список токенов          |
| DELETE| `/api/v1/users/{id}/api-tokens/{tokenID}` | admin  | 204 | Отзыв токена            |

### Метрики и статистика

| Метод | Путь                       | Auth        | Код | Назначение                          |
|-------|----------------------------|-------------|-----|-------------------------------------|
| GET   | `/api/v1/cache/stats`      | admin       | 200 | hits/misses/hit_ratio/bytes         |
| GET   | `/api/v1/audit`            | admin       | 200 | keyset-пагинация: `after_id`, `limit`|
| GET   | `/metrics`                 | admin (session или `admin`-scoped токен) | 200 | Prometheus exposition |

Метрики Prometheus (`/metrics`): `khrazhevnik_cache_{hits,misses,
stale_served,negative_hits,upstream_errors}_total`,
`khrazhevnik_cache_bytes_{from_upstream,to_clients}_total` — глобально
и по экосистемам (`ecosystem` лейбл, суффикс `_ecosystem_`); две
гистограммы — `khrazhevnik_request_duration_seconds` (method, status)
и `khrazhevnik_object_bytes` (ecosystem).

### Коды ошибок

`not_found`, `conflict`, `forbidden`, `validation_error`, `too_large`,
`stale`, `task_duplicate`, `task_limit`, `invalid_json`, `setup_already_done`,
`invalid_setup_token`, `invalid_credentials`, `tasks_unavailable`, `internal`.

## Экосистемы

Реализованные экосистемы:

- **apt** (сессия 07) — кеш-прокси Debian/Ubuntu. Путь
  `/apt/<remote-name>/<остальной-путь>` маппится на upstream из таблицы
  `remotes`; `StorageKey` = `cache/apt/<remote-id>/<upstream-path>`.
  Классификация: пакеты под `pool/` и `by-hash/` — immutable; индексы
  `dists/` (Release, Packages*, Sources*, Contents-*, i18n/, dep11/,
  cnf/) — mutable{TTL 5m}; прочее — conservative mutable{TTL 1m}.
  Stanza-парсер RFC822 (deb822) для Packages/Release —
  `mod/ecosystem/apt/parse.go`, переиспользуется зеркалом (сессия 11)
  для Enumerate: Release → Components/Architectures → Packages-файлы
  → поле Filename. `Remote.Include` фильтрует dists и компоненты
  («stable», «stable/main»); пустой Include — ошибка (apt не имеет
  корневого индекса dists).
- **rpm-md** (сессия 08) — кеш-прокси Fedora/RHEL/openSUSE (один адаптер
  для dnf и Zypper — формат общий repomd). Путь
  `/rpm/<remote-name>/<остальной-путь>` (префикс «rpm», короче имени
  «rpm-md» — как пишут в .repo baseurl); `StorageKey` =
  `cache/rpm-md/<remote-id>/<upstream-path>`. Классификация: `*.rpm`,
  `*.drpm`, `*.src.rpm` — immutable; `repodata/repomd.xml` и его подписи
  (`repomd.xml.asc`, `repomd.xml.key`) — mutable{TTL 5m}; repodata-файлы
  с хешом-чексуммой в имени (`<sha>-primary.xml.gz` и т.п.) — immutable
  (content-addressed); прочие repodata без хеша (primary/filelists/other/
  *-UPDATE_INFO.xml/*.sqlite.bz2/*zck) — mutable{TTL 5m}; остальное
  (`media.1/products` и т.п.) — conservative mutable{TTL 1m}. Streaming
  XML-парсер repomd.xml — `mod/ecosystem/rpmmmd/parse.go`, streaming
  XML-парсер primary.xml — `mod/ecosystem/rpmmmd/primary.go`; оба
  переиспользуются зеркалом (сессия 11) для Enumerate: repomd →
  `<data type="primary">` location-href → primary.xml[.gz] → hrefs пакетов.
  `Remote.Include` для rpm-md не используется (репо — единое целое по repomd).
- **pacman** (сессия 12) — кеш-прокси Arch Linux (pacman). Путь
  `/pacman/<remote-name>/<остальной-путь>`; `StorageKey` =
  `cache/pacman/<remote-id>/<upstream-path>`. Классификация:
  `*.pkg.tar.zst|.xz|.gz` и их `.sig` — immutable (content-addressed по
  NEVRA в имени); репозитарные базы `{repo}.db`, `{repo}.files` и их
  `.sig`, legacy `.db.tar.*` / `.files.tar.*` — mutable{TTL 5m}; публичные
  ключи `keys/*` — mutable{TTL 1h}; прочее — conservative mutable{TTL 1m}.
  Streaming-парсер `{repo}.db` (tar.zst → tar → desc) —
  `mod/ecosystem/pacman/parse.go`, декомпресс-лимит 1GiB (zip-bomb guard);
  переиспользуется зеркалом (сессия 11) для Enumerate: `{repo}.db` →
  desc-записи → поле `%FILENAME%`. `Remote.Include` — список
  `repo/arch` (например, `["core/x86_64", "extra/x86_64"]`); пустой —
  ошибка (pacman не имеет корневого индекса репозиториев).
- **apk** (сессия 12) — кеш-прокси Alpine Linux (apk). Путь
  `/apk/<remote-name>/<остальной-путь>`; `StorageKey` =
  `cache/apk/<remote-id>/<upstream-path>`. Классификация: `*.apk` —
  immutable (content-addressed по имени+версии); `APKINDEX.tar.gz` и
  `APKINDEX.json` (задел для v3) и их `.sig` — mutable{TTL 5m}; публичные
  ключи `keys/*` — mutable{TTL 1h}; прочее — conservative mutable{TTL 1m}.
  Streaming-парсер `APKINDEX.tar.gz` (gzip+tar → текст «K:V») —
  `mod/ecosystem/apk/parse.go`, декомпресс-лимит 1GiB (zip-bomb guard);
  переиспользуется зеркалом (сессия 11) для Enumerate: `APKINDEX` →
  записи → поле `F:` (путь к .apk). `Remote.Include` — список архитектур
  (например, `["x86_64", "aarch64"]`); пустой — ошибка (apk не имеет
  корневого индекса архитектур).
- **nix** (сессия 13) — кеш-прокси nix binary cache (narinfo + nar.xz).
  Путь `/nix/<remote-name>/<остальной-путь>`; `StorageKey` =
  `cache/nix/<remote-id>/<upstream-path>`. Контент адресован — идеальный
  immutable-кеш. Полное зеркало `cache.nixos.org` (десятки ТБ) не
  поддерживается — только pull-through; `Enumerate` возвращает
  `*domain.UnsupportedError` («зеркало по использованию»: narinfo → nar
  через `WantNar` — задел для будущего префетча). Классификация:
  `nar/<32hex>.nar.xz` и `nar/<32hex>.nar` — immutable (навсегда);
  `<32hex>.narinfo` — mutable{TTL 1h} (маленький, byte-exact, реиспоуз
  и патчи путей невозможны); `nix-cache-info` — mutable{TTL 1h};
  `log/<…>` — immutable; прочее — conservative mutable{TTL 1m}.
  Инвариант nix: narinfo содержит `URL: nar/…` и `Sig: <key>:…` — НЕ
  переписываем, отдаём побайтово (подписи остаются валидными, если клиент
  доверяет ключу upstream; `trusted-public-keys` остаётся от upstream).
  404 на narinfo — штатная ситуация nix-клиента (перебор substituter'ов):
  negative-cache движка (сессия 06) отдаёт корректный 404 (не 502) и
  быстро. Парсер narinfo (строки `key: value` + валидатор 32-hex) —
  `mod/ecosystem/nix/parse.go`, фаззинг `FuzzParseNarinfo` (без паники,
  размер записи < 16KiB, пути в `URL:`-поле валидны относительно `/nar/`
  или запись отброшена). `Remote.Include` для nix не используется.

URL-префикс (`port.Ecosystem.URLPrefix()`) чаще совпадает с именем, но
не всегда (rpm-md → «rpm»); роутер :29202 MATCHит `/{URLPrefix}/*` и
ищет экосистему по префиксу.

До админ-API (сессия 09) первый remote записывается одноразовым
CLI-флагом:

```
khrazhevnik -config khrazhevnik.toml -add-remote apt/debian=https://deb.debian.org/debian
```

Флаг парсит `<eco>/<name>=<base-url>`, проверяет, что экосистема
слинкована (blank-import в wire), и пишет remote в БД; сервер не
поднимает. jwt_secret при этом не требуется (CLI подставляет заглушку
для прохождения валидации конфига).

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
| `sync_jobs`    | sync-задачи зеркал (состояние, resume-данные; курсор кодирует прогресс `files=N;bytes=M`)     |
| `audit_log`    | аудит мутаций (actor/action/object/result/detail) |
| `object_index` | etag/expires mutable-объектов кеша; `storage_key` — ключ версионных байт (миграция 0003; пустой — байты под самим `key`, записи до версионирования) |

Драйверы — плагин через TOML:

- sqlite: modernc (CGO-free), WAL, busy_timeout=5000, foreign_keys=ON,
  пул не 1 (мы сервер), retry при SQLITE_BUSY.
- postgres: jackc/pgx/v5/stdlib. mariadb: go-sql-driver/mysql.
- SQL переносимый: диалект-шим для placeholder и upsert;
  диалект-специфичные миграции — свои каталоги `migrations/<driver>/`.
