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

Канон для разработчиков (слои, контракты, БД, REST). Пользовательская
документация — [func/ru/](func/ru/) (quickstart, config, api, deploy,
ui, ecosystems, personal-repos).

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

HTTP-таймауты (аудит 2026-08-27): оба слушателя — ReadHeaderTimeout
10s, IdleTimeout 120s. Админ — ReadTimeout/WriteTimeout 30s (JSON-API,
стримов нет). Публичный — ReadTimeout 60s, WriteTimeout отсутствует
(не убивать стриминг больших пакетов); медленного читателя вырубает
per-write deadline 30s в стриминг-хендлерах (`web/stream.go`). Админ,
слушающий не-loopback адрес (включая дефолт `:30202`), пишет warning
в лог при старте.

## Конфигурация

TOML-файл подключается только явным флагом `-config <путь>` (дефолт
флага — пусто; без флага TOML не читается вовсе — defaults+env, так
работает контейнер) + env-слой. Слои: **defaults → TOML → env**.
Пакет `internal/core/config`.

```toml
[server]
public_listen = ":29202"
admin_listen = ":30202"

[http]
# trusted_proxies = ["10.0.0.0/8"]  # CIDR'ы reverse-прокси: rate-limit
#                                   # логина считает по клиенту из
#                                   # X-Forwarded-For; пусто — RemoteAddr.

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
bcrypt_cost = 12                 # стоимость bcrypt паролей (4–15)
touch_interval = "1m"            # мин. интервал записи last_used API-токена

[cache]
stale_if_error = true
max_object_size = "20GiB"
negative_ttl_404 = "5m" ; negative_ttl_5xx = "30s"

[mirror]
workers = 4 ; interval_jitter = "10m"

[publish]
max_object_size = "1GiB"          # лимит одного загружаемого объекта
default_quota_bytes = "5GiB"      # квота нового репо по умолчанию (0 = без лимита)
default_quota_files = 10000       # то же по числу файлов (0 = без лимита)

[signing]
keys_dir = "/var/lib/khrazhevnik/keys"
# passphrase = ""                  # опц.: защищает приватный ключ инстанса (S2K, AES-256).
#                                   # env KHRZ_SIGNING__PASSPHRASE (file://-развёртка работает).
#                                   # пусто — ключ хранится в private.asc открыто (0600).

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
  непуст (env обязателен) и не короче 32 байт (HS256 с коротким ключом
  брутфорсится оффлайн; генерация — `openssl rand -base64 32`),
  `http.trusted_proxies` — валидные CIDR'ы, драйверы из допустимых,
  `auth.bcrypt_cost` ∈ [4, 15], duration/порты валидны, для выбранного
  драйвера обязательны его поля (у s3 — endpoint/region/bucket/ключи).
- Уровень логов — env `KHRZ_LOG_LEVEL` (`debug|info|warn|error`,
  default `info`), читается при старте.

## REST API

Админ-API (порт :30202) под корнем `/api/v1`. Аутентификация — JWT-
сессии (`Authorization: Bearer <jwt>`) или scoped API-токены
(`Bearer khz_...`); role/`token_version` сверяются с БД на каждом
запросе. Scope `admin` API-токена требует текущую admin-роль
владельца: смена роли гасит admin-токены немедленно, repo-токены —
нет (права репо сверяются живьём на каждом запросе). Ошибки
хендлеров — JSON `{"error":"snake_case_code"}`; фронт
маппит в i18n (сессия 18). Исключение — 401/403 из auth-middleware
(и 503 при сбое БД в нём же): отдаются plain text (`unauthorized`,
`forbidden`), не JSON. Мутации (не-GET) автоматом пишутся в аудит-лог
через `AuditMiddleware`: actor из auth-контекста, action из
`WithAuditAction` (или выводится из метода+пути), result по коду
ответа, detail из `WithAuditDetail`.

### Авторизация и bootstrap

| Метод | Путь                       | Auth        | Код | Назначение                          |
|-------|----------------------------|-------------|-----|-------------------------------------|
| POST  | `/api/v1/setup`            | — (пустая БД), `X-Setup-Token`; rate-limit 10/min | 201/403 | Первый админ. Атомарно: `INSERT ... WHERE NOT EXISTS` (EnsureFirstUser) — параллельные вызовы создают ровно одного админа, проигравшие — 403 `setup_already_done` |
| POST  | `/api/v1/auth/login`       | —           | 200/401 | Выдача JWT; rate-limit 10/min      |
| POST  | `/api/v1/auth/logout`      | session     | 204 | Персистентный отзыв JWT (переживает рестарт; сбой каталога — 503) |

Сноска кодов: `setup`/`login` сверх лимита 10/min с IP — 429; пароль
длиннее 72 байт (граница bcrypt) — 413 `too_large` на `setup`/`login`/
создании пользователя.

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

### Личные репозитории (publish, сессия 14)

Upload пакетов пользователями, генерация apt-метаданных, публичная
раздача из `repo/<id>/<eco>/<путь>`. Подпись InRelease/Release.gpg —
сессия 15: один ключ инстанса (ed25519 OpenPGP) генерируется в
`signing.keys_dir` на первом старте, грузится на повторных; после
`Release` генератор эмитит `InRelease` (cleartext) и `Release.gpg`
(detached, бинарный). v1 — ключ один на все репо; per-repo ключи и
per-repo `signed=false` — не-цели (KISS). Деградация подписи — только
для мягких ошибок инициализации (модуль не слинкован, keygen-сбой на
пустом `signing.keys_dir`): репо работают без подписи (`apt` с
`trusted=yes`). Битый ключевой материал — `domain.KeyMaterialError`
(порченый файл, публичный вместо приватного, нечитается; сессия 40) —
фатален: старт падает, а не деградирует.

Публичный ключ раздаётся на публичном порту:

| Метод | Путь                          | Auth | Код | Назначение                          |
|-------|-------------------------------|------|-----|-------------------------------------|
| GET   | `/repo/{name}/key.asc`        | —    | 200/404 | Armored публичный ключ инстанса (для `signed-by` в `sources.list`) |
| GET   | `/repo/{name}/nix-key.asc`    | —    | 200/404 | Публичный nix-ключ, одна строка `name:pubkey-b64` (для `trusted-public-keys`; см. [ecosystems/nix.md](func/ru/ecosystems/nix.md)) |

404 — репо с таким именем не существует **или** подписчик не
инициализирован: роут `/key.asc` регистрируется только при успешной
инициализации подписчика, в деградированном режиме (репо без подписи,
`apt` с `trusted=yes`) запрос проваливается в wildcard-раздачу и
заканчивается 404 — 503 не отдаётся. Диагностика: 404 на живом репо —
проверить запись `signing.keys_dir` и ошибки подписчика в логе старта
(`curl -s -w '%{http_code}\n' -o /dev/null
http://<хражевник>:29202/repo/<name>/key.asc`).

| Метод | Путь                                      | Auth                              | Код | Назначение                          |
|-------|-------------------------------------------|-----------------------------------|-----|-------------------------------------|
| GET   | `/api/v1/repos`                           | admin                             | 200 | Список репозиториев                 |
| POST  | `/api/v1/repos`                           | admin                             | 201/400/409 | Создание репо (`name`, `ecosystem`, `owner_id`, `quota`) |
| GET   | `/api/v1/repos/{id}`                      | admin                             | 200/404 | Данные одного репо             |
| PATCH | `/api/v1/repos/{id}`                      | admin                             | 200/400/404/409 | Изменение имени/квоты/владельца (400 — неизвестная экосистема, смена экосистемы) |
| DELETE| `/api/v1/repos/{id}`                      | admin                             | 204/404 | Удаление репо (права каскадом) |
| GET   | `/api/v1/repos/{id}/perms`                | admin                             | 200/404 | Список прав на запись          |
| POST  | `/api/v1/repos/{id}/perms`                | admin                             | 204/400/404 | Выдать право записи (`user_id`) |
| DELETE| `/api/v1/repos/{id}/perms/{userID}`       | admin                             | 204/404 | Отозвать право записи          |
| GET   | `/api/v1/repos/{id}/objects`              | admin или владелец или `repo:<id>:write` | 200 | Листинг объектов репо |
| PUT   | `/api/v1/repos/{id}/objects/*`            | admin или владелец или `repo:<id>:write` | 201/409/411/413 | Upload объекта (стрим, `Content-Length` обязателен; без него — 411 `length_required`) |
| DELETE| `/api/v1/repos/{id}/objects/*`            | admin или владелец или `repo:<id>:write` | 204/404 | Удаление объекта |
| POST  | `/api/v1/repos/{id}/reindex`              | admin или владелец или `repo:<id>:write` | 202/409/429 | Запуск reindex-задачи; 409 — дубль, 429 — лимит воркеров |

Поля repo: `name` (slug), `ecosystem` (`apt` — единственный с
генератором в M3), `owner_id` (существующий пользователь), `quota`
(`{max_bytes, max_objects}`, нулевое поле = без лимита). Загрузка: путь после
`/objects/` — ключ внутри `repo/<id>/<eco>/...` (apt принимает только
`pool/*` с известными расширениями; `dists/*` генерируются reindex).

RBAC: admin — везде; владелец репо — upload/delete/reindex/list;
`repo:<id>:write` scoped-токен — то же. Чтение публичное — без auth.

Публичный роутер (:29202): `GET /repo/<repo-name>/<путь>` — lookup
репо по имени (не id, для красивых URL клиентов), раздача объектов и
сгенерированных индексов напрямую из Storage с `ETag`/`ModTime` от
хранилища. Иммутабельные пакеты кешируются клиентами. `GET /repo/<name>/key.asc`
— публичный ключ инстанса (сессия 15); `Cache-Control: public, max-age=3600`.
Сбой носителя в любой точке обслуживания (fs PathError на
чтении/записи/листинге; S3-ответ с кодом ошибки или без ответа
endpoint'а) или каталога БД при lookup — 503 `storage unavailable`:
502 зарезервирован за сбоем upstream, мониторинг различает «сломан
upstream» и «сломан инстанс» (сессии 50, 60). На read-пути «компонента
пути — файл» (ENOTDIR) считается отсутствием объекта — 404.

Инвариант квоты: сумма `Storage.List("repo/<id>/")` считается при
каждом upload (KISS v1: репо обычно единицы-десятки файлов); при
превышении `quota.max_bytes`/`quota.max_objects` — 413 `quota_exceeded`.
При force-перезаписи старый размер объекта вычитается из used, а
число объектов не растёт (без вычета — двойной счёт и ложный отказ).
Квота перепроверяется по фактическому размеру тела после загрузки в
tmp, до Commit (заявленный Content-Length мог солгать). Граница v1:
гонка двух параллельных upload разных ключей сужается окном
tmp→Commit; строгая квота требует учёта в БД (не-цель v1).
Upload одного и того же ключа сериализуется per-key in-flight в
движке: второй параллельный upload получает 409 `conflict` (TOCTOU
Stat→Put); граница между инстансами не сериализуется (v1 — один
инстанс). Ошибка листинга или Stat (терминальная ошибка Storage) —
отказ upload (5xx), не «пустая квота»: сбой носителя не должен
выглядеть как освободившееся место. Лимит одного объекта —
`publish.max_object_size` (413 `too_large`).

Стриминг: `Content-Length` обязателен (ограничение v1, в доках);
несовпадение заявленного и фактического размера → abort + чистый
`tmp/`. Перезапись существующего ключа → 409 `conflict` (force=false).

RBAC-матрица по `force` (аудит 2026-08-27):

| Субъект                        | PUT без force | PUT force=true |
|--------------------------------|---------------|----------------|
| админ-сессия (JWT)            | 201           | 201            |
| владелец репо (сессия)         | 201           | 403 `admin_required` |
| scoped-токен `repo:<id>:write` | 201           | 403 `admin_required` |
| admin-scoped API-токен         | 201           | 403 `admin_required` |

`force=true` — только админ-сессия, с записью аудита; перезапись
опубликованных content-addressed объектов = отравление репо, поэтому
даже компрометация scoped/admin-токена перезапись не даёт.

Генерация apt-индексов (`mod/ecosystem/apt/gen.go`, реализует
`port.RepoAdapter`): обход `repo/<id>/apt/pool/` → для каждого `.deb`
читается control-stanza через мини-читатель ar+tar+gz/zst (без
распаковки data-секции — экономим байты и время); выход —
`dists/stable/main/binary-amd64/Packages` (+ `.gz`), `by-hash/SHA256/*`,
`dists/stable/Release` (Date/Suite/Components/Architectures/SHA256
всех файлов). Атомарность v1: перезапись ключей по одному после
полной генерации staging (окно рассинхрона ~секунды; полный atomic-
swap — сессия 17 с s3). Полный swap с подписью — сессия 15.

### Фоновые задачи

| Метод | Путь                       | Auth        | Код | Назначение                          |
|-------|----------------------------|-------------|-----|-------------------------------------|
| GET   | `/api/v1/tasks`            | admin       | 200 | Снимки всех задач (сортировка по `started_at`, ранние первыми)|
| GET   | `/api/v1/tasks/{id}`       | admin       | 200/404 | Снимок одной задачи            |

Снимок задачи: `{id, kind, label, state, phase, current, processed,
total, percent, speed_bps, logs, error, started_at, finished_at}`.
`logs` — последние 50 строк кольцевого буфера. TaskRegistry —
in-memory, не персистится; персистентное состояние sync-задач
(`sync_jobs`: state, last_run_at, cursor с прогрессом `files=N;bytes=M`)
пишут сами воркеры зеркал (сессия 11): одна sync_job на remote,
`cursor` кодирует прогресс, `state` ∈ pending|running|succeeded|failed.
Записи, зависшие в running после рестарта процесса, при старте
помечаются failed с причиной «interrupted by restart» (recovery,
сессия 23) — живых воркеров для них больше нет. Отмена идущего sync
(выключение remote, таймаут задачи) фиксируется как failed с причиной
«interrupted by cancel» и сохранённым прогрессом в курсоре —
следующий прогон докачивает хвост по diff (ремонт, сессия 28).

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
| GET   | `/api/v1/cache/stats`      | admin       | 200 | hits/misses/hit_ratio/stale_served/negative_hits/upstream_errors/bytes_from_upstream/bytes_to_clients |
| GET   | `/api/v1/audit`            | admin       | 200 | keyset-пагинация: `after_id`, `limit`|
| GET   | `/metrics`                 | admin (session или `admin`-scoped токен) | 200 | Prometheus exposition |

Метрики Prometheus (`/metrics`): `khrazhevnik_cache_{hits,misses,
stale_served,negative_hits,upstream_errors}_total`,
`khrazhevnik_cache_bytes_{from_upstream,to_clients}_total` — глобально
и по экосистемам (`ecosystem` лейбл, суффикс `_ecosystem_`); две
гистограммы — `khrazhevnik_request_duration_seconds` (method, status)
и `khrazhevnik_object_bytes` (ecosystem); счётчик
`khrazhevnik_cache_background_panics_total` — паники, recover'нутые
в фоновых операциях кеша; плюс runtime-коллекторы Go
(`go_*` — heap/goroutines/GC) и процесса (`process_*` — CPU/fd/uptime).

### Коды ошибок

`not_found`, `conflict`, `forbidden`, `admin_required` (force-only
действие не-админом), `unavailable` (сбой каталога БД в auth-путях),
`invalid_key` (некорректный ключ/путь объекта), `validation_error`,
`too_large`, `payload_too_large` (тело JSON-запроса > 1 MiB),
`length_required` (411, upload без `Content-Length`), `quota_exceeded`,
`stale`, `task_duplicate`, `task_limit`, `invalid_json`,
`setup_already_done`, `invalid_setup_token`, `invalid_credentials`,
`tasks_unavailable`, `mirror_unavailable`, `publish_unavailable`,
`unsupported`, `internal`.

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
   `nar/<52 nix-base32 fileHash>.nar.xz` и `nar/<52 nix-base32
   fileHash>.nar` — immutable (навсегда; sha256 сжатого файла,
   (256−1)/5+1 = 52 символа — сессия 47); `<32 nix-base32>.narinfo` —
   mutable{TTL 1h} (маленький, byte-exact, реиспоуз
   и патчи путей невозможны); `nix-cache-info` — mutable{TTL 1h};
   `log/<…>` — immutable; прочее — conservative mutable{TTL 1m}.
   Инвариант nix: narinfo содержит `URL: nar/…` и `Sig:
   name:signature` (2 поля: имя ключа и base64 ed25519) — в прокси НЕ
   переписываем, отдаём побайтово (подписи остаются валидными, если клиент
   доверяет ключу upstream; `trusted-public-keys` остаётся от upstream);
   единственное исключение — личные репо, где reindex переподписывает
   `Sig` ключом инстанса в том же формате `name:signature`
   (`nix-key.asc` = `name:pubkey-b64`).
   404 на narinfo — штатная ситуация nix-клиента (перебор substituter'ов):
   negative-cache движка (сессия 06) отдаёт корректный 404 (не 502) и
   быстро. Парсер narinfo (строки `key: value` + валидатор nix-base32
   (алфавит `[0-9a-z]` без `e`/`o`/`t`/`u`): narinfo — 32, nar — 52) —
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
(etag/expires mutable-объектов кеша). Дальнейшие миграции: 0002 —
`api_tokens.revoked_at` (мягкий отзыв с сохранением записи для аудита);
0003 — `object_index.storage_key` (версионные байты mutable-объектов);
0004 — `remotes.sync_interval_sec` и `remotes.include` (планируемый
sync и include-фильтры); 0005 — `revoked_sessions` (персистентный
отзыв JWT-сессий, сессия 25). `schema_migrations` — служебная таблица
goose.

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
| `revoked_sessions` | отзывы JWT (jti, expires_at); logout переживает рестарт; просроченные чистятся при вставке |

Драйверы — плагин через TOML:

- sqlite: modernc (CGO-free), WAL, busy_timeout=5000, foreign_keys=ON,
  пул не 1 (мы сервер), retry при SQLITE_BUSY.
- postgres: jackc/pgx/v5/stdlib. mariadb: go-sql-driver/mysql.
- SQL переносимый: диалект-шим для placeholder и upsert;
  диалект-специфичные миграции — свои каталоги `migrations/<driver>/`.
