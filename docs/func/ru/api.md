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

# REST API

Админ-API на порту :30202 под корнем `/api/v1`. Большинство ручных
операций выполняется через [веб-админку](ui.md); она использует тот же
API.

## Аутентификация

Два вида `Authorization: Bearer <…>`:

- **JWT-сессия** — выдаётся `POST /auth/login`, TTL `auth.session_ttl`
  (8h по умолчанию). Для админки/UI.
- **Scoped API-токен** (`khz_…`) — выдаётся админом пользователю для
  скриптов/CI; секрет показывается один раз. Роль и `token_version`
  сверяются с БД **на каждом запросе**: отзыв токена/смена роли
  действуют немедленно.

Ошибки хендлеров — единый JSON: `{"error":"snake_case_code"}`.
Исключение — 401/403 из auth-middleware (включая 503 при сбое БД):
отдаются plain text (`unauthorized`, `forbidden`). Мутации (не-GET)
пишутся в аудит-лог.

## Общие эндпоинты

| Метод | Путь                    | Auth | Код    | Назначение                    |
|-------|-------------------------|------|--------|-------------------------------|
| GET   | `/healthz` (оба порта)  | —    | 200    | Liveness (`ok`)               |
| GET   | `/api/v1/`              | —    | 200    | JSON-описание сервиса         |
| GET   | `/metrics`              | admin| 200    | Prometheus exposition         |

## Авторизация и bootstrap

| Метод | Путь                | Auth | Код       | Назначение                       |
|-------|---------------------|------|-----------|----------------------------------|
| POST  | `/api/v1/setup`     | пустая таблица users (атомарно), опц. заголовок `X-Setup-Token`; rate-limit 10/min | 201/400/403 | Создать первого админа `{username,password}` (пароль ≥ 8 байт) |
| POST  | `/api/v1/auth/login`| —    | 200/401   | `{username,password}` → `{token}` (JWT; TTL — `auth.session_ttl`); rate-limit 10/min |
| POST  | `/api/v1/auth/logout`| session | 204    | Персистентный отзыв JWT (переживает рестарт; сбой каталога — 503) |

Сноска кодов: `setup`/`login` сверх лимита 10/min с IP — 429; пароль
длиннее 72 байт (граница bcrypt) — 413 `too_large` на `setup`/`login`/
`POST /users`. Минимальная длина пароля — 8 байт: короче (в т.ч.
пустой) — 400 `validation_error` на `setup` и `POST /users`; на
`login` короткий пароль — обычный `401 invalid_credentials`.

## Пользователи и API-токены (admin)

| Метод | Путь                                      | Код       | Назначение             |
|-------|-------------------------------------------|-----------|------------------------|
| GET   | `/api/v1/users`                           | 200       | Список пользователей   |
| POST  | `/api/v1/users`                           | 201/400   | `{username,password,role?}` (role — `admin`/`user`, по умолчанию `user`); пароль ≥ 8 байт, иначе 400 `validation_error` |
| DELETE| `/api/v1/users/{id}`                      | 204/404   | Удаление; API-токены пользователя отзываются каскадом (FK ON DELETE CASCADE) и не возвращаются — счётчик их не возвращает |
| POST  | `/api/v1/users/{id}/api-tokens`           | 201/400   | `{name,scopes[],ttl}` → `{token,id,name,scopes,expires_at}`; токен показывается **один раз** |
| GET   | `/api/v1/users/{id}/api-tokens`           | 200       | Список токенов (без секретов) |
| DELETE| `/api/v1/users/{id}/api-tokens/{tokenID}` | 204/404   | Отзыв токена           |

Скоупы токенов: `admin` (всё), `repo:<id>:write` (upload/delete/
reindex/листинг конкретного репо). Scope `admin` требует текущую
admin-роль владельца: смена роли гасит admin-токены немедленно,
repo-токены — нет.

`ttl` — duration: 0/отсутствие = бессрочный токен (нулевой
`expires_at`), отрицательное — 400 `validation_error`.

## Remotes — upstream'ы (admin)

| Метод | Путь                        | Код            | Назначение            |
|-------|-----------------------------|----------------|-----------------------|
| GET   | `/api/v1/remotes`           | 200            | Список                |
| POST  | `/api/v1/remotes`           | 201/400/409    | Создание              |
| PATCH | `/api/v1/remotes/{id}`      | 200/404        | Обновление полей      |
| DELETE| `/api/v1/remotes/{id}`      | 204/404        | Удаление (кеш остаётся) |
| POST  | `/api/v1/remotes/{id}/sync` | 202/409/429    | Запустить sync-задачу зеркала; 409 — уже идёт, 429 — лимит воркеров |

Поля remote: `name` (slug `[a-z0-9._-]`), `ecosystem` (`apt`, `rpm-md`,
`pacman`, `apk`, `nix`), `base_url` (http(s)://), `mode` (`proxy` |
`mirror`), `enabled`, `sync_interval` (duration, 0 — только вручную),
`include` (массив строк: apt — dists[`/component`]; pacman —
`repo/arch`; apk — архитектуры; rpm-md/nix — не используется).

## Личные репозитории

Создание/настройка — admin; upload/delete/reindex/листинг — admin,
владелец или токен `repo:<id>:write`.

| Метод | Путь                                 | Код                  | Назначение               |
|-------|--------------------------------------|----------------------|--------------------------|
| GET   | `/api/v1/repos`                      | 200                  | Список репо              |
| POST  | `/api/v1/repos`                      | 201/400/409          | `{name,ecosystem,owner_id,quota}` |
| GET   | `/api/v1/repos/{id}`                 | 200/404              | Данные репо              |
| PATCH | `/api/v1/repos/{id}`                 | 200/400/404/409      | Имя/квота/владелец (400 — неизвестная экосистема, смена экосистемы) |
| DELETE| `/api/v1/repos/{id}`                 | 204/404              | Удаление с правами       |
| GET   | `/api/v1/repos/{id}/perms`           | 200/404              | Права на запись          |
| POST  | `/api/v1/repos/{id}/perms`           | 204/400/404          | Выдать право (`{user_id}`) |
| DELETE| `/api/v1/repos/{id}/perms/{userID}`  | 204/404              | Отозвать право           |
| GET   | `/api/v1/repos/{id}/objects`         | 200                  | Листинг объектов         |
| PUT   | `/api/v1/repos/{id}/objects/*`       | 201/409/411/413 | Upload (стрим; `Content-Length` обязателен, без него — 411) |
| DELETE| `/api/v1/repos/{id}/objects/*`       | 204/404              | Удаление объекта         |
| POST  | `/api/v1/repos/{id}/reindex`         | 202/409/429          | Задача генерации индексов |

`quota` — `{max_bytes, max_objects}`, нулевое поле = без лимита. Upload:
перезапись существующего ключа → 409 `conflict` (параметр `force=true`
— только админ-сессия: scoped-токен и владелец получают 403
`admin_required`); превышение квоты → 413 `quota_exceeded`; лимит
объекта → 413 `too_large`; несовпадение `Content-Length` → abort и
чистый `tmp/`. Формат путей и генерируемые индексы — по экосистемам в
[personal-repos.md](personal-repos.md).

## Публичная раздача (:29202, без auth)

| Метод | Путь                            | Код        | Назначение                     |
|-------|---------------------------------|------------|--------------------------------|
| GET   | `/{eco}/{remote}/{путь}`        | 200/404…   | Кеш-прокси upstream            |
| GET   | `/repo/{name}/{путь}`           | 200/404    | Личное репо (объекты+индексы)  |
| GET   | `/repo/{name}/key.asc`          | 200/404    | Публичный OpenPGP-ключ инстанса|
| GET   | `/repo/{name}/nix-key.asc`      | 200/404    | Публичный nix-ключ (для narinfo-подписи) |

`/{eco}/*` — URL-префикс экосистемы: `apt`, `rpm` (для rpm-md),
`pacman`, `apk`, `nix`. Заголовок `X-Cache: HIT|MISS|STALE` —
диагностика попаданий.

Сбой нашего стека в любой точке раздачи (хранилище на
чтении/записи/листинге или каталог БД при lookup репо) — 503
`storage unavailable`; 502 — только за сбоем upstream: мониторинг
различает «сломан upstream» и «сломан инстанс» (сессии 50, 60).

## Фоновые задачи (admin)

| Метод | Путь                 | Код     | Назначение            |
|-------|----------------------|---------|-----------------------|
| GET   | `/api/v1/tasks`      | 200     | Снимки задач (сортировка по `started_at`, ранние первыми) |
| GET   | `/api/v1/tasks/{id}` | 200/404 | Снимок задачи         |

Снимок: `{id, kind, label, state, phase, current, processed, total,
percent, speed_bps, logs, error, started_at, finished_at}`; `logs` —
последние 50 строк. Реестр in-memory; персистентное состояние
sync-задач — в `sync_jobs` (одна на remote).

## Статистика и аудит (admin)

| Метод | Путь                | Код  | Назначение                                |
|-------|---------------------|------|-------------------------------------------|
| GET   | `/api/v1/cache/stats` | 200 | `{hits, misses, hit_ratio, stale_served, negative_hits, upstream_errors, bytes_from_upstream, bytes_to_clients, packages, per_ecosystem}` |
| POST  | `/api/v1/cache/stats/reset` | 204 | Сброс статистики: обнуляет атомики памяти и строки `cache_stats`; идемпотентен, аудируется (`cache.stats.reset`). Сбой БД → 503 `unavailable`, счётчики не тронуты |
| GET   | `/api/v1/cache/transactions` | 200 | Последние клиентские транзакции кеша newest-first, `?limit=` (1–50, по умолчанию 50); ряд `{at, ecosystem, path, status, size, error}` |
| GET   | `/api/v1/audit`     | 200  | Аудит, keyset-пагинация `?after_id=&limit=` |

`per_ecosystem` — массив рядов по одной на экосистему с трафиком
(лексический порядок имён):
`{ecosystem, hits, misses, hit_ratio, stale_served, negative_hits,
upstream_errors, bytes_from_upstream, bytes_to_clients, packages}` — те
же поля, что и глобал, плюс имя и свой hit_ratio (по hits/misses ряда);
суммы рядов равны глобальным полям. `packages` — число
закешированных immutable-объектов (пакетов); сброс статистики и
рестарт легитимно роняют его. Пример:

```json
{
  "hits": 1, "misses": 2, "hit_ratio": 0.333,
  "per_ecosystem": [
    {"ecosystem": "apt", "hits": 1, "misses": 1, "hit_ratio": 0.5},
    {"ecosystem": "apk", "hits": 0, "misses": 1, "hit_ratio": 0}
  ]
}
```

После сброса (`POST /cache/stats/reset`) Prometheus-серии счётчиков
увидят counter reset — штатное поведение прома (график «пила»), не баг.

`GET /api/v1/cache/transactions?limit=20` — последние клиентские
транзакции кеша newest-first (операционная панель «что происходит», не
аудит): `{at, ecosystem, path, status, size, error}`; `status` —
HIT/MISS/STALE/error. Буфер — in-memory на 50 записей (prefetch зеркала
и битые пути не пишутся), пагинации нет; `limit` — «не более N»,
целое 1–50, невалидный → 400 `validation_error`.

## Коды ошибок

`not_found`, `conflict`, `forbidden`, `admin_required` (force-only
действие не-админом), `unavailable` (сбой каталога БД в auth-путях),
`invalid_key` (некорректный ключ/путь объекта), `validation_error`,
`too_large`, `payload_too_large` (тело JSON-запроса > 1 MiB),
`length_required` (411, upload без `Content-Length`), `quota_exceeded`,
`stale`, `task_duplicate`, `task_limit`, `invalid_json`,
`setup_already_done`, `invalid_setup_token`, `invalid_credentials`,
`tasks_unavailable`, `mirror_unavailable`, `publish_unavailable`,
`unsupported`, `internal`.
