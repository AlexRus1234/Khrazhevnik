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

# Конфигурация

Слои: **defaults → TOML → env**. TOML-флаг `-config <путь>` подключает
файл; дефолт флага — пусто, без флага TOML не читается вовсе
(defaults+env — так работает контейнер). Env переопределяет TOML, TOML
переопределяет defaults.

Формат env: префикс `KHRZ_`, сегменты пути через `__` (двойное
подчёркивание), верхний регистр, дефисы — подчёркиваниями:

```
KHRZ_SERVER__PUBLIC_LISTEN=:29203
KHRZ_STORAGE__S3__SECRET_ACCESS_KEY=file:///run/secrets/s3-key
```

Пустое значение env трактуется как «не задано».

## Секреты из файлов (`file://`)

Любое строковое значение (env или TOML) вида `file:///путь/к/файлу`
заменяется содержимым файла: пробелы и переводы строк по краям
обрезаются. Предназначено для quadlet `Secret` (файл появляется в
`/run/secrets/…`) — секрет не светится в env и `systemctl show`:

```ini
# khrazhevnik.container (drop-in)
[Container]
Secret=jwt-secret,env=KHRZ_AUTH__JWT_SECRET
Secret=s3-key,env=KHRZ_STORAGE__S3__SECRET_ACCESS_KEY
```

Типы полей: duration — строка `time.ParseDuration` (`"8h"`, `"5m"`);
размер — `"20GiB"`, `"512MiB"`, `"1024"` (байты); bool — `true/false`.

## `[server]`

| Ключ           | Default   | Env                          | Назначение                  |
|----------------|-----------|------------------------------|-----------------------------|
| `public_listen`| `:29202`  | `KHRZ_SERVER__PUBLIC_LISTEN` | Раздача пакетов + `/healthz`|
| `admin_listen` | `:30202`  | `KHRZ_SERVER__ADMIN_LISTEN`  | `/api/v1`, `/metrics`, `/ui`|

## `[http]`

| Ключ              | Default | Env                                   | Назначение                |
|-------------------|---------|---------------------------------------|---------------------------|
| `trusted_proxies` | —       | `KHRZ_HTTP__TRUSTED_PROXIES` (CSV)    | CIDR'ы reverse-прокси     |

Пусто — rate-limit логина считает по `RemoteAddr` (статус-кво).
Заполнено — адрес клиента берётся из `X-Forwarded-For` справа налево
до первой недоверенной позиции. Без этого все клиенты за прокси делят
одну корзину 10/мин (глобальный lockout логина); с лишней доверенностью
клиент подделывает XFF и обходит лимит. Карта корзин ограничена
10000 записей (ротация IPv6 не растит её бесконечно).

## `[storage]`

| Ключ     | Default | Env                    | Назначение            |
|----------|---------|------------------------|-----------------------|
| `driver` | `fs`    | `KHRZ_STORAGE__DRIVER` | `fs` \| `s3`          |

### `[storage.fs]`

| Ключ  | Default                          | Env                            |
|-------|----------------------------------|--------------------------------|
| `path`| `/var/lib/khrazhevnik/store`     | `KHRZ_STORAGE__FS__PATH`       |

### `[storage.s3]` (обязательны при `driver = "s3"`)

| Ключ              | Default | Env                                     |
|-------------------|---------|-----------------------------------------|
| `endpoint`        | —       | `KHRZ_STORAGE__S3__ENDPOINT`            |
| `region`          | —       | `KHRZ_STORAGE__S3__REGION`              |
| `bucket`          | —       | `KHRZ_STORAGE__S3__BUCKET`              |
| `access_key_id`   | —       | `KHRZ_STORAGE__S3__ACCESS_KEY_ID`       |
| `secret_access_key`| —      | `KHRZ_STORAGE__S3__SECRET_ACCESS_KEY`   |
| `path_style`      | `true`  | `KHRZ_STORAGE__S3__PATH_STYLE`          |
| `spool_dir`       | `/var/lib/khrazhevnik/spool` | `KHRZ_STORAGE__S3__SPOOL_DIR` |

Подробнее о драйверах — [storage-db.md](storage-db.md).

## `[database]`

| Ключ     | Default                                     | Env                       |
|----------|---------------------------------------------|---------------------------|
| `driver` | `sqlite`                                    | `KHRZ_DATABASE__DRIVER`   |
| `dsn`    | `/var/lib/khrazhevnik/khrazhevnik.db`       | `KHRZ_DATABASE__DSN`      |

`driver` ∈ `sqlite` \| `postgres` \| `mariadb`. DSN: путь к файлу
(sqlite), `postgres://user:pass@host/db?…`, `user:pass@tcp(host:3306)/db?…`.

## `[auth]`

| Ключ            | Default | Env                            | Назначение                       |
|-----------------|---------|--------------------------------|----------------------------------|
| `jwt_secret`    | —       | `KHRZ_AUTH__JWT_SECRET`        | **обязателен** (env/файл)        |
| `session_ttl`   | `8h`    | `KHRZ_AUTH__SESSION_TTL`       | TTL JWT-сессии админки           |
| `setup_token`   | —       | `KHRZ_AUTH__SETUP_TOKEN`       | Опц. защита одноразового `/setup`|
| `bcrypt_cost`   | `12`    | `KHRZ_AUTH__BCRYPT_COST`       | Стоимость bcrypt паролей (4–15)  |
| `touch_interval`| `1m`    | `KHRZ_AUTH__TOUCH_INTERVAL`    | Мин. интервал записи last_used токена |

`jwt_secret` непуст и не короче **32 байт** — fail-fast валидация
падает на старте иначе (короткий секрет HS256 брутфорсится оффлайн;
сгенерируйте `openssl rand -base64 32`). Не кладите его в TOML проде:
env или `file://`.

## `[cache]`

| Ключ               | Default  | Env                                   | Назначение                        |
|--------------------|----------|---------------------------------------|-----------------------------------|
| `stale_if_error`   | `true`   | `KHRZ_CACHE__STALE_IF_ERROR`         | Отдавать устаревшее при 5xx upstream |
| `max_object_size`  | `20GiB`  | `KHRZ_CACHE__MAX_OBJECT_SIZE`        | Потолок кешируемого объекта       |
| `negative_ttl_404` | `5m`     | `KHRZ_CACHE__NEGATIVE_TTL_404`       | Отрицательное кеширование 404     |
| `negative_ttl_5xx` | `30s`    | `KHRZ_CACHE__NEGATIVE_TTL_5XX`       | Отрицательное кеширование 5xx     |
| `stats_flush_interval` | `1m` | `KHRZ_CACHE__STATS_FLUSH_INTERVAL`   | Период фонового флаша счётчиков статистики в БД (`cache_stats`); `0` = выключено |

## `[mirror]`

| Ключ             | Default | Env                              | Назначение                     |
|------------------|---------|----------------------------------|--------------------------------|
| `workers`        | `4`     | `KHRZ_MIRROR__WORKERS`           | Параллельных sync-задач        |
| `interval_jitter`| `10m`   | `KHRZ_MIRROR__INTERVAL_JITTER`   | Разброс плановых sync          |
| `max_bandwidth`  | `0`     | `KHRZ_MIRROR__MAX_BANDWIDTH`     | Суммарная скорость скачивания всех sync-воркеров, байт/с (строка вида `10MiB`); `0` = безлимит |

## `[publish]`

| Ключ                 | Default | Env                                    | Назначение                  |
|----------------------|---------|----------------------------------------|-----------------------------|
| `max_object_size`    | `1GiB`  | `KHRZ_PUBLISH__MAX_OBJECT_SIZE`        | Лимит одного upload'а       |
| `default_quota_bytes`| `5GiB`  | `KHRZ_PUBLISH__DEFAULT_QUOTA_BYTES`    | Квота нового репо (0 = нет) |
| `default_quota_files`| `10000` | `KHRZ_PUBLISH__DEFAULT_QUOTA_FILES`    | То же по числу файлов (0 = нет) |

## `[signing]`

| Ключ        | Default                         | Env                                  |
|-------------|---------------------------------|--------------------------------------|
| `keys_dir`  | `/var/lib/khrazhevnik/keys`     | `KHRZ_SIGNING__KEYS_DIR`             |
| `passphrase`| —                               | `KHRZ_SIGNING__PASSPHRASE`           |

Ключ инстанса (OpenPGP ed25519) генерируется на первом старте. Пустой
`passphrase` — приватный ключ лежит в `private.asc` с правами 0600.
`file://`-развёртка работает (подходит quadlet Secret).

## `[metrics]`

| Ключ     | Default | Env                      |
|----------|---------|--------------------------|
| `enabled`| `true`  | `KHRZ_METRICS__ENABLED`  |

## `[ecosystem.<имя>]` — apt, rpm-md, pacman, apk, nix

Все 5 экосистем включены в дефолтном конфиге; секция нужна только чтобы
переопределить:

```toml
[ecosystem.rpm-md]        # в TOML rpm_md и "rpm-md" эквивалентны
enabled = false           # выключить адаптер
```

Env может включить экосистему и без упоминания в TOML:
`KHRZ_ECOSYSTEM__RPM_MD__ENABLED=true`. Сборка без blank-import'а
нужного адаптера падает на старте с понятной ошибкой реестра.

## Прочий env

| Переменная        | Default | Назначение                                |
|-------------------|---------|-------------------------------------------|
| `KHRZ_LOG_LEVEL`  | `info`  | `debug` \| `info` \| `warn` \| `error`    |

## Валидация

Fail-fast на старте, список **всех** проблем сразу: `jwt_secret` непуст,
драйверы из допустимых, duration/порты валидны, для выбранного драйвера
обязательны его поля (у s3 — endpoint/region/bucket/ключи).
