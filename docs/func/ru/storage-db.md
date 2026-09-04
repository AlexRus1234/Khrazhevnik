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

# Выбор хранилища и БД

Хражевник абстрагирует байты объектов (`port.Storage`) и каталог
метаданных (`port.Catalog*`) через порты; реализации подключаются
blank-import'ом в `cmd/khrazhevnik/wire.go` и выбираются TOML-конфигом.
Все пары драйверов проходят одни и те же контрактные suite
(`internal/contract`), поэтому поведение идентично — отличается только
масштаб и эксплуатационные свойства.

## Хранилище объектов

| Драйвер | Назначение | Объём |Writable-volume в контейнере |
|---------|------------|-------|-----------------------------|
| `fs` (posix) | KISS для homelab, один узел | десятки GiB | `/var/lib/khrazhevnik/store` |
| `s3` | прод, любое S3-совместимое (minio, AWS, garage, …) | TiB+ | только спул `storage.s3.spool_dir` |

- **fs** (`[storage] driver = "fs"`, `[storage.fs] path = "…"`):
  объекты — файлы в корне `path`, запись в `tmp/<uuid>` → атомарный
  `rename` на Commit. Простейший вариант: всё в одном каталоге, бэкап —
  копирование каталога. Не масштабируется за пределы одного узла и
  объёма локального диска.
- **s3** (`[storage] driver = "s3"`, `[storage.s3] …`): объекты — в
  бакете S3. `Put` спулирует байты в локальный `spool_dir` (дефолт
  `/var/lib/khrazhevnik/spool`), `Commit` — одиночный `PutObject`
  (атомарен в S3: объект виден целиком или не виден), `Abort` — удаляет
  спул. Стриминг-мультипарт на лету — не-цель v1: `max_object_size`
  ограничивает и спул, и объект (задокументировано). S3-режим **не
  требует volume для объектов** — бакет вне контейнера; writable нужен
  только спулу. ETag (md5 объекта) и Content-Type сохраняются в
  метаданных S3 и возвращаются через `Stat` (fs их не знает — пусто).

## БД каталога

| Драйвер | Назначение | Внешний сервис | Миграции |
|---------|------------|----------------|----------|
| `sqlite` (modernc, CGO-free) | KISS, embedded | нет (`:memory:` или файл) | `migrations/sqlite/` |
| `postgres` (pgx/v5) | прод, внешний сервер | postgres ≥ 13 | `migrations/postgres/` |
| `mariadb` (go-sql-driver/mysql) | прод, внешняя MariaDB | mariadb ≥ 10.3 (MySQL — не-цель v1) | `migrations/mariadb/` |

- **sqlite** (`[database] driver = "sqlite"`, `dsn = "путь"`): embedded,
  WAL, `busy_timeout=5000`, retry на `SQLITE_BUSY`. Ноль внешних
  зависимостей — дефолт для homelab и контейнер-смоука. Пул 8
  соединений; `:memory:` для тестов.
- **postgres**: внешний сервер, MVCC, retry на дедлок/lock_not_available
  (40P01/55P03). Нумерованные плейсхолдеры `$n`, `ON CONFLICT … DO
  UPDATE SET col=EXCLUDED.col`. DSN — стандартная postgres-строка
  (`postgres://user:pass@host/db?…`).
- **mariadb**: внешний сервер (MariaDB ≥ 10.3 / MySQL — не-цель v1),
  InnoDB для FK enforcement, retry на дедлок/lock_wait_timeout
  (1213/1205). Позиционные плейсхолдеры `?`, upsert — `ON DUPLICATE
  KEY UPDATE col=VALUES(col)` (row-alias `AS new` — синтаксис MySQL
  8.0.19+, MariaDB его не поддерживает), id через `LastInsertId`. DSN —
  стандартная mysql-строка (`user:pass@tcp(host:3306)/db?params…`);
  `clientFoundRows=true` выставляется принудительно — UPDATE отдаёт
  matched rows, как у sqlite/postgres.

Миграции — goose v3, embedded SQL, по диалекту на драйвер. `Up`
идемпотентен: повторный старт на актуальной схеме — no-op. Состав
колонок и история миграций параллельны между драйверами (отличия —
только типы: `INTEGER PK` → `BIGSERIAL`/`BIGINT AUTO_INCREMENT`, эпоха —
`BIGINT`).

### Маппинг ошибок записи (паритет драйверов)

Один сценарий нарушения целостности → одна доменная ошибка на всех
драйверах (`mapWrite` в каждом адаптере; сессия 21):

| Сценарий            | sqlite                   | postgres | mariadb   | Доменная ошибка                       |
|---------------------|--------------------------|----------|-----------|---------------------------------------|
| UNIQUE-конфликт     | `CONSTRAINT_UNIQUE`/`_PRIMARYKEY` | 23505 | 1062      | `ConflictError` («уже существует»)    |
| Нарушение FK        | `CONSTRAINT_FOREIGNKEY`  | 23503    | 1452/1451 | `ConflictError` (внешний ключ)        |
| NOT NULL            | `CONSTRAINT_NOTNULL`     | 23502    | 1048      | `ConflictError` (NOT NULL)            |
| CHECK               | `CONSTRAINT_CHECK`       | 23514    | 4025      | `ConflictError` (CHECK)               |
| Длиннее колонки     | — (TEXT без лимита)      | —        | 1406      | `InvalidKeyError` (лимит ключа 767)   |
| Неверный тип значения | catch-all `CONSTRAINT` | —        | 1366      | `ValidationError`                     |

Ключи длиннее 767 байт отбрасываются `domain.ValidateKey` ещё на входе —
ровно предел `VARCHAR(767)` PK `object_index` у mariadb: честный
400-й ответ вместо ошибки 1406 на записи. Прочие нераспознанные коды
проходят наружу как есть (сырая ошибка драйвера).

## Рекомендации

- **Homelab / один узел**: `fs` + `sqlite` (defaults). Один writable
  volume `/var/lib/khrazhevnik`, бэкап — снимок каталога. См.
  `deploy/quadlet/khrazhevnik.container`.
- **Прод / масштабирование**: `s3` + `postgres` (или `mariadb`).
  Объекты в S3 (масштабируется независимо), каталог в внешней БД
  (репликация/бэкап — средствами СУБД). Спул — единственный writable
  volume. См. `deploy/quadlet/khrazhevnik-s3.container`. Граница v1 —
  **один инстанс на bucket**: корни `cache/` и `repo/` общие для
  процесса, и стартовый sweep неполных multipart-загрузок абортит всё
  под этими корнями — параллельный инстанс в том же bucket (в т.ч.
  его идущие загрузки) под sweep попадает.
- **Смешивать нельзя**: `storage.driver` и `database.driver` независимы
  (можно `fs`+`postgres` или `s3`+`sqlite`), но `s3`+`sqlite` для прода
  не рекомендуется — sqlite не переживает конкурентную запись из
  нескольких инстансов.

## Переключение драйвера

Переключение — смена `driver` в TOML/env + рестарт. Данные не
мигрируются автоматически: объекты и записи каталога нужно перенести
внешним инструментом (rsync для fs→s3 через `aws s3 sync`; pg_dump/
`mysqldump` + restore для БД). Миграции схемы на новом драйвере
поднимаются `goose.Up` при старте автоматически.
