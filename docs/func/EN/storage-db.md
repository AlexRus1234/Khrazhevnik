<!--
Hrazhevnik — caching proxy and mirror for Linux package repositories
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

# Choosing storage and the database

Hrazhevnik abstracts object bytes (`port.Storage`) and the metadata
catalog (`port.Catalog*`) behind ports; implementations are wired in
via blank imports in `cmd/khrazhevnik/wire.go` and selected by the
TOML config. All driver pairs pass the same contract suites
(`internal/contract`), so the behavior is identical — only the scale
and operational properties differ.

## Object storage

| Driver     | Purpose                                        | Capacity  | Writable volume in the container |
|------------|------------------------------------------------|-----------|----------------------------------|
| `fs` (posix) | KISS for a homelab, a single node            | tens of GiB | `/var/lib/khrazhevnik/store`   |
| `s3`       | production, any S3-compatible (minio, AWS, garage, …) | TiB+ | only the spool `storage.s3.spool_dir` |

- **fs** (`[storage] driver = "fs"`, `[storage.fs] path = "…"`):
  objects are files at the root of `path`; a write goes to `tmp/<uuid>`
  → an atomic `rename` on Commit. The simplest option: everything in
  one directory, backup is copying the directory. Does not scale
  beyond a single node and the local disk capacity.
- **s3** (`[storage] driver = "s3"`, `[storage.s3] …`): objects live
  in an S3 bucket. `Put` spools the bytes to a local `spool_dir`
  (default `/var/lib/khrazhevnik/spool`); `Commit` is a single
  `PutObject` (atomic in S3: an object is visible in full or not at
  all); `Abort` deletes the spool. Streaming multipart on the fly is
  a v1 non-goal: `max_object_size` bounds both the spool and the
  object (documented). S3 mode **requires no volume for objects** —
  the bucket is outside the container; only the spool needs to be
  writable. The ETag (the object's md5) and Content-Type are
  preserved in S3 metadata and returned via `Stat` (fs does not know
  them — empty).

## Catalog database

| Driver    | Purpose                     | External service                        | Migrations          |
|-----------|-----------------------------|-----------------------------------------|---------------------|
| `sqlite` (modernc, CGO-free) | KISS, embedded | none (`:memory:` or a file)    | `migrations/sqlite/`   |
| `postgres` (pgx/v5)          | production, an external server | postgres ≥ 13          | `migrations/postgres/` |
| `mariadb` (go-sql-driver/mysql) | production, an external MariaDB | mariadb ≥ 10.3 (MySQL is a v1 non-goal) | `migrations/mariadb/` |

- **sqlite** (`[database] driver = "sqlite"`, `dsn = "path"`):
  embedded, WAL, `busy_timeout=5000`, retry on `SQLITE_BUSY`. Zero
  external dependencies — the default for a homelab and the container
  smoke test. A pool of 8 connections; `:memory:` for tests.
- **postgres**: an external server, MVCC, retry on deadlock/
  lock_not_available (40P01/55P03). Numbered placeholders `$n`,
  `ON CONFLICT … DO UPDATE SET col=EXCLUDED.col`. The DSN is a
  standard postgres string (`postgres://user:pass@host/db?…`).
- **mariadb**: an external server (MariaDB ≥ 10.3 / MySQL is a v1
  non-goal), InnoDB for FK enforcement, retry on deadlock/
  lock_wait_timeout (1213/1205). Positional placeholders `?`, upsert
  via `ON DUPLICATE KEY UPDATE col=VALUES(col)` (the row alias
  `AS new` is MySQL 8.0.19+ syntax; MariaDB does not support it), id
  via `LastInsertId`. The DSN is a standard mysql string
  (`user:pass@tcp(host:3306)/db?params…`); `clientFoundRows=true` is
  forced on — UPDATE returns matched rows, as in sqlite/postgres.

Migrations are goose v3, embedded SQL, one dialect per driver. `Up` is
idempotent: a repeated start on an up-to-date schema is a no-op. The
column sets and migration history are parallel across drivers (the
differences are only in types: `INTEGER PK` → `BIGSERIAL`/`BIGINT
AUTO_INCREMENT`, the epoch is `BIGINT`).

### Write error mapping (driver parity)

One integrity violation scenario → one domain error on all drivers
(`mapWrite` in each adapter; session 21):

| Scenario                 | sqlite                            | postgres | mariadb  | Domain error                       |
|--------------------------|-----------------------------------|----------|----------|------------------------------------|
| UNIQUE conflict          | `CONSTRAINT_UNIQUE`/`_PRIMARYKEY` | 23505    | 1062     | `ConflictError` ("already exists") |
| FK violation             | `CONSTRAINT_FOREIGNKEY`           | 23503    | 1452/1451| `ConflictError` (foreign key)      |
| NOT NULL                 | `CONSTRAINT_NOTNULL`              | 23502    | 1048     | `ConflictError` (NOT NULL)         |
| CHECK                    | `CONSTRAINT_CHECK`                | 23514    | 4025     | `ConflictError` (CHECK)            |
| Longer than the column   | — (TEXT without a limit)          | —        | 1406     | `InvalidKeyError` (key limit 767)  |
| Invalid value type       | catch-all `CONSTRAINT`            | —        | 1366     | `ValidationError`                  |

Keys longer than 767 bytes are rejected by `domain.ValidateKey` at the
entry point — exactly the `VARCHAR(767)` limit of the `object_index`
PK in mariadb: an honest 400 response instead of error 1406 on writes.
Other unrecognized codes pass through as is (the raw driver error).

## Recommendations

- **Homelab / a single node**: `fs` + `sqlite` (defaults). One
  writable volume `/var/lib/khrazhevnik`, backup is a directory
  snapshot. See `deploy/quadlet/khrazhevnik.container`.
- **Production / scaling**: `s3` + `postgres` (or `mariadb`). Objects
  in S3 (scales independently), the catalog in an external database
  (replication/backup via the DBMS's own means). The spool is the
  only writable volume. See `deploy/quadlet/khrazhevnik-s3.container`.
  The v1 boundary — **one instance per bucket**: the `cache/` and
  `repo/` roots are shared by the process, and the startup sweep of
  incomplete multipart uploads aborts everything under those roots —
  a parallel instance in the same bucket (including its in-flight
  uploads) falls under the sweep.
- **Do not mix**: `storage.driver` and `database.driver` are
  independent (`fs`+`postgres` or `s3`+`sqlite` are possible), but
  `s3`+`sqlite` is not recommended for production — sqlite does not
  survive concurrent writes from several instances.

## Switching drivers

Switching means changing `driver` in TOML/env + a restart. Data is not
migrated automatically: objects and catalog records must be moved with
an external tool (rsync for fs→s3 via `aws s3 sync`; pg_dump/
`mysqldump` + restore for the database). Schema migrations on the new
driver are applied by `goose.Up` automatically at startup.
