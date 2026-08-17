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

# Архитектура

Версия: 1.0. Канон решений; при расхождении доку-код сначала обновляется
дока, потом код.

## 1. Что это

Один Go-бинарник + Vue 3 SPA (go:embed): кеш-прокси и зеркало
linux-репозиториев + личные репозитории пользователей. Основная
дистрибьюция — OCI-контейнер (scratch) под rootless podman quadlet.

Три функции:

1. **Кеш-прокси** — прозрачный pull-through для всех поддерживаемых
   пакетных менеджеров.
2. **Зеркало** — полный локальный копия upstream-репозитория, фоновый
   sync.
3. **Личные репо** — upload пакетов пользователями, генерация и подпись
   метаданных.

Не-цели v1: Windows/macOS пакетные менеджеры, OCI registry,
runtime-плагины (задел сохранён контрактами), приватный read-доступ к
репо (только запись по токену, чтение публичное).

## 2. Зафиксированные решения

| Область          | Решение                                                         |
|------------------|-----------------------------------------------------------------|
| Модульность      | Compile-time реестр (Caddy-style): `init()` + blank-import в wire |
| Скелет           | `core/{port,domain,engine,web}` + `mod/*`; depguard в CI         |
| Инвариант кеша   | Метаданные upstream отдаются **побайтово** — подписи/чексуммы валидны |
| Экосистемы v1    | apt; rpm-md (dnf+zypper одним адаптером); pacman; apk; nix      |
| Storage          | Интерфейс + реализации: fs (posix) и s3 (первичный для прод)    |
| БД               | Плагин через TOML: sqlite (modernc) / postgres (pgx) / mariadb  |
| Миграции         | pressly/goose v3, embedded SQL, по диалекту на драйвер          |
| Подпись          | In-process: ProtonMail/go-crypto (OpenPGP), ed25519 (nix)       |
| Auth             | JWT-сессии админки + scoped API-токены                           |
| Сеть             | Два слушателя: публика :29202, админка :30202                   |
| Контейнер        | Multi-stage → scratch, non-root UID 65534, ReadOnlyRootfs       |
| Shutdown         | PID 1: SIGTERM → HTTP 5с → cancel → задачи 30с (WaitAll)        |
| Тесты            | stdlib testing, fakes руками, пирамида unit/integration/smoke   |
| DI               | `Deps`-структура с фабриками + единственный `wire.go`, без фреймворков |

## 3. Слои и правила импортов

```
cmd/khrazhevnik/           main.go (~40 строк), wire.go — единственная склейка
internal/core/
  port/       контракты: Storage, Ecosystem, Catalog*, Signer, Clock, Rand, HTTP
  domain/     модели + типизированные ошибки; только stdlib, без os/net
  engine/     usecase-логика: cache, mirror, publish, auth; без net/http
  registry/   compile-time реестр модулей
  web/        chi-роутеры, middleware, TaskRegistry, embed SPA; тонкая доставка
  metrics/    leaf-пакет счётчиков (breaks import cycles)
internal/mod/             МОДУЛИ (каждый регистрируется в init())
  ecosystem/  apt/, rpmmmd/, pacman/, apk/, nix/
  storage/    fs/, s3/
  db/         sqlite/, postgres/, mariadb/
  sign/       openpgp/, ed25519/
internal/testutil/        FixedClock, SeqClock, FixedRand, FakeStorage, fakes Catalog*
web/                      Vue 3 + Vite + TS SPA
deploy/                   Containerfile, quadlet/
docs/                     ARCHITECTURE, SPECIFICATION, ROADMAP, TESTING; func/ru/
test/                     integration/, smoke/
```

Enforced линтером (depguard):

- `core/domain/**`, `core/engine/**`: запрет `os`, `syscall`, `net`,
  `net/http`, `golang.org/x/sys` (доставка — только в `core/web`).
- `core/**`: запрет импортов `khrazhevnik/internal/mod/**`.
- `mod/**` и `cmd/**` друг друга не импортируют (только core и
  stdlib/либы).

Прочие правила (в AGENTS.md): время — только через `port.Clock`;
случайность — только через `port.Rand`; ошибки возвращаем, не логируем в
месте создания; panic только в main.go; package-level var только
`cmd/khrazhevnik.Version`; комментарии «почему», не «что».

## 4. Ключевые контракты (эскизы, уточняются при реализации)

```go
// port/storage.go — единый namespace объектов
type Storage interface {
    Get(ctx context.Context, key string) (Object, error) // ReadCloser+Meta
    Stat(ctx context.Context, key string) (Meta, error)
    Put(ctx context.Context, key string) (Writer, error) // Write/Commit/Abort
    Delete(ctx context.Context, key string) error
    List(ctx context.Context, prefix string) iter.Seq[Meta]
}

// port/ecosystem.go
type Ecosystem interface {
    Name() string
    // Путь публичного порта → upstream + путь upstream'а
    Resolve(path string) (Target, bool)
    Classify(upstreamPath string) (Class, error) // Immutable | Mutable{TTL}
}
// Target: {UpstreamURL, UpstreamPath, StorageKey} — StorageKey вида
// cache/<eco>/<remote-id>/<upstream-path>, уникален и стабилен.

// port/catalog.go — Interface Segregation: маленькие интерфейсы
// UserStore, TokenStore, RepoStore, RemoteStore, JobStore, AuditLog,
// ObjectIndex — реализуются одним адаптером БД, но фейки в тестах
// пишутся только для нужного среза.

// port/signer.go, port/clock.go, port/rand.go, port/http.go (Doer).
```

Инварианты движка кеша:

- immutable-объект: cache-or-fetch, singleflight на ключ, отдача стримом;
- mutable: conditional revalidate (ETag/Last-Modified passthrough),
  stale-if-error опционально включён;
- атомарный commit: полный объём + Content-Length сверены, иначе Abort;
- отрицательное кеширование 404/5xx — только в памяти, с TTL;
- ни байта переписывания метаданных upstream.

## 5. Namespace хранения

- `cache/<eco>/<remote-id>/<путь-upstream>` — прокси/зеркало, byte-exact.
- `repo/<repo-id>/<схема-экосистемы>/<путь>` — личные репо.
- `tmp/<uuid>` — незавершённые загрузки (fs: локальный data-dir; s3:
  спул на локальный диск, затем одиночный PUT — атомарен).

## 6. Паранойя

- API-токены scoped (`admin`, `repo:<id>:write`), хранится только sha256,
  показывается один раз; JWT-секрет ≠ токены.
- Роль и `token_version` сверяются с БД **на каждом запросе** — роль из
  claim не доверяется.
- bcrypt с guard на 72 байта (ошибка bcrypt → «пароль слишком длинный»,
  аккаунт не брикается).
- Constant-time сравнение всех секретов; rate-limit /login 10/min c
  ресетом при успехе.
- Единая точка path-traversal для всех путей из запросов.
- /api/v1/setup создаёт первого админа только при пустой таблице users
  (+опциональный KHRZ_SETUP_TOKEN).
- Аудит всех мутаций (actor/action/object/result/detail) — в БД,
  чтение с пагинацией.
- Фаззинг всех парсеров чужих форматов с первого адаптера; crash-корпус
  коммитится в testdata.

## 7. Сеть

- :29202 — только раздача пакетов (без auth) + /healthz.
- :30202 — /api/v1 (auth), /metrics (Prometheus, за auth), SPA /ui.
- Env-слой поддерживает `KHRZ_ИМЯ=file:///run/secrets/x` — значение
  читается из файла (quadlet Secret).

## 8. Контейнер

- Multi-stage: golang:1.26-alpine (CGO_ENABLED=0, -trimpath) → scratch.
- `USER 65534:65534`, `EXPOSE 29202 30202`, `VOLUME /var/lib/khrazhevnik`.
- Writable только `/var/lib/khrazhevnik` (sqlite, fs-store, ключи);
  ReadOnlyRootfs=true в quadlet.
- Binary = PID 1, никаких сабпроцессов (GPG in-process) — зомби-реапер
  не нужен.
- Rootless: порты ≥1024 дефолтами; пабликуем 29202, админку — на
  127.0.0.1:30202.
