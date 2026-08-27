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
  config/     struct-конфиг: defaults → TOML → env KHRZ_* (+file://-секреты)
  dbtalk/     мини-шим SQL-диалектов каталога: Placeholder/Upsert/эпоха
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
migrations/<driver>/      embedded goose-миграции каталога (по каталогу на БД)
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
случайность — только через `port.Rand`; ошибки возвращаем, не логируем
в месте создания; panic только в main.go и в `registry.Register*`
(двойная регистрация — ошибка программиста); package-level var только
`cmd/khrazhevnik.Version` и закрытое состояние
`internal/core/registry` (compile-time реестр без него не собрать);
комментарии «почему», не «что».

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
    URLPrefix() string // первый сегмент пути :29202 («apt», «rpm»); чаще == Name
    // Путь публичного порта → upstream + путь upstream'а
    Resolve(path string) (Target, bool)
    Classify(upstreamPath string) (Class, error) // Immutable | Mutable{TTL}
    // Список upstream-путей пакетов remote для sync зеркала (сессия 11):
    // адаптер знает, какие метаданные fetch'ить и как их разобрать;
    // meta — cache-движок (singleflight/TTL/метрики переиспользуются).
    // UnsupportedError — sync всего upstream не реализуем (nix: только
    // pull-through «по использованию»).
    Enumerate(ctx, remote, meta MetaFetcher) ([]string, error)
}
type MetaFetcher interface {
    Fetch(ctx, ecosystemPath string) (io.ReadCloser, error) // через cache
}
// Target: {UpstreamURL, UpstreamPath, StorageKey} — StorageKey вида
// cache/<eco>/<remote-id>/<upstream-path>, уникален и стабилен.
// URLPrefix отличают от Name: rpm-md держит один адаптер под dnf+zypper,
// а URL держит короткий «rpm» (как в .repo baseurl). Роутер MATCHит
// /{URLPrefix}/* и ищет экосистему по префиксу, а не по имени.

// port/catalog.go — Interface Segregation: маленькие интерфейсы
// UserStore, TokenStore, RepoStore, RemoteStore, JobStore, AuditLog,
// ObjectIndex — реализуются одним адаптером БД, но фейки в тестах
// пишутся только для нужного среза.

// registry.EcosystemDeps — порция каталога и инфраструктуры, которую
// фабрика экосистемы получает от wire: {Remotes, Clock}. Первый
// адаптер, которому они нужны (apt, сессия 07), резолвит remotes по
// пути и инвалидирет их кеш по TTL; прочие экосистемы берут своё,
// оставляя неиспользуемое нулевым. Зависимости новых движков
// (sync-воркеры зеркал — сессия 11) дописываются сюда.

// port/signer.go, port/clock.go, port/rand.go, port/http.go (Doer).
```

Инварианты движка кеша:

- immutable-объект: cache-or-fetch, singleflight на ключ, отдача стримом;
- mutable: conditional revalidate (ETag/Last-Modified passthrough),
  stale-if-error опционально включён;
- атомарный commit: полный объём + Content-Length сверены, иначе Abort;
- отрицательное кеширование 404/5xx — только в памяти, с TTL;
- ни байта переписывания метаданных upstream;
- outbound-клиент без прозрачного gzip (`DisableCompression` в
  `wire.outboundHTTPClient`): upstream всегда получает identity — в кеш
  попадают ровно те байты, что отдал сервер, с родными ETag и
  Content-Encoding. Без этого транспорт расживал бы ответы за спиной
  кеша: расжатое тело с ETag сжатого варианта — poisoning подписанных
  метаданных;
- верификация чексумм: если индекс экосистемы знает хеш объекта
  (`port.Target.Checksum`), движок на лету сверяет sha256/sha1/md5
  (hashing-tee в `copyBody`) и при несовпадении не коммитит объект:
  Abort + negative-cache на TTL 5xx — битый/подменённый upstream не
  отравляет immutable-кеш («навсегда»). Наполнение — на адаптерах при
  Enumerate (sync зеркала): apt — SHA256 из stanza Packages, rpm-md —
  checksum из repomd.xml (repodata-файлы), apk — SHA1 из поля C:
  APKINDEX; pacman — не-цель v1 (парсер .db не читает %SHA256SUM%).
  Нет чексуммы в индексе — честная деградация к сверке Content-Length.

Инварианты движка зеркала (сессия 11):

- reuse cache-движка: sync качает через `cache.Prefetch` (singleflight,
  TTL, метрики общие с прокси), не лезет в сеть сам;
- Enumerate через `MetaFetcher` (cache.Fetch под капотом) — адаптер
  знает формат метаданных, зеркало не дублирует парсеры;
- resume по diff, не по курсору: каждый запуск пересчитывает
  (Storage.Stat отфильтровывает имеющееся), идемпотентно и дешевле
  очереди в БД; sync_jobs.cursor хранит прогресс `files=N;bytes=M`;
- worker pool (mirror.workers горутин) с retry до 3 и bandwidth-лимитом
  (`golang.org/x/time/rate` token-bucket по скачанным байтам);
- отмена ctx гасит воркеры; доля ошибок >5% → sync failed;
- планировщик: per-remote тикер (SyncInterval ± jitter через port.Rand),
  один на процесс; mode=proxy — только ручной sync через API.

Инварианты движка publish (сессия 14):

- ключи личных репо — `repo/<repo-id>/<eco>/<путь>`; путь из запроса
  проходит `domain.ValidateKey` + `port.RepoAdapter.ValidateObjectPath`
  (apt — только `pool/*` с известными расширениями; `dists/*` — только
  генератор, не клиентский upload);
- immutable-ключи: перезапись существующего пути → 409 `conflict`;
  `force=true` — только админ, с аудит-записью;
- квоты — по сумме `Storage.List("repo/<id>/")` на каждый upload
  (KISS v1: репо обычно единицы-десятки файлов; `repo_objects`-таблица
  для чек-сумм — в сессии 17, когда s3 без List-обхода);
- стриминг прямо в `Storage.Put`: `Content-Length` обязателен
  (ограничение v1), сверка байт на лету; Abort при недокачке/перелимите
  чистит `tmp/`;
- RBAC: admin — везде; владелец (`repo.OwnerID == user.ID`) — upload/
  delete/reindex/list; `repo:<id>:write` scoped-токен — то же; чтение
  публичное (`GET /repo/<name>/*` на порту :29202);
- генерация индексов — фоновой задачей TaskRegistry (kind=reindex,
  label=repo.Name); `port.RepoAdapter.GenerateIndexes` — экосистемный
  генератор (apt в сессии 14, rpm-md/pacman/apk/nix — сессия 16);
  атомарность v1 — перезапись ключей после полной генерации staging,
  полный atomic-swap вместе с s3 — сессия 17;
- подпись метаданных (сессия 15): один ключ инстанса (ed25519 OpenPGP)
  генерируется в `signing.keys_dir` на первом старте, грузится на
  повторных (опц. passphrase через `KHRZ_SIGNING__PASSPHRASE`).
  `port.Signer` внедряется в `RepoAdapter` через `port.SignerInjector`
  (v1 — apt: InRelease + Release.gpg; rpm-md/pacman/apk: detached
  индекс-sig через тот же OpenPGP Signer, сессия 16): после
  `Release`/`repomd.xml`/`<repo>.db`/`APKINDEX.tar.gz` эмитится
  `*.asc`/`*.sig` (detached, бинарный) — подписывается ровно тот байтовый
  состав индекса, что записан в Storage (ни байта переписывания).
  `InRelease`/`Release.gpg` НЕ попадают в SHA256-блок `Release`
  (подписи самого Release — circular). Публичный ключ — `GET /repo/<name>/key.asc`
  на :29202. v1 — ключ один на все репо; per-repo ключи и per-repo
  `signed=false` — не-цели (KISS). nix narinfo-подпись (ed25519, формат
  `name:pubkey:sig`) — `port.NarSigner` (живёт вне `port.Signer`: своя,
  более простая модель подписи), внедряется в nix RepoAdapter через
  `port.NarSignerInjector` (сессия 16): narinfo переподписывается по
  строгим правилам (только поле Sig заменяется, остальное байт-точно;
  golden-тест на дифф). Публичный narinfo-ключ — `GET /repo/<name>/nix-key.asc`
  (формат `name:pubkey-b64`) на :29202.

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
