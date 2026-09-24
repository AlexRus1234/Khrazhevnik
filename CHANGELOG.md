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

# Changelog

Формат — [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/),
версионирование — semver. Правки копятся в **[Unreleased]** под
категорией (### Исправлено / Добавлено / Изменено / Безопасность /
Удалено) сразу в момент правки. При релизе секция [Unreleased]
переименовывается в `[X.Y.Z] — дата`, сверху появляется свежий пустой
[Unreleased]; тело секции релиза — основа release notes
([docs/RELEASE.md](docs/RELEASE.md), §4). Номер по semver: только
фиксы — patch, новая функциональность — minor, ломающее изменение —
major.

Канонический файл — этот (ru); перевод —
[CHANGELOG.EN.md](CHANGELOG.EN.md). История разработки до 1.0.0
включительно (волны «Постаудит…Зеркало-форматы») —
[CHANGELOG.old.md](CHANGELOG.old.md).

## [Unreleased]

### Исправлено

- Бинарь: флейк graceful shutdown — exit 1 вместо 0 на SIGTERM
  (`khrazhevnik: context deadline exceeded`): Shutdown ждёт
  StateNew-коннекты (keep-alive пул клиентов) ~5s по golang/go#22682,
  дефолтный HTTP-бюджет был ровно 5s — монетка. Бюджет бинаря поднят
  до 10s (`web.Server.ShutdownTimeout`; интеграционные in-process
  тесты уже несли 10s с фикса флейка TestWireBootShutdown, бинарь был
  единственным носителем дефолта). Репродукция: TestBinarySmoke 5/50
  красных при `-race` (golang:1.27, локальный контейнер) → 0/50 после
  фикса. Контракт контейнера «SIGTERM → exit 0» восстановлен.
- CI: флейк «сервер: context deadline exceeded» в интеграционных
  тестах (TestAdminMetricsLive/TestWireBootShutdown и соседи по
  паттерну) — Shutdown ждёт StateNew-коннекты (принят клиентом,
  запроса нет) ~5s по golang/go#22682 и на бюджете ровно 5s
  возвращал DeadlineExceeded на грани монетки. Поле
  web.Server.shutdownTimeout экспортировано в ShutdownTimeout,
  интеграционные env'ы получают 10s — grace теперь целиком внутри
  бюджета; контракт «Run вернул nil после cancel» не ослаблен.
  Репродукция: 12/100 красных на TestWireBootShutdown → 0/100 после
  фикса (go test -race, локально).
- CI: контрактные suite mariadb на образе mariadb:13 — миграция 0006
  падала («Can't DROP FOREIGN KEY `api_tokens_ibfk_1`»): сервер 13
  автогенерит имя безымянного FK как `1`, а не `<таблица>_ibfk_N`;
  дроп обоих кандидатов под `IF EXISTS` (синтаксис MariaDB, не MySQL),
  имя нового констрейнта по-прежнему явное. Репродукция на локальном
  mariadb:13 — красный → зелёный (весь TestCatalogContractMariaDB).
- Web: кнопка «Скопировать» у свежевыпущенного API-токена не работала
  вне secure context (админка по http в LAN: `navigator.clipboard`
  неопределён, TypeError глотался молча — кнопка «ничего не делает»);
  добавлен fallback через скрытый textarea +
  `document.execCommand('copy')`, при неудаче обоих путей — строка
  «Не удалось скопировать…» под кнопкой. Подпись «Скопировано» теперь
  гаснет сама через ~2с (раньше висела до следующего выпуска токена).

### Изменено

- Тулчейн и CI обновлены до актуальных версий: Go 1.26.3 → 1.27.1
  (go.mod `go 1.27` + `toolchain go1.27.1`), golangci-lint 1.64.8 →
  2.13.2 (конфиг мигрирован в формат v2), actions/checkout v4 → v7.
- Образы CI обновлены: сервисные postgres 16 → 18 и mariadb 11 → 13;
  сборочные node:22-alpine → 24-alpine и golang:1.26-alpine →
  1.27-alpine; distro-нога debian bookworm → trixie. Job-контейнеры и
  fedora-нога остаются на fedora:44 (актуальный релиз; branched-образ
  46 в quay — не релиз). Pin minio не тронут — запиненная версия
  остаётся последним community-релизом на quay.
- CI: S3-сервис контрактных suite заменён MinIO → SeaweedFS
  (docker.io/chrislusf/seaweedfs:4.47, пин): minio/minio с Docker Hub
  удалён (прекращение community-публикаций, 2025-10), quay-образ тянулся
  байпасом мимо Nora — seaweedfs идёт через неё, как postgres/mariadb.
  Промежуточный кандидат rustfs:1.0.0 забракован: контейнер умирал
  SIGSEGV (exit 139) посреди прогона (runs be8c1fa/58aac96 — «lookup
  rustfs: no such host» 200s+: teardown мёртвого контейнера удаляет
  DNS-запись; локальная репродукция — смерть после первого suite-
  прогона; 1.0.0-alpha.67 стабильна, вернёмся к rustfs после
  устаканивания релизов). Схема SeaweedFS: cmd через родной
  /entrypoint.sh (кейс 'server'; --entrypoint из options форк act'а
  раннера игнорирует — контейнер падал Exited(2) на «weed -c»), БЕЗ
  s3.json: анонимный режим отвергает только подписанные запросы, а
  minio-go с пустыми кредами (env KHRZ_TEST_S3_*_KEY) шлёт
  неподписанные; -volume.max=1000 (дефолт 8, SeaweedFS плодит том
  почти на каждый object-assign — suite-прогон ≈ 100 томов).
  Прод-код не тронут (minio-go); suite+soak 18/18 зелёный локально.
- CI: гейт доступности сервисов (s3/postgres/mariadb) перед сборкой:
  резолв имён до 60с + TCP-путь до S3; падение сервиса (как SIGSEGV-
  инцидент rustfs) или потеря регистрации в aardvark-dns сети job'а
  даёт ранний ::error с инструкцией по диагностике раннера вместо
  200s+ шума minio-клиента в фазе тестов. Порядок сервисов не
  управляем (act итерирует Go-мапу).

## [1.2.1] — 2026-09-19

### Изменено

- CI: distro-test Cleanup выметает старые образы
  (`podman image prune -f --filter until=2h`) — на раннере кончается
  место (падение `cmd/go` с SIGBUS в mmap телеметрии при переполнении
  диска); свежие образы параллельных job'ов фильтр не трогает.

### Исправлено

- CI: void-нога distro-test — образ `voidlinux/voidlinux:latest` отстаёт
  от снапшота upstream, `xbps-install` отказывался ставить пакет
  («The 'xbps' package must be updated», exit 16) — перед целевым
  пакетом синк индексов и обновление самого менеджера
  (`xbps-install -S -y`; `xbps-install -u -y xbps`).
- Конфиг: `xbps` добавлен в `knownEcosystemNames` — без этого экосистема
  не входила в дефолтный конфиг, адаптер не собирался в wire и любой
  `/xbps/...` отдавал мгновенный 404, минуя upstream (недосмотр сессии
  129; выявлено первым реальным прогоном void-ноги distro-test).

### Изменено

- Доки: ROADMAP «Текущий статус» синхронизирован с фактом релиза
  v1.2.0 (2026-09-19) — статусная секция не была обновлена в релизной
  сессии 147.
- Доки: ROADMAP — расширение экосистем (pkg/Guix/Flatpak) понижено в
  приоритете, фокус пост-v1 — функциональные направления (решение
  владельца 2026-09-19).
- Доки: ROADMAP — приоритеты пост-v1 (решение владельца 2026-09-19):
  высокий — ретеншн личных репо → eviction кеш-прокси («жизненный
  цикл объектов»), средний — уведомления, низкий — остальные
  направления, самый низкий — расширение экосистем.

## [1.2.0] — 2026-09-19

### Добавлено

- **xbps (Void Linux) — кеш-прокси и зеркало:** шестая экосистема —
  префикс `/xbps/`, регистрочувствительная классификация (пакеты
  `*.xbps` и подписи `*.sig2`/`*.sig` — immutable навсегда,
  `<arch>-repodata` в корне — mutable 5m, прочее — mutable 1m).
  Прокси: метаданные и пакеты byte-exact, повторный запрос
  `X-Cache: HIT`, ревалидация mutable-индекса (304 без тела),
  negative-кеш 404. Зеркало: `Enumerate` по include-архитектурам
  (`<arch>-repodata`), пути `<pkgver>.<arch>.xbps` строит `Filename()`,
  noarch входит один раз (дедуп), SHA256 из `filename-sha256` (64 hex)
  наполняет таблицу чексумм remote (`Target.Checksum`); sync с
  resume-diff, тело с чужим sha256 роняет sync и НЕ коммитит объект
  (Abort, инвариант §4), частичный sync таблицу не затирает.
- **xbps — парсеры метаданных и пакетов (streaming + фаззинг):**
  контейнер `<arch>-repodata` (zstd+tar: `index.plist` — потоком,
  `index-meta.plist` — байтами, `stage.plist` — skip; капы
  декомпрессии 1 GiB / meta 64 KiB); XML-plist парсер `index.plist`
  (словарь `pkgname` → поля колбэком, лимиты поля 64 KiB / массива
  4096 / записей 1 млн, скип неизвестных ключей — forward-совместимость
  proplib); парсер pkgver (`SplitPkgver`/`SplitRevision`/`Filename` —
  дефисы/`++`/`~`, ревизия `_N` только из цифр); ar-парсер `.xbps`
  (zstd/gzip/raw по магику, только `props.plist`, кап 1 MiB; xz —
  `ErrUnsupportedCompression`). Типизированные ошибки формата
  (`ErrBadPlist`/`ErrBadZstd`/`ErrBadTar`/`ErrBadAr`/`ErrPropsMissing`/
  …). Фаззинг `FuzzParseRepoData`/`FuzzOpenPackage`/`FuzzSplitPkgver`
  + golden-фикстура `repodata-golden.zst` на реальных именах Void
  (`0ad`, `libstdc++`, `libxml2`, `python3-pip`, `Mustache`).
- **xbps — RSA-подписчик инстанса и ручка ключа:** `port.RsaSigner` +
  `port.RsaSignerInjector` и модуль `mod/sign/rsasha256` (RSA-4096,
  PKCS#1 v1.5 поверх SHA-256 — формат `.sig2`): приватный ключ
  `xbps-rsa.key` (PKCS#1 PEM, 0600, атомарно, без перезаписи),
  публичный — SPKI-PEM (`PUBLIC KEY`) для index-meta и раздачи;
  passphrase нет, битый ключевой материал фатален на старте.
  `GET /repo/<name>/xbps-key` отдаёт PEM для сверки fingerprint при
  TOFU-импорте (регистрируется только при живом подписчике, неизвестное
  репо — 404), блок «xbps» на экране «Ключи».
- **xbps — личные репо (генератор, writer, интеграция):** streaming-
  writer `index.plist` (XML-plist токенами `encoding/xml`, детерминизм
  reindex: записи по `pkgname`, поля по алфавиту, пустые опущены;
  roundtrip с парсером без потерь) и генератор — аналог
  `xbps-rindex --add --sign --sign-pkg`: плоские `.xbps` →
  `<arch>-repodata` (zstd level 9 + pax-tar) + `.sig2` на каждый пакет
  (RSA/SHA-256 ключом инстанса), noarch в каждую arch-группу, публичный
  ключ в index-meta (base64-PEM); без ключа — repodata без `.sig2`,
  кривое имя файла/битый пакет — честная ошибка задачи. End-to-end
  (integration): upload `.xbps` → reindex → `<arch>-repodata`
  (читается своими парсерами) и `.sig2` (верификация `crypto/rsa`
  против `/xbps-key`); повторный reindex — байт-в-байт тот же индекс.
- **xbps в UI и SPECIFICATION:** выбор экосистемы на экранах
  remotes/repos, конфиг, ручка ключа и генератор в спецификации.

### Изменено

- **Доки (сессия 128):** ROADMAP XBPS приведён к фактам формата —
  плоский лэйаут (`<arch>-repodata` в корне, не `current/<arch>/`),
  подпись `.sig2` — RSA-4096 PKCS#1 v1.5/SHA-256 (не ed25519), ключ
  встроен в `index-meta.plist` (TOFU-импорт клиентом); волна v1.2 —
  ветка `v1.2.0dev`.
- **CI (сессия 144):** distro-test — шестая нога: void
  (`xbps-install` через прокси, `xbps/<remote>`, герметичность через
  `/etc/xbps.d`); RELEASE-чеклист синхронизирован (6/6 ног, пункты
  xbps в §1/§2).
- **Доки (сессия 146):** функциональная документация xbps
  (`docs/func/ru|EN/ecosystems/xbps.md`), синхронизация TESTING
  (кейсы/покрытие), ARCHITECTURE (экосистемы, `mod/sign/rsasha256`,
  инварианты publish и checksum), HISTORY (секция волны), ROADMAP
  (статус v1.2.0, XBPS убран из пост-v1), README.

## [1.1.0] — 2026-09-17

### Добавлено

- **API:** смена пароля — `POST /api/v1/auth/password` (self: проверка
  старого пароля, ответ со свежим JWT; под общим login-rate-limit,
  аудит `user.password.change`) и `POST /api/v1/users/{id}/password`
  (admin: без старого, 204; аудит `user.password.set`). Обе бампят
  `token_version`: JWT-сессии гаснут, `khz_`-токены переживают
  (прецедент сессии 67).
- **UI:** смена пароля в разделе «Пользователи» (сессия 126) — блок
  «Смена своего пароля» (текущий/новый + подтверждение, `minlength=8`)
  с подменой токена на лету (сессия не гаснет) и действие «Сменить
  пароль» для админа над пользователем; i18n ru/en, e2e-смоук входа
  новым паролем.
- **Хранилище:** периодическая выметающая чистка (storagegc, сессии
  119–120) — осиротевшие версии mutable-объектов кеша и объекты
  `repo/<id>/` удалённых репозиториев; ручки `storage.gc_interval`
  (дефолт `24h`, `0` = выключено) и `storage.gc_grace` (дефолт `168h`,
  строго `> 0`), метрики `khrazhevnik_storage_gc_*` (runs/deleted/
  bytes/failed/duration). Keeper-горутина гасится в каскаде shutdown
  без финального прохода.
- **API:** ручной запуск выметающей чистки хранилища —
  `POST /api/v1/storage/gc` (admin, аудит `storage.gc`): фоновая задача
  (kind=`gc`, label=`storage`), 202 + `task_id`; `?dry_run=1|true` —
  ревизия без удалений (счётчики кандидатов в логе задачи); 409 при
  активной задаче, 429 при лимите воркеров, 503 без модуля чистки.

### Изменено

- **БД:** индекс `idx_sync_jobs_remote_id` на `sync_jobs(remote_id)`
  (миграция 0008, все три диалекта); `JobStore.JobByRemote` —
  точечный lookup вместо полного обхода `Jobs()` в
  `mirror.findJobByRemote` (вызывался на каждом `touchJob` активного
  sync, `ProgressInterval=2s`). Закрыто обещание ROADMAP «заодно
  индекс sync_jobs по remote_id».
- **Репозитории:** `DELETE /api/v1/repos/{id}` выметает объекты
  `repo/<id>/` из хранилища сразу — фоновой задачей (kind=`gc`,
  label=`repo-<id>`), а не копит осиротевший префикс до следующей
  выметающей чистки. Сбой задачи не фейлит DELETE: остаток подберёт
  периодический sweep. Синхронное удаление в хендлере отклонено — на
  s3 тысячи Delete держали бы HTTP-запрос минутами.

## [1.0.3] — 2026-09-13

### Исправлено

- **БД (mariadb):** транзиентная ошибка `1467 ER_AUTOINC_READ_FAILED`
  при гонке bootstrap-пользователя (`EnsureFirstUser`) больше не
  вылетает наружу — отнесена к retryable-конфликтам InnoDB (1213/1205):
  проигравший писатель повторяет `INSERT…SELECT WHERE NOT EXISTS` и
  видит строку победителя (`RowsAffected=0`). Проявлялось как
  периодическое `Error 1467 (HY000): Failed to read auto-increment
  value from storage engine` на 20 параллельных `EnsureFirstUser`
  (контрактный suite; воспроизведено 400-итерационным прогоном,
  исправлено retry).

- **Range-раздача (206/416):** прокси и публичный порт личных репо
  (:29202) понимают HTTP Range — одиночный срез `206` с точным
  `Content-Range`, `multipart/byteranges` до 256 диапазонов (кап —
  стартовое `max_ranges` librepo), `416` с `Content-Range: bytes */N`,
  `Accept-Ranges: bytes` на 200/206 Range-пути, `If-Range` (сильный
  ETag или дата `Last-Modified`), мусорный Range → 200-полный
  (RFC 9110 MAY). Срез byte-exact — инвариант побайтовой раздачи
  расширен на подстроки. Закрывает падение dnf5 за прокси на
  zchunk-метаданных (`primary data not present`): dnf5/librepo качает
  `.zck` диапазонами. Порт хранилища получил
  `GetRange` (fs + s3), движок — `FetchMeta`/`OpenBody`/`OpenRange`
  (resolve без открытия тела, один resolve на клиентский запрос).
  Метрика `khrazhevnik_cache_range_responses_total{ecosystem}`;
  fedora-нога distro-test стала обязательной и проверяет факт 206 после
  `dnf install` (verify-range).

### Изменено

- **Прокси и :29202:** HEAD-запросы с Range отдают заголовки 206/416
  без открытия тела — счётчики байт честны (0 байт тела); единая точка
  Range-семантики — `web.serveRanged` для прокси и личных репо.

## [1.0.2] — 2026-09-12

### Исправлено

- **UI (дашборд):** заявленный в 1.0.1 внутренний скролл панели
  «Последние транзакции» не работал — flex-цепочка не имела
  определённой высоты (у `.app` только `min-height`), при контенте
  выше окна панель растягивалась по контенту и скроллилась вся
  страница. Секция дашборда получила жёсткую высоту «окно минус
  шапка» — лента скроллится внутри панели на любом размере окна.

## [1.0.1] — 2026-09-12

### Исправлено

- **Кеш:** whitelist `ValidateKey` допускает «:» — epoch-версии Arch
  (`nftables-1:1.1.7-3-…`, двоеточие epoch'а лежит в имени файла)
  прежде падали 400 (`InvalidKeyError`), pacman откатывал транзакцию
  целиком; сырое «:» и %3A-написание дают один объект кеша. Тот же
  класс, что caret-«^» Fedora (CI-факт №6). Инцидент 2026-09-12
  (TEST-KHRZ-ARCH).

### Добавлено

- **CI:** релизы Forgejo/GitHub/Codeberg получают body — секция
  `[X.Y.Z]` из CHANGELOG.md автоматически вписывается в выпуск
  (раньше body создавался пустым).

### Изменено

- **UI (дашборд):** панель «Последние транзакции» растягивается на
  остаток высоты окна — лента скроллится внутри панели (шапка таблицы
  закреплена), а не всей страницей; при нехватке места панель сжимается
  до минимальной высоты, скролл остаётся внутренним.
