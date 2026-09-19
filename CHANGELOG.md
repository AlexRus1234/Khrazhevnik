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

### Добавлено

- **XBPS (сессия 129):** экосистема xbps (Void Linux): кеш-прокси —
  классификация repodata/packages, префикс `/xbps/` (адаптер
  зарегистрирован, разбор индекса и зеркало — следующими сессиями волны).
- **XBPS (сессия 130):** интеграция xbps-прокси — repodata и пакеты
  побайтово, повторный запрос `X-Cache: HIT`, ревалидация mutable
  repodata (304 без тела), negative-кеш 404 (integration-тест).
- **XBPS (сессия 131):** streaming-парсер контейнера xbps repodata
  (zstd+tar: `index.plist` — потоком, `index-meta.plist` — байтами,
  `stage.plist` — skip); капы декомпрессии 1 GiB и meta-записи 64 KiB,
  типизированные ошибки формата (`ErrBadZstd`/`ErrBadTar`/
  `ErrIndexMissing`/`ErrIndexNotFirst`/`ErrDecompressTooLarge`).
- **XBPS (сессия 132):** streaming XML-plist парсер `index.plist` — словарь
  `pkgname` → поля отдаётся колбэком по записи (без сборки ~20 MiB XML в карту),
  только `encoding/xml` (энтити `&lt;`/`&amp;` раскодирует stdlib); лимиты поля
  64 KiB / массива 4096 / записей 1 млн, типизированная ошибка `ErrBadPlist`,
  скип неизвестных ключей (forward-совместимость proplib).
- **XBPS (сессия 133):** парсер pkgver xbps (`SplitPkgver`/
  `SplitRevision`/`Filename`) — имена с дефисами/`++`/цифрами, ревизия
  `_N` только из цифр, мусор — `ValidationError`; таблица живых имён
  Void и фаззинг.
- **XBPS (сессия 134):** фаззинг композиции repodata (`FuzzParseRepoData`:
  zstd→tar→index.plist одним таргетом, колбэк-счётчик без накопления) и
  golden-фикстура `testdata/repodata-golden.zst` — 5+ реальных пакетов
  (`0ad`, `libstdc++`, `libxml2`, `python3-pip`, `Mustache`), энтити
  `&lt;`/`&amp;`, `~` в версии, регистр `filename-sha256`, public-key в
  `index-meta.plist` (вход подписи 139/141).
- **XBPS (сессия 135):** зеркало xbps — `Enumerate` по
  include-архитектурам (`<arch>-repodata`): пути пакетов
  `<pkgver>.<arch>.xbps` строятся `Filename()` (сессия 133), к каждому
  добавлена подпись `.sig2`; noarch-пакет входит в результат один раз
  (дедуп seen-картой). SHA256 из поля `filename-sha256` (валидация 64
  hex) наполняет таблицу чексумм remote — `Resolve` отдаёт её в
  `Target.Checksum`; невалидный sha256 и `.sig2` честно деградируют к
  сверке Content-Length. Частичный sync таблицу не затирает.
- **XBPS (сессия 136):** зеркало xbps end-to-end (integration) — sync
  качает repodata + пакеты + `.sig2`, повторный sync не делает ни одного
  upstream-запроса (resume-diff по `Storage.Stat`), общий noarch-пакет из
  двух arch-индексов скачивается ровно один раз; тело, не совпавшее с
  `filename-sha256`, роняет sync и НЕ коммитит объект (Abort, инвариант
  ARCHITECTURE §4), а после починки upstream и истечения negative-окна
  повторный sync succeeds.
- **XBPS (сессия 137):** ar-парсер пакетов `.xbps` (`OpenPackage`) —
  авто-детект компрессии по магику (zstd `28 B5 2F FD`, gzip `1F 8B`,
  raw ar `!<arch>\n`; xz — `ErrUnsupportedCompression`), обход
  классических ar-членов (`props.plist`/`./props.plist`) и чтение только
  `props.plist` в тип `Props`; `files.plist` и payload скипаются
  стримингом; общий кап декомпрессии 1 GiB и `props.plist` ≤ 1 MiB,
  типизированные ошибки `ErrBadAr`/`ErrPropsMissing`.
- **XBPS (сессия 138):** фаззинг ar-парсера пакетов `.xbps`
  (`FuzzOpenPackage`) — сиды по всем трём веткам компрессии
  (raw/zstd/gzip), обрезки на границах ar-заголовка (8/60/68 байт),
  мусор с валидной zstd-магией, гигантское поле размера члена;
  инварианты — без паник, детерминизм ошибки и структуры `Props`.
- **XBPS (сессия 139):** RSA-4096-подписчик инстанса (формат `.sig2`
  xbps) — `port.RsaSigner`/`RsaSignerInjector` и модуль
  `mod/sign/rsasha256`: PKCS#1 v1.5 поверх SHA-256-дайджеста, приватный
  ключ `xbps-rsa.key` (PKCS#1 PEM, 0600, атомарно, без перезаписи),
  публичный — SPKI-PEM (`PUBLIC KEY`) для index-meta и ручки раздачи;
  passphrase не поддерживается, битый ключевой материал фатален на старте.
- **XBPS (сессия 140):** streaming-writer `index.plist` xbps
  (`WriteIndexPlist`) — XML-plist proplib токенами `encoding/xml`
  (энтити `&`/`<`/`>` кодирует stdlib), детерминизм reindex (записи по
  `pkgname`, поля по алфавиту, пустые опущены), roundtrip с парсером
  сессии 132 без потерь; 10k-записей стримингом без накопления.
- **XBPS (сессия 141):** генератор личного xbps-репо (аналог
  `xbps-rindex --add --sign --sign-pkg`): плоские `.xbps` →
  `<arch>-repodata` (zstd level 9 + pax-tar: index.plist/
  index-meta.plist/stage.plist), noarch-пакеты входят в каждую
  arch-группу, `.sig2` на каждый пакет (RSA/SHA-256 ключом инстанса),
  публичный ключ в index-meta.plist (base64-PEM); без ключа — repodata
  без `.sig2`; кривое имя файла/битый пакет — честная ошибка задачи.
- **XBPS (сессия 142):** ручка `GET /repo/<name>/xbps-key` (PEM
  RSA-ключа инстанса) для сверки fingerprint при TOFU-импорте;
  регистрируется только при живом подписчике, неизвестное репо — 404;
  блок «xbps» на экране «Ключи».
- **XBPS (сессия 143):** интеграция личного xbps-репо end-to-end
  (integration): bootstrap → repo eco=xbps → upload `.xbps` (x86_64 +
  noarch) → reindex-задача → публичный порт отдаёт `<arch>-repodata`
  (читается парсерами 131/132, noarch входит в x86_64-группу,
  `filename-sha256` сверяется с телом) и `.sig2` (верификация
  `crypto/rsa` против `/xbps-key`); пакет с props, не совпадающими с
  именем файла, роняет reindex, после удаления — байт-в-байт тот же
  индекс (детерминизм).
- **XBPS (сессия 145):** xbps в UI (remotes/repos) и SPECIFICATION
  (конфиг, ручка, генератор).

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
