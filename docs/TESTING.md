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

# Стратегия тестирования

## Coverage-цели

| Слой                    | Цель покрытия | Инструмент                       |
|-------------------------|---------------|----------------------------------|
| core/domain             | 100%          | unit                             |
| core/engine             | ≥90%          | unit + fakes (testutil)          |
| core/engine/storagegc   | ≥90%          | unit + fakes (ModTime-инжект)    |
| core/engine/retention   | ≥90%          | unit + fakes + integration       |
| core/engine/eviction    | ≥90%          | unit + fakes + integration       |
| core/engine/accesskeeper| ≥90%          | unit + fakes (FixedClock)        |
| mod/ecosystem/* (парсеры)| ≥90%         | unit + golden + fuzz             |
| mod/ecosystem/xbps      | ≥90%          | unit + golden + fuzz + integration |
| mod/storage, mod/db     | ≥85%          | контрактные suite на всех драйверах |
| core/web                | 60–80%        | httptest API-тесты               |

## Подсчёт покрытия (merged-профиль)

Цифра покрытия в CI (шаг Coverage report build.yml) считается по
**объединённому профилю unit + integration**, а не только по unit:
вклад integration-suite (реальные слушатели, fs/s3-хранилища,
sqlite/postgres/mariadb) в покрытие движков и модулей существенен.
Unit-only цифра (~67% на момент внедрения) была занижена и вводила в
заблуждение; фактическая merged-цифра фиксируется прогоном CI — за
конкретным числом не гоняемся, цели — таблица выше.

- unit: `go test ./... -covermode=atomic -coverprofile …`
- integration: `go test -tags integration -covermode=atomic
  -coverpkg=./... -coverprofile … ./test/integration/...` (контрактные
  suite pg/mariadb/s3 требуют сервисных env `KHRZ_TEST_*`, как в шаге
  Go tests; локально скипаются)
- merge — конкатенация без gocovmerge: шапка `mode: atomic` один раз,
  тела обоих профилей с дедупликацией одинаковых строк (`sort -u`);
  одинаковые блоки с разными счётчиками `go tool cover` суммирует.

Локально — `make test-integration-cover` (integration-профиль
отдельно); полный merged — только в CI.

## Уровни

1. **Unit** — рядом с кодом (`*_test.go`), stdlib testing, фейки пишутся
   руками (без testify).
2. **Integration** — `test/integration`: реальный sqlite `:memory:`,
   fs-хранилище, seaweedfs/pg/mariadb через CI-сервисы; build-tag
   `integration`, запуск `make test-integration` (с `-race`). Включает
   `binary_smoke_test.go`: exec собранного артефакта как процесса
   (`/healthz`→`/setup`→`/auth/login`→прокси byte-exact→404→SIGTERM
   exit 0) — покрывает `main()` (TOML/env, signal-handling), что
   недоступно in-process тестам.
3. **E2E (Playwright, opt-in)** — `web/e2e`: global-setup сам exec'ит
   бинарник и поднимает UI-смоук (publish + i18n) в реальном браузере;
   включается входом `run_e2e_tests` workflow (L4). Это смоук
   пользовательского пути, а не фронтовые автотесты: **регрессионных
   UI-автотестов фронта нет (KISS)** — экраны тонкие, вся логика в
   engine и покрыта API-тестами.
4. **Distro E2E (opt-in)** — CI job `distro-test` (workflow_dispatch,
   вход `run_distro_tests`): 5 контейнеров-дистрибутивов (matrix:
   debian/fedora/arch/alpine/nix) против контейнера Хражевника из
   `Containerfile.test`. DooD через сокет раннера
   (`/run/user/968/podman/podman.sock`) — sibling-контейнер, демон
   хостовый, не вложенность. Тест-контейнер — тот же бинарь,
   окружение alpine (curl/jq/sqlite3), sqlite+fs; sqlite-дефолт —
   через env `KHRZ_AUTH__JWT_SECRET`. Критерий: пакет ставится
   реальным пакетным менеджером + второй HEAD → `X-Cache: HIT` +
   `/api/v1/cache/stats` `hits>0`, `bytes_from_upstream>0`;
   внешние источники ног вырезаны (герметичность). Волатильность
   внешних зеркал — не баг: падение ноги = дословный лог владельцу.
5. **Smoke** — `test/smoke`: живой контейнер, проверка curl'ом. В
   build-test/oci job'ах НЕ запускается (PinP-вложенность невозможна
   на rootless-раннере; контейнер через `podman run` в CI покрыт
   job'ом distro-test, п. 4) — только **локально перед релизом**
   (`make image && make smoke`, см.
   [RELEASE.md](RELEASE.md)); контейнер идентичен артефакту
   (scratch + протестированный CI бинарник + CA-bundle).
6. **Fuzz** — короткие прогоны в CI; crash-корпус коммитится в
   testdata.

`-race` обязателен в CI (`make test-race`).

## Детерминированность

Время — только `Clock`/`FixedClock`/`SeqClock` из `internal/testutil`,
случайность — `FixedRand`; golden-файлы для парсеров и генераторов
метаданных.

## Регресс-кейсы зеркальных индексов

Форматы индексов upstream'ов меняются независимо от парсера (волна
«Зеркало-форматы», 2026-09-09: Arch отдаёт sync-БД tar.gz, Fedora
41+/Leap 16.0 — primary.xml.zst); закреплены кейсы:

- pacman: gzip-golden (те же desc-записи, что у zstd-варианта),
  авто-детект компрессии по magic-байтам (gzip|zstd, короткий поток —
  без паники), gzip-бомба — стриминг итератором в `io.Discard`,
  `ErrDecompressTooLarge` (точный кап+δ честен для gzip);
- rpm-md: primary.xml.zst на Enumerate (те же пути пакетов, что у
  .gz-фикстуры; чексумма сжатого файла из repomd попадает в sums),
  zstd-бомба — стриминг в `io.Discard` («бомба не дочитана»,
  упреждение декодера делает точный кап нечестным);
- integration: полный mirror sync против httptest-фикстур реальных
  форматов (pacman gzip-БД, rpm-md zst-primary) — remote → sync
  succeeded → MISS → HIT, byte-exact.

## Range-раздача (волна «Range-206»)

Прокси и :29202 отдают срезы (сессии 108–115); закреплены кейсы:

- контракт `Storage.GetRange` — общий storage-suite на fs и s3
   (seaweedfs-контейнер): срез `[start, start+length)` byte-exact
  относительно `Get`, `InvalidRangeError` на выход за границы и мусор,
  `NotFoundError` на отсутствующий ключ;
- движок (`FetchMeta`/`OpenBody`/`OpenRange`): resolve без открытия
  тела (`HIT`/`MISS`/`STALE` совпадают с `FetchStatus`, счётчик
  открытых тел не растёт), `OpenRange` == срезу полного тела,
  `InvalidRangeError` проходит наружу;
- web-хелпер `serveRanged`: 206 single (края/суффикс/open-ended), 416 +
  `bytes */N`, мусорный Range → 200, multipart до 256 частей (порядок,
  точный `Content-Length`), обрыв клиента закрывает ридеры, `If-Range`
  (совпадение ETag/даты, `W/`-слабый тег, без Range), кап 257 → 200,
  метрика 206;
- integration `proxy_range_test.go` (build-tag) — полный GET → MISS,
  `bytes=100-199` → 206 byte-exact, повтор → HIT 206 с идентичными
  заголовками, суффикс/416/мусор, multipart, If-Range;
- distro-test, **fedora-нога обязательна**: `dnf install` качает `.zck`
  диапазонами, шаг verify-range требует
  `khrazhevnik_cache_range_responses_total > 0` в `/metrics`; падение
  ноги — стоп волны (не «волатильность»).

## Выметающая чистка и смена пароля (волна «Гигиена»)

Хранилище выметает консервативный sweeper (сессии 117–123), пароль
меняется через API (124–126); закреплены кейсы:

- контракт каталога (общий suite, три драйвера): `JobByRemote` —
  roundtrip полей и `NotFoundError` после `DeleteJob`;
  `ForEachObjectMeta` — полный обход в порядке key, включая строки с
  пустым `storage_key` (до-0003), fn-ошибка прерывает итерацию и
  возвращается наружу;
- юнит `engine/storagegc/gc_test.go` (правило 17 — контракты, не
  механику): живая версия (`storage_key` строки == ключ) не тронута;
  старая версия (строка указывает на новый ключ) удалена при grace=0 и
  жива при `grace=24h` (ModTime от инжектируемых часов); «чужое имя»
  без строки `object_index` не тронуто; `repo/` живого репо не тронут,
  мёртвого — выметен; dry-run — счётчики без удалений; `NotFoundError`
  от Delete не считается сбоем; ошибка `List` — fail-closed (проход
  завершается ошибкой);
- unit storagegc: `Run`+ManualClock — тик вызывает `Sweep` (счётчик
  через `OnSweep`), ctx-отмена гасит, `Stop` ждёт; config — дефолты и
  негативы (`gc_interval < 0`, `gc_grace ≤ 0`); метрики после прохода;
- web: `POST /storage/gc` — 202+`task_id` → задача succeeded, объекты
  выметены; `?dry_run` — объекты живы; 409 при активной задаче; 503
  без Sweeper; аудит `storage.gc`; `DELETE /repos/{id}` запускает
  фон-задачу `repo-<id>`, а при отсутствии Sweeper/занятых воркерах
  DELETE всё равно 204; пароль — self 200 + свежий JWT (прежний 401),
  неверный старый 403, короткий 400, 11-я попытка 429, admin 204 +
  `token_version` +1, аудит `user.password.change`/`user.password.set`;
- integration `storage_gc_test.go` (build-tag): реальные fs+sqlite,
  `gc_interval=0` (только ручной проход), сев versioned-ключей и
  `object_index` вторым подключением к DSN, `os.Chtimes` для grace;
  POST → succeeded → orphan выметен, живое цело; dry-run не удаляет;
  `/metrics` — `khrazhevnik_storage_gc_deleted_keys_total > 0`;
- e2e (Playwright): смена своего пароля в форме → logout → вход новым
  паролем.

## XBPS — экосистема Void Linux (волна «XBPS», сессии 128–145)

Шестая экосистема: прокси+зеркало, парсеры с фаззингом, RSA-подписчик,
генератор личных репо, ручка ключа и distro-нога void; закреплены
кейсы:

- unit адаптера (`xbps_test.go`): матрица классификации на реальных
  именах — `x86_64-repodata`/`aarch64-repodata` → Mutable{5m},
  `Mustache-4.1_1.x86_64.xbps`/`libstdc++-13.2.0_1.x86_64.xbps` →
  Immutable, `…xbps.sig2`/`…xbps.sig` → Immutable, пустой путь →
  `ValidationError`; `Resolve` — `UpstreamURL`/`StorageKey` без
  лоуэркейса (ассерт на регистр `Mustache`), чужой префикс/неизвестный/
  выключенный remote/`..`-traversal → false;
- unit контейнера `repodata` (131): zstd+pax-tar, `index.plist` строго
  первой записью, `index-meta.plist` после вычитывания индекса,
  `stage.plist` skip; капы 1 GiB декомпрессии / 64 KiB meta;
  типизированные ошибки формата; частичное вычитывание индекса
  (`TestOpenRepoDataPartialIndexDrain`), zstd-бомба — стриминг;
- unit `index.plist` (132): потоковый plist-парсер, энтити
  `&lt;`/`&amp;` и `~`/`>=`/`+` в значениях, roundtrip полей,
  неизвестные ключи и типы (`data`/`dict`/`date`/`real`) скипаются —
  forward-совместимость, известный ключ с чужим типом → `ErrBadPlist`;
  лимиты поля 64 KiB / массива 4096 / записей 1 млн (тест лимита
  записей — потоковый `repeatReader`, без материализации XML);
- unit pkgver (133): таблица живых имён (`0ad-0.27.1_6`,
  `python3-pip-24.0_1`, `libstdc++-13.2.0_1`, `Mustache-4.1_1`,
  `66-init-0.8.2.2_1`, `foo-2~beta1_2`), ревизия `_N` только из цифр,
  мусор (`foo-bar`, `-1.0_1`) → `ValidationError`,
  `name+"-"+version == вход`;
- unit tar-парсера пакета (137→190): авто-детект zstd/gzip/raw по magic
  (xz → `ErrUnsupportedCompression`), читается ровно `./props.plist`
  (имя без канонического префикса — не наш член → `ErrPropsMissing`),
  skip `files.plist`/payload стримингом, `≥1 MiB` props → ошибка капа,
  zstd-бомба > 1 GiB → `ErrDecompressTooLarge` (чтение в `io.Discard`);
  фикстуры — реальный `Mustache-4.1_1.x86_64.xbps` из upstream (sha256
  закреплён) и минимальный tar.gz без payload (сессия 190; ar-парсер и
  его фикстуры удалены);
- фаззинг: `FuzzParseRepoData` (композиция zstd→tar→index.plist,
  колбэк-счётчик без накопления), `FuzzOpenPackage` (три ветки
  компрессии, обрезки tar-заголовка 257/512/520, zstd-мусор, гигантское
  поле размера), `FuzzSplitPkgver` (нет паник; roundtrip при err==nil);
  golden-фикстура `testdata/repodata-golden.zst` (5+ реальных имён,
  `public-key` в meta) + `TestRepoDataGolden`/`…Meta`; crash-корпус
  коммитится только из находок;
- unit генератора/writer (140–141): roundtrip `WriteIndexPlist` ↔
  `ParseIndexPlist`, детерминизм (байт-в-байт при повторном вызове,
  сортировка записей по `pkgname`), 10k записей стримингом без OOM;
  генератор — кривое имя файла/битый `.xbps`/несовпадение props →
  честная ошибка, nil-Signer → индекс без подписей (`.sig2`/`.sig`),
  повторный reindex
  идемпотентен (байты repodata и подписей равны);
- unit RSA-подписчика (139): roundtrip `SignSHA256` →
  `rsa.VerifyPKCS1v15`, digest ≠ 32 байт → ошибка, `LoadOrGenerate`
  перезагрузкой отдаёт тот же публичный PEM, заголовки `RSA PRIVATE
  KEY`/`PUBLIC KEY`, `Generate(0)`/битый материал → `KeyMaterialError`;
- web (142): `GET /repo/<name>/xbps-key` — 200 + тело от
  `-----BEGIN PUBLIC KEY-----`, неизвестное репо → 404, без
  `RsaSigner` маршрут не регистрируется → 404;
- integration `xbps_mirror_test.go` (build-tag): sync качает
  repodata+пакеты+`.sig2`/`.sig`, повторный sync — 0 новых загрузок
  (resume-diff по `Storage.Stat`), общий noarch из двух arch-индексов
  скачивается один раз, тело с чужим `filename-sha256` роняет sync и
  НЕ коммитит объект (Abort), после починки upstream повторный sync
  succeeds;
- integration `xbps_repo_test.go` (build-tag): upload `.xbps` (x86_64 +
  noarch) → reindex succeeded → `<arch>-repodata` читается парсерами
  131/132 (noarch в x86_64-группе, `filename-sha256` == телу) →
  `.sig2` и `.sig` верифицируются `crypto/rsa` против `/xbps-key`
  (`.sig` — по digest-info контракту); не-`.xbps`
  upload → 400; несовпадение props с именем → reindex failed;
  повторный reindex — байты индекса неизменны;
- proxy integration (130): repodata и пакеты byte-exact, повторный
  запрос `X-Cache: HIT`, ревалидация mutable `*-repodata` (upstream
  304 без тела → клиенту копия из кеша), 404 negative-кеш;
- distro-test, нога **void** (144): `xbps-install -S` через прокси
  (`/etc/xbps.d`), TOFU-импорт ключа, второй HEAD → `X-Cache: HIT`,
  `/api/v1/cache/stats` `hits>0`.

## Прокси и импорт/экспорт (сессии 148–163)

Глобальный и per-remote прокси исходящих запросов + табличный
импорт/экспорт источников; закреплены кейсы (покрытие-цели без
изменений):

- unit `domain` (`proxy_test.go`, 100%): `ValidateProxyURL` —
  `""`/`direct` валидны тривиально, whitelist схем
  http/https/socks5/socks5h, пустой host, потолок длины, мусор →
  `ValidationError`; `MaskProxyURL` — `scheme://***@host:port`, без
  userinfo/битый URL возвращается как есть; `remotefmt_test.go` —
  roundtrip `ParseRemoteLine` ↔ `FormatRemote(s)`, комментарии/пустые
  строки, ровно 8 полей, негативы (пустое обязательное поле, плохой
  mode/proxy/enabled/interval), `0` duration — пустое поле;
- unit `engine/cache` (`proxy_doer_test.go`): движок зовёт
  `DoerFor(target.ProxyURL)` — выбранный Doer определяет, куда ушёл
  запрос (per-target выбор, а не один общий клиент);
- unit `cmd/khrazhevnik` (`transport_test.go`): три ветки tri-state
  (env-дефолт / `direct` без прокси / URL-прокси), кеш «один прокси —
  один клиент» (повторный вызов — тот же указатель), `upstreamProxyTTL`
  (смена настройки видна после TTL), сбой чтения стора не роняет
  трафик (отдаётся последнее значение);
- контракт каталога (`settings_test.go` на sqlite/postgres/mariadb):
  `UpstreamProxy` пустой БД — `""` без ошибки, `SetUpstreamProxy`
  (upsert) → чтение, повторная запись перезаписывает; миграции 0009
  (`remotes.proxy_url`) и 0010 (`settings`) накатываются идемпотентно;
- web (`handlers_admin_test.go`, `handlers_settings_test.go`,
  `handlers_remotes_io_test.go`): `proxy_url` в POST/PATCH/GET remotes
  (tri-state, 400 на мусор), маска в audit-detail create/update;
  GET/PUT `/settings/upstream-proxy` (пусто/`direct`/URL, 400, 503 без
  стора, аудит `settings.update` с маской); GET `/remotes/export` —
  `text/plain` + `Content-Disposition`; POST `/remotes/import` — отчёт
  `{created, skipped, errors}` (дубли в БД и в файле — `skipped`,
  битая строка — `errors`), 413 при теле >256 KiB, 400
  `import_too_many` при >1000 строк, всегда 200 при разобранном теле;
- e2e (Playwright, `run_e2e_tests`): копирование свежего API-токена
  (fallback вне secure context, подпись гаснет через ~2с); прокси —
  свой URL и `direct` на источнике, сохранение глобального прокси и
  переживание перезагрузки, клиентская валидация пустого URL; экспорт
  файла и импорт из текста с отчётом (дубли пропущены).

## Ретеншн-политики личных репо (волна «Ретеншн-политики», сессии 164–175)

Авто-очистка старых версий: политика per-repo, учёт обращений, пины,
суточный проход; закреплены кейсы:

- unit `domain` (`retention_test.go`, 100%): `ValidateRetention` —
  границы политики (`0/0` — выключена, `min_versions≥2` при заданном
  возрасте, отказ на `min_versions=1` с возрастом, на `max_age_days`
  без `min_versions` и на отрицательных значениях → `ValidationError`);
- unit движка `engine/retention` (`retention_test.go`, 12 кейсов
  `Apply`): топ-N семейства по `ModTime` с тай-брейком по ключу,
  защита свежим обращением, пином и топ-N (счётчики `ProtectedBy*`),
  `dry-run` без изменений носителя, «только keep-N» при
  `max_age_days=0`, исчезнувший объект — не сбой удаления, сбои
  удалений копятся, ошибка чтения обращений — fail-closed,
  `UnsupportedError` для экосистемы без `FamilyResolver`;
  `runner_test.go` — проход только по репо с включённой политикой,
  сбой одного репо не стопает остальных, отмена между репо,
  переиндексация только при непустых удалениях (`ApplyAndReindex`);
- unit `engine/accesskeeper` (`keeper_test.go`): накопитель и
  флаш-мёрж одной транзакцией, пустой флаш — без похода в БД,
  время не откатывается назад, `Run`/`Stop` (финальный флаш,
  идемпотентность), потолок карты (`maxKeys`) считает `dropped`, а не
  вытесняет;
- unit конфига (`config_test.go`): дефолты (`30s`, `24h`) и негативы
  `storage.access_flush_interval` / `retention.interval` (`<0` —
  ошибка конфига);
- unit резолверов семейств — `TestObjectFamily` в apt, rpm-md, pacman,
  apk и xbps: семейство из реальных имён пакетов, объекты вне семейств
  (индексы, подписи) — `ok=false`; nix метода не имеет;
- контракт каталога (`internal/contract`, sqlite/postgres/mariadb):
  `repo_retention_roundtrip` (колонки 0011 переживают roundtrip;
  строки, созданные до миграции, получают `0/0`), `object_access_merge`
  (префикс с литеральным `_`, скоупы не смешиваются, `last_access_at`
  не откатывается назад, `hits` складываются, пустой батч — no-op,
  `NotFound` у `AccessEntry`), `repo_pins_roundtrip` (идемпотентный
  `SetPin`, порядок по `key`, CASCADE при удалении репо); миграции
  0011–0013 накатываются идемпотентно;
- web (`handlers_retention_test.go`): политика через POST/PATCH/GET
  `/repos` (`min_versions=1` с возрастом → 400), прогноз кандидатов и
  счётчики защит, применение — удаления и переиндексация, 409 при
  активной задаче репо, пины (полный ключ в `GET`, путь внутри репо в
  `PUT`/`DELETE`, 404 на несуществующий объект), 503
  `retention_unavailable` без движка; фиксация обращений —
  `repo_public_test.go` (публичный GET, обе ветки — полная и Range) и
  `proxy_test.go` (кеш-HIT/STALE в `object_access`, MISS — нет);
- integration `retention_test.go` (build-tag): сквозной сценарий на
  живых sqlite + fs — upload, обращение через публичный роутер, флаш
  keeper'а, проход движка удаляет забытую версию и перегенерирует
  индексы; пин-сценарий и выключенная политика (no-op);
- e2e (Playwright, `run_e2e_tests`): политика в панели «Ретеншн»,
  прогноз, пин/анпин и клиентская валидация (`min=1` с возрастом).

## Eviction кеша прокси (волна «Eviction кеш-прокси», сессии 197–205)

Авто-очистка старого кеша pull-through прокси: двухусловный критерий
удаления, tri-state политика per-remote, суточный проход; закреплены
кейсы:

- unit `domain` (`remote_test.go`): поле `Remote.Eviction` переиспользует
  доменную политику `Retention` и её `ValidateRetention` — nil
  (наследование) и `{0,0}` (явно выключено) валидны, `{1,N>0}` (окно 404)
  и `{0,N>0}` (удаление без гарантии минимума) → `ValidationError`;
- unit движка `engine/eviction` (`eviction_test.go`, 11 тестов): `Apply`
  — выключенная политика и зеркальный remote — no-op без ошибки,
  экосистема без `CacheFamilyResolver` (`UnsupportedError`), арбитраж
  топ-N по `ModTime`, защита свежим обращением, бутстрап давности от
  `ModTime` при отсутствии строки обращений, versioned-ключи и `.retained`
  не трогаются, скоуп листинга по `remote-id`; `Preview` без мутаций
  носителя; сбой чтения обращений — fail-closed; `Policy` tri-state (nil —
  глобальный дефолт, `{0,0}` — выключено, значения — свои);
  `runner_test.go` — проход только по proxy-remote с включённой
  эффективной политикой, сбой одного remote не стопает остальных, отмена
  между remote, `Run`/`Stop` (идемпотентность, без финального прохода);
- unit конфига: `TestLoadDefaults` — `eviction.interval` = `24h`;
  `TestLoadEviction` — политика и период читаются (`{6h, 3, 90}`),
  `interval` = 0 легален (проход выключен), отрицательный `interval`,
  `min_versions=1` с возрастом (окно 404) и `max_age_days` без
  `min_versions` → ошибка конфига;
- unit резолверов семейств кеша — `TestCacheObjectFamily` в apt, rpm-md,
  pacman, apk и xbps: семейство кеш-пути из реального upstream-пути,
  объекты вне семейств (индексы, подписи) — `ok=false`; nix метода не
  имеет;
- контракт каталога (`internal/contract`, sqlite/postgres/mariadb):
  `remote_eviction_columns` — NULL (nil в домене, наследование) и `{0,0}`
  (указатель на нули, явно выключено) различаются и переживают roundtrip,
  `UpdateRemote` проходит цепочку nil → `{2,90}` → `{0,0}` → nil; миграция
  0014 накатывается идемпотентно, существующие строки получают NULL
  (`catalog_test.go`: `TestMigration0014EvictionOnExistingRows`,
  `TestRemoteEvictionRoundtrip`);
- web (`handlers_eviction_test.go`): прогноз — кандидаты и счётчики защит
  (`protected_by_min`/`protected_by_access`), применение — удаления и итог
  задачи (`kind=eviction`), 409 при активной задаче того же remote,
  503 `eviction_unavailable` без движка, политика через POST/PATCH/GET
  `/remotes` (tri-state: отсутствие ключа — не трогать, `null` —
  наследование, `{0,0}` — выключено; `min_versions=1` с возрастом → 400);
- integration `eviction_test.go` (build-tag): сквозной сценарий на живых
  sqlite + fs — листинг кеша, проход удаляет забытую версию, свежее
  обращение защищает (`object_access` scope `cache`), унаследованный
  глобальный дефолт, nix — 400 `eviction_unsupported`;
- e2e (Playwright, `run_e2e_tests`): блок «Очистка кеша» в карточке
  источника — tri-state политика, прогноз, подсказка зеркала, клиентская
  валидация (`min=1` с возрастом).

## Pacman-совместимость (волна «Pacman-совместимость», сессии 181–186)

Живой `pacman` против личного репо — раскладка записей `.db` и
GnuPG-совместимость ключа инстанса; закреплён кейс:

- integration `signing_gnupg_test.go` (build-tag, 183):
  `TestGnupgVerifiesSignatures` — подписи инстанса проверяются живым
  `gpg --verify` (тот же движок, что у apt и pacman-key/gpgv): cleartext
  `InRelease` и detached `Release.gpg` — тот же класс бинарной
  отсоединённой подписи, что `.db.sig` у pacman и `repomd.xml.asc` у
  rpm-md; `gnupg2` есть в образе `fedora:44` job'а `build-test`
  (строка шага установки — страховка от смены базового образа).
- живая проба 2026-10-07 (реальный клиент `archlinux:latest` в
  подман-контейнере против боевого инстанса, TLS — корневой CA контура,
  проба `repo/pacman-alexrus1234`): рабочий рецепт —
  `pacman-key --add key.asc` + `pacman-key --lsign-key <fpr>` +
  `SigLevel = Never DatabaseRequired` → `pacman -Syy` exit 0,
  `pacman -S incus-tools-loc` exit 0, `pacman -Q` = 7.5.1-1. Тем же
  прогоном вскрыты два нерабочих рецепта (исправлены в
  [func/ru/ecosystems/pacman.md](func/ru/ecosystems/pacman.md)): без
  `--lsign-key` — «unknown trust»; канон `Required DatabaseOptional` —
  pacman требует подпись пакета, идёт за `<пакет>.pkg.tar.zst.sig` (404)
  и падает на «failed to commit transaction». Там же зафиксирован
  сценарий смены ключа инстанса: до reindex `.db.sig` подписан прежним
  ключом, а `key.asc` уже отдаёт новый — `key "<fpr>" is unknown` и
  уход на внешний keyserver.

## Надёжность

Graceful shutdown каскадом; идемпотентные миграции; resume sync-задач
по etag/size; singleflight против stampede; bounded очереди; все
внешние операции с context-таймаутами; метрики hit-ratio/errors/bytes.
