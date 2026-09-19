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
   fs-хранилище, minio/pg/mariadb через CI-сервисы; build-tag
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
  (minio-контейнер): срез `[start, start+length)` byte-exact
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
- unit ar-парсера пакета (137): авто-детект zstd/gzip/raw по magic
  (xz → `ErrUnsupportedCompression`), `props.plist`/`./props.plist`,
  skip `files.plist`/payload стримингом, `≥1 MiB` props → ошибка капа,
  zstd-бомба > 1 GiB → `ErrDecompressTooLarge` (чтение в `io.Discard`);
- фаззинг: `FuzzParseRepoData` (композиция zstd→tar→index.plist,
  колбэк-счётчик без накопления), `FuzzOpenPackage` (три ветки
  компрессии, обрезки ar-заголовка 8/60/68, zstd-мусор, гигантское
  поле размера), `FuzzSplitPkgver` (нет паник; roundtrip при err==nil);
  golden-фикстура `testdata/repodata-golden.zst` (5+ реальных имён,
  `public-key` в meta) + `TestRepoDataGolden`/`…Meta`; crash-корпус
  коммитится только из находок;
- unit генератора/writer (140–141): roundtrip `WriteIndexPlist` ↔
  `ParseIndexPlist`, детерминизм (байт-в-байт при повторном вызове,
  сортировка записей по `pkgname`), 10k записей стримингом без OOM;
  генератор — кривое имя файла/битый `.xbps`/несовпадение props →
  честная ошибка, nil-Signer → индекс без `.sig2`, повторный reindex
  идемпотентен (байты repodata и `.sig2` равны);
- unit RSA-подписчика (139): roundtrip `SignSHA256` →
  `rsa.VerifyPKCS1v15`, digest ≠ 32 байт → ошибка, `LoadOrGenerate`
  перезагрузкой отдаёт тот же публичный PEM, заголовки `RSA PRIVATE
  KEY`/`PUBLIC KEY`, `Generate(0)`/битый материал → `KeyMaterialError`;
- web (142): `GET /repo/<name>/xbps-key` — 200 + тело от
  `-----BEGIN PUBLIC KEY-----`, неизвестное репо → 404, без
  `RsaSigner` маршрут не регистрируется → 404;
- integration `xbps_mirror_test.go` (build-tag): sync качает
  repodata+пакеты+`.sig2`, повторный sync — 0 новых загрузок
  (resume-diff по `Storage.Stat`), общий noarch из двух arch-индексов
  скачивается один раз, тело с чужим `filename-sha256` роняет sync и
  НЕ коммитит объект (Abort), после починки upstream повторный sync
  succeeds;
- integration `xbps_repo_test.go` (build-tag): upload `.xbps` (x86_64 +
  noarch) → reindex succeeded → `<arch>-repodata` читается парсерами
  131/132 (noarch в x86_64-группе, `filename-sha256` == телу) →
  `.sig2` верифицируется `crypto/rsa` против `/xbps-key`; не-`.xbps`
  upload → 400; несовпадение props с именем → reindex failed;
  повторный reindex — байты индекса неизменны;
- proxy integration (130): repodata и пакеты byte-exact, повторный
  запрос `X-Cache: HIT`, ревалидация mutable `*-repodata` (upstream
  304 без тела → клиенту копия из кеша), 404 negative-кеш;
- distro-test, нога **void** (144): `xbps-install -S` через прокси
  (`/etc/xbps.d`), TOFU-импорт ключа, второй HEAD → `X-Cache: HIT`,
  `/api/v1/cache/stats` `hits>0`.

## Надёжность

Graceful shutdown каскадом; идемпотентные миграции; resume sync-задач
по etag/size; singleflight против stampede; bounded очереди; все
внешние операции с context-таймаутами; метрики hit-ratio/errors/bytes.
