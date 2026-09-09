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
| mod/ecosystem/* (парсеры)| ≥90%         | unit + golden + fuzz             |
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

## Надёжность

Graceful shutdown каскадом; идемпотентные миграции; resume sync-задач
по etag/size; singleflight против stampede; bounded очереди; все
внешние операции с context-таймаутами; метрики hit-ratio/errors/bytes.
