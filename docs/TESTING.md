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

## Уровни

1. **Unit** — рядом с кодом (`*_test.go`), stdlib testing, фейки пишутся
   руками (без testify).
2. **Integration** — `test/integration`: реальный sqlite `:memory:`,
   fs-хранилище, minio/pg/mariadb через CI-сервисы; build-tag
   `integration`, запуск `make test-integration` (с `-race`).
3. **Smoke** — `test/smoke`: живой контейнер, проверка curl'ом.
4. **Fuzz** — короткие прогоны в CI; crash-корпус коммитится в
   testdata.

`-race` обязателен в CI (`make test-race`).

## Детерминированность

Время — только `Clock`/`FixedClock`/`SeqClock` из `internal/testutil`,
случайность — `FixedRand`; golden-файлы для парсеров и генераторов
метаданных.

## Надёжность

Graceful shutdown каскадом; идемпотентные миграции; resume sync-задач
по etag/size; singleflight против stampede; bounded очереди; все
внешние операции с context-таймаутами; метрики hit-ratio/errors/bytes.
