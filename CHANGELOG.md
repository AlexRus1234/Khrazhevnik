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

### Изменено

- **БД:** индекс `idx_sync_jobs_remote_id` на `sync_jobs(remote_id)`
  (миграция 0008, все три диалекта); `JobStore.JobByRemote` —
  точечный lookup вместо полного обхода `Jobs()` в
  `mirror.findJobByRemote` (вызывался на каждом `touchJob` активного
  sync, `ProgressInterval=2s`). Закрыто обещание ROADMAP «заодно
  индекс sync_jobs по remote_id».

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
