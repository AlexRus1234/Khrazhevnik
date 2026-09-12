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
