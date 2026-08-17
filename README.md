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

**Русский**

<div align="center">

<h1>Хражевник</h1>

**Кеш-прокси и зеркало linux-репозиториев**

Хражевник — один Go-бинарник + Vue 3 SPA: прозрачный pull-through
кеш-прокси для пакетных менеджеров (apt, dnf/zypper, pacman, apk, nix),
фоновое зеркало upstream-репозиториев и личные подписанные репозитории
пользователей. Метаданные upstream отдаются побайтово — подписи и
чексуммы остаются валидными. Основная дистрибьюция — OCI-контейнер
(scratch, non-root) под rootless podman quadlet; СУБД и хранилище
подключаются через TOML (sqlite/postgres/mariadb, fs/S3).

**Статус: в разработке** (первый релиз ещё не вышел; см.
[docs/ROADMAP.md](docs/ROADMAP.md))

[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg?style=flat-square)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8.svg?style=flat-square)](https://go.dev/)
[![Vue](https://img.shields.io/badge/Vue-3-4FC08D.svg?style=flat-square)](https://vuejs.org/)
[![Platform](https://img.shields.io/badge/Linux-any-1793D1.svg?style=flat-square)](#)

</div>

## Лицензия

AGPL-3.0-or-later — см. [LICENSE](LICENSE).
