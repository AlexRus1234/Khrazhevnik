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

# Документация Хражевника

Каталог содержит функциональную документацию Хражевника на русском
языке. Обзор системы и инструкция по первоначальному запуску — в
корневом `README.md`; вопросы, требующие отдельного рассмотрения,
документированы здесь.

| Файл | Содержание |
|---|---|
| [quickstart.md](quickstart.md) | Быстрый старт: установка контейнера, bootstrap, первый remote, проверка кеша. |
| [config.md](config.md) | Конфигурация: все секции TOML, env `KHRZ_*`, секреты `file://`, валидация, прокси upstream (HTTP/HTTPS/SOCKS5). |
| [api.md](api.md) | REST API админки: аутентификация, эндпоинты, коды ошибок. |
| [ui.md](ui.md) | Веб-админка: экраны и типовые операции. |
| [deploy.md](deploy.md) | Развёртывание: quadlet, docker, bootstrap, настройка клиентов, сборка образа. |
| [reverse-proxy.md](reverse-proxy.md) | Реверс-прокси: Caddy/Traefik/nginx, TLS, trusted_proxies. |
| [storage-db.md](storage-db.md) | Хранилище объектов (fs/S3) и каталог (sqlite/postgres/mariadb): выбор и переключение. |
| [personal-repos.md](personal-repos.md) | Личные репозитории: upload, подпись, настройка клиентов по экосистемам. |
| [ecosystems/](ecosystems/) | Клиенты экосистем: [apt](ecosystems/apt.md), [rpm-md](ecosystems/rpm-md.md), [pacman](ecosystems/pacman.md), [apk](ecosystems/apk.md), [nix](ecosystems/nix.md). |

Английская документация — в [`docs/func/EN/`](../EN/README.md).

Внутренняя документация разработки — в [`docs/`](../../):
`ARCHITECTURE.md` (слои и правила импортов), `SPECIFICATION.md` (полные
требования и схемы), `TESTING.md` (стратегия тестирования),
`ROADMAP.md` (история этапов).
