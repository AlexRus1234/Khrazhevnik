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

<div align="center">

<h1>Хражевник</h1>

**Кеш-прокси, зеркало и хостинг linux-репозиториев**

Один Go-бинарник + встроенная Vue 3 веб-админка. Экономит трафик и
ускоряет сборки: пакеты и метаданные кешируются локально, а личные
репозитории загружаются и подписываются прямо на инстансе.

[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg?style=flat-square)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8.svg?style=flat-square)](https://go.dev/)
[![Vue](https://img.shields.io/badge/Vue-3-4FC08D.svg?style=flat-square)](https://vuejs.org/)
[![Platform](https://img.shields.io/badge/Linux-any-1793D1.svg?style=flat-square)](#)
[![CI](https://img.shields.io/badge/CI-Forgejo%20Actions-ff7b00.svg?style=flat-square)](.forgejo/workflows/build.yml)

</div>

## Что это

1. **Кеш-прокси** — прозрачный pull-through для пакетных менеджеров:
   первый запрос уходит upstream, ответ складывается в кеш и дальше
   отдаётся локально. Метаданные upstream — **побайтово**: подписи и
   чексуммы остаются валидными, keyring клиентов не меняется.
2. **Зеркало** — полная локальная копия upstream-репозитория с фоновым
   sync (resume по etag/size, планировщик, jitter).
3. **Личные репо** — upload пакетов пользователями (scoped-токены,
   квоты, RBAC), автоматическая генерация индексов и **подпись**
   ключом инстанса (OpenPGP ed25519; для nix — переподпись narinfo).

Поддерживаемые экосистемы: **apt** (Debian/Ubuntu), **rpm-md**
(dnf + zypper), **pacman** (Arch), **apk** (Alpine), **nix**
(binary cache).

Хранилище объектов — `fs` или любое S3-совместимое; каталог —
`sqlite`, `postgres` или `mariadb`; всё переключается TOML-конфигом
без пересборки. Дистрибуция — OCI-контейнер из scratch (non-root,
read-only rootfs, PID 1 = бинарник) под rootless podman quadlet.

## Quickstart

```sh
cp deploy/quadlet/khrazhevnik.container ~/.config/containers/systemd/
podman secret create jwt-secret "$(openssl rand -hex 32)"
systemctl --user daemon-reload && systemctl --user start khrazhevnik
```

Дальше — `http://127.0.0.1:30202/ui/`: веб-админка проведёт
bootstrap (первый админ), добавление upstream'ов и настройку личных
репо. Пошагово — [docs/func/ru/quickstart.md](docs/func/ru/quickstart.md).

## Документация

| Документ                                       | Содержание                     |
|------------------------------------------------|--------------------------------|
| [quickstart](docs/func/ru/quickstart.md)       | Установка за 5 минут          |
| [deploy](docs/func/ru/deploy.md)               | Quadlet, rootless, secrets     |
| [config](docs/func/ru/config.md)               | Все ключи TOML + env `KHRZ_*` |
| [api](docs/func/ru/api.md)                     | REST-справочник                |
| [ui](docs/func/ru/ui.md)                       | Веб-админка                    |
| [ecosystems](docs/func/ru/ecosystems/)         | Клиенты: apt/dnf/pacman/apk/nix|
| [personal-repos](docs/func/ru/personal-repos.md)| Личные подписанные репо       |
| [storage-db](docs/func/ru/storage-db.md)       | fs/S3, sqlite/postgres/mariadb |
| [ARCHITECTURE](docs/ARCHITECTURE.md) / [SPECIFICATION](docs/SPECIFICATION.md) / [TESTING](docs/TESTING.md) | Для разработчиков |

## Разработка

```sh
make build    # bin/khrazhevnik (локально — только сборка и линт)
make lint     # golangci-lint (строгий, depguard слоёв)
```

Тесты (unit/integration/binary-smoke) гоняются в CI — Forgejo
Actions (`.forgejo/workflows/build.yml`), включая контрактные suite
на postgres/mariadb/minio и опциональные race/e2e. Контейнер-смоук —
локально перед релизом ([docs/RELEASE.md](docs/RELEASE.md)).

## Лицензия

AGPL-3.0-or-later — см. [LICENSE](LICENSE).
