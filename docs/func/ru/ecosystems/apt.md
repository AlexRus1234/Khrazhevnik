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

# apt (Debian / Ubuntu)

URL-префикс — `apt`. Путь после `/<remote>/` пробрасывается upstream
побайтово: подписи InRelease и чексуммы остаются валидными, ключи
upstream не меняются.

## Remote

```sh
curl -s -X POST http://127.0.0.1:30202/api/v1/remotes \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"debian","ecosystem":"apt","base_url":"https://deb.debian.org/debian","mode":"proxy","enabled":true}'
```

`mode = "mirror"` — фоновый sync всего репозитория (план: `sync_interval`,
запуск вручную `POST /remotes/{id}/sync`). Для mirror обязателен
`include` — список dists с опциональной компонентой: `["stable"]`,
`["stable/main"]`, `["bookworm","bookworm-updates"]`. Пустой `include`
для apt — ошибка (у apt нет корневого индекса dists).

## Кеш-прокси: sources.list

Классический формат (`/etc/apt/sources.list` или
`/etc/apt/sources.list.d/khrazhevnik.list`):

```
deb http://<хражевник>:29202/apt/debian stable main
```

deb822 (`/etc/apt/sources.list.d/debian.sources`):

```
Types: deb
URIs: http://<хражевник>:29202/apt/debian
Suites: stable
Components: main
```

Подписи upstream валидны — `trusted=yes` не нужен, keyring не меняется.

## Личное репо

Upload `pool/...` (`.deb/.udeb/.ddeb/.dsc/.orig.tar.*/.debian.tar.*`),
запрет на `dists/*` (генерируется). Reindex создаёт
`dists/stable/main/binary-amd64/Packages` (+`.gz`, by-hash) и
`dists/stable/Release` + подписи `InRelease`/`Release.gpg` ключом
инстанса. Клиент:

```sh
curl -sO http://<хражевник>:29202/repo/<name>/key.asc
echo 'deb [signed-by=/root/key.asc] http://<хражевник>:29202/repo/<name> stable main' \
  > /etc/apt/sources.list.d/<name>.list
apt-get update && apt-get install <пакет>
```

Подробности — [personal-repos.md](../personal-repos.md).

## Классификация объектов

| Путь upstream                         | Класс    | TTL      |
|---------------------------------------|----------|----------|
| `pool/*`, `by-hash/*`                 | immutable| навсегда |
| `dists/*` (Release, Packages*, dep11, cnf, i18n) | mutable | 5m |
| прочее                                | mutable  | 1m       |

Mutable-индексы ревалидируются по ETag/Last-Modified (условный запрос
upstream); при его 5xx и включённом `stale_if_error` отдаётся устаревшая
копия с `X-Cache: STALE`.
