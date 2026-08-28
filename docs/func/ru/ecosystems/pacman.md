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

# pacman (Arch Linux)

URL-префикс — `pacman`. Пакеты content-addressed по NEVRA в имени —
идеальный immutable-кеш; репозитарные базы `{repo}.db` ревалидируются
коротким TTL. Метаданные upstream отдаются побайтово — подписи
`.sig` валидны.

## Remote

```sh
curl -s -X POST http://127.0.0.1:30202/api/v1/remotes \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"arch","ecosystem":"pacman","base_url":"https://geo.mirror.pkgbuild.com","mode":"proxy","enabled":true}'
```

`mode = "mirror"` — фоновый sync; `include` — список `repo/arch`
(например `["core/x86_64","extra/x86_64"]`), пустой `include` —
ошибка (у pacman нет корневого индекса репозиториев).

## Кеш-прокси: pacman.conf

`/etc/pacman.d/mirrorlist` — просто URL без репозиториев, pacman сам
подставит `core/`, `extra/`:

```
Server = http://<хражевник>:29202/pacman/arch/$repo/os/$arch
```

## Личное репо

Upload `.pkg.tar.zst` где угодно под корнем репо; `.db`,
`.files`, `.sig` — генерируются, upload туда запрещён. Legacy
`.pkg.tar.xz`/`.gz` не принимаются (400): в whitelist зависимостей нет
xz/gz-декодера — переупакуйте (`zstd` поверх распакованного tar).
Reindex создаёт
`<repo-name>.db` (tar.zst с desc-записями) + detached-подпись
`<repo-name>.db.sig` ключом инстанса. Клиент:

```sh
curl -sO http://<хражевник>:29202/repo/<name>/key.asc
pacman-key --add key.asc   # и подписать локально, при необходимости
```

`/etc/pacman.conf`:

```ini
[<name>]
SigLevel = Required DatabaseOptional
Server = http://<хражевник>:29202/repo/<name>
```

Подробности — [personal-repos.md](../personal-repos.md).

## Классификация объектов

| Путь upstream                       | Класс    | TTL      |
|-------------------------------------|----------|----------|
| `*.pkg.tar.zst|.xz|.gz` (+`.sig`)   | immutable| навсегда |

| `{repo}.db`, `{repo}.files` (+`.sig`, legacy `.tar.*`) | mutable | 5m |
| `keys/*` (публичные ключи)          | mutable  | 1h       |
| прочее                              | mutable  | 1m       |
