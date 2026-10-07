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
immutable-кеш; репозитарные базы `{repo}.db` ревалидируются
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

`/etc/pacman.d/mirrorlist` содержит только URL, без имён репозиториев;
pacman сам подставит `core/`, `extra/`:

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
pacman-key --add key.asc
pacman-key --lsign-key <fingerprint>   # обязательно: иначе ключ «unknown trust»
```

`/etc/pacman.conf`:

```ini
[<name>]
SigLevel = Never DatabaseRequired
Server = http://<хражевник>:29202/repo/<name>
```

`Never DatabaseRequired` — подпись базы обязательна (генератор эмитит
`<repo-name>.db.sig` ключом инстанса, проверка идёт через GnuPG), а
подписи пакетов клиент не требует: **пакеты в личных репо не подписаны**
— генератор подписывает только метаданные. Канон Arch
`SigLevel = Required DatabaseOptional` для такого репо НЕ работает: с
`Required` на пакетах pacman идёт за `<пакет>.pkg.tar.zst.sig`, которого
в репо нет (404), и падает на «failed to commit transaction» (живая
проба 2026-10-07, `archlinux:latest`). Импорта ключа без локального
доверия тоже мало: с `pacman-key --add` (без `--lsign-key`) ответ —
`signature from "Khrazhevnik <repo@localhost>" is unknown trust`.

Если ключ не импортирован вообще, обход — `SigLevel = Never
DatabaseNever` (ничего не проверяется — рабочая, но НЕбезопасная
конфигурация).

**Смена ключа инстанса ломает проверку до reindex:** `key.asc` уже отдаёт
новый ключ, а `.db.sig` подписан прежним — клиент видит
`error: <repo>: key "<fpr>" is unknown` и уходит резолвить ключ на
внешний keyserver (в суверенном контуре его нет). Диагностика —
`gpg --list-packets <repo-name>.db.sig` (issuer fpr) против
`gpg --show-keys key.asc`; лечение — reindex всех репо инстанса.
Инстансы, созданные до v1.3.1, перегенерируют ключ инстанса при старте
(EdDSA legacy — прежний alg 27 GnuPG не разбирает), поэтому им reindex
нужен безусловно, а клиентам — повторный импорт `key.asc`.

Подробности — [personal-repos.md](../personal-repos.md).

## Классификация объектов

| Путь upstream                       | Класс    | TTL      |
|-------------------------------------|----------|----------|
| `*.pkg.tar.zst|.xz|.gz` (+`.sig`)   | immutable| навсегда |

| `{repo}.db`, `{repo}.files` (+`.sig`, legacy `.tar.*`) | mutable | 5m |
| `keys/*` (публичные ключи)          | mutable  | 1h       |
| прочее                              | mutable  | 1m       |
