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

# apk (Alpine Linux)

URL-префикс — `apk`. Пакеты content-addressed по имени+версии —
immutable-кеш навсегда; `APKINDEX.tar.gz` ревалидируется коротким TTL.
Метаданные upstream отдаются побайтово — подписи `.sig` валидны.

## Remote

```sh
curl -s -X POST http://127.0.0.1:30202/api/v1/remotes \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"alpine","ecosystem":"apk","base_url":"https://dl-cdn.alpinelinux.org/alpine","mode":"proxy","enabled":true}'
```

`mode = "mirror"` — фоновый sync; `include` — список архитектур
(например `["x86_64","aarch64"]`), пустой `include` — ошибка (у apk
нет корневого индекса архитектур).

## Кеш-прокси: /etc/apk/repositories

```
http://<хражевник>:29202/apk/alpine/v3.21/main
http://<хражевник>:29202/apk/alpine/v3.21/community
```

## Личное репо

Пакет кладётся в каталог своей архитектуры: `<архитектура>/<файл>.apk`
(`arch` из `.PKGINFO`); пакет `arch = noarch` — в каталог `noarch/`. Иные
пути (в том числе корень репо) — `400 validation_error`. Reindex пишет по
индексу на архитектуру — `<архитектура>/APKINDEX.tar.gz` (gzip+tar с
файлом `APKINDEX` в формате «K:V»; поле `F:` — фактический путь пакета от
корня репо) и detached-подпись `<архитектура>/APKINDEX.tar.gz.sig` ключом
инстанса. `noarch`-записи входят в индекс КАЖДОЙ архитектуры (клиент
читает индекс только своей и файл тянет из `/noarch/`). Индекс в корне
репо не генерируется (ранее записанный не удаляется — чистится руками).
Клиент:

```sh
curl -sO http://<хражевник>:29202/repo/<name>/key.asc
cp key.asc /etc/apk/keys/<name>.pem    # apk принимает ключи в /etc/apk/keys
echo 'http://<хражевник>:29202/repo/<name>' >> /etc/apk/repositories
apk update --allow-untrusted && apk add --allow-untrusted <пакет>
```

Архитектуру в строке `/etc/apk/repositories` указывать не нужно — клиент
подставляет свою сам и запрашивает `<repo-url>/<арх>/APKINDEX.tar.gz`.
`--allow-untrusted` нужен, пока подпись индекса не принимается клиентом
(`UNTRUSTED signature` — отложенный вопрос подписи личных apk-репо).
Поле `C:` записи — `Q1` + base64 от sha1 СЖАТЫХ байт control-секции `.apk`
(gzip-члена с `./.PKGINFO`), ровно как считает apk-tools: генерировать
иначе нельзя — клиент отвергает пакет на сверке (`BAD signature` в 2.x /
`v2 package integrity error` в 3.x). Инвариант проверен живьём на реальном
пакете Alpine (`tree-2.2.1-r0` из v3.21: `C:` совпал с апстримным
APKINDEX) и установкой `apk add` в alpine:3.21 и alpine:edge. `S:` —
размер всего файла.

Подробности — [personal-repos.md](../personal-repos.md).

## Классификация объектов

| Путь upstream                        | Класс    | TTL      |
|--------------------------------------|----------|----------|
| `*.apk`                              | immutable| навсегда |
| `APKINDEX.tar.gz`, `APKINDEX.json` (+`.sig`) | mutable | 5m |
| `keys/*` (публичные ключи)           | mutable  | 1h       |
| прочее                               | mutable  | 1m       |
