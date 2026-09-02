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

# nix (binary cache)

URL-префикс — `nix`. Кеш-прокси narinfo + nar.xz: контент адресован —
идеальный immutable-кеш (`nar/<52 nix-base32>.nar.xz` кешируется
навсегда, `<32 nix-base32>.narinfo` ревалидируется раз в час).

## Remote

```sh
curl -s -X POST http://127.0.0.1:30202/api/v1/remotes \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"cache","ecosystem":"nix","base_url":"https://cache.nixos.org","mode":"proxy","enabled":true}'
```

Или headless-флагом:

```sh
khrazhevnik -config khrazhevnik.toml -add-remote nix/cache=https://cache.nixos.org
```

`mode = "mirror"` для nix не поддерживается (`UnsupportedError` при
запуске sync): полное зеркало `cache.nixos.org` — десятки ТБ, не-цель;
только pull-through «по использованию». `include` не используется.

## Кеш-прокси: nix.conf

`/etc/nix/nix.conf` (или `~/.config/nix/nix.conf`):

```
substituters = http://<хражевник>:29202/nix/cache https://cache.nixos.org
trusted-public-keys = cache.nixos.org-1:6NCHbD9f... (остаётся от upstream)
```

Хражевник ставится **первым** substituter'ом: попадание в кеш — HIT
без обращения к upstream; промах — прозрачный pull-through. Резервный
`https://cache.nixos.org` гарантирует доступ, если прокси недоступен.

`trusted-public-keys` **не трогаем** — narinfo отдаётся byte-exact,
подписи (`Sig:`) upstream валидны, клиент проверяет их теми же
ключами, что и для `cache.nixos.org`.

Проверка:

```sh
nix-shell -p hello --substituters http://<хражевник>:29202/nix/cache
```

`X-Cache` заголовок: nar после первого запроса — всегда `HIT`;
narinfo — `MISS`/`HIT` по TTL 1h. 404 на narinfo — штатная ситуация
nix-клиента (перебор substituter'ов): отдаётся корректный 404 (не
502) и negative-cached.

## Личное репо

Upload: `<хеш>.narinfo` (в корне репо) + `nar/<fileHash>.nar.xz|.nar`:
хеш — 32 символа nix-base32 (канонический алфавит nix: цифры и латиница
без `e`/`o`/`t`/`u` — так кодирует хеши store path сам nix);
fileHash — 52 символа nix-base32 (sha256 сжатого файла,
`(256−1)/5+1 = 52` — сессия 47); прочие пути — 400.

Reindex **переподписывает** narinfo: поле `Sig` заменяется ключом
инстанса (ed25519, формат `name:pubkey:signature`), остальное —
байт-точно. Это единственное место в проекте, где меняется чужой
файл; nar-файлы immutable, не трогаются. Клиент:

```
substituters = http://<хражевник>:29202/repo/<name> https://cache.nixos.org
trusted-public-keys = khrazhevnik:<pubkey-b64> cache.nixos.org-1:6NCHbD9f...
```

`<pubkey-b64>` = `GET /repo/<name>/nix-key.asc` — одна строка
`khrazhevnik:<base64>` (формат nix, НЕ armored OpenPGP — у nix своя
модель подписи). Без NarSigner (деградированный режим) narinfo
отдаются как есть — подписи upstream валидны, если клиент им доверяет.

Подробности — [personal-repos.md](../personal-repos.md).

## Классификация объектов

| Путь upstream                 | Класс    | TTL      |
|-------------------------------|----------|----------|
| `nar/<52 nix-base32>.nar.xz`  | immutable| навсегда |
| `nar/<52 nix-base32>.nar`     | immutable| навсегда |
| `<32 nix-base32>.narinfo`     | mutable  | 1h       |
| `nix-cache-info`              | mutable  | 1h       |
| `log/<…>`                     | immutable| навсегда |
| прочее                        | mutable  | 1m       |

## Ограничения

- Только pull-through; фоновый sync не поддерживается.
- Личные репо валидируют narinfo как 32 символа nix-base32, nar —
  как 52 (fileHash, сессия 47); прокси-классификация использует те
  же длины, несматченные пути уходят в conservative mutable{TTL 1m}.
- Narinfo отдаётся byte-exact; переподпись и патчи путей невозможны
  (подписи upstream должны быть валидны) — кроме личных репо, где
  переподпись и есть функция.
