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

# nix

Кеш-прокси nix binary cache (`narinfo` + `nar.xz`). Контент адресован —
идеальный immutable-кеш: `nar/<32hex>.nar.xz` кешируется навсегда,
`<32hex>.narinfo` ревалидируется раз в час. Метаданные upstream
отдаются побайтово — подписи (`Sig:`) остаются валидными, мы не
переписываем narinfo.

Поддерживается только **pull-through** (по использованию). Полное
зеркало `cache.nixos.org` (десятки ТБ) не цель: `Enumerate` возвращает
`UnsupportedError`, фоновой sync недоступен. 404 на narinfo — штатная
ситуация nix-клиента (перебор `substituters`): отдаётся корректный 404
(не 502) и negative-cached (повтор не бьёт upstream).

## Подключение remote

Зарегистрируйте upstream как remote (один раз):

```
khrazhevnik -config khrazhevnik.toml \
  -add-remote nix/cache=https://cache.nixos.org
```

Здесь `nix` — экосистема, `cache` — имя remote (slug), base-url —
upstream. Имя remote войдёт в публичный путь. После этого пакеты
доступны по `http://<host>:29202/nix/cache/<путь-upstream>`.

Адаптер nix включён в дефолтном конфиге (сессия 13, M2 — все
экосистемы). Экосистема активна сразу после добавления remote.

## nix.conf

В `/etc/nix/nix.conf` (или `~/.config/nix/nix.conf`):

```
substituters = http://localhost:29202/nix/cache https://cache.nixos.org
trusted-public-keys = cache.nixos.org-1:6NCHbD9f... (остаётся от upstream)
```

Хражевник ставится **первым** substituter'ом: попадание в кеш — HIT
без обращения к upstream; промах — прозрачный pull-through (upstream
качается и складывается в кеш). Резервный `https://cache.nixos.org`
гарантирует доступ, если прокси недоступен.

`trusted-public-keys` **не трогаем** — Хражевник не подменяет ключи и
не переподписывает narinfo. Клиент проверяет подписи upstream теми же
ключами, что и для `cache.nixos.org`. narinfo отдаётся byte-exact,
поэтому `Sig:` валиден, пока клиент доверяет ключу upstream.

## Проверка

```
# дёрнуть narinfo и nar через прокси; upstream не получит повторных
# запросов на nar (immutable, кеш навсегда):
nix-shell -p hello --substituters http://localhost:29202/nix/cache
```

Хражевник отдаёт `X-Cache: HIT`/`MISS` для диагностики: nar после
первого запроса — всегда `HIT`; narinfo — `MISS`/`HIT` по TTL 1h.

## Классификация объектов

| Путь upstream                 | Класс           | TTL        |
|-------------------------------|-----------------|------------|
| `nar/<32hex>.nar.xz`          | immutable       | навсегда   |
| `nar/<32hex>.nar`             | immutable       | навсегда   |
| `<32hex>.narinfo`             | mutable         | 1h         |
| `nix-cache-info`              | mutable         | 1h         |
| `log/<…>`                     | immutable       | навсегда   |
| прочее                        | mutable          | 1m         |

Хеш store path валидируется как 32 hex-символа (`[0-9a-f]{32}`). Это
контракт адаптера (сессия 13); реальный nix использует собственное
base32-подобное кодирование store path — несматченные nar/narinfo
уходят в conservative mutable{TTL 1m}, что не ломает pull-through, но
снижает hit-rate immutable-кеша. При необходимости контракт хеша
расширяется в следующей сессии.

## Ограничения

- Только pull-through; фоновый sync всего `cache.nixos.org` не
  поддерживается (`mode = mirror` для nix-remote возвращает
  `UnsupportedError` при запуске sync).
- `Remote.Include` для nix не используется.
- Narinfo отдаётся byte-exact; переподпись и патчи путей невозможны
  (подписи upstream должны быть валидны).
