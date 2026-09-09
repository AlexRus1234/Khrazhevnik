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

# Реверс-прокси: Caddy / Traefik / nginx

Хражевник раздаёт голый HTTP на портах ≥1024 (rootless). Реверс-прокси
на хосте закрывает два сценария: TLS с сертификатом домена на 443 и
раздачу на стандартных портах 80/443. Инстанс в контейнере или голым
бинарником — без разницы, прокси смотрит на слушателя `127.0.0.1:29202`.

## Схема и порты

| Порт | Что | Как выставлять |
|---|---|---|
| 29202 | раздача пакетов `/<eco>/<remote>/*`, `/repo/<name>/*`, `/healthz` | основной домен, открыт всем клиентам пакетных менеджеров |
| 30202 | админ-API `/api/v1`, `/metrics`, веб-админка `/ui` | наружу не выставлять; при необходимости — отдельный субдомен за IP-allowlist/VPN |

В quadlet/compose-деплое 30202 уже привязан к loopback хоста — прокси,
стоящему на том же хосте, он доступен через `127.0.0.1:30202`.

## Правила, общие для любого прокси

- **Не включайте кеширование на прокси.** Кеш — работа Хражевника:
  дублирующий слой ломает ревалидацию mutable-индексов
  (ETag/Last-Modified), инвариант побайтовой раздачи и статистику.
- **Заголовок `X-Cache` (HIT/MISS/BYPASS) проходит клиенту без
  изменений** — не прячьте его и не подменяйте.
- **Стриминг в обе стороны.** Раздача больших пакетов клиенту и upload
  в личные репо должны идти через прокси без буферизации на диск.
- **Лимит тела запроса ≥ `publish.max_object_size`** (дефолт 1GiB):
  upload пакетов идёт через `POST` на админский порт, дефолтные лимиты
  прокси (например 1m у nginx) режут его 413-м до достижений приложения.
- WebSocket не нужен: админка поллит обычным HTTP.

## `trusted_proxies` — обязательно

Rate-limit `/login` и аудит считают адрес клиента по `RemoteAddr`;
заполненный `http.trusted_proxies` разрешает брать его из
`X-Forwarded-For` (обход справа налево до первой недоверенной записи —
подделать свою позицию клиент не может). Без списка XFF игнорируется,
и все клиенты за прокси делят одну корзину лимита.

Подставьте CIDR, откуда к инстансу приходят соединения от прокси:

- прокси на хосте, инстанс в docker — шлюз bridge-сети (дефолтный
  docker: `172.17.0.1/16`);
- прокси на хосте, инстанс в rootless podman — подсеть сети podman
  (смотрите `podman network inspect`);
- прокси и инстанс в одном compose — подсеть проекта;
- оба на хосте без контейнеров — `127.0.0.1/32`.

```
KHRZ_HTTP__TRUSTED_PROXIES=172.17.0.1/16,10.89.0.0/24
```

В TOML — `http.trusted_proxies = ["172.17.0.1/16"]`; схема —
[config.md](config.md).

## Caddy

HTTPS и сертификаты — автоматически (ACME). Стриминг — по умолчанию,
тела запросов Caddy не лимитирует.

```text
# /etc/caddy/Caddyfile — публичная раздача.
pkg.example.org {
	reverse_proxy 127.0.0.1:29202
}

# Админка (опционально): отдельный субдомен, пускаем только LAN/VPN.
khrz-admin.example.org {
	@lan remote_ip 10.0.0.0/8 192.168.0.0/16
	handle @lan {
		reverse_proxy 127.0.0.1:30202
	}
	respond 403
}
```

## Traefik (v3)

В compose-деплое — лейблы на сервисе (пример продолжает
`deploy/docker-compose.yml`; прокси и Хражевник в одной сети —
entrypoint `websecure` и resolver `le` определяются в статическом
конфиге Traefik). Admin-порт доступен внутри сети контейнера напрямую:
loopback-публикация `127.0.0.1:30202` — свойство хоста, Traefik ходит
на контейнер мимо неё.

```yaml
services:
  khrazhevnik:
    labels:
      - traefik.enable=true
      # Публичная раздача.
      - traefik.http.routers.khrz-public.rule=Host(`pkg.example.org`)
      - traefik.http.routers.khrz-public.entrypoints=websecure
      - traefik.http.routers.khrz-public.tls.certresolver=le
      - traefik.http.services.khrz-public.loadbalancer.server.port=29202
      # Админка (опционально): только из приватных сетей.
      - traefik.http.routers.khrz-admin.rule=Host(`khrz-admin.example.org`)
      - traefik.http.routers.khrz-admin.entrypoints=websecure
      - traefik.http.routers.khrz-admin.tls.certresolver=le
      - traefik.http.routers.khrz-admin.middlewares=khrz-lan-only
      - traefik.http.middlewares.khrz-lan-only.ipallowlist.sourcerange=10.0.0.0/8,192.168.0.0/16
      - traefik.http.services.khrz-admin.loadbalancer.server.port=30202
```

Без docker-лейблов — file provider (динамический конфиг):

```yaml
http:
  routers:
    khrz-public:
      rule: "Host(`pkg.example.org`)"
      entryPoints: [websecure]
      service: khrz-public
      tls: {}
  services:
    khrz-public:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:29202"
```

Стриминг у Traefik по умолчанию; лимита тела запроса нет — потолок
upload задаёт сам Хражевник (`publish.max_object_size`).

## nginx

Критичные директивы: стриминг в обе стороны, лимит тела, таймауты на
большие пакеты.

```nginx
# /etc/nginx/conf.d/khrazhevnik.conf — публичная раздача.
server {
    listen 443 ssl;
    http2 on;
    server_name pkg.example.org;

    ssl_certificate     /etc/letsencrypt/live/pkg.example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/pkg.example.org/privkey.pem;

    # Upload в личные репо: дефолт nginx 1m режет POST 413-м.
    # Держите не меньше publish.max_object_size (дефолт 1GiB).
    client_max_body_size 2g;

    location / {
        proxy_pass http://127.0.0.1:29202;
        proxy_http_version 1.1;

        # Стриминг: пакеты клиентам и upload от клиентов идут без
        # буферизации на диск прокси.
        proxy_buffering off;
        proxy_request_buffering off;

        # Большой пакет медленному клиенту занимает соединение надолго.
        proxy_read_timeout 1h;
        proxy_send_timeout 1h;

        # Не подменять и не прятать заголовок X-Cache из ответа.
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    server_name pkg.example.org;
    return 301 https://$host$request_uri;
}
```

Админка (опционально) — отдельный server с IP-allowlist; upload идёт
через неё, поэтому лимит тела и стриминг те же:

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name khrz-admin.example.org;

    ssl_certificate     /etc/letsencrypt/live/khrz-admin.example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/khrz-admin.example.org/privkey.pem;

    client_max_body_size 2g;

    location / {
        allow 10.0.0.0/8;
        allow 192.168.0.0/16;
        deny all;

        proxy_pass http://127.0.0.1:30202;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 1h;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Проверка после настройки

```sh
# 1. Healthz через домен.
curl -s https://pkg.example.org/healthz          # → ok

# 2. Индекс дважды: второй — X-Cache: HIT (кеш жив, заголовок прошёл).
curl -sI https://pkg.example.org/apt/debian/dists/stable/Release | grep -i x-cache
curl -sI https://pkg.example.org/apt/debian/dists/stable/Release | grep -i x-cache

# 3. trusted_proxies: пять неверных логинов с разных машин за прокси
#    НЕ должны уронить друг друга в rate-limit (если уронили — CIDR
#    прокси не попал в KHRZ_HTTP__TRUSTED_PROXIES).
```

Клиенты экосистем настраиваются на домен прокси вместо
`<хражевник>:29202` — [ecosystems/](ecosystems/); примеры клиентов и
bootstrap — [deploy.md](deploy.md).
