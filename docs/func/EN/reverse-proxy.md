<!--
Khrazhevnik — caching proxy and mirror for Linux package repositories
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

# Reverse proxy: Caddy / Traefik / nginx

Khrazhevnik serves plain HTTP on ports ≥1024 (rootless). A reverse
proxy on the host covers two scenarios: TLS with a domain certificate
on 443 and serving on the standard ports 80/443. A containerized
instance or a bare binary makes no difference — the proxy talks to the
listener at `127.0.0.1:29202`.

## Layout and ports

| Port | What | How to expose |
|---|---|---|
| 29202 | package serving `/<eco>/<remote>/*`, `/repo/<name>/*`, `/healthz` | the primary domain, open to all package-manager clients |
| 30202 | admin API `/api/v1`, `/metrics`, web admin UI `/ui` | do not expose; if necessary — a separate subdomain behind an IP allowlist/VPN |

In the quadlet/compose deployment 30202 is already bound to the host
loopback — a proxy on the same host reaches it via `127.0.0.1:30202`.

## Rules common to any proxy

- **Do not enable caching on the proxy.** Caching is Khrazhevnik's
  job: a duplicate layer breaks mutable-index revalidation
  (ETag/Last-Modified), the byte-exact serving invariant, and the stats.
- **The `X-Cache` header (HIT/MISS/BYPASS) passes to the client
  unchanged** — do not hide or override it.
- **Streaming in both directions.** Serving large packages to clients
  and uploads to personal repositories must pass through the proxy
  without buffering to disk.
- **Request body limit ≥ `publish.max_object_size`** (default 1GiB):
  package uploads go via `POST` to the admin port; proxy defaults
  (e.g. nginx's 1m) cut them off with a 413 before the app sees them.
- No WebSocket needed: the admin UI polls over plain HTTP.

## `trusted_proxies` — mandatory

The `/login` rate limit and the audit derive the client address from
`RemoteAddr`; a filled `http.trusted_proxies` allows taking it from
`X-Forwarded-For` (walked right-to-left up to the first untrusted
entry — a client cannot spoof its own position). Without the list XFF
is ignored, and all clients behind the proxy share a single limit
bucket.

Substitute the CIDR the proxy's connections to the instance come from:

- proxy on the host, instance in docker — the bridge network gateway
  (default docker: `172.17.0.1/16`);
- proxy on the host, instance in rootless podman — the podman network
  subnet (see `podman network inspect`);
- proxy and instance in one compose project — the project subnet;
- both on the host without containers — `127.0.0.1/32`.

```
KHRZ_HTTP__TRUSTED_PROXIES=172.17.0.1/16,10.89.0.0/24
```

In TOML — `http.trusted_proxies = ["172.17.0.1/16"]`; the schema — in
[config.md](config.md).

## Caddy

HTTPS and certificates are automatic (ACME). Streaming is the default;
Caddy does not limit request bodies.

```text
# /etc/caddy/Caddyfile — public serving.
pkg.example.org {
	reverse_proxy 127.0.0.1:29202
}

# Admin UI (optional): a separate subdomain, LAN/VPN only.
khrz-admin.example.org {
	@lan remote_ip 10.0.0.0/8 192.168.0.0/16
	handle @lan {
		reverse_proxy 127.0.0.1:30202
	}
	respond 403
}
```

## Traefik (v3)

In a compose deployment — labels on the service (the example extends
`deploy/docker-compose.yml`; the proxy and Khrazhevnik share a network
— the `websecure` entrypoint and the `le` resolver are defined in
Traefik's static config). The admin port is reachable directly inside
the container network: the `127.0.0.1:30202` loopback publishing is a
host-side property; Traefik hits the container bypassing it.

```yaml
services:
  khrazhevnik:
    labels:
      - traefik.enable=true
      # Public serving.
      - traefik.http.routers.khrz-public.rule=Host(`pkg.example.org`)
      - traefik.http.routers.khrz-public.entrypoints=websecure
      - traefik.http.routers.khrz-public.tls.certresolver=le
      - traefik.http.services.khrz-public.loadbalancer.server.port=29202
      # Admin UI (optional): private networks only.
      - traefik.http.routers.khrz-admin.rule=Host(`khrz-admin.example.org`)
      - traefik.http.routers.khrz-admin.entrypoints=websecure
      - traefik.http.routers.khrz-admin.tls.certresolver=le
      - traefik.http.routers.khrz-admin.middlewares=khrz-lan-only
      - traefik.http.middlewares.khrz-lan-only.ipallowlist.sourcerange=10.0.0.0/8,192.168.0.0/16
      - traefik.http.services.khrz-admin.loadbalancer.server.port=30202
```

Without docker labels — the file provider (dynamic config):

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

Traefik streams by default; there is no request body limit — the
upload ceiling is enforced by Khrazhevnik itself
(`publish.max_object_size`).

## nginx

The critical directives: streaming in both directions, the body limit,
timeouts for large packages.

```nginx
# /etc/nginx/conf.d/khrazhevnik.conf — public serving.
server {
    listen 443 ssl;
    http2 on;
    server_name pkg.example.org;

    ssl_certificate     /etc/letsencrypt/live/pkg.example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/pkg.example.org/privkey.pem;

    # Uploads to personal repositories: nginx's 1m default cuts POSTs
    # with a 413. Keep it at least publish.max_object_size (default 1GiB).
    client_max_body_size 2g;

    location / {
        proxy_pass http://127.0.0.1:29202;
        proxy_http_version 1.1;

        # Streaming: packages to clients and uploads from clients pass
        # without the proxy buffering them to disk.
        proxy_buffering off;
        proxy_request_buffering off;

        # A large package to a slow client holds the connection long.
        proxy_read_timeout 1h;
        proxy_send_timeout 1h;

        # Do not hide or override the X-Cache response header.
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

The admin UI (optional) is a separate server with an IP allowlist;
uploads go through it, so the body limit and streaming are the same:

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

## Verifying the setup

```sh
# 1. Healthz via the domain.
curl -s https://pkg.example.org/healthz          # → ok

# 2. An index twice: the second one is X-Cache: HIT (the cache works,
#    the header passes).
curl -sI https://pkg.example.org/apt/debian/dists/stable/Release | grep -i x-cache
curl -sI https://pkg.example.org/apt/debian/dists/stable/Release | grep -i x-cache

# 3. trusted_proxies: five failed logins from different machines
#    behind the proxy must NOT lock each other out (if they do — the
#    proxy CIDR is missing from KHRZ_HTTP__TRUSTED_PROXIES).
```

Ecosystem clients are pointed at the proxy domain instead of
`<khrazhevnik>:29202` — see [ecosystems/](ecosystems/); client
examples and bootstrap — in [deploy.md](deploy.md).
