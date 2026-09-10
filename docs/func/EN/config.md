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

# Configuration

Layers: **defaults → TOML → env**. The TOML flag `-config <path>`
attaches a file; the flag default is empty, and without the flag no TOML
is read at all (defaults+env — this is how the container operates). Env
overrides TOML, TOML overrides defaults.

Env format: the prefix `KHRZ_`, path segments joined with `__` (double
underscore), upper case, hyphens replaced with underscores:

```
KHRZ_SERVER__PUBLIC_LISTEN=:29203
KHRZ_STORAGE__S3__SECRET_ACCESS_KEY=file:///run/secrets/s3-key
```

An empty env value is treated as "not set".

## Secrets from files (`file://`)

Any string value (env or TOML) of the form `file:///path/to/file` is
replaced with the contents of the file: leading and trailing spaces and
newlines are trimmed. This is intended for quadlet `Secret` (the file
appears under `/run/secrets/…`) — the secret is not exposed in env or
in `systemctl show`:

```ini
# khrazhevnik.container (drop-in)
[Container]
Secret=jwt-secret,env=KHRZ_AUTH__JWT_SECRET
Secret=s3-key,env=KHRZ_STORAGE__S3__SECRET_ACCESS_KEY
```

Field types: duration — a `time.ParseDuration` string (`"8h"`, `"5m"`);
size — `"20GiB"`, `"512MiB"`, `"1024"` (bytes); bool — `true/false`.

## `[server]`

| Key             | Default  | Env                          | Purpose                      |
|-----------------|----------|------------------------------|------------------------------|
| `public_listen` | `:29202` | `KHRZ_SERVER__PUBLIC_LISTEN` | Package serving + `/healthz` |
| `admin_listen`  | `:30202` | `KHRZ_SERVER__ADMIN_LISTEN`  | `/api/v1`, `/metrics`, `/ui` |

## `[http]`

| Key               | Default | Env                                    | Purpose             |
|-------------------|---------|----------------------------------------|---------------------|
| `trusted_proxies` | —       | `KHRZ_HTTP__TRUSTED_PROXIES` (CSV)     | Reverse-proxy CIDRs |

Empty — the login rate limit counts by `RemoteAddr` (the status quo).
Filled — the client address is taken from `X-Forwarded-For`, walking
from right to left up to the first untrusted position. Without this,
all clients behind a proxy share a single 10/min bucket (a global login
lockout); with excessive trust, a client can forge XFF and bypass the
limit. The bucket map is limited to 10000 entries (IPv6 rotation does
not grow it indefinitely).

## `[storage]`

| Key     | Default | Env                    | Purpose      |
|---------|---------|------------------------|--------------|
| `driver`| `fs`    | `KHRZ_STORAGE__DRIVER` | `fs` \| `s3` |

### `[storage.fs]`

| Key   | Default                      | Env                      |
|-------|------------------------------|--------------------------|
| `path`| `/var/lib/khrazhevnik/store` | `KHRZ_STORAGE__FS__PATH` |

### `[storage.s3]` (required when `driver = "s3"`)

| Key                | Default                      | Env                                   |
|--------------------|------------------------------|---------------------------------------|
| `endpoint`         | —                            | `KHRZ_STORAGE__S3__ENDPOINT`          |
| `region`           | —                            | `KHRZ_STORAGE__S3__REGION`            |
| `bucket`           | —                            | `KHRZ_STORAGE__S3__BUCKET`            |
| `access_key_id`    | —                            | `KHRZ_STORAGE__S3__ACCESS_KEY_ID`     |
| `secret_access_key`| —                            | `KHRZ_STORAGE__S3__SECRET_ACCESS_KEY` |
| `path_style`       | `true`                       | `KHRZ_STORAGE__S3__PATH_STYLE`        |
| `spool_dir`        | `/var/lib/khrazhevnik/spool` | `KHRZ_STORAGE__S3__SPOOL_DIR`         |

For details on the drivers, see [storage-db.md](storage-db.md).

## `[database]`

| Key     | Default                                | Env                     |
|---------|----------------------------------------|-------------------------|
| `driver`| `sqlite`                               | `KHRZ_DATABASE__DRIVER` |
| `dsn`   | `/var/lib/khrazhevnik/khrazhevnik.db`  | `KHRZ_DATABASE__DSN`    |

`driver` ∈ `sqlite` \| `postgres` \| `mariadb`. DSN: a file path
(sqlite), `postgres://user:pass@host/db?…`, `user:pass@tcp(host:3306)/db?…`.

## `[auth]`

| Key              | Default | Env                         | Purpose                                       |
|------------------|---------|-----------------------------|-----------------------------------------------|
| `jwt_secret`     | —       | `KHRZ_AUTH__JWT_SECRET`     | **required** (env/file)                       |
| `session_ttl`    | `8h`    | `KHRZ_AUTH__SESSION_TTL`    | TTL of the web admin UI JWT session           |
| `setup_token`    | —       | `KHRZ_AUTH__SETUP_TOKEN`    | Optional protection of the one-time `/setup`  |
| `bcrypt_cost`    | `12`    | `KHRZ_AUTH__BCRYPT_COST`    | bcrypt cost of passwords (4–15)               |
| `touch_interval` | `1m`    | `KHRZ_AUTH__TOUCH_INTERVAL` | Minimum interval for persisting a token's last_used |

`jwt_secret` must be non-empty and no shorter than **32 bytes** —
otherwise fail-fast validation aborts at startup (a short HS256 secret
can be brute-forced offline; generate one with `openssl rand -base64
32`). Do not put it into a production TOML: use env or `file://`.

## `[cache]`

| Key               | Default  | Env                                | Purpose                             |
|-------------------|----------|------------------------------------|-------------------------------------|
| `stale_if_error`  | `true`   | `KHRZ_CACHE__STALE_IF_ERROR`       | Serve stale content on upstream 5xx |
| `max_object_size` | `20GiB`  | `KHRZ_CACHE__MAX_OBJECT_SIZE`      | Upper limit of a cacheable object   |
| `negative_ttl_404`| `5m`     | `KHRZ_CACHE__NEGATIVE_TTL_404`     | Negative caching of 404             |
| `negative_ttl_5xx`| `30s`    | `KHRZ_CACHE__NEGATIVE_TTL_5XX`     | Negative caching of 5xx             |
| `stats_flush_interval` | `1m` | `KHRZ_CACHE__STATS_FLUSH_INTERVAL` | Periodic flush of cache stats counters to the DB (`cache_stats`); `0` = disabled |

## `[mirror]`

| Key               | Default | Env                              | Purpose                                                        |
|-------------------|---------|----------------------------------|----------------------------------------------------------------|
| `workers`         | `4`     | `KHRZ_MIRROR__WORKERS`           | Concurrent sync background tasks                               |
| `interval_jitter` | `10m`   | `KHRZ_MIRROR__INTERVAL_JITTER`   | Jitter of scheduled syncs                                      |
| `max_bandwidth`   | `0`     | `KHRZ_MIRROR__MAX_BANDWIDTH`     | Total download rate of all sync workers, bytes/s (a string of the form `10MiB`); `0` = unlimited |

## `[publish]`

| Key                   | Default  | Env                                      | Purpose                               |
|-----------------------|----------|------------------------------------------|---------------------------------------|
| `max_object_size`     | `1GiB`   | `KHRZ_PUBLISH__MAX_OBJECT_SIZE`          | Limit for a single upload             |
| `default_quota_bytes` | `5GiB`   | `KHRZ_PUBLISH__DEFAULT_QUOTA_BYTES`     | Quota of a new repository (0 = none)  |
| `default_quota_files` | `10000`  | `KHRZ_PUBLISH__DEFAULT_QUOTA_FILES`     | The same by file count (0 = none)     |

## `[signing]`

| Key          | Default                     | Env                            |
|--------------|-----------------------------|--------------------------------|
| `keys_dir`   | `/var/lib/khrazhevnik/keys` | `KHRZ_SIGNING__KEYS_DIR`       |
| `passphrase` | —                           | `KHRZ_SIGNING__PASSPHRASE`     |

The instance key (OpenPGP ed25519) is generated on the first start.
With an empty `passphrase`, the private key resides in `private.asc`
with 0600 permissions. The `file://` expansion works (suitable for a
quadlet Secret).

## `[metrics]`

| Key      | Default | Env                      |
|----------|---------|--------------------------|
| `enabled`| `true`  | `KHRZ_METRICS__ENABLED`  |

## `[ecosystem.<name>]` — apt, rpm-md, pacman, apk, nix

All 5 ecosystems are enabled in the default config; the section is
needed only to override:

```toml
[ecosystem.rpm-md]        # in TOML, rpm_md and "rpm-md" are equivalent
enabled = false           # disable the adapter
```

Env can enable an ecosystem even without it being mentioned in TOML:
`KHRZ_ECOSYSTEM__RPM_MD__ENABLED=true`. A build without the blank-import
of the required adapter fails at startup with a clear registry error.

## Other env

| Variable         | Default | Purpose                                |
|------------------|---------|----------------------------------------|
| `KHRZ_LOG_LEVEL` | `info`  | `debug` \| `info` \| `warn` \| `error` |

## Upstream (outbound) proxy

All upstream requests — both the caching proxy and mirror sync — go
through a single outbound HTTP client (`outboundHTTPClient`,
`cmd/khrazhevnik/wire.go`) using the standard
`http.ProxyFromEnvironment`. The proxy is configured via regular Go
env variables — **without** the `KHRZ_` prefix and outside of TOML:

| Variable    | Purpose                                                            |
|-------------|--------------------------------------------------------------------|
| `HTTP_PROXY`| proxy for `http://` upstreams                                      |
| `HTTPS_PROXY`| proxy for `https://` upstreams                                    |
| `NO_PROXY`  | exceptions (CSV: hosts, domain suffixes, CIDRs) — go directly      |

Lowercase names (`https_proxy`, etc.) are also honored. Go does not
read `ALL_PROXY` — to route "everything through one proxy", set both
`HTTP_PROXY` and `HTTPS_PROXY`.

URL schemes: `http://`, `https://`, `socks5://`, `socks5h://`
(equivalent for SOCKS5 — the hostname is resolved by the proxy). The
scheme is mandatory: a schemeless value is treated by Go as an HTTP
proxy, and an HTTP CONNECT sent to a SOCKS port will not work.

Authentication is the userinfo in the URL
(`socks5://user:pass@host:port`): SOCKS5 — RFC 1929 login/password,
HTTP(S) — Basic. Percent-encode special characters in the
login/password, otherwise the URL parser silently truncates the value.

Container: everything outbound through SOCKS5, loopback direct:

```sh
podman run ... \
  -e HTTP_PROXY="socks5://user:pass%21@192.0.2.10:1080" \
  -e HTTPS_PROXY="socks5://user:pass%21@192.0.2.10:1080" \
  -e NO_PROXY="localhost,127.0.0.1" \
  git.yadr00.internal/alexrus1234/khrazhevnik
```

These variables affect outbound fetch requests only — the
`public_listen`/`admin_listen` listeners are not proxied. The loopback
exception in `NO_PROXY` is needed by utilities running next to the app
(self-bootstrap curl, etc.) that read the same variables. CI coverage:
distro-test with the `use_socks_proxy` input.

## Validation

Fail-fast at startup, with the list of **all** problems reported at
once: `jwt_secret` is non-empty, drivers are among the allowed values,
durations/ports are valid, and the fields required by the selected
driver are present (for s3 — endpoint/region/bucket/keys).
