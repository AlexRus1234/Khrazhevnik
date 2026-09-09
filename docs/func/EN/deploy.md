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

# Deployment

The primary distribution is a scratch OCI image under rootless podman
quadlet (or docker compose). The alternative is a [bare binary
(CGO-free, static)](#running-from-the-binary-systemd) under systemd or
any process supervisor. For a quick setup see
[quickstart.md](quickstart.md); this page is a deployment reference.

The container listens on two ports:

| Port  | Access                       | Purpose                                                       |
|-------|------------------------------|---------------------------------------------------------------|
| 29202 | public                       | package serving (`/<eco>/<remote>/<path>`, `/repo/<name>/*`) + `/healthz` |
| 30202 | 127.0.0.1 only (quadlet)     | admin API `/api/v1`, `/metrics`, web admin UI `/ui`           |

The loopback-bound admin interface is a property of the quadlet
deployment (`PublishPort=127.0.0.1:...`). A bare binary without a
config listens on both ports on all interfaces (with a startup
warning); how to keep the admin interface closed from the outside —
see [SECURITY.md](../../SECURITY.md).

Rootless: both ports are ≥1024; ports below 1024 are served via a
reverse proxy on the host — see [reverse-proxy.md](reverse-proxy.md)
(Caddy/Traefik/nginx). Container: `USER 65534:65534`,
scratch (only the binary + a CA bundle), read-only rootfs
(`ReadOnlyRootfs=true` in the quadlet); the only writable path is the
`/var/lib/khrazhevnik` volume; PID 1 is the binary (no subprocesses,
a zombie reaper is not needed); graceful shutdown: SIGTERM → HTTP 5s
→ tasks 30s.

## Requirements

- podman ≥ 4 (quadlet, `host-gateway` for smoke), rootless mode;
- systemd --user (for quadlet) or a bare `podman run`;
- the data directory `/var/lib/khrazhevnik` (sqlite, fs-store, keys);
- OpenSSL (for JWT secret generation).

## Installation via quadlet

```sh
# 1. Quadlet config into the user generator path.
mkdir -p ~/.config/containers/systemd
cp deploy/quadlet/khrazhevnik.container ~/.config/containers/systemd/

# 2. JWT secret — as a Podman Secret (not exposed in env/`systemctl show`).
podman secret create jwt-secret "$(openssl rand -hex 32)"

# 3. Data directory; the container runs under UID 65534 (nobody).
sudo mkdir -p /var/lib/khrazhevnik
sudo chown 65534:65534 /var/lib/khrazhevnik

# 4. Reload the generator and start.
systemctl --user daemon-reload
systemctl --user start khrazhevnik.service
systemctl --user status khrazhevnik.service
```

`AutoUpdate=registry` in the quadlet enables image auto-updates via
`podman auto-update` (the `podman-auto-update.timer` timer). To pin a
specific version, replace the tag in `Image=` and remove `AutoUpdate=`.

Verification: `curl -s http://localhost:29202/healthz` → `ok`;
`curl -s http://127.0.0.1:30202/api/v1/` → JSON with
`service: khrazhevnik`.

## Running via Docker

The same image runs under plain docker — no podman or systemd needed.
A ready compose file is `deploy/docker-compose.yml` (ports, read-only
rootfs, the volume and stop-timeout mirror the quadlet):

```sh
# 1. Config + JWT secret into .env (next to the compose file; do not commit).
cp deploy/docker-compose.yml docker-compose.yml
echo "KHRZ_AUTH__JWT_SECRET=$(openssl rand -hex 32)" > .env

# 2. Data directory; the container runs under UID 65534 (nobody).
sudo mkdir -p /var/lib/khrazhevnik
sudo chown 65534:65534 /var/lib/khrazhevnik

# 3. Start.
docker compose up -d
curl -s http://localhost:29202/healthz   # → ok
```

The same as a single `docker run` (the secret is generated at container
creation and lives until the container is re-created — for stable
sessions use compose with `.env`):

```sh
docker run -d --name khrazhevnik \
  -p 29202:29202 -p 127.0.0.1:30202:30202 \
  --read-only \
  -v /var/lib/khrazhevnik:/var/lib/khrazhevnik \
  -e KHRZ_AUTH__JWT_SECRET="$(openssl rand -hex 32)" \
  --stop-timeout 40 \
  --restart on-failure \
  git.yadr00.internal/build/khrazhevnik:latest
```

Differences from the quadlet: the JWT secret is passed via env from
`.env` (Podman Secrets are unavailable) — the value is visible in
`docker inspect`, keep `.env` out of git and backups; to pin a version,
replace the tag with `vX.Y.Z`. Publishing on 80/443 and TLS — via a
reverse proxy ([reverse-proxy.md](reverse-proxy.md)).

## Running from the binary (systemd)

The binary is static (`CGO_ENABLED=0`, sqlite is pure Go) with no
runtime dependencies — only a data directory and an env secret.
Release artifacts `khrazhevnik-<version>-linux-amd64` + `.sha256` are
published by CI to Releases (Forgejo/GitHub/Codeberg, see
[RELEASE.md](../../RELEASE.md)); for other platforms build from source
([README](../../README.en.md#building-from-source)).

```sh
# 1. Download the release artifact and verify the checksum.
curl -fLO <release-url>/khrazhevnik-vX.Y.Z-linux-amd64
curl -fLO <release-url>/khrazhevnik-vX.Y.Z-linux-amd64.sha256
sha256sum -c khrazhevnik-vX.Y.Z-linux-amd64.sha256

# 2. Install the binary.
sudo install -m 0755 khrazhevnik-vX.Y.Z-linux-amd64 /usr/local/bin/khrazhevnik

# 3. System user and the data directory (sqlite, fs-store, keys).
sudo useradd --system --user-group --home-dir /var/lib/khrazhevnik --no-create-home khrazhevnik
sudo install -d -o khrazhevnik -g khrazhevnik /var/lib/khrazhevnik

# 4. Env file: the JWT secret and a loopbound admin — a bare binary
#    without a config listens on :30202 on all interfaces (warn in the log).
sudo install -d -m 0750 /etc/khrazhevnik
sudo sh -c 'umask 077; printf "KHRZ_AUTH__JWT_SECRET=%s\nKHRZ_SERVER__ADMIN_LISTEN=127.0.0.1:30202\n" "$(openssl rand -hex 32)" > /etc/khrazhevnik/khrazhevnik.env'

# 5. The unit and start.
sudo cp deploy/systemd/khrazhevnik.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now khrazhevnik
curl -s http://localhost:29202/healthz   # → ok
```

The ready unit is `deploy/systemd/khrazhevnik.service`:
`TimeoutStopSec=40` for the graceful shutdown cascade (SIGTERM → HTTP
5s → tasks 30s — the same margin as `StopTimeout=40` in the quadlet)
and hardening (`ProtectSystem=strict`, writable only
`/var/lib/khrazhevnik`, `NoNewPrivileges`, an empty
`CapabilityBoundingSet` — the ports are ≥1024). The env file is read
by systemd as root — `0600 root:root` is enough. For a TOML config —
a drop-in:

```sh
sudo systemctl edit khrazhevnik
# [Service]
# ExecStart=
# ExecStart=/usr/local/bin/khrazhevnik -config /etc/khrazhevnik/khrazhevnik.toml
```

Headless bootstrap without a container — the same `-add-remote` flag
(writes the remote to the database and exits; no jwt_secret needed —
the CLI substitutes a stub):

```sh
sudo -u khrazhevnik /usr/local/bin/khrazhevnik -add-remote apt/debian=https://deb.debian.org/debian
```

Another process supervisor (OpenRC, runit, supervisord) or a manual
run: an env `KHRZ_AUTH__JWT_SECRET` and a writable data directory are
enough — `khrazhevnik [-config <path>]`; flags: `-version`,
`-add-remote`. Then follow the common
[bootstrap](#first-start-bootstrap) and client setup.

## First start: bootstrap

If the database catalog is empty → open `http://127.0.0.1:30202/ui/` —
the web admin UI itself will offer to create the first admin
([ui.md](ui.md)). The same steps via the API: create an admin via
`/api/v1/setup`, then add upstreams (remotes). The headless
alternative is the `-add-remote` flag (writes a remote to the database
without starting the server).

```sh
# 1. First admin (once, while the users table is empty).
curl -s -X POST http://127.0.0.1:30202/api/v1/setup \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<password>"}'

# 2. Login — obtain the admin UI session JWT.
TOKEN=$(curl -s -X POST http://127.0.0.1:30202/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<password>"}' | jq -r .token)

# 3. Register an upstream (Debian apt caching proxy).
curl -s -X POST http://127.0.0.1:30202/api/v1/remotes \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"debian","ecosystem":"apt","base_url":"https://deb.debian.org/debian","mode":"proxy","enabled":true}'
```

The same via the flag (no server — convenient from CI/init scripts):

```sh
podman exec khrazhevnik /khrazhevnik -add-remote apt/debian=https://deb.debian.org/debian
```

All 5 ecosystems are enabled by default — no separate env opt-in is
needed. A 404 on `/<eco>/*` means either a disabled ecosystem
(`KHRZ_ECOSYSTEM__<NAME>__ENABLED=false`) or that no remote with that
name is registered.

## Pointing clients at the proxy

Khrazhevnik is transparent: the path after `/<remote-name>/` is
forwarded to the upstream byte-for-byte; signatures and checksums
remain valid — the client keyring does not change. Examples (full
pages covering mirror/include — in [ecosystems/](ecosystems/)):

### apt (Debian/Ubuntu)

`/etc/apt/sources.list.d/khrazhevnik.list`:

```
deb http://<Khrazhevnik>:29202/apt/debian stable main
```

### dnf / Zypper (rpm-md)

`/etc/yum.repos.d/khrazhevnik.repo` (dnf) or
`/etc/zypp/repos.d/khrazhevnik.repo` (zypper). The rpm-md URL prefix
is `rpm` (shorter than the adapter name `rpm-md`, as written in the
`.repo` baseurl).

```ini
[khrazhevnik-fedora]
name=khrazhevnik proxy of Fedora
baseurl=http://<Khrazhevnik>:29202/rpm/fedora/releases/$releasever/Everything/$basearch/os/
enabled=1
gpgcheck=1
```

### pacman / apk / nix

`Server = http://<Khrazhevnik>:29202/pacman/<remote>/$repo/os/$arch`,
a line in `/etc/apk/repositories`, `substituters` in `nix.conf` — see
[ecosystems/pacman.md](ecosystems/pacman.md),
[ecosystems/apk.md](ecosystems/apk.md), [ecosystems/nix.md](ecosystems/nix.md).

## A custom TOML config (optional)

By default the container runs on defaults + env (port, fs, sqlite,
ecosystems — everything from env). For an advanced config, mount a
TOML file and pass `-config` via `Exec=` in a quadlet drop-in:

```sh
mkdir -p ~/.config/containers/systemd/khrazhevnik.container.d
cat > ~/.config/containers/systemd/khrazhevnik.container.d/10-config.conf << 'EOF'
[Container]
Mount=type=bind,source=/etc/khrazhevnik/khrazhevnik.toml,destination=/etc/khrazhevnik/khrazhevnik.toml,readonly=true
Exec=-config /etc/khrazhevnik/khrazhevnik.toml
EOF
systemctl --user daemon-reload
systemctl --user restart khrazhevnik.service
```

The TOML and env schema (secrets via `file://`, all keys and
defaults) — in [config.md](config.md); the developers' canon — in
[docs/SPECIFICATION.md](../../SPECIFICATION.md#Конфигурация).

> **Strict TOML parsing.** An unknown or mistyped key is a startup
> error naming the key and the file line, for example:
> `unknown TOML keys — a typo or a stray key: "auth.session_tt"
> (line 3)`. Previously stray keys were silently ignored: when
> upgrading from earlier versions, remove them from the config or fix
> the typos. The env layer (`KHRZ_*`) has not changed.

## Building the image locally

```sh
make image                      # native platform, dev tag
make image TAG=v0.1.0           # with a version
make image PLATFORMS=linux/amd64,linux/arm64 TAG=v0.1.0  # multi-arch (requires qemu-user-static)
make smoke                      # smoke test of the built image
```

## Choosing storage and the database

The default (fs + sqlite) is KISS for a homelab. For production —
S3 + postgres/mariadb: see the quadlet example
`deploy/quadlet/khrazhevnik-s3.container`. Details and
recommendations — in [storage-db.md](storage-db.md).
