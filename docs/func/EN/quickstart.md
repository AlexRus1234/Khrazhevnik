<!--
Hrazhevnik — caching proxy and mirror for Linux package repositories
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

# Quick Start

In five minutes: container → first admin → first remote → an apt client
through the caching proxy. Rootless podman + systemd --user on a Linux
machine is assumed.

## 1. Container installation

```sh
# quadlet into the user systemd generator path.
mkdir -p ~/.config/containers/systemd
cp deploy/quadlet/khrazhevnik.container ~/.config/containers/systemd/

# JWT secret as a Podman Secret (not exposed in env or systemctl show).
podman secret create jwt-secret "$(openssl rand -hex 32)"

# Data directory: the container runs under UID 65534 (nobody).
sudo mkdir -p /var/lib/khrazhevnik
sudo chown 65534:65534 /var/lib/khrazhevnik

# Start.
systemctl --user daemon-reload
systemctl --user start khrazhevnik.service
curl -s http://localhost:29202/healthz   # → ok
```

Details, environment variables, and a custom TOML — in
[deploy.md](deploy.md) and [config.md](config.md).

## 2. Bootstrap: the first admin

While the `users` table is empty, the web admin UI offers to create an
admin on the first visit. The same via the API:

```sh
curl -s -X POST http://127.0.0.1:30202/api/v1/setup \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<password>"}'
```

Open `http://127.0.0.1:30202/ui/` and log in — from there on,
everything can be done from the UI ([ui.md](ui.md)). The steps below
are the same actions via the API.

## 3. The first remote (Debian caching proxy)

```sh
TOKEN=$(curl -s -X POST http://127.0.0.1:30202/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<password>"}' | jq -r .token)

curl -s -X POST http://127.0.0.1:30202/api/v1/remotes \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"debian","ecosystem":"apt","base_url":"https://deb.debian.org/debian","mode":"proxy","enabled":true}'
```

A headless alternative (without bringing up the UI/API — for init
scripts):

```sh
podman exec khrazhevnik /khrazhevnik -add-remote apt/debian=https://deb.debian.org/debian
```

## 4. Client configuration

On any Debian/Ubuntu machine, specify Hrazhevnik instead of the
upstream:

```sh
echo 'deb http://<hrazhevnik>:29202/apt/debian stable main' \
  > /etc/apt/sources.list.d/khrazhevnik.list
apt-get update
apt-get install hello
```

Signatures and checksums remain valid: upstream metadata is served
byte-for-byte.

## 5. Cache verification

```sh
curl -sI http://<hrazhevnik>:29202/apt/debian/dists/stable/main/binary-amd64/Packages.gz | grep -i x-cache
```

A repeated request is served from the cache (`X-Cache: HIT`); packages
(`pool/…`) are cached forever, indexes (`dists/…`) are revalidated by
ETag/Last-Modified.

## What is next

- All ecosystems (apt, dnf/zypper, pacman, apk, nix) — [ecosystems/](ecosystems/).
- Mirrors (`mode = mirror`) — [README.en.md](../../README.en.md#mirror).
- Personal repositories with signing — [personal-repos.md](personal-repos.md).
- The web admin UI — [ui.md](ui.md).
- REST API reference — [api.md](api.md).
