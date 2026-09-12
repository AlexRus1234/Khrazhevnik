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

# Khrazhevnik Documentation

This directory contains Khrazhevnik functional documentation in English.
The root `README.en.md` provides a system overview and initial setup
instructions; details requiring separate treatment are documented here.

| File | Contents |
|---|---|
| [quickstart.md](quickstart.md) | Quick start: container installation, bootstrap, the first remote, cache verification. |
| [config.md](config.md) | Configuration: all TOML sections, the `KHRZ_*` env, `file://` secrets, validation, the upstream proxy (HTTP/HTTPS/SOCKS5). |
| [api.md](api.md) | Admin REST API: authentication, endpoints, error codes. |
| [ui.md](ui.md) | Web admin UI: screens and typical operations. |
| [deploy.md](deploy.md) | Deployment: the quadlet, docker, bootstrap, client setup, image build. |
| [reverse-proxy.md](reverse-proxy.md) | Reverse proxy: Caddy/Traefik/nginx, TLS, trusted_proxies. |
| [storage-db.md](storage-db.md) | Object storage (fs/S3) and the catalog (sqlite/postgres/mariadb): selection and switching. |
| [personal-repos.md](personal-repos.md) | Personal repositories: upload, signing, client setup per ecosystem. |
| [benchmarks.md](benchmarks.md) | Performance: load-test methodology ([bench/](../../bench/README.md)) and reference results. |
| [ecosystems/](ecosystems/) | Ecosystem clients: [apt](ecosystems/apt.md), [rpm-md](ecosystems/rpm-md.md), [pacman](ecosystems/pacman.md), [apk](ecosystems/apk.md), [nix](ecosystems/nix.md). |

The Russian documentation is in [`docs/func/ru/`](../ru/README.md).

Internal development documentation is in [`docs/`](../../):
`ARCHITECTURE.md` (layers and import rules), `SPECIFICATION.md` (full
requirements and schemas), `TESTING.md` (testing strategy),
`ROADMAP.md` (the plan guide), `HISTORY.md` (stage history).
