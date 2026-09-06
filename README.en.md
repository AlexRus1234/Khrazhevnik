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

**English** | [Русский](README.md) |

<div align="center">

<h1>Khrazhevnik</h1>

**Caching proxy, mirror, and hosting for Linux package repositories**

Khrazhevnik is a self-contained server for caching and mirroring Linux
package repositories. The Go binary and the built-in web admin UI
(Vue 3) are combined into a single executable; the object store is a
local directory or any S3-compatible storage, the catalog is SQLite,
PostgreSQL, or MariaDB, selected via TOML configuration without
rebuilding. The primary distribution is an OCI container from `scratch`
(non-root, read-only rootfs) run under a rootless podman quadlet.

[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg?style=flat-square)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8.svg?style=flat-square)](https://go.dev/)
[![Vue](https://img.shields.io/badge/Vue-3-4FC08D.svg?style=flat-square)](https://vuejs.org/)
[![Vite](https://img.shields.io/badge/Vite-7-646CFF.svg?style=flat-square)](https://vite.dev/)
[![Platform](https://img.shields.io/badge/Linux-any-1793D1.svg?style=flat-square)](#quick-start)
[![CI](https://img.shields.io/badge/CI-Forgejo%20Actions-ff7b00.svg?style=flat-square)](.forgejo/workflows/build.yml)

</div>

> **Transparency for clients.** Upstream metadata is served
> **byte-for-byte** — not a single byte is rewritten: signatures and
> checksums remain valid, and client keyrings do not change:
>
> ```bash
> # /etc/apt/sources.list.d/khrazhevnik.list
> deb http://<Khrazhevnik>:29202/apt/debian stable main
> ```
>
> Khrazhevnik only adds a cache on top (packages — permanently, indexes —
> revalidation by ETag/Last-Modified), background mirrors, and personal
> signed user repositories.

---

## Contents

- [Features](#features)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Deployment and security](#deployment-and-security)
- [API and web admin UI](#api-and-web-admin-ui)
- [Project structure](#project-structure)
- [Technology stack](#technology-stack)
- [Development](#development)
- [Plans](#plans)
- [License](#license)

> Extended documentation on deployment, configuration, the REST API,
> ecosystem clients, and personal repositories is available in
> [`docs/func/EN/`](docs/func/EN/quickstart.md). This file provides a
> system overview and initial setup instructions.

The project was developed according to a predefined architecture; an AI
assistant was used while preparing the source code.[^1]

---

## Features

### Caching proxy

- Transparent pull-through for the supported package managers: the first
  request for an object goes upstream, the response is stored in the
  cache, and subsequent requests are served locally (`X-Cache: HIT`)
- Object classification by ecosystem rules: packages and
  content-addressed objects are immutable (kept permanently); indexes
  (`dists/`, `repodata/`, `APKINDEX`, `{repo}.db`, narinfo) are mutable
  with conditional revalidation by ETag/Last-Modified and a TTL
- `stale-if-error` (optional) and negative caching of 404/5xx in memory:
  an upstream failure is not passed through to clients
- Singleflight per key: concurrent requests for the same object do not
  hit the upstream; a cacheable object size limit
  (`cache.max_object_size`)

### Mirror

- A complete local copy of an upstream repository (`mode = mirror`):
  background sync with a worker pool, retries, and a bandwidth limit
  (token bucket)
- Idempotent resume: every run compares the upstream listing with the
  objects already present and downloads the missing ones; progress is
  kept in the catalog (`files=N;bytes=M`), task state survives a restart
- Per-remote scheduler: `sync_interval` plus a random jitter; manual runs
  via the API or the web admin UI (409 on duplicate, 429 on the worker
  limit)
- Include filters: apt — dists and components (`stable`, `stable/main`);
  pacman — `repo/arch`; apk — architectures

### Personal repositories

- Package uploads by users: streamed directly into the store with a
  mandatory `Content-Length` and on-the-fly byte verification (an abort
  cleans up `tmp/`)
- RBAC: admins — everywhere; the repository owner and a scoped token
  `repo:<id>:write` — upload/delete/reindex/list; reading is public
  without authentication
- Per-repository quotas `bytes`/`files`, a single-object limit,
  overwriting an existing key returns 409 (`force` — admin only, audited)
- Index generation by the background reindex task (apt: `Packages` +
  `.gz`, `by-hash/SHA256/*`, `Release`)
- Signing with the instance key (OpenPGP ed25519): `InRelease`
  (cleartext) and `Release.gpg` (detached); for nix — narinfo re-signing
  (only the `Sig` field is replaced, the rest is byte-exact); when the
  signer is unavailable, repositories keep working without signatures
- The public key is served at `GET /repo/<name>/key.asc` on the public
  port

### Ecosystems

| Ecosystem | Clients | URL prefix | Mirror |
|---|---|---|---|
| **apt** | Debian, Ubuntu | `/apt/` | yes (+ include filter) |
| **rpm-md** | dnf, Zypper | `/rpm/` | yes |
| **pacman** | Arch Linux | `/pacman/` | yes (+ include filter) |
| **apk** | Alpine Linux | `/apk/` | yes (+ include filter) |
| **nix** | binary cache | `/nix/` | no — pull-through on use only |

Metadata parsers of all ecosystems (deb822, repomd/primary XML, tar.zst
`{repo}.db`, `APKINDEX.tar.gz`, narinfo) are streaming, with a
decompression limit and fuzzing since the first adapter.

### Interfaces and security

- Two listeners: the public `:29202` (package serving without
  authentication + `/healthz`), the admin `:30202` (`/api/v1`,
  `/metrics`, SPA `/ui`). The default for `:30202` is all interfaces
  (startup writes a warning to the log); loopback is provided by the
  quadlet (`PublishPort=127.0.0.1:30202:30202`)
- Web admin UI (Vue 3, Russian/English): a dashboard with cache
  statistics and live tasks, remotes, repositories with
  upload/reindex, users and scoped tokens, the audit log, public keys
  with ready-made client lines (`signed-by=…`, `rpm --import`,
  `pacman-key --add`, …)
- Authentication: JWT sessions (bcrypt, rate limit 10/min on login,
  revocation on logout) and scoped API tokens (only sha256 is stored,
  shown once); role and `token_version` are checked against the DB on
  every request
- Audit of all mutations (actor/action/object/result/detail) with
  keyset pagination
- Prometheus metrics (`/metrics`, behind auth): hits/misses/stale/
  negative per ecosystem, bytes from upstream/to clients, histograms of
  durations and object sizes
- A single path-traversal check point for all request paths

A detailed description is provided in [`docs/func/EN/`](docs/func/EN/).

---

## Quick start

### Requirements

| Component | Version | Purpose |
|---|---|---|
| **podman** | 4+ | Rootless container, quadlet |
| **systemd --user** | — | Quadlet generator |
| **OpenSSL** | — | JWT secret generation |
| **Go** | 1.26+ | Building from source (optional) |
| **Node.js** | 22+ | Building the Web UI (optional) |

### Installation (container)

```bash
# 1. Quadlet — into the user systemd generator path.
mkdir -p ~/.config/containers/systemd
cp deploy/quadlet/khrazhevnik.container ~/.config/containers/systemd/

# 2. The JWT secret — a Podman Secret (not exposed in env or `systemctl show`).
podman secret create jwt-secret "$(openssl rand -hex 32)"

# 3. Data directory: the container runs under UID 65534 (nobody).
sudo mkdir -p /var/lib/khrazhevnik
sudo chown 65534:65534 /var/lib/khrazhevnik

# 4. Start.
systemctl --user daemon-reload
systemctl --user start khrazhevnik.service
curl -s http://localhost:29202/healthz   # → ok
```

### Bootstrap and the first remote

When the `users` table is empty, the web admin UI at
`http://127.0.0.1:30202/ui/` offers to create the first administrator;
upstreams and personal repositories are then configured from the UI.
The same steps via the API:

```bash
# The first administrator (once, while the users table is empty).
curl -s -X POST http://127.0.0.1:30202/api/v1/setup \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<password>"}'

# Login → JWT; register the Debian caching proxy.
TOKEN=$(curl -s -X POST http://127.0.0.1:30202/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<password>"}' | jq -r .token)

curl -s -X POST http://127.0.0.1:30202/api/v1/remotes \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"debian","ecosystem":"apt","base_url":"https://deb.debian.org/debian","mode":"proxy","enabled":true}'
```

A headless alternative for init scripts (without starting the server):

```bash
podman exec khrazhevnik /khrazhevnik -add-remote apt/debian=https://deb.debian.org/debian
```

### Client setup

On any Debian/Ubuntu machine, point the client at Khrazhevnik instead of
the upstream:

```bash
echo 'deb http://<Khrazhevnik>:29202/apt/debian stable main' \
  > /etc/apt/sources.list.d/khrazhevnik.list
apt-get update && apt-get install hello
```

Signatures and checksums remain valid: upstream metadata is served
byte-for-byte. Cache check: a repeated request for `dists/…/Packages.gz`
returns `X-Cache: HIT`. dnf/zypper, pacman, apk, and nix clients — in
[`docs/func/EN/ecosystems/`](docs/func/EN/ecosystems/).

### Building from source

```bash
# The Web UI and the server part, in the order used by CI:
make web-build
make build        # the executable bin/khrazhevnik
```

No CGO is required (SQLite — `modernc.org/sqlite`), the executable is
static. A build for the target environment (as in CI):

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags="-s -w \
  -X main.Version=1.0.0" \
  -o khrazhevnik ./cmd/khrazhevnik
```

> For package main the linker accepts only `-X main.Version=…`; the
> full import path (`khrazhevnik/cmd/khrazhevnik.Version`) is silently
> not applied — the version stays `dev` (as in CI and the
> Containerfile).

> Release binaries (`khrazhevnik-<version>-linux-amd64` + `.sha256`)
> and the OCI image are published manually from CI to the Packages and
> Releases of the connected registries. For development — build from
> source.

A step-by-step guide is in
[`docs/func/EN/quickstart.md`](docs/func/EN/quickstart.md).

---

## Configuration

`khrazhevnik.toml` (the `-config` flag; an empty value means defaults +
env only):

```toml
[server]
public_listen = ":29202"        # package serving + /healthz
admin_listen  = ":30202"        # /api/v1, /metrics, /ui

[storage]
driver = "fs"                   # fs | s3
[storage.fs]
path = "/var/lib/khrazhevnik/store"
[storage.s3]
endpoint = "" ; region = "" ; bucket = "" ; path_style = true

[database]
driver = "sqlite"               # sqlite | postgres | mariadb
dsn    = "/var/lib/khrazhevnik/khrazhevnik.db"

[auth]
jwt_secret   = ""               # NOT in a production file: env/file (required)
session_ttl  = "8h"
setup_token  = ""               # optional protection for the first-admin bootstrap

[cache]
stale_if_error  = true
max_object_size = "20GiB"
negative_ttl_404 = "5m" ; negative_ttl_5xx = "30s"

[mirror]
workers = 4 ; interval_jitter = "10m"

[publish]
max_object_size    = "1GiB"     # a single uploadable object limit
default_quota_bytes = "5GiB"    # new repository quota (0 = no limit)
default_quota_files = 10000

[signing]
keys_dir = "/var/lib/khrazhevnik/keys"   # instance ed25519 key
# passphrase = ""              # optional: env KHRZ_SIGNING__PASSPHRASE

[metrics]
enabled = true

[ecosystem.apt]                 # apt | rpm-md | pacman | apk | nix;
enabled = true                  # the section is only needed for overrides
```

Application layers: **defaults → TOML → env**. The env prefix is `KHRZ_`,
path segments are joined with `__` in upper case:
`KHRZ_AUTH__JWT_SECRET`, `KHRZ_STORAGE__S3__SECRET_ACCESS_KEY`,
`KHRZ_ECOSYSTEM__RPM_MD__ENABLED`. Values of the form
`file:///run/secrets/x` (env or TOML) are read from a file — quadlet
Secret support. Validation is fail-fast with a list of all problems at
once. The full scheme is in
[`docs/func/EN/config.md`](docs/func/EN/config.md).

---

## Deployment and security

The primary distribution is an OCI image from `scratch`: the binary +
a CA bundle, `USER 65534:65534`, a read-only rootfs; writable is only
the volume `/var/lib/khrazhevnik` (SQLite, the fs-store, signing keys).
The binary is PID 1, there are no subprocesses (OpenPGP is in-process),
so no zombie reaper is needed; graceful shutdown: SIGTERM → HTTP 5s →
background tasks 30s.

| Port | Access | Purpose |
|---|---|---|
| 29202 | public | package serving (`/<eco>/<remote>/<path>`, `/repo/<name>/*`), `/healthz` |
| 30202 | all interfaces (default; a warning at startup — loopback via the quadlet's `PublishPort`) | admin API `/api/v1`, `/metrics`, web admin UI `/ui` |

Rootless mode: both ports are ≥1024; publishing on 80/443 is done via a
reverse proxy on the host. `AutoUpdate=registry` in the quadlet enables
image auto-updates via `podman auto-update`. The default (fs + sqlite)
is for a homelab; for production — S3 + postgres/mariadb (an example
quadlet — `deploy/quadlet/khrazhevnik-s3.container`, recommendations —
in [`docs/func/EN/storage-db.md`](docs/func/EN/storage-db.md)).

An alternative to the container is a bare binary under systemd or any
process supervisor; the JWT secret is passed via the env variable
`KHRZ_AUTH__JWT_SECRET=file:///run/secrets/jwt-secret`.

The full deployment guide is in
[`docs/func/EN/deploy.md`](docs/func/EN/deploy.md).

---

## API and web admin UI

| Interface | Summary | Details |
|---|---|---|
| **REST API** | `/api/v1`: setup/login, remotes, repos (+objects/perms/reindex), users, api-tokens, tasks, cache/stats, audit; errors — `{"error":"snake_case"}` | [`docs/func/EN/api.md`](docs/func/EN/api.md) |
| **Web admin UI** | `/ui/` on the admin port; RU/EN; embedded into the binary (`go:embed`) | [`docs/func/EN/ui.md`](docs/func/EN/ui.md) |
| **Metrics** | `/metrics` (Prometheus exposition, behind auth) | [`docs/func/EN/api.md`](docs/func/EN/api.md) |
| **Personal repositories** | upload by token, reindex, signing, client setup | [`docs/func/EN/personal-repos.md`](docs/func/EN/personal-repos.md) |

Admin API authentication: `Authorization: Bearer <jwt>` (browser) or a
scoped API token `Bearer khz_...` (CI scripts: `admin`,
`repo:<id>:write`).

---

## Project structure

```
.
├── cmd/khrazhevnik/          # Entry point: main.go (~40 lines), wire.go —
│                             # the only wiring (compile-time registry)
├── internal/
│   ├── core/
│   │   ├── port/             # Contracts: Storage, Ecosystem, Catalog*, Signer, Clock, Rand, HTTP
│   │   ├── domain/           # Models + typed errors (stdlib only)
│   │   ├── config/           # Layers: defaults → TOML → env KHRZ_* (+file:// secrets)
│   │   ├── dbtalk/           # Catalog SQL dialect shim (placeholder/upsert)
│   │   ├── engine/           # Usecase logic: cache, mirror, publish, auth
│   │   ├── registry/         # Compile-time module registry
│   │   └── web/              # chi routers, middleware, TaskRegistry, embedded SPA
│   ├── mod/                  # Modules (registered in init()): ecosystem/
│   │                         # {apt, rpmmmd, pacman, apk, nix}, storage/{fs, s3},
│   │                         # db/{sqlite, postgres, mariadb}, sign/{openpgp, ed25519}
│   ├── testutil/             # Shared test doubles (FixedClock, FakeStorage, …)
│   └── contract/             # Catalog/storage contract suites (integration)
├── migrations/<driver>/      # Embedded goose migrations (per-DBMS directory)
├── web/                      # Vue 3 + Vite + TypeScript SPA (bundle → core/web/assets)
├── deploy/                   # Containerfile (node → golang → scratch) + quadlet/
├── test/                     # integration/ (in-process + binary-smoke), smoke/
├── docs/                     # ARCHITECTURE/SPECIFICATION/TESTING/ROADMAP; func/EN/
└── .forgejo/workflows/       # CI: build, tests, e2e, OCI
```

The business logic (`core/domain`, `core/engine`) does not import `os`,
`syscall`, `net`, `net/http`, or concrete modules — all I/O goes through
the `core/port` interfaces; the core and the modules do not know about
each other, wiring happens only in `wire.go`. The rules are enforced by
the `depguard` linter.

---

## Technology stack

**Backend:** Go 1.26 · chi v5 · pelletier/go-toml/v2 ·
modernc.org/sqlite (no CGO) · jackc/pgx/v5 · go-sql-driver/mysql ·
pressly/goose/v3 · golang-jwt/jwt/v5 · golang.org/x/crypto (bcrypt) ·
golang.org/x/sync (singleflight) · golang.org/x/time (rate) ·
ProtonMail/go-crypto (OpenPGP) · minio/minio-go/v7 ·
klauspost/compress (zstd) · prometheus/client_golang · `log/slog` ·
`go:embed`.

**Frontend:** Vue 3 (Composition API) · vue-router 4 · Vite 7 ·
TypeScript 5.9 (vue-tsc).

**Infrastructure and quality:** Forgejo Actions (CI) · golangci-lint
(strict config, layer depguard) · `go vet` / `gofmt` · unit /
integration / binary-smoke test levels · fuzzing of third-party format
parsers · Playwright E2E (optional) · podman (OCI from scratch,
multi-arch).

---

## Development

| Command | Purpose |
|---|---|
| `make lint` | `golangci-lint run ./...` (strict config) |
| `make vet` | `go vet ./...` |
| `make test` | `go test ./...` |
| `make test-race` | `go test -race ./...` |
| `make test-integration` | `go test -race -tags integration ./test/integration/...` |
| `make cover` | Coverage report |
| `make build` | Build `bin/khrazhevnik` |
| `make web-build` | Vite build of the Web UI into `internal/core/web/assets/` |
| `make web-dev` | Vite dev server proxying `/api` to `:30202` |
| `make image` | OCI image from `deploy/Containerfile` (`PLATFORMS`, `TAG`) |
| `make smoke` | Live container smoke test (locally, before a release) |
| `make clean` | Remove `bin/`, `coverage/`, restore the web-assets stub |

On a fresh clone, the web-assets stub takes effect first (Go commands
build without the frontend); the real bundle — `make web-build`. All
tests run in CI (Forgejo Actions): contract suites on
postgres/mariadb/minio, binary-smoke of the built artifact, optional
`-race` and Playwright E2E.

Developer documentation (reading order before making changes):

1. [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — layers, import rules, engine invariants.
2. [docs/SPECIFICATION.md](docs/SPECIFICATION.md) — requirements, REST API, DB schema.
3. [docs/TESTING.md](docs/TESTING.md) — testing strategy.
4. [docs/ROADMAP.md](docs/ROADMAP.md) — the plan and stage history.

---

## Plans

Development directions after the v1.0.0 release (old-version eviction
and other post-v1 questions are covered in
[docs/ROADMAP.md](docs/ROADMAP.md)). Priority: XBPS and
pkg first — their "directory + index" model repeats already solved
tasks; Flatpak requires a new publishing mechanism and comes last.

Every new ecosystem is a `port.Ecosystem` adapter: object
classification (immutable/mutable), a metadata parser, mirror
enumeration, and a personal-repository index generator — without core
or contract changes. The acceptance criteria stay the same: byte-exact
metadata proxying, a mirror with resume, personal repositories with
signing, parser fuzzing, and a real client in verification.

### Void Linux (XBPS)

A repository is a directory of the form `current/<arch>/`: `.xbps`
packages and a `repodata` index with an ed25519 `.sig2` signature. The
classification is straightforward: packages are immutable and stored
permanently, `repodata` is mutable with revalidation by
ETag/Last-Modified. A mirror is a recursive directory copy; resume and
include filters by architecture fit the existing machinery (similar to
apk).

Adapter work: a streaming repodata parser (a proprietary archive
format with plist metadata inside) — for the mirror, statistics, and
detection of non-index objects; a repodata generator for personal
repositories — a functional analogue of `xbps-rindex`; the `.sig2`
signature is a format distinct from both OpenPGP and the instance
ed25519 key, requiring a separate Signer adapter (the `port.Signer`
contract allows this). The Void client is available in the container
distro-test matrix — automated verification with a real `xbps-install`
is possible on par with the five current ecosystems.

### pkg (FreeBSD, OpenBSD)

FreeBSD pkg(8): a repository is a directory with `meta.conf`, the
`packagesite.txz`/`digests.txz` archives (YAML metadata), and
`.pkg`/`.txz` packages. Indexes are mutable, packages are immutable;
repository signing uses an RSA key published in the client
configuration. Personal repositories need a `packagesite`+`digests`
generator and a third key format (RSA) in the signing module.

OpenBSD pkg_add(7): there is no shared index file — each package
carries its own metadata, and the client resolves dependencies itself;
a repository is merely a `packages/<arch>/` directory. For a caching
proxy this is the simplest possible case: all objects are immutable,
negative caching and singleflight work without any parser at all; a
mirror is an exact directory copy.

The limitation of both: the clients are not Linux, and the CI runner
(Linux containers) does not cover them — acceptance verification
remains manual per the RELEASE.md checklist; a VM or a separate runner
is an open question.

### Flatpak

A Flatpak repository is an OSTree store: a signed `summary`,
content-addressed objects (sha256, zstd packing), and static deltas.
The byte-exact invariant holds naturally: objects are immutable
forever, `summary`/`summary.sig` are mutable with revalidation; a
mirror is a recursive HTTP copy of the store.

Personal repositories are the hardest of the three tasks, and the
stage is deferred separately: publishing means creating OSTree commits
(`flatpak build-export` + `build-update-repo`), not uploading ready
artifacts; at the first stage Flatpak will be limited to the proxy and
the mirror. Signing is GPG, matching the OpenPGP adapter format. Open
questions: client behavior when a mirror lacks part of its deltas,
range requests to pack files, and the feasibility of GC for
unreferenced objects.

---

## License

The project is distributed under the **[GNU Affero General Public
License v3.0](LICENSE)** or later.

```
Khrazhevnik — caching proxy and mirror for Linux package repositories
Copyright (C) 2026  AlexRus1234

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
```

[^1]: The source code was developed with an AI assistant according to the
predefined project architecture; architectural decisions, result
verification, and final integration were performed by the author.
