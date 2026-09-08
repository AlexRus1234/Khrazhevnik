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

# REST API

The admin API is served on port :30202 under the root `/api/v1`. Most
manual operations are more convenient from the [web admin UI](ui.md) —
it uses the same API.

## Authentication

Two kinds of `Authorization: Bearer <…>`:

- **JWT session** — issued by `POST /auth/login`, TTL `auth.session_ttl`
  (8h by default). For the admin UI.
- **Scoped API token** (`khz_…`) — issued by an admin to a user for
  scripts/CI; the secret is shown once. The role and `token_version`
  are checked against the database **on every request**: token
  revocation and role changes take effect immediately.

Handler errors use a uniform JSON format: `{"error":"snake_case_code"}`.
The exception is 401/403 from the auth middleware (including 503 on a
database failure): returned as plain text (`unauthorized`, `forbidden`).
Mutations (non-GET) are written to the audit log.

## Common endpoints

| Method | Path                    | Auth | Code | Purpose                |
|--------|-------------------------|------|------|------------------------|
| GET    | `/healthz` (both ports) | —    | 200  | Liveness (`ok`)        |
| GET    | `/api/v1/`              | —    | 200  | JSON service description |
| GET    | `/metrics`              | admin| 200  | Prometheus exposition  |

## Authorization and bootstrap

| Method | Path                 | Auth                                                                                        | Code       | Purpose                                                       |
|--------|----------------------|---------------------------------------------------------------------------------------------|------------|---------------------------------------------------------------|
| POST   | `/api/v1/setup`      | empty users table (atomic), optional `X-Setup-Token` header; rate limit 10/min              | 201/400/403| Create the first admin `{username,password}` (password ≥ 8 bytes) |
| POST   | `/api/v1/auth/login` | —                                                                                           | 200/401    | `{username,password}` → `{token}` (JWT; TTL is `auth.session_ttl`); rate limit 10/min |
| POST   | `/api/v1/auth/logout`| session                                                                                     | 204        | Persistent JWT revocation (survives a restart; catalog failure — 503) |

Status code notes: `setup`/`login` above the 10/min per-IP limit — 429;
a password longer than 72 bytes (the bcrypt boundary) — 413 `too_large`
on `setup`/`login`/`POST /users`. The minimum password length is 8
bytes: anything shorter (including empty) — 400 `validation_error` on
`setup` and `POST /users`; on `login` a short password is a regular
`401 invalid_credentials`.

## Users and API tokens (admin)

| Method | Path                                      | Code       | Purpose                                                        |
|--------|-------------------------------------------|------------|----------------------------------------------------------------|
| GET    | `/api/v1/users`                           | 200        | List users                                                     |
| POST   | `/api/v1/users`                           | 201/400    | `{username,password,role?}` (role is `admin`/`user`, default `user`); password ≥ 8 bytes, otherwise 400 `validation_error` |
| DELETE | `/api/v1/users/{id}`                      | 204/404    | Deletion; the user's API tokens are revoked via cascade (FK ON DELETE CASCADE) and are never returned — the counter does not return them |
| POST   | `/api/v1/users/{id}/api-tokens`           | 201/400    | `{name,scopes[],ttl}` → `{token,id,name,scopes,expires_at}`; the token is shown **once** |
| GET    | `/api/v1/users/{id}/api-tokens`           | 200        | List tokens (no secrets)                                       |
| DELETE | `/api/v1/users/{id}/api-tokens/{tokenID}` | 204/404    | Token revocation                                               |

Token scopes: `admin` (everything), `repo:<id>:write` (upload/delete/
reindex/listing of a specific repository). The `admin` scope requires
the owner's current role to be admin: a role change disables admin
tokens immediately; repo tokens are unaffected.

`ttl` is a duration: 0/absent = a non-expiring token (zero
`expires_at`); a negative value — 400 `validation_error`.

## Remotes — upstreams (admin)

| Method | Path                        | Code         | Purpose                                                      |
|--------|-----------------------------|--------------|--------------------------------------------------------------|
| GET    | `/api/v1/remotes`           | 200          | List                                                         |
| POST   | `/api/v1/remotes`           | 201/400/409  | Create                                                       |
| PATCH  | `/api/v1/remotes/{id}`      | 200/404      | Update fields                                                |
| DELETE | `/api/v1/remotes/{id}`      | 204/404      | Delete (the cache remains)                                   |
| POST   | `/api/v1/remotes/{id}/sync` | 202/409/429  | Start a mirror sync background task; 409 — already running, 429 — worker limit |

Remote fields: `name` (slug `[a-z0-9._-]`), `ecosystem` (`apt`,
`rpm-md`, `pacman`, `apk`, `nix`), `base_url` (http(s)://), `mode`
(`proxy` | `mirror`), `enabled`, `sync_interval` (duration, 0 — manual
only), `include` (an array of strings: apt — dists[`/component`];
pacman — `repo/arch`; apk — architectures; rpm-md/nix — not used).

## Personal repositories

Creation/configuration — admin; upload/delete/reindex/listing — admin,
the owner, or a `repo:<id>:write` token.

| Method | Path                                  | Code             | Purpose                         |
|--------|---------------------------------------|------------------|---------------------------------|
| GET    | `/api/v1/repos`                       | 200              | List repositories               |
| POST   | `/api/v1/repos`                       | 201/400/409      | `{name,ecosystem,owner_id,quota}` |
| GET    | `/api/v1/repos/{id}`                  | 200/404          | Repository data                 |
| PATCH  | `/api/v1/repos/{id}`                  | 200/400/404/409  | Name/quota/owner (400 — unknown ecosystem, ecosystem change) |
| DELETE | `/api/v1/repos/{id}`                  | 204/404          | Delete with permissions         |
| GET    | `/api/v1/repos/{id}/perms`            | 200/404          | Write permissions               |
| POST   | `/api/v1/repos/{id}/perms`            | 204/400/404      | Grant a permission (`{user_id}`) |
| DELETE | `/api/v1/repos/{id}/perms/{userID}`   | 204/404          | Revoke a permission             |
| GET    | `/api/v1/repos/{id}/objects`          | 200              | Object listing                  |
| PUT    | `/api/v1/repos/{id}/objects/*`        | 201/409/411/413  | Upload (streaming; `Content-Length` is required, without it — 411) |
| DELETE | `/api/v1/repos/{id}/objects/*`        | 204/404          | Delete an object                |
| POST   | `/api/v1/repos/{id}/reindex`          | 202/409/429      | Index generation background task |

`quota` is `{max_bytes, max_objects}`; a zero field means no limit.
Upload: overwriting an existing key → 409 `conflict` (the `force=true`
parameter — admin session only: a scoped token and the owner receive
403 `admin_required`); exceeding the quota → 413 `quota_exceeded`;
exceeding the object limit → 413 `too_large`; a `Content-Length`
mismatch → abort and a clean `tmp/`. Path formats and generated indexes
per ecosystem — in [personal-repos.md](personal-repos.md).

## Public serving (:29202, no auth)

| Method | Path                       | Code      | Purpose                          |
|--------|----------------------------|-----------|----------------------------------|
| GET    | `/{eco}/{remote}/{path}`   | 200/404…  | Upstream caching proxy           |
| GET    | `/repo/{name}/{path}`      | 200/404   | Personal repository (objects + indexes) |
| GET    | `/repo/{name}/key.asc`     | 200/404   | Instance public OpenPGP key      |
| GET    | `/repo/{name}/nix-key.asc` | 200/404   | Public nix key (for narinfo signing) |

`/{eco}/*` is the ecosystem URL prefix: `apt`, `rpm` (for rpm-md),
`pacman`, `apk`, `nix`. The `X-Cache: HIT|MISS|STALE` header is used
for hit diagnostics.

A failure of our stack at any point of serving (storage on read/write/
listing, or the database catalog during repository lookup) — 503
`storage unavailable`; 502 is returned only for an upstream failure:
monitoring distinguishes "the upstream is broken" from "the instance
is broken" (sessions 50, 60).

## Background tasks (admin)

| Method | Path                 | Code     | Purpose                                                |
|--------|----------------------|----------|--------------------------------------------------------|
| GET    | `/api/v1/tasks`      | 200      | Task snapshots (sorted by `started_at`, earliest first) |
| GET    | `/api/v1/tasks/{id}` | 200/404  | Task snapshot                                          |

Snapshot: `{id, kind, label, state, phase, current, processed, total,
percent, speed_bps, logs, error, started_at, finished_at}`; `logs` is
the last 50 lines. The registry is in-memory; the persistent state of
sync tasks lives in `sync_jobs` (one per remote).

## Statistics and audit log (admin)

| Method | Path                  | Code | Purpose                                                                       |
|--------|-----------------------|------|-------------------------------------------------------------------------------|
| GET    | `/api/v1/cache/stats` | 200  | `{hits, misses, hit_ratio, stale_served, negative_hits, upstream_errors, bytes_from_upstream, bytes_to_clients, per_ecosystem}` |
| GET    | `/api/v1/audit`       | 200  | Audit log, keyset pagination `?after_id=&limit=`                              |

`per_ecosystem` is an array with one row per ecosystem that has traffic
(lexicographic name order): `{ecosystem, hits, misses, hit_ratio,
stale_served, negative_hits, upstream_errors, bytes_from_upstream,
bytes_to_clients}` — the same fields as the global values, plus the
name and its own hit_ratio (from the row's hits/misses); row sums
equal the global fields. Example:

```json
{
  "hits": 1, "misses": 2, "hit_ratio": 0.333,
  "per_ecosystem": [
    {"ecosystem": "apt", "hits": 1, "misses": 1, "hit_ratio": 0.5},
    {"ecosystem": "apk", "hits": 0, "misses": 1, "hit_ratio": 0}
  ]
}
```

## Error codes

`not_found`, `conflict`, `forbidden`, `admin_required` (a force-only
action by a non-admin), `unavailable` (database catalog failure in
auth paths), `invalid_key` (an invalid object key/path),
`validation_error`, `too_large`, `payload_too_large` (JSON request
body > 1 MiB), `length_required` (411, upload without
`Content-Length`), `quota_exceeded`, `stale`, `task_duplicate`,
`task_limit`, `invalid_json`, `setup_already_done`,
`invalid_setup_token`, `invalid_credentials`, `tasks_unavailable`,
`mirror_unavailable`, `publish_unavailable`, `unsupported`,
`internal`.
