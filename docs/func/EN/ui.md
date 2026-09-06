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

# Web admin UI

The SPA is embedded into the binary (`//go:embed`) and served on the
admin port: **`http://127.0.0.1:30202/ui/`**. The language is
Russian/English (a switcher in the header); all operations go through
the [REST API](api.md).

## Login

- **Login**: username + password → a JWT session (TTL
  `auth.session_ttl`, 8h by default). Logging out revokes the JWT.
- **Bootstrap**: when the users table is empty, creation of the first
  admin is offered instead of a login (the second tab). If
  `auth.setup_token` is set, it is entered as well.
- Without a token, only `/ui/login` is accessible; session expiry (a
  401 from any request) automatically returns the user to the login
  screen.

## Dashboard

Cache statistics (`/api/v1/cache/stats`): hits/misses, hit-ratio,
stale serves, negative-hits, upstream errors, bytes from upstream and
to clients. Below — a live list of background tasks (state, progress,
speed). A hint with a link to Prometheus `/metrics`.

## Remotes

Upstream management: creation/editing/deletion, switching
`proxy`/`mirror`, `sync_interval`, `include` (a mirror filter — the
format depends on the ecosystem, see [ecosystems/](ecosystems/)),
enable/disable, a button to start a sync for mirrors (the background
task state is visible right here and on the dashboard).

## Repos and the repository

- **Repo list**: creation (name-slug, ecosystem, owner,
  max_bytes/max_objects quota), editing, deletion.
- **Repository page**:
  - **Upload**: a path inside the repository
    (`pool/main/f/foo/foo_1.0_amd64.deb`) + a file; `force` —
    overwriting of an existing key (admin only: other subjects receive
    403 `admin_required`). After the upload — `reindex` (a button):
    background generation of indexes and signatures.
  - **Objects**: listing (path/size/modified), deletion of objects.
  - **Permissions**: granting/revoking the write permission for users.
- The path format and the generated indexes —
  [personal-repos.md](personal-repos.md).

## Users

Creation/deletion of users, issuance of scoped API tokens
(`repo:<id>:write` with repository selection; the secret is shown
once — copy it immediately), revocation of tokens, a list of the
active ones.

## Audit

A log of mutations (actor/action/object/result/detail) with loading of
older entries (keyset pagination by `after_id`).

## Keys

The public key of the selected repository: copying/downloading
`key.asc`, ready-made lines for clients (`signed-by=…`, `rpm --import`,
a file in `/etc/apk/keys/`, `pacman-key --add`); for a nix repository
— separately `nix-key.asc` (the `name:pubkey-b64` format). If the key
has not been generated yet — a hint (the repository is unsigned until
the first reindex / degraded mode).

## Tasks

The dashboard task list is also available via the API
(`/api/v1/tasks`); the UI shows active registry background tasks and
those that finished with an error (in-memory; survives a reload of the
list, but not a restart of the server).
