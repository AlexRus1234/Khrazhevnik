<!--
Khrazhevnik — cache proxy and mirror of linux repositories
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

# Changelog (English translation)

Format — [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning — semver. The canonical file is
[CHANGELOG.md](CHANGELOG.md) (Russian); this file is its translation
and may lag slightly behind. Pre-1.0.0 development history (in
Russian) — [CHANGELOG.old.md](CHANGELOG.old.md).

## [Unreleased]

## [1.1.0] — 2026-09-17

### Added

- **API:** password change — `POST /api/v1/auth/password` (self: the old
  password is verified, the response carries a fresh JWT; under the
  common login rate limit, audited as `user.password.change`) and
  `POST /api/v1/users/{id}/password` (admin: no old password, 204;
  audited as `user.password.set`). Both bump `token_version`: JWT
  sessions die, `khz_` tokens survive (session 67 precedent).
- **UI:** password change in the “Users” section (session 126) — a
  “Change your password” block (current/new + confirmation,
  `minlength=8`) that swaps the token on the fly (the session survives),
  plus a “Change password” action for an admin over a user; i18n ru/en,
  an e2e smoke of signing in with the new password.
- **Storage:** periodic sweeping cleanup (storagegc, sessions 119–120) —
  orphaned versions of mutable cache objects and `repo/<id>/` objects of
  deleted repositories; knobs `storage.gc_interval` (default `24h`,
  `0` = disabled) and `storage.gc_grace` (default `168h`, strictly
  `> 0`), metrics `khrazhevnik_storage_gc_*` (runs/deleted/bytes/failed/
  duration). The keeper goroutine is stopped in the shutdown cascade
  without a final pass.
- **API:** manual run of the sweeping storage cleanup —
  `POST /api/v1/storage/gc` (admin, audited as `storage.gc`): a
  background task (kind=`gc`, label=`storage`), 202 + `task_id`;
  `?dry_run=1|true` — a revision pass without deletions (candidate
  counters in the task log); 409 while the task is active, 429 on the
  worker limit, 503 without the cleanup module.

### Changed

- **DB:** index `idx_sync_jobs_remote_id` on `sync_jobs(remote_id)`
  (migration 0008, all three dialects); `JobStore.JobByRemote` — a
  point lookup instead of a full `Jobs()` scan in
  `mirror.findJobByRemote` (called on every `touchJob` of an active
  sync, `ProgressInterval=2s`). Fulfills the ROADMAP promise of a
  `sync_jobs` remote_id index.
- **Repositories:** `DELETE /api/v1/repos/{id}` now sweeps the
  `repo/<id>/` objects out of storage immediately — via a background
  task (kind=`gc`, label=`repo-<id>`) instead of accumulating an orphan
  prefix until the next sweeping cleanup. A task failure does not fail
  the DELETE: the periodic sweep picks up the remainder. Synchronous
  deletion in the handler was rejected — on s3 thousands of Deletes
  would hold the HTTP request for minutes.

## [1.0.3] — 2026-09-13

### Fixed

- **DB (mariadb):** the transient `1467 ER_AUTOINC_READ_FAILED` error
  during the bootstrap-user race (`EnsureFirstUser`) no longer escapes —
  it is now treated as an InnoDB retryable conflict (1213/1205): the
  losing writer re-runs `INSERT…SELECT WHERE NOT EXISTS` and sees the
  winner's row (`RowsAffected=0`). It surfaced as an intermittent
  `Error 1467 (HY000): Failed to read auto-increment value from storage
  engine` on 20 concurrent `EnsureFirstUser` calls (contract suite;
  reproduced over a 400-iteration run, fixed by the retry).

- **Range serving (206/416):** the proxy and the personal-repo public
  port (:29202) understand HTTP Range — a single slice `206` with an
  exact `Content-Range`, `multipart/byteranges` up to 256 ranges (cap =
  librepo's initial `max_ranges`), `416` with `Content-Range: bytes */N`,
  `Accept-Ranges: bytes` on 200/206 of the Range path, `If-Range` (a
  strong ETag or a `Last-Modified` date), garbage Range → 200 full
  (RFC 9110 MAY). A slice is byte-exact — the byte-exact serving
  invariant is extended to substrings. Fixes dnf5 failing behind the
  proxy on zchunk metadata (`primary data not present`): dnf5/librepo
  downloads `.zck` as ranges. The storage port gained `GetRange`
  (fs + s3), the engine — `FetchMeta`/`OpenBody`/`OpenRange` (resolve
  without opening the body, one resolve per client request). Metric
  `khrazhevnik_cache_range_responses_total{ecosystem}`; the distro-test
  fedora leg became mandatory and verifies the 206 fact after
  `dnf install` (verify-range).

### Changed

- **Proxy and :29202:** HEAD requests with Range return the 206/416
  headers without opening the body — byte counters are honest (0 body
  bytes); the single point of Range semantics is `web.serveRanged` for
  the proxy and personal repositories.

## [1.0.2] — 2026-09-12

### Fixed

- **UI (dashboard):** the "Recent transactions" panel's internal
  scrolling promised in 1.0.1 did not work — the flex chain had no
  definite height (`.app` only has `min-height`), so with content
  taller than the window the panel stretched to its content and the
  whole page scrolled. The dashboard section now has a definite
  height of "window minus chrome" — the feed scrolls inside the panel
  at any window size.

## [1.0.1] — 2026-09-12

### Fixed

- **Cache:** the `ValidateKey` whitelist now allows `:` — Arch epoch
  versions (`nftables-1:1.1.7-3-…`, the epoch colon is part of the
  file name) previously failed with 400 (`InvalidKeyError`), making
  pacman roll back the whole transaction; a raw `:` and its %3A
  encoding resolve to the same cache object. Same bug class as the
  Fedora caret `^` (CI fact #6). Incident 2026-09-12
  (TEST-KHRZ-ARCH).

### Added

- **CI:** Forgejo/GitHub/Codeberg releases now get a body — the
  `[X.Y.Z]` section from CHANGELOG.md is written into the release
  automatically (the body used to be created empty).

### Changed

- **UI (dashboard):** the "Recent transactions" panel now stretches to
  fill the remaining window height — the feed scrolls inside the panel
  (table header pinned) instead of the whole page; when space is tight
  the panel shrinks to a minimum height while keeping internal
  scrolling.
