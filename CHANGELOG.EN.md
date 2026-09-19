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

### Added

- **XBPS (session 129):** the xbps ecosystem (Void Linux): cache proxy —
  repodata/package classification, the `/xbps/` prefix (the adapter is
  registered; index parsing and mirroring come in the following sessions
  of the wave).
- **XBPS (session 130):** xbps proxy integration — repodata and packages
  byte-exact, a repeated request returns `X-Cache: HIT`, mutable repodata
  revalidation (304 without a body), negative-cache 404 (integration test).
- **XBPS (session 131):** streaming parser of the xbps repodata container
  (zstd+tar: `index.plist` as a stream, `index-meta.plist` as bytes,
  `stage.plist` skipped); a 1 GiB decompression cap and a 64 KiB meta-entry
  cap, typed format errors (`ErrBadZstd`/`ErrBadTar`/`ErrIndexMissing`/
  `ErrIndexNotFirst`/`ErrDecompressTooLarge`).
- **XBPS (session 132):** streaming XML-plist parser for `index.plist` — the
  `pkgname` → fields dictionary is delivered to a callback entry by entry (no
  ~20 MiB XML in memory), `encoding/xml` only (stdlib decodes
  `&lt;`/`&amp;` entities); caps of 64 KiB per field / 4096 array elements /
  1M records, typed `ErrBadPlist`, unknown keys skipped (proplib forward
  compatibility).
- **XBPS (session 133):** the xbps pkgver parser (`SplitPkgver`/
  `SplitRevision`/`Filename`) — names with dashes/`++`/digits, an `_N`
  revision made of digits only, garbage becomes a `ValidationError`; a
  table of live Void names plus fuzzing.
- **XBPS (session 134):** fuzzing of the repodata composition
  (`FuzzParseRepoData`: zstd→tar→index.plist as a single target, a counter
  callback with no accumulation) and a golden fixture
  `testdata/repodata-golden.zst` — 5+ real packages (`0ad`, `libstdc++`,
  `libxml2`, `python3-pip`, `Mustache`), `&lt;`/`&amp;` entities, `~` in a
  version, `filename-sha256` case, a public key in `index-meta.plist`
  (input for signing sessions 139/141).
- **XBPS (session 135):** xbps mirroring — `Enumerate` over the include
  architectures (`<arch>-repodata`): package paths
  `<pkgver>.<arch>.xbps` are built by `Filename()` (session 133), each
  gets a `.sig2` signature; a noarch package appears once in the result
  (deduplicated by a seen map). The SHA256 from the `filename-sha256`
  field (64 hex validated) populates the remote checksum table —
  `Resolve` exposes it in `Target.Checksum`; an invalid sha256 and
  `.sig2` honestly degrade to Content-Length verification. A partial
  sync does not overwrite the table.
- **XBPS (session 136):** xbps mirroring end to end (integration) — sync
  downloads repodata + packages + `.sig2`, a repeated sync makes not a
  single upstream request (resume diff via `Storage.Stat`), a shared
  noarch package from two arch indexes is downloaded exactly once; a body
  that does not match `filename-sha256` fails the sync and does NOT commit
  the object (Abort, ARCHITECTURE §4 invariant), and after the upstream is
  fixed and the negative window expires the repeated sync succeeds.
- **XBPS (session 137):** `.xbps` package ar parser (`OpenPackage`) —
  compression auto-detected by magic (zstd `28 B5 2F FD`, gzip `1F 8B`,
  raw ar `!<arch>\n`; xz becomes `ErrUnsupportedCompression`), classic
  ar members (`props.plist`/`./props.plist`) walked and only
  `props.plist` read into the `Props` type; `files.plist` and the payload
  are skipped as a stream; a shared 1 GiB decompression cap and a
  `props.plist` ≤ 1 MiB cap, typed errors `ErrBadAr`/`ErrPropsMissing`.
- **XBPS (session 138):** fuzzing of the `.xbps` package ar parser
  (`FuzzOpenPackage`) — seeds for all three compression branches
  (raw/zstd/gzip), truncations at ar header boundaries (8/60/68 bytes),
  garbage with a valid zstd magic, an oversized member-size field;
  invariants: no panics, deterministic error and `Props` shape.
- **XBPS (session 139):** instance RSA-4096 signer (the `.sig2` xbps
  format) — `port.RsaSigner`/`RsaSignerInjector` and the
  `mod/sign/rsasha256` module: PKCS#1 v1.5 over a SHA-256 digest, the
  private key `xbps-rsa.key` (PKCS#1 PEM, 0600, atomic, no overwrite),
  the public one as SPKI-PEM (`PUBLIC KEY`) for index-meta and the key
  endpoint; passphrase unsupported, corrupt key material is fatal at start.
- **XBPS (session 140):** streaming `index.plist` writer for xbps
  (`WriteIndexPlist`) — proplib XML-plist via `encoding/xml` tokens
  (stdlib encodes `&`/`<`/`>` entities), deterministic reindex (records by
  `pkgname`, fields alphabetically, empty ones omitted), lossless roundtrip
  with the session 132 parser; 10k records streamed without accumulation.
- **XBPS (session 141):** personal xbps repo generator (an `xbps-rindex
  --add --sign --sign-pkg` analogue): flat `.xbps` →
  `<arch>-repodata` (zstd level 9 + pax-tar: index.plist/
  index-meta.plist/stage.plist), noarch packages enter every arch group, a
  `.sig2` for each package (RSA/SHA-256 with the instance key), the public
  key embedded in index-meta.plist (base64 PEM); without a key — repodata
  without `.sig2`; a mismatched filename or a broken package is an honest
  task error.
- **XBPS (session 142):** the `GET /repo/<name>/xbps-key` endpoint (the
  instance's RSA key PEM) for fingerprint verification during TOFU import;
  it is registered only when a signer is live, an unknown repo is a 404;
  an “xbps” block on the “Keys” screen.
- **XBPS (session 143):** end-to-end personal xbps repo integration
  (integration): bootstrap → repo eco=xbps → upload `.xbps` (x86_64 +
  noarch) → reindex task → the public port serves `<arch>-repodata`
  (parsed by the 131/132 parser, noarch lands in the x86_64 group,
  `filename-sha256` matching the body) and `.sig2` (verified with
  `crypto/rsa` against `/xbps-key`); a package whose props do not match
  its filename fails reindex, and after its removal the index is
  byte-identical (determinism).

### Changed

- **Docs (session 128):** the XBPS ROADMAP is brought in line with the
  format facts — a flat layout (`<arch>-repodata` in the root, not
  `current/<arch>/`), `.sig2` signatures are RSA-4096 PKCS#1 v1.5/SHA-256
  (not ed25519), the key is embedded in `index-meta.plist` (client-side
  TOFU import); the v1.2 wave lives in the `v1.2.0dev` branch.
- **CI (session 144):** distro-test — the sixth leg: void
  (`xbps-install` through the proxy, `xbps/<remote>`, hermeticity via
  `/etc/xbps.d`); the RELEASE checklist is synced (6/6 legs, xbps items
  in §1/§2).

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
