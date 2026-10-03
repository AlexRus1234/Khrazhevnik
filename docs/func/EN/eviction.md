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

# Cache eviction (automatic cleanup of stale proxy cache)

Eviction is the automatic cleanup of old versions in the pull-through
proxy cache. Without it the immutable objects of the cache are kept
forever and the cache grows to the size of the volume: versions of the
same package pile up, and a fresh download evicts nothing.

Cleanup deletes only cache objects (`cache/<ecosystem>/<remote-id>/…`).
Personal repositories are cleaned by the
[retention policy](personal-repos.md), not by eviction — they have
different policies but share the same access-tracking table.

**Eviction is off by default.** Until an admin enables a policy nothing
is deleted (a conservative debut: the pass deletes objects rather than
merely reading them).

## What is cleaned

The pass runs over one remote and considers versions within a “family” —
a group of objects that are versions of the same package. The family is
resolved by the ecosystem adapter from the object's upstream path:

| Ecosystem | Family |
|---|---|
| apt | the source package's pool directory — `pool/main/h/htop/` |
| rpm-md, pacman, apk, xbps | the file name prefix up to the version epoch |

Objects outside families — indexes, signatures, public keys, service
files — are never touched: families are resolved for packages only.

A version is deleted when **two conditions hold at once**:

1. the family has **more than `min_versions` live versions** (otherwise
   the pass leaves a family with fewer than or equal to the minimum
   alone);
2. the candidate **has not been accessed for longer than `max_age_days`**.

A version is considered live when **at least one** condition holds — it is
among the family's top-`min_versions` by download date **OR** the last
access is fresher than `now − max_age_days`. The protections combine with
OR, so a frequently downloaded old version is not deleted even if it is
not in the top set.

Versions are ordered by download date (`ModTime`), not by parsing version
numbers: freshness matters, not semantic order.

Access recency comes from the `object_access` table (`scope=cache`): the
cache records accesses when serving **HIT/STALE**, not on MISS. If there
is no access row (an object cached before tracking was enabled), recency
is counted from the download date. Access writes are asynchronous and
batched, with the period `storage.access_flush_interval` (default `30s`);
a freshly downloaded object may not yet have an access row — that is
normal and not an error.

### MISS self-healing

If eviction deletes an object that a client requests again, the proxy for
a `proxy`-mode remote serves a transparent **MISS**: the object is
downloaded from upstream again and cached anew. This is not an error and
not a 404 for the user. This is exactly why the pass does not parse
indexes into links: any repeated access refreshes recency in
`object_access` by itself, and a miss self-heals by refetching.

## Policy: per remote and inheritance

The policy is configured per upstream (remote) and has **three states**
(the `eviction` field in the remote body, the
`remotes.eviction_min_versions` / `eviction_max_age_days` columns,
migration 0014):

| State | How it is set | Meaning |
|---|---|---|
| inherit | `null` field in the remote body (`NULL` in the DB) | use the global `[eviction]` default from the config |
| off | the object `{min_versions: 0, max_age_days: 0}` | no cleanup for this remote |
| on | an object with thresholds | own `min_versions` / `max_age_days` |

The difference between “inherit” and “off” matters: `NULL` in the columns
means “no value of its own”, `{0,0}` means “explicitly disabled for this
remote”. That is why the columns allow `NULL` rather than `DEFAULT 0`.

The global default is the `[eviction]` config section (see
[config.md](config.md)):

```toml
[eviction]
interval      = "24h"  # recurring pass period; 0 — disabled
min_versions  = 0      # global policy default; 0 — eviction disabled
max_age_days  = 0      # 0 — no age limit
```

With `min_versions = 0` and `max_age_days = 0` (the defaults) the policy is
disabled. Field combinations are validated by the domain at startup:
`min_versions=1` with an age set (a single live version — a 404 window: TTL
indexes in the cache may reference the previous version) and `max_age_days`
without `min_versions` (deletion without a minimum guarantee) are rejected
as a config error.

With `max_age_days = 0` and `min_versions≥2` a “keep-N only” mode applies:
everything beyond the top-`min_versions` is deleted regardless of access.

## Forecast and apply

The **forecast (dry-run)** deletes nothing — it shows what the policy would
consider:

```sh
curl -s -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:30202/api/v1/remotes/1/eviction/preview
```

The response holds `candidates` (versions that passed the `min_versions`
filter) and `totals`. A candidate's `protected_by` is the first protection
that fired: `""` — deleted, `access` — access fresher than `max_age_days`.
Versions held by the top-N are not listed (they are counted by
`totals.protected_by_min`). The cache has no pins: only `""` and `access`
appear in the forecast.

**Apply** starts the real pass as a background task:

```sh
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:30202/api/v1/remotes/1/eviction/apply
# → 202 {"task_id": "..."}
```

The task runs with `kind=eviction`, label `remote-<id>`; watch it with
`GET /api/v1/tasks/{id}`. A repeated run while a task for the same remote
is active returns 409, the worker limit returns 429, degradation without
the engine returns 503. The full field and status-code description is in
[api.md](api.md).

In the [web admin UI](ui.md) the policy, forecast and apply are gathered
in the “Cache eviction” block of the upstream card.

### Triggers

- **recurring pass** — over every proxy remote with an effective policy
  enabled; the period is `eviction.interval` (`24h`; `0` — disabled, then
  cleanup is manual only). The pass is sequential; an error on one remote
  does not stop the others;
- **manual forecast** — `GET …/eviction/preview` (admin);
- **manual apply** — `POST …/eviction/apply` (admin) or the GUI button.

The “right after download” trigger is not used: cleanup in the hot
download path adds risk to serving, and recency only matters in the long
run.

## What is NOT cleaned

- **Mirrors (`mode=mirror`).** The pass runs over proxy remotes only: a
  mirror is a full upstream copy, and “download → delete → download”
  churn conflicts with resume-diff sync. A mirror is cleaned by upstream,
  not by the instance.
- **nix.** Its store is content-addressed — there are no old versions of a
  path and no families. The nix adapter does not implement the cache family
  resolver, so `preview`/`apply` for such a remote return 400
  `eviction_unsupported` (an honest error, not a silent no-op).
- **Previous versions of mutable objects** (keys like `…-v<base36>`).
  They are cleaned by the sweeping storage cleanup (storagegc); eviction
  merely leaves them alone.
- **The `.retained` marker** of apt by-hash generations — a service object
  of the personal-repo generator; it never arrives from upstream.
- **Objects outside families** — indexes, signatures, keys.
- **Personal repositories** — cleaned by the retention policy
  ([personal-repos.md](personal-repos.md)).
- **A cache size budget (LRU/LFU under a size limit)** — out of the
  implemented scope: the pass criterion is version count and recency only.

## Metrics

The pass exports to `/metrics` (behind auth, port :30202):

- `khrazhevnik_eviction_runs_total` — completed passes over a remote;
- `khrazhevnik_eviction_deleted_keys_total` — objects deleted;
- `khrazhevnik_eviction_deleted_bytes_total` — bytes freed;
- `khrazhevnik_eviction_failed_deletes_total` — failed deletes;
- `khrazhevnik_eviction_last_pass_timestamp` — time of the last pass;
- `khrazhevnik_eviction_duration_seconds` — duration of one pass.

See also: [config.md](config.md) — the `[eviction]` section;
[api.md](api.md) — endpoints and codes; [ui.md](ui.md) — the “Cache
eviction” block; [personal-repos.md](personal-repos.md) — personal-repo
retention; `docs/ARCHITECTURE.md` — the engine's place in the
architecture.
