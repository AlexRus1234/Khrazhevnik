<!--
Khrazhevnik — Linux repository cache-proxy and mirror
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

# Performance

Benchmark methodology and reference results. Reproduction uses the
tools in [`bench/`](../../bench/README.md) (the runbook is in Russian;
commands and file names are language-neutral). Read the "Methodology
limits" section before applying the numbers to other hardware.

## Reference environment

Run of 2026-09-11 on a live homelab instance (not an isolated rig —
see the caveats below).

| Parameter | Value |
|---|---|
| Khrazhevnik version | v1.0.0 (`git.yadr00.internal/alexrus1234/khrazhevnik:latest`) |
| Configuration | S3 + PostgreSQL: RustFS and postgres are bare-metal systemd services on the NAS (4 vCPU), connected over a dedicated P2P link |
| Container host | panelka VM: 4 vCPU / 8 GB RAM, rootless podman (quadlet), NORA co-located on the same VM |
| Load generator | k6 v2.2.0, a separate Windows machine in the LAN |
| Generator↔instance network | ~2.5 Gb/s (peak delivery 295 MB/s) |
| Remote | debian (apt, proxy); objects: 4 metadata files 140 KB–13.3 MB + 10 packages 53 KB–8.9 MB + a 107.7 MB kernel |
| Date | 2026-09-11 |

## Scenarios

| # | Scenario | Measures |
|---|---|---|
| A | `hit-mixed` | warm cache, metadata+packages mix (~3 MB average): RPS ceiling, latency, CPU/RAM |
| B | `stream-large` | streaming throughput of a single large object (107.7 MB), VU = parallel streamers |
| C | `apt-storm` | a storm of "apt update + install" iterations (~31 MB each: 4 metadata + 4 packages), VU = clients |

Stages are fixed-intensity (constant-arrival-rate / VU) with 30 s
pauses in between; each stage is a separate k6 scenario correlated
with container and backend samples by time.

## Results

### A. hit-mixed (warm cache, 14 objects)

| Stage | RPS plan | RPS actual | delivered | err, % | container CPU, % | RSS, MB | postgres CPU, % | RustFS CPU, % |
|---|---|---|---|---|---|---|---|---|
| r50 | 50 | 50 | 100% | 0.00 | 0.8 | 146 | 0.7 | 43 |
| r200 | 200 | 197 | 98.7% | 0.35 | 0.8 | 461 | 0.9 | 65 |
| r500 | 500 | 343 | 68.6% | 1.36 | 1.0 | 651 | 1.8 | 85 |
| r1000 | 1000 | 311 | 31.1% | 1.33 | 1.1 | 612 | 1.7 | 86 |
| r2000 | 2000 | 324 | 16.2% | 1.31 | 1.3 | 628 | 1.8 | 91 |

Run aggregates (730 s, 147k client requests, 141.5 GB delivered,
~194 MB/s on average): client p50 92 ms / p95 6.4 s (p95 grows on
stages ≥ r500 — big objects streaming through a saturated path);
server side — **148 836 GETs, all 200**, 128 misses (TTL index
revalidation), 0 upstream errors, 0 stale. The k6 "errors"
(1.1–1.4% on high stages) are network aborts on the congested pipe:
the server did not return a single 5xx.

Conclusion: the ~340 rps delivery ceiling is set by the S3 read path
(RustFS at 85→91% CPU) and the link, not by Khrazhevnik. Up to and
including r200 everything is perfectly clean.

### B. stream-large (107.7 MB kernel)

| Stage | VU | MB/s (aggregate) | stream p50 | stream p95 | err, % | container CPU, % | RSS, MB |
|---|---|---|---|---|---|---|---|
| v1 | 1 | 43.7 | 0.39 s | 6.5 s | 0 | 1.4 | 198 |
| v2 | 2 | 60.8 | 1.66 s | 8.9 s | 0 | 1.4 | 202 |
| v4 | 4 | 81.3 | 4.57 s | 12.2 s | 0 | 1.4 | 218 |
| v8 | 8 | 113.9 | 6.83 s | 13.6 s | 0 | 1.4 | 289 |

A single stream is bursty: median 0.39 s (≈276 MB/s from the RustFS
memory cache) with tails up to 24–40 s. The aggregate scales
sublinearly (43.7→113.9 MB/s at 8× VU) — per-stream degradation while
contending for RustFS.

Conclusion: throughput is capped by the S3 storage, not the instance:
8 parallel 107 MB streams cost the container 1.4% CPU and 289 MB RSS.

### C. apt-storm (iteration "apt update + install", ~31 MB)

| Stage | VU (clients) | sessions/min | session p50 | session p95 | delivery, MB/s | err, % | container CPU, % | RSS, MB |
|---|---|---|---|---|---|---|---|---|
| v10 | 10 | 565 | 0.9 s | 2.1 s | ~295 | 0.00 | 1.4 | 219 |
| v50 | 50 | 471 | 5.4 s | 14.3 s | ~246 | 0.00 | 1.5 | 410 |
| v200 | 200 | 386 | 23.2 s | 63.4 s | ~201 | 1.60 | 1.6 | 530 |

All v200 errors are metadata (large `Packages.*` under contention);
packages are 100%. Server side over the scenario: 123.6 GB delivered,
23 516 hits / 384 misses, 0 upstream errors, server p50 40 ms.

Conclusion: ~50 apt machines are served comfortably (a full
update+install takes ~5 s per machine at 50 parallel); 200 parallel
machines saturate the path (p50 23 s).

### Resource usage (summary)

| Parameter | Value |
|---|---|
| Idle RSS (fresh start) | 26 MB |
| Idle RSS (after large downloads; Go GC keeps the heap) | 90–194 MB |
| RSS under load | 146–651 MB (grows with parallel streams, returns after load drops) |
| Peak RSS (`memory.peak` cgroup across all runs) | **981 MB** |
| Idle CPU | 0.7% (of a 4 vCPU VM) |
| CPU at saturation (all scenarios) | ≤1.6% (~0.06 vCPU) |
| PostgreSQL (catalog) under load | ≤1.8% CPU, flat RSS ~520 MB |
| RustFS (storage) | ~25% idle, 85–91% CPU at saturation, RSS up to 9 GB (cache) |

## Bottlenecks

1. **Neither the binary nor the catalog.** At ~340 rps and ~300 MB/s
   the instance spends ≤1.6% CPU and <1 GB RAM; the PostgreSQL catalog
   under hundreds of thousands of SELECTs — ≤1.8% CPU. The "the DB
   will suffocate first" hypothesis is refuted for this profile.
2. **The bottleneck is the S3 read path.** RustFS scales delivery
   sublinearly: 276 MB/s for a single stream → 114 MB/s at 8 parallel;
   its CPU reaches 90% at saturation. Capacity growth means RustFS
   cores/replication, not Khrazhevnik resources.
3. **The ~2.4 Gbps path** (peak 295 MB/s): once exhausted, degradation
   lands on the clients (k6 timeouts/aborts) while the server keeps
   delivering without a single 5xx (269 GB total, zero errors).

## Methodology limits

- Live instance: RustFS on the NAS had background activity (25% idle
  CPU, spikes to 1.4 cores — it also serves NORA); an idle baseline
  was captured before the run and subtracted qualitatively.
- Generator and instance share a LAN (~2.5 Gb/s): the measured
  throughput ceiling belongs to the path, not the application; judge
  the application by CPU/RSS rather than MB/s.
- Per-stage client latency was captured for B and C (raw json); for A
  only run aggregates are available.
- fs+sqlite moves the bottleneck from the network to the local disk:
  magnitudes stay comparable, A/B numbers transfer qualitatively only.
