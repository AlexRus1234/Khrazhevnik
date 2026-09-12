#!/usr/bin/env bash
# Хражевник — сэмплер бэкендов Хражевника на NAS (bare-metal systemd-юниты):
# PostgreSQL и RustFS читаются из cgroup v2 (cpu.stat, memory.current,
# memory.peak), CPU% считается онлайн по дельтам usage_usec.
# Часть bench/sampling (docs/func/ru/benchmarks.md).
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Запуск на NAS от обычного пользователя (файлы cgroup v2 system.slice
# обычно world-readable; если закрыты — запускать через sudo):
#   UNITS='postgresql.service rustfs.service' INTERVAL=10 \
#     OUT=/tmp/nas-stats.csv ./nas-stats.sh
# Выход: ts,unit,cpu_perc,mem_cur_kb,mem_peak_kb.
#
# Почему не podman stats: БД NAS — bare-metal systemd-сервисы, cgroup v2
# даёт те же числа без зависимостей (sysstat ставить не хочется).

set -uo pipefail

INTERVAL="${INTERVAL:-10}"
UNITS="${UNITS:-postgresql.service rustfs.service}"
CGROOT="${CGROOT:-/sys/fs/cgroup/system.slice}"
OUT="${OUT:-nas-stats.csv}"

echo "ts,unit,cpu_perc,mem_cur_kb,mem_peak_kb" >> "$OUT"

declare -A PREV_USEC PREV_TS

usage_usec() { # <cgroup>
  awk '/^usage_usec /{print $2}' "$1/cpu.stat" 2>/dev/null
}

cleanup() {
  echo "готово: $OUT" >&2
}
trap cleanup EXIT

while true; do
  ts=$(date +%s)
  for u in $UNITS; do
    cg="$CGROOT/$u"
    if [[ ! -d "$cg" ]]; then
      echo "$ts,$u,NO_CGROUP,," >> "$OUT"
      continue
    fi
    usec=$(usage_usec "$cg")
    mem_kb=$(awk '{printf "%d", $1/1024}' "$cg/memory.current" 2>/dev/null)
    peak_kb=$(awk '{printf "%d", $1/1024}' "$cg/memory.peak" 2>/dev/null)
    cpu=""
    if [[ -n "$usec" && -n "${PREV_USEC[$u]:-}" && "$ts" != "${PREV_TS[$u]:-}" ]]; then
      cpu=$(awk -v du="$usec" -v pu="${PREV_USEC[$u]}" -v dt=$((ts - PREV_TS[$u])) \
        'BEGIN{printf "%.1f", (du-pu)/10000/dt}')
    fi
    PREV_USEC[$u]="$usec"
    PREV_TS[$u]="$ts"
    echo "$ts,$u,$cpu,$mem_kb,$peak_kb" >> "$OUT"
  done
  sleep "$INTERVAL"
done
