#!/usr/bin/env bash
# Хражевник — сэмплер контейнеров ВМ (panelka): podman stats → CSV +
# пики памяти cgroup. Часть bench/sampling (docs/func/ru/benchmarks.md).
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Запуск на хосте с контейнерами (panelka, пользователь app-runner):
#   INTERVAL=10 CONTAINERS='khrazhevnik nora' OUT=~/bench/podman-stats.csv \
#     ./podman-stats.sh
# Остановка: Ctrl-C. Выход: podman-stats.csv (ts,name,cpu,mem,net,block)
# и cgroup-peaks.csv (ts,name,memory_peak_kb).
#
# Почему podman stats, а не только cgroup: stats даёт готовые net/block
# IO за интервал; cgroup отдельно добирает memory.peak — «полку» RSS,
# которую stats не показывает (usage и так в stats, но пик между тиками
# теряется).

set -uo pipefail

INTERVAL="${INTERVAL:-10}"
CONTAINERS="${CONTAINERS:-khrazhevnik nora}"
OUT="${OUT:-podman-stats.csv}"
PEAKS="${PEAKS:-cgroup-peaks.csv}"

echo "ts,name,cpu_perc,mem_usage,mem_perc,net_io,block_io" >> "$OUT"
echo "ts,name,memory_peak_kb" >> "$PEAKS"

# CgroupPath контейнера не меняется за жизнь процесса — кешируем.
declare -A CGPATH

cleanup() {
  echo "готово: $OUT, $PEAKS" >&2
}
trap cleanup EXIT

while true; do
  ts=$(date +%s)
  for c in $CONTAINERS; do
    line=$(podman stats --no-stream --format \
      '{{.Name}},{{.CPUPerc}},{{.MemUsage}},{{.MemPercent}},{{.NetIO}},{{.BlockIO}}' \
      "$c" 2>/dev/null)
    if [[ -n "$line" ]]; then
      echo "$ts,$line" >> "$OUT"
    else
      echo "$ts,$c,ERR" >> "$OUT"
    fi
    if [[ -z "${CGPATH[$c]:-}" ]]; then
      # CgroupPath через JSON, а не --format: у части версий podman
      # шаблонное поле на interface{} падает, JSON-вывод всегда честный.
      CGPATH[$c]=$(podman inspect "$c" 2>/dev/null \
        | grep -o '"CgroupPath": *"[^"]*"' | head -1 \
        | sed 's/.*: *"//; s/"$//')
    fi
    peak_file="/sys/fs/cgroup${CGPATH[$c]}/memory.peak"
    if [[ -n "${CGPATH[$c]:-}" && -r "$peak_file" ]]; then
      kb=$(awk '{printf "%d", $1/1024}' "$peak_file")
      echo "$ts,$c,$kb" >> "$PEAKS"
    fi
  done
  sleep "$INTERVAL"
done
