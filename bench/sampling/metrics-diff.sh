#!/usr/bin/env bash
# Хражевник — дифф двух снапшотов /metrics (metrics-scrape.sh): дельты
# счётчиков кеша, p50/p90/p99 гистограммы request_duration по
# (method,status), count/sum/mean object_bytes по экосистемам.
# Часть bench/sampling (docs/func/ru/benchmarks.md).
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Использование:
#   ./metrics-diff.sh metrics/metrics-1757000000.txt metrics/metrics-1757000300.txt
# Счётчики монотонны; отрицательная дельта = сброс статистики или
# рестарт инстанса между снапшотами — интервал недействителен.

set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <base-снапшот> <target-снапшот>" >&2
  exit 1
fi

awk '
# lbkey — отсортированный ключ меток без le: стабильные серии между файлами.
function lbkey(lbl,   n, a, i, m, list, j, tmp, out) {
  n = split(lbl, a, ",")
  m = 0
  for (i = 1; i <= n; i++) {
    if (a[i] == "" || a[i] ~ /^le=/) continue
    list[++m] = a[i]
  }
  for (i = 2; i <= m; i++) {
    tmp = list[i]
    for (j = i - 1; j >= 1 && list[j] > tmp; j--) list[j + 1] = list[j]
    list[j + 1] = tmp
  }
  out = ""
  for (i = 1; i <= m; i++) out = out (i > 1 ? "," : "") list[i]
  return out
}
function getle(lbl,   n, a, i) {
  n = split(lbl, a, ",")
  for (i = 1; i <= n; i++)
    if (a[i] ~ /^le=/) {
      sub(/^le="/, "", a[i]); sub(/"$/, "", a[i])
      return a[i]
    }
  return ""
}
# addbound — вставка границы бакета с сохранением возрастающего порядка.
function addbound(skey, le,   i, tmp) {
  for (i = 1; i <= SBn[skey] && SB[skey, i] < le + 0; i++) ;
  for (j = SBn[skey]; j >= i; j--) SB[skey, j + 1] = SB[skey, j]
  SB[skey, i] = le + 0
  SBn[skey]++
}
# quantile — линейная интерполяция по КУМУЛЯТИВНЫМ дельтам бакетов:
# exposition-бакеты уже накопительные, повторное суммирование (как с
# инкрементами) сдвинуло бы квантиль на бакет — интерполируем D_i напрямую.
function quantile(skey, q, total,   target, i, b, bprev, D, Dprev) {
  target = q * total
  Dprev = 0; bprev = 0
  for (i = 1; i <= SBn[skey]; i++) {
    b = SB[skey, i]
    D = B[2, skey, b] - B[1, skey, b]
    if (D < 0) return -1
    if (D >= target) {
      if (i == 1) return b
      if (D - Dprev == 0) return bprev
      return bprev + (target - Dprev) / (D - Dprev) * (b - bprev)
    }
    bprev = b; Dprev = D
  }
  return bprev # весь целевой квантиль за последней конечной границей
}
FNR == 1 { phase++ }
/^[^#]/ && NF >= 2 {
  name = $1; val = $2 + 0; lbl = ""
  if (match(name, /\{[^}]*\}/)) {
    lbl = substr(name, RSTART + 1, RLENGTH - 2)
    name = substr(name, 1, RSTART - 1)
  }
  if (name ~ /_bucket$/) {
    sname = name; sub(/_bucket$/, "", sname)
    le = getle(lbl)
    if (le != "" && le != "+Inf") {
      skey = sname "|" lbkey(lbl)
      SER[skey] = 1
      B[phase, skey, le + 0] = val
      if (phase == 1) addbound(skey, le + 0)
    }
  } else if (name ~ /_count$/ || name ~ /_sum$/) {
    sname = name; sub(/_(count|sum)$/, "", sname)
    skey = sname "|" lbkey(lbl)
    SER[skey] = 1
    H[phase, skey, name ~ /_count$/ ? "count" : "sum"] = val
  } else {
    C[phase, name "|" lbkey(lbl)] = val
    CKEY[name "|" lbkey(lbl)] = 1
  }
}
END {
  print "== дельты счётчиков khrazhevnik_cache_* =="
  printf "%-58s %14s %14s\n", "метрика", "base", "delta"
  n = 0
  for (k in CKEY) { ORD[++n] = k }
  # insertion sort для детерминированного вывода
  for (i = 2; i <= n; i++) {
    tmp = ORD[i]
    for (j = i - 1; j >= 1 && ORD[j] > tmp; j--) ORD[j + 1] = ORD[j]
    ORD[j + 1] = tmp
  }
  for (i = 1; i <= n; i++) {
    k = ORD[i]
    split(k, p, "|"); mname = p[1]
    if (mname !~ /^khrazhevnik_cache_/) continue
    b = C[1, k] + 0; t = C[2, k] + 0
    printf "%-58s %14.0f %14.0f\n", k, b, t - b
  }
  print ""
  print "== гистограммы (дельты за интервал) =="
  for (s in SER) {
    split(s, sp, "|"); hname = sp[1]
    total = H[2, s, "count"] - H[1, s, "count"]
    sum = H[2, s, "sum"] - H[1, s, "sum"]
    if (total <= 0) {
      printf "%-46s нет наблюдений/сброс\n", s
      continue
    }
    printf "%-46s count=%-10.0f mean=%.4gs\n", s, total, sum / total
    if (hname ~ /request_duration/) {
      printf "    p50=%.4gs p90=%.4gs p99=%.4gs\n", \
        quantile(s, 0.50, total), quantile(s, 0.90, total), quantile(s, 0.99, total)
    }
  }
}
' "$1" "$2"
