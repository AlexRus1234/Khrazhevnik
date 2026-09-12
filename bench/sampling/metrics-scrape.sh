#!/usr/bin/env bash
# Хражевник — циклический scrape /metrics в файлы-снапшоты (по файлу на
# тик). Счётчики монотонны, гистограммы кумулятивны: дельты считаются
# офлайн metrics-diff.sh по паре снапшотов. Часть bench/sampling.
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Запуск с любой машины с доступом к админ-порту (например panelka):
#   ADMIN=http://172.20.6.9:10003 KHRZ_USER=admin KHRZ_PASS='...' \
#     OUT_DIR=~/bench/metrics INTERVAL=15 ./metrics-scrape.sh
# Либо готовый токен (JWT сессии или scoped khz_… с admin-скоупом):
#   KHRZ_TOKEN='…' ADMIN=… ./metrics-scrape.sh
# Логин — rate-limit 10/min с IP; скрипт логинится один раз и
# перелогинивается только после 401 (JWT живёт session_ttl, дефолт 8h).

set -uo pipefail

ADMIN="${ADMIN:-http://172.20.6.9:10003}"
OUT_DIR="${OUT_DIR:-metrics}"
INTERVAL="${INTERVAL:-15}"

command -v jq >/dev/null || { echo "нужен jq" >&2; exit 1; }
mkdir -p "$OUT_DIR"

login() {
  curl -sf -X POST "$ADMIN/api/v1/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$KHRZ_USER\",\"password\":\"$KHRZ_PASS\"}" \
    | jq -r .token
}

TOKEN="${KHRZ_TOKEN:-}"
if [[ -z "$TOKEN" && -n "${KHRZ_USER:-}" && -n "${KHRZ_PASS:-}" ]]; then
  TOKEN=$(login) || { echo "логин не удался" >&2; exit 1; }
fi
[[ -n "$TOKEN" ]] || { echo "задайте KHRZ_TOKEN или KHRZ_USER/KHRZ_PASS" >&2; exit 1; }

cleanup() {
  echo "готово: $OUT_DIR/metrics-<ts>.txt" >&2
}
trap cleanup EXIT

while true; do
  ts=$(date +%s)
  tmp=$(mktemp)
  code=$(curl -s -o "$tmp" -w '%{http_code}' \
    -H "Authorization: Bearer $TOKEN" "$ADMIN/metrics")
  case "$code" in
    200)
      mv "$tmp" "$OUT_DIR/metrics-$ts.txt"
      ;;
    401)
      echo "$(date +%T): 401, перелогин" >&2
      TOKEN=$(login) || true
      rm -f "$tmp"
      ;;
    *)
      echo "$(date +%T): HTTP $code, пропускаю тик" >&2
      rm -f "$tmp"
      ;;
  esac
  sleep "$INTERVAL"
done
