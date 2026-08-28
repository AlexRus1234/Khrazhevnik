#!/usr/bin/env bash
# Хражевник — дымовой тест живого контейнера.
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Поднимает fixture-upstream (python3 -m http.server), запускает образ
# khrazhevnik, гоняет через прокси apt-метаданные и проверяет:
#   - /healthz 200 на обоих слушателях;
#   - /api/v1/setup → login → create remote apt → GET Release через прокси
#     → sha256 совпал с файлом (byte-exact инвариант кеша);
#   - 404 на мусорном пути;
#   - SIGTERM → контейнер exit 0 за <10с (graceful shutdown каскад).
#
# Выход: 0, если все проверки прошли ИЛИ все падения — известные баги
# (см. known-bugs.txt); иначе 1. Формат унаследован из Intermasq.
#
# Запуск: make image && test/smoke/smoke.sh   (или: make smoke)
#   IMAGE=... TAG=... test/smoke/smoke.sh     (переопределить образ)
#
# Требует: podman, python3, curl, jq, sha256sum, timeout.

set -uo pipefail

IMAGE="${IMAGE:-ghcr.io/alexrus1234/khrazhevnik}"
TAG="${TAG:-dev}"
REF="${IMAGE}:${TAG}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIXTURES="$SCRIPT_DIR/fixtures"
KNOWN_BUGS="$SCRIPT_DIR/known-bugs.txt"
WORK="$(mktemp -d)"
CTR="khrazhevnik-smoke-$$"
FIX_PORT=18080
JWT_SECRET="smoke-jwt-secret-smoke-jwt-secret-0123456789-$$"
REMOTE_NAME="debian"
RELEASE_PATH="dists/stable/Release"
GARBAGE_PATH="dists/stable/does-not-exist-${$}"

FAILURES=()
FIX_PID=""

log()  { printf 'smoke: %s\n' "$*" >&2; }
fail() { printf 'smoke: FAIL: %s\n' "$*" >&2; FAILURES+=("$*"); }

cleanup() {
  local rc=$?
  [ -n "$FIX_PID" ] && kill "$FIX_PID" >/dev/null 2>&1 || true
  podman rm -f "$CTR" >/dev/null 2>&1 || true
  rm -rf "$WORK"
  exit $rc
}
trap cleanup EXIT INT TERM

# --- проверки окружения -----------------------------------------------------
for t in podman python3 curl jq sha256sum timeout; do
  command -v "$t" >/dev/null || { fail "утилита $t не найдена в PATH"; exit 1; }
done
[ -f "$FIXTURES/$RELEASE_PATH" ] || { fail "фикстура $FIXTURES/$RELEASE_PATH отсутствует"; exit 1; }

# --- сборка образа, если его нет локально -----------------------------------
if ! podman image exists "$REF" >/dev/null 2>&1; then
  log "образ $REF не найден, собираю из $ROOT/deploy/Containerfile"
  podman build --platform=linux/amd64 --build-arg VERSION="$TAG" \
      -t "$REF" -f "$ROOT/deploy/Containerfile" "$ROOT" >&2 || { fail "сборка образа упала"; exit 1; }
fi

# --- fixture upstream: каталог фикстур через python http.server -------------
# Биндим на 0.0.0.0, чтобы контейнер дотягивался через host-gateway.
python3 -m http.server "$FIX_PORT" --bind 0.0.0.0 --directory "$FIXTURES" >"$WORK/fix.log" 2>&1 &
FIX_PID=$!
# Готовность fixture: опрашиваем сами себя.
for _ in $(seq 1 50); do
  if curl -fsS "http://127.0.0.1:$FIX_PORT/$RELEASE_PATH" -o "$WORK/fix-probe" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
[ -s "$WORK/fix-probe" ] || { fail "fixture-upstream не поднялся на :$FIX_PORT"; exit 1; }
log "fixture-upstream слушает 0.0.0.0:$FIX_PORT"

# --- khrazhevnik контейнер --------------------------------------------------
# host-gateway: контейнер дотягивается до fixture-upstream на хосте.
# :U — podman чоунит bind-mount под UID 65534; :Z — SELinux relabel.
# --stop-timeout=30 — чтобы podman не убил SIGKILL раньше smoke-таймера.
VOL="$WORK/data"
mkdir -p "$VOL"
podman run -d --name "$CTR" \
    --add-host=fixture-host:host-gateway \
    -p 29202 -p 30202 \
    -e "KHRZ_AUTH__JWT_SECRET=$JWT_SECRET" \
    -e "KHRZ_ECOSYSTEM__APT__ENABLED=true" \
    -v "$VOL:/var/lib/khrazhevnik:U,Z" \
    --stop-timeout=30 \
    "$REF" >"$WORK/container.id" 2>"$WORK/run.err" || {
  fail "podman run упал: $(cat "$WORK/run.err")"; exit 1
}

# Случайные host-порты, куда podman пробросил 29202/30202.
port_of() { podman port "$CTR" "$1" 2>/dev/null | sed -n '1s/.*://p'; }
PUBLIC_PORT=""
ADMIN_PORT=""
for _ in $(seq 1 50); do
  PUBLIC_PORT="$(port_of 29202)"
  ADMIN_PORT="$(port_of 30202)"
  [ -n "$PUBLIC_PORT" ] && [ -n "$ADMIN_PORT" ] && break
  sleep 0.1
done
[ -n "$PUBLIC_PORT" ] && [ -n "$ADMIN_PORT" ] || { fail "порты не пробросились"; exit 1; }
log "контейнер $CTR: public=127.0.0.1:$PUBLIC_PORT admin=127.0.0.1:$ADMIN_PORT"

# --- ожидание healthz на обоих слушателях -----------------------------------
wait_health() {
  local url="$1" name="$2" code=""
  for _ in $(seq 1 100); do
    code="$(curl -s -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || true)"
    [ "$code" = "200" ] && return 0
    sleep 0.1
  done
  fail "$name: /healthz не ответил 200 (последний код: ${code:-пусто})"
  return 1
}
wait_health "http://127.0.0.1:$PUBLIC_PORT/healthz" "public"
wait_health "http://127.0.0.1:$ADMIN_PORT/healthz"  "admin"

# --- bootstrap: setup → login → create remote -------------------------------
ADMIN="http://127.0.0.1:$ADMIN_PORT/api/v1"

# setup первого админа.
sc="$(curl -s -o "$WORK/setup" -w '%{http_code}' -X POST "$ADMIN/setup" \
    -H 'Content-Type: application/json' \
    -d '{"username":"admin","password":"smoke-password"}' 2>/dev/null)"
[ "$sc" = "201" ] || fail "setup: код $sc, тело $(cat "$WORK/setup" 2>/dev/null)"

# login -> JWT.
lc="$(curl -s -o "$WORK/login" -w '%{http_code}' -X POST "$ADMIN/auth/login" \
    -H 'Content-Type: application/json' \
    -d '{"username":"admin","password":"smoke-password"}' 2>/dev/null)"
[ "$lc" = "200" ] || fail "login: код $lc"
TOKEN="$(jq -r .token "$WORK/login" 2>/dev/null)"
[ -n "$TOKEN" ] && [ "$TOKEN" != "null" ] || fail "login: нет token в ответе"

# create remote apt -> fixture-upstream.
rc_body='{"name":"'"$REMOTE_NAME"'","ecosystem":"apt","base_url":"http://fixture-host:'"$FIX_PORT"'","mode":"proxy","enabled":true}'
rcc="$(curl -s -o "$WORK/remote" -w '%{http_code}' -X POST "$ADMIN/remotes" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d "$rc_body" 2>/dev/null)"
[ "$rcc" = "201" ] || fail "create remote: код $rcc, тело $(cat "$WORK/remote" 2>/dev/null)"

# --- GET метаданных через прокси -> sha256 совпал с файлом (byte-exact) ------
curl -s -o "$WORK/release.proxy" \
    "http://127.0.0.1:$PUBLIC_PORT/apt/$REMOTE_NAME/$RELEASE_PATH" 2>/dev/null
if [ ! -s "$WORK/release.proxy" ]; then
  fail "прокси отдал пустой Release"
else
  want="$(sha256sum "$FIXTURES/$RELEASE_PATH" | cut -d' ' -f1)"
  got="$(sha256sum "$WORK/release.proxy" | cut -d' ' -f1)"
  [ "$want" = "$got" ] || fail "Release sha256 не совпал: upstream=$want proxy=$got (byte-exact нарушен)"
fi

# --- 404 на мусорном пути ---------------------------------------------------
gcode="$(curl -s -o /dev/null -w '%{http_code}' \
    "http://127.0.0.1:$PUBLIC_PORT/apt/$REMOTE_NAME/$GARBAGE_PATH" 2>/dev/null)"
[ "$gcode" = "404" ] || fail "мусорный путь: код $gcode, хочу 404"

# --- SIGTERM -> exit 0 за <10с ----------------------------------------------
t0="$(date +%s)"
podman kill -s TERM "$CTR" >/dev/null 2>&1
st="running"
for _ in $(seq 1 60); do
  st="$(podman inspect --format '{{.State.Status}}' "$CTR" 2>/dev/null || echo exited)"
  [ "$st" = "exited" ] && break
  sleep 0.25
done
elapsed=$(( $(date +%s) - t0 ))
exitcode="$(podman inspect --format '{{.State.ExitCode}}' "$CTR" 2>/dev/null || echo -1)"
[ "$st" = "exited" ]     || fail "контейнер не остановился за ${elapsed}s (state=$st)"
[ "$exitcode" = "0" ]    || fail "контейнер завершился с кодом $exitcode (хочу 0)"
[ "$elapsed" -lt 10 ]    || fail "контейнер останавливался ${elapsed}s (хочу <10s)"

# --- итог: известные баги не краснят ----------------------------------------
unknown=0
if [ "${#FAILURES[@]}" -gt 0 ] && [ -f "$KNOWN_BUGS" ]; then
  for f in "${FAILURES[@]}"; do
    known=0
    while IFS= read -r pat; do
      [ -z "$pat" ] && continue
      case "$pat" in '#'*) continue ;; esac
      if [[ "$f" == *"$pat"* ]]; then known=1; break; fi
    done < "$KNOWN_BUGS"
    [ "$known" = 0 ] && unknown=$((unknown+1))
  done
else
  unknown="${#FAILURES[@]}"
fi

echo
if [ "$unknown" -eq 0 ]; then
  if [ "${#FAILURES[@]}" -gt 0 ]; then
    log "OK (все ${#FAILURES[@]} падений — известные баги, регрессий нет)"
  else
    log "OK (все проверки прошли)"
  fi
  exit 0
fi
log "FAIL: $unknown неизвестных падений из ${#FAILURES[@]}"
exit 1
