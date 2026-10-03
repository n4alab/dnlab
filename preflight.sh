#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

PROJECT="${DNLAB_PREFLIGHT_PROJECT:-dnlabpre}"
HTTP_PORT="${DNLAB_PREFLIGHT_HTTP_PORT:-18080}"
HTTPS_PORT="${DNLAB_PREFLIGHT_HTTPS_PORT:-18443}"
PROXY_SERVER_NAME="${DNLAB_PREFLIGHT_PROXY_SERVER_NAME:-dnlab.preflight.test}"
TLS_DIR="${DNLAB_PREFLIGHT_TLS_DIR:-/tmp/dnlab-pre-tls}"
TOPO_DIR="${DNLAB_PREFLIGHT_TOPO_DIR:-/tmp/dnlab-pre-topologies}"
LOG_ROOT="${DNLAB_PREFLIGHT_LOG_ROOT:-/tmp/dnlab-pre-log-root}"
IMAGE_BUILD_WORKSPACE="${DNLAB_PREFLIGHT_IMAGE_BUILD_WORKSPACE:-/tmp/dnlab-pre-image-build}"
POSTGRES_PASSWORD="${DNLAB_PREFLIGHT_POSTGRES_PASSWORD:-dnlab-preflight-password}"
ADMIN_USERNAME="${DNLAB_PREFLIGHT_ADMIN_USERNAME:-preflightadmin}"
ADMIN_PASSWORD="${DNLAB_PREFLIGHT_ADMIN_PASSWORD:-preflight-password}"
PROXY_URL="https://${PROXY_SERVER_NAME}:${HTTPS_PORT}"

compose() {
  POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
  DNLAB_PROXY_SERVER_NAME="$PROXY_SERVER_NAME" \
  DNLAB_PROXY_HTTP_PORT="$HTTP_PORT" \
  DNLAB_PROXY_HTTPS_PORT="$HTTPS_PORT" \
  DNLAB_PROXY_TLS_DIR="$TLS_DIR" \
  DNLAB_TOPOLOGIES_DIR="$TOPO_DIR" \
  DNLAB_LOG_ROOT="$LOG_ROOT" \
  DNLAB_IMAGE_BUILD_WORKSPACE="$IMAGE_BUILD_WORKSPACE" \
  docker compose -p "$PROJECT" -f compose.yml "$@"
}

cleanup() {
  if [ "${DNLAB_PREFLIGHT_KEEP:-0}" != "1" ]; then
    compose down -v >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

mkdir -p "$TOPO_DIR" "$LOG_ROOT" "$IMAGE_BUILD_WORKSPACE" "$TLS_DIR"
if [ ! -f "${TLS_DIR}/dnlab-gui.crt" ] || [ ! -f "${TLS_DIR}/dnlab-gui.key" ] \
  || ! openssl x509 -in "${TLS_DIR}/dnlab-gui.crt" -noout -checkhost "${PROXY_SERVER_NAME}" >/dev/null 2>&1 \
  || ! openssl x509 -in "${TLS_DIR}/dnlab-gui.crt" -noout -checkhost "test.${PROXY_SERVER_NAME}" >/dev/null 2>&1; then
  openssl req -x509 -nodes -newkey rsa:2048 -days 7 \
    -keyout "${TLS_DIR}/dnlab-gui.key" \
    -out "${TLS_DIR}/dnlab-gui.crt" \
    -subj "/CN=${PROXY_SERVER_NAME}" \
    -addext "subjectAltName=DNS:${PROXY_SERVER_NAME},DNS:*.${PROXY_SERVER_NAME}" >/dev/null 2>&1
fi

echo "== fresh install stack =="
compose up -d proxy

echo "== empty auth DB =="
compose exec -T auth-db sh -lc \
  'PGPASSWORD="$POSTGRES_PASSWORD" psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "select count(*) from users;"' \
  | tr -d '[:space:]' \
  | grep -qx '0'

echo "== seed admin =="
DNLABGUI_BOOTSTRAP_ADMIN_USERNAME="$ADMIN_USERNAME" \
DNLABGUI_BOOTSTRAP_ADMIN_PASSWORD="$ADMIN_PASSWORD" \
POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
DNLAB_PROXY_SERVER_NAME="$PROXY_SERVER_NAME" \
DNLAB_PROXY_HTTP_PORT="$HTTP_PORT" \
DNLAB_PROXY_HTTPS_PORT="$HTTPS_PORT" \
DNLAB_PROXY_TLS_DIR="$TLS_DIR" \
DNLAB_TOPOLOGIES_DIR="$TOPO_DIR" \
DNLAB_LOG_ROOT="$LOG_ROOT" \
DNLAB_IMAGE_BUILD_WORKSPACE="$IMAGE_BUILD_WORKSPACE" \
docker compose -p "$PROJECT" -f compose.yml --profile seed-admin run --rm auth-seed

echo "== login =="
login_code="$(curl -k -sS -o /tmp/dnlab-preflight-login.json -w '%{http_code}' \
  --max-time 10 \
  --resolve "${PROXY_SERVER_NAME}:${HTTPS_PORT}:127.0.0.1" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"${ADMIN_USERNAME}\",\"password\":\"${ADMIN_PASSWORD}\"}" \
  "${PROXY_URL}/api/auth/login")"
test "$login_code" = "200"
ADMIN_USERNAME="$ADMIN_USERNAME" python3 - <<'PY'
import json
import os
data = json.load(open("/tmp/dnlab-preflight-login.json", encoding="utf-8"))
assert data["username"] == os.environ["ADMIN_USERNAME"], data
assert data["role"] == "admin", data
print(data)
PY

echo "== smoke =="
docker compose -p "$PROJECT" -f compose.yml exec -T gui python - <<'PY'
import importlib.util
assert importlib.util.find_spec("dnlab_multinode") is None
print("gui-no-dnlab-multinode-package")
PY

docker compose -p "$PROJECT" -f compose.yml exec -T gui sh -lc 'test ! -S /var/run/docker.sock && echo no-docker-socket'

docker compose -p "$PROJECT" -f compose.yml exec -T image-build python - <<'PY'
import json
from urllib.request import urlopen
with urlopen("http://127.0.0.1:8082/health", timeout=10) as response:
    health = json.load(response)
assert health.get("ok") is True, health
with urlopen("http://127.0.0.1:8082/kinds", timeout=10) as response:
    kinds = json.load(response)
assert kinds.get("available") is True, kinds
assert isinstance(kinds.get("patchable"), list), kinds
print({"image_build_patchable": len(kinds["patchable"])})
PY

echo "preflight ok"
