#!/usr/bin/env bash
# Build the demo-app image and check its runtime properties:
#   - the image config sets a non-root user, and the container runs as uid 10001
#   - the container reaches Docker's "healthy" state (HEALTHCHECK passes)
#   - the API answers on /health and /items/1
#   - no ARG/ENV in the image history has a secret-looking name
#
# Usage: scripts/verify_demo_image.sh [build-context]   (default: demo-app)
# Needs a running Docker daemon and network access to pull the base image
# and PyPI packages. CI runs it on the committed demo-app/ unmodified.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTEXT="${1:-$ROOT/demo-app}"
TAG="shipsafe-demo:verify-$$"
PORT="${SHIPSAFE_VERIFY_PORT:-18080}"
failures=0
cid=""
cleanup() { [ -n "$cid" ] && docker rm -f "$cid" >/dev/null 2>&1; docker rmi -f "$TAG" >/dev/null 2>&1; }
trap cleanup EXIT

ok()   { echo "IMAGE CHECK OK   [$1]"; }
fail() { echo "IMAGE CHECK FAIL [$1]: $2"; failures=$((failures+1)); }

echo "building $TAG from $CONTEXT"
if ! docker build -q -t "$TAG" "$CONTEXT" >/dev/null; then
  echo "IMAGE CHECK FAIL [build]: docker build failed"; exit 1
fi
ok "build"

cfg_user="$(docker image inspect -f '{{.Config.User}}' "$TAG")"
case "${cfg_user%%:*}" in
  ""|root|0) fail "image USER" "Config.User is '${cfg_user}' (root)";;
  *) ok "image USER is '$cfg_user'";;
esac

uid="$(docker run --rm --entrypoint id "$TAG" -u)"
if [ "$uid" = "10001" ]; then ok "runs as uid $uid"; else fail "runtime uid" "id -u = '$uid', expected 10001"; fi

secretish="$(docker history --no-trunc --format '{{.CreatedBy}}' "$TAG" \
  | grep -oiE '(ARG|ENV) [A-Za-z_]*(PASSW|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|CREDENTIAL)[A-Za-z_]*' || true)"
if [ -z "$secretish" ]; then ok "no secret-looking ARG/ENV in history"; else fail "build secrets" "$secretish"; fi

cid="$(docker run -d -p "127.0.0.1:${PORT}:8000" "$TAG")"
status=""
for _ in $(seq 1 60); do
  status="$(docker inspect -f '{{.State.Health.Status}}' "$cid" 2>/dev/null)"
  [ "$status" = "healthy" ] && break
  [ "$(docker inspect -f '{{.State.Running}}' "$cid")" = "true" ] || break
  sleep 1
done
if [ "$status" = "healthy" ]; then ok "container healthy"; else fail "healthcheck" "status '$status'"; docker logs "$cid" | tail -n 20; fi

health="$(curl -sS "http://127.0.0.1:${PORT}/health" || true)"
if [ "$health" = '{"status":"ok"}' ]; then ok "GET /health -> $health"; else fail "GET /health" "got '$health'"; fi
item="$(curl -sS "http://127.0.0.1:${PORT}/items/1" || true)"
if [ "$item" = '{"id":1,"name":"alpha"}' ]; then ok "GET /items/1 -> $item"; else fail "GET /items/1" "got '$item'"; fi

if [ "$failures" -ne 0 ]; then echo "demo image check: $failures check(s) failed"; exit 1; fi
echo "demo image check: all checks passed"
