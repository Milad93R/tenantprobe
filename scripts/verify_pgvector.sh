#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
COMPOSE=(docker compose -f "$ROOT/demo_pgvector/compose.yaml")

cleanup() {
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for_app() {
  for _ in $(seq 1 90); do
    if curl -sf http://127.0.0.1:8078/health >/dev/null; then
      return 0
    fi
    sleep 1
  done
  "${COMPOSE[@]}" logs app db
  return 1
}

assert_jwt_boundary() {
  local status
  status=$(curl -sS -o /dev/null -w '%{http_code}' \
    -X POST http://127.0.0.1:8078/v1/query \
    -H "Authorization: $TP_ACME_AUTH" \
    -H 'Content-Type: application/json' \
    --data '{"tenant_id":"org-b","query":"internal secret","top_k":3}')
  if [ "$status" != "403" ]; then
    echo "pgvector integration: tenant spoof with another principal returned HTTP $status, expected 403" >&2
    return 1
  fi
}

run_case() {
  local safe=$1
  local expected=$2

  cleanup
  SAFE="$safe" "${COMPOSE[@]}" up -d --build
  wait_for_app

  eval "$("${COMPOSE[@]}" exec -T app python tokens.py)"
  export TP_ACME_AUTH TP_GLOBEX_AUTH TP_DEMO_ADMIN
  assert_jwt_boundary

  set +e
  "$ROOT/tenantprobe" -scenario "$ROOT/testdata/scenarios/pgvector-jwt.yaml"
  local actual=$?
  set -e

  if [ "$actual" -ne "$expected" ]; then
    echo "pgvector integration: SAFE=$safe exit=$actual, expected=$expected" >&2
    "${COMPOSE[@]}" logs app db
    return 1
  fi
}

CGO_ENABLED=0 go build -trimpath -o "$ROOT/tenantprobe" "$ROOT/cmd/tenantprobe"
run_case 0 1
run_case 1 0
echo "pgvector/JWT integration passed: vulnerable target failed, isolated target passed"
