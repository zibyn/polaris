#!/usr/bin/env bash
# Runs the Basic OP, Config OP and RP-Initiated Logout conformance plans
# against the harness OP (PG-backed, see compose.yaml). Used by CI and for
# local regression runs.
#
#   CS_DIR   built conformance-suite checkout (default ./conformance-suite):
#            git clone --branch release-v5.1.45 --depth=1 https://gitlab.com/openid/conformance-suite.git
#            docker run --rm -v ./conformance-suite:/usr/src/mymaven -w /usr/src/mymaven \
#              maven:3-eclipse-temurin-21 mvn -B clean package -DskipTests=true
#   ISSUER   harness issuer (default https://auth.localhost); give it a port,
#            e.g. https://auth.localhost:9443, where 443 is not bindable
#   OUT_DIR  where the logs and plan result zips go (default ./conformance-results)
set -euo pipefail

root=$(cd "$(dirname "$0")/../../.." && pwd)
here="$root/internal/oidc/conformance"
export CS_DIR=$(realpath "${CS_DIR:-$root/conformance-suite}")
export ISSUER=${ISSUER:-https://auth.localhost}
out=$(realpath -m "${OUT_DIR:-$root/conformance-results}")
mkdir -p "$out"
compose=(docker compose -p polaris-conformance -f "$here/compose.yaml")

wait_for() { # url
  for _ in $(seq 60); do
    [ "$(curl -sk -o /dev/null -w '%{http_code}' "$1")" = 200 ] && return
    sleep 2
  done
  echo "timed out waiting for $1" >&2
  return 1
}

op=
cleanup() {
  [ -n "$op" ] && kill "$op" 2>/dev/null
  "${compose[@]}" logs server > "$out/suite.log" 2>&1 || true
  "${compose[@]}" down
}
trap cleanup EXIT

"${compose[@]}" up -d --build --wait
(cd "$root" && go build -o "$out/op" ./internal/oidc/conformance)
DATABASE_URL=postgres://postgres:pg@127.0.0.1:55433/postgres "$out/op" > "$out/op.log" 2>&1 &
op=$!
wait_for https://localhost:8443/api/runner/available
wait_for "$ISSUER/.well-known/openid-configuration"

sed "s#https://auth.localhost/#$ISSUER/#" "$here/config.json" > "$out/config.json"
cp "$here/failures.json" "$here/skips.json" "$out/"

# The runner talks to the suite over the compose network, so the host needs
# no Python environment.
docker run --rm --network polaris-conformance_default \
  -v "$CS_DIR/scripts:/scripts:ro" -v "$out:/out" -w /out \
  -e CONFORMANCE_SERVER=https://nginx:8443/ -e CONFORMANCE_DEV_MODE=1 \
  python:3.13-slim sh -c '
    pip install -q --root-user-action=ignore -r /scripts/requirements.txt &&
    python3 /scripts/run-test-plan.py \
      "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]" config.json \
      "oidcc-config-certification-test-plan" config.json \
      "oidcc-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]" config.json \
      --expected-failures-file failures.json \
      --expected-skips-file skips.json \
      --export-dir /out'
