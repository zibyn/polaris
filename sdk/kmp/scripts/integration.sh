#!/usr/bin/env bash
# Runs the SDK's integration test against a local Polaris binary: builds it
# (Go in Docker), starts PostgreSQL in Docker, creates the owner and a test
# Application, then runs IntegrationTest. Needs Docker, and web/dist/client
# built (cd web && pnpm build).
set -euo pipefail
cd "$(dirname "$0")/.."
repo=$(cd ../.. && pwd)
work=build/integration
mkdir -p "$work"
pg=polaris-sdk-it-pg
port=18080

docker run --rm -v polaris-gomod:/go/pkg/mod -v "$repo":/src -w /src -e CGO_ENABLED=0 \
  golang:1.27 go build -buildvcs=false -o "/src/sdk/kmp/$work/polaris" ./cmd/polaris

docker rm -f "$pg" >/dev/null 2>&1 || true
docker run -d --name "$pg" -e POSTGRES_PASSWORD=pg -p 127.0.0.1:55432:5432 postgres:15-alpine >/dev/null
trap 'kill "${server:-}" 2>/dev/null || true; docker rm -f "$pg" >/dev/null' EXIT
until docker exec "$pg" pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done
sleep 1

POLARIS_DATABASE_URL=postgres://postgres:pg@127.0.0.1:55432/postgres?sslmode=disable \
POLARIS_MASTER_KEY=$(openssl rand -base64 32) \
POLARIS_ISSUER=https://localhost \
POLARIS_LISTEN=127.0.0.1:$port \
  "$work/polaris" >"$work/server.log" 2>&1 &
server=$!
until curl -sf "http://127.0.0.1:$port/healthz" >/dev/null; do
  kill -0 "$server" || { cat "$work/server.log"; exit 1; }
  sleep 0.5
done

token=$(grep -o 'setup?token=[^"]*' "$work/server.log" | head -1 | cut -d= -f2)
password=$(openssl rand -hex 12)
curl -sf -o /dev/null "http://127.0.0.1:$port/setup" --data-urlencode "token=$token" \
  --data-urlencode username=owner --data-urlencode "password=$password"
docker exec "$pg" psql -qU postgres -c "INSERT INTO applications (client_id, name, type, default_api)
  VALUES ('sdk-it', 'SDK integration test', 'public', 'urn:polaris:management-api')"

POLARIS_TEST_URL=http://127.0.0.1:$port POLARIS_TEST_CLIENT=sdk-it \
POLARIS_TEST_USERNAME=owner POLARIS_TEST_PASSWORD=$password \
  ./gradlew --console=plain testAndroidHostTest --tests '*IntegrationTest*' --rerun
