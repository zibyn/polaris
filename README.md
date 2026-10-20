# Polaris

[![ci](https://github.com/zibyn/polaris/actions/workflows/ci.yml/badge.svg)](https://github.com/zibyn/polaris/actions/workflows/ci.yml)
[![conformance](https://github.com/zibyn/polaris/actions/workflows/conformance.yml/badge.svg)](https://github.com/zibyn/polaris/actions/workflows/conformance.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Self-hosted, single-tenant identity for the apps you build.** One user pool, one
sign-in for all of them — your applications stop implementing authentication
themselves.

Polaris is the shared identity foundation for your applications. It ships as a
single Go binary whose only external dependency is PostgreSQL, speaks OIDC to
web apps, a direct API to native apps, and issues JWTs your backends verify
locally with JWKS.

## What you get

- **One user pool across every application.** The same person is one User in
  all of them. SMS or email sign-in creates the account, leaving one user pool
  with no per-app accounts to reconcile.
- **Two faces, one token.** Web and standards-based clients use OIDC
  (authorization code + PKCE). iOS and Android sign in without a browser through
  `/v1/auth/challenge` — SMS, email, password, Passkey or Sign in with Apple.
  Both paths exchange at the same `/token` endpoint and issue identical access,
  ID and refresh tokens.
- **China-first sign-in.** +86 SMS OTP (Alibaba Cloud SMS) and email OTP out of
  the box, plus username/phone/email + password, Passkey, TOTP with recovery
  codes, and external providers: generic OIDC, generic OAuth2, Apple, Google,
  Microsoft and GitHub.
- **Authorization, not just authentication.** Register each backend as an API
  with its own Permissions and Roles; `roles` and `entitlements` ride in the
  RFC 9068 access token, and the backend decides access itself. A Management API
  lets M2M applications administer users, applications and roles.
- **Boring to operate.** One binary and one database. No Redis, no sidecars, no
  runtime plugin loading. Migrations are embedded and run on start; replicas are
  stateless. Signing keys, TOTP secrets and provider secrets are encrypted with
  a single master key.

## How it fits

```
  iOS / Android ── KMP SDK ──► POST /v1/auth/challenge ──┐
  Web / OIDC RP ── browser ──► /authorize + /login ──────┤
  Console / account center ──────────────────────────────┤
                                                         ▼
                                                   POST /token
                                                         │
                                access token (JWT) ◄─────┘
                                        │
        business backend ── JWKS ───────┴── verifies locally
        M2M application ── client_credentials ──► Management API
```

The console (`/console`), account center (`/account`) and hosted login pages are
served by the same binary.

## Quick start

Production, with Caddy issuing HTTPS certificates:

```bash
mkdir polaris && cd polaris
curl -fLO https://raw.githubusercontent.com/zibyn/polaris/main/compose.yaml
curl -fLO https://raw.githubusercontent.com/zibyn/polaris/main/Caddyfile

cat > .env <<END
POLARIS_DOMAIN=auth.example.com
POLARIS_VERSION=0.1.0
POLARIS_MASTER_KEY=$(openssl rand -base64 32)
POSTGRES_PASSWORD=$(openssl rand -hex 16)
END
chmod 600 .env

docker compose up -d
docker compose logs polaris | grep setup
# WARN no admin yet: open the setup page to create the owner url="https://auth.example.com/setup?token=..."
```

Open the setup link and create the owner account. The setup page closes for
good afterwards; the owner signs in to the console at `/console`.

> **Back up `POLARIS_MASTER_KEY`.** Signing keys, TOTP secrets and
> Channel/Provider secrets are encrypted with it. Lose it and no database
> backup can recover them.

Without a domain, leave `POLARIS_DOMAIN` unset to try it on
`https://localhost` with Caddy's local CA. Deployment, backups, upgrades and
recovery are covered in [docs/deploy.md](docs/deploy.md).

Development needs Go 1.27, Node 24, pnpm 12 and Docker:

```bash
docker run -d --name polaris-pg -e POSTGRES_PASSWORD=pg \
  -p 127.0.0.1:5432:5432 postgres:15-alpine

cd web && pnpm install && pnpm dev          # Vite on :3000

POLARIS_DATABASE_URL=postgres://postgres:pg@127.0.0.1:5432/postgres?sslmode=disable \
POLARIS_MASTER_KEY=$(openssl rand -base64 32) \
POLARIS_ISSUER=https://localhost \
POLARIS_DEV_WEB_URL=http://localhost:3000 \
  go run ./cmd/polaris                   # browse http://localhost:8080
```

Without `POLARIS_DEV_WEB_URL` the binary serves the SPA embedded from
`web/dist/client`, so run `pnpm build` before `go build`. Tests that need
PostgreSQL run when `POLARIS_TEST_DATABASE_URL` is set (for example
`postgres://postgres:pg@127.0.0.1:5432/postgres?sslmode=disable`); they create
their own databases.

## SDK and APIs

- **KMP SDK** for iOS and Android: OTP, password, Apple, Passkey, refresh,
  logout and account deletion; protocol only, no UI. See [sdk/kmp](sdk/kmp) and
  [docs/sdk-behavior.md](docs/sdk-behavior.md).
- **OpenAPI documents** are served by the instance: `/v1/auth/openapi.json`
  (direct auth), `/v1/management/openapi.json` (Management API) and
  `/v1/account/openapi.json` (account center).
- **Management API guide**: [docs/management-api.md](docs/management-api.md).
- **Webhooks**: `user.deleted` is signed the Standard Webhooks way; see
  [docs/spec/protocol.md](docs/spec/protocol.md#webhook).

## Documentation

| Read this | For |
|---|---|
| [GLOSSARY.md](GLOSSARY.md) | The domain vocabulary, and what the product deliberately is not |
| [docs/spec/](docs/spec/README.md) | What the system is — identity, authentication, protocol, RBAC, operations |
| [docs/adr/](docs/adr/) | Why it is built this way |
| [docs/research/](docs/research/) | Surveys of prior art and protocol decisions |

## Status

Pre-1.0, single-tenant, sized for roughly ten thousand users. The first
integration is a KMP navigation app for iOS and Android. Conformance for OpenID
Basic OP, Config OP and RP-Initiated Logout runs in CI on every pull request;
formal certification is the 1.0 milestone. The API may still change before then.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE); bundled go-oidc code
keeps its MIT notice.
