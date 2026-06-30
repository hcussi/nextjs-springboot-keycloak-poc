# Next.js + Spring Boot + Keycloak: OAuth2/OIDC Proof of Concept

A proof of concept demonstrating an end-to-end OAuth2 / OpenID Connect flow across
three applications wired together with Docker Compose:

- **Frontend**: Next.js (App Router, TypeScript) with NextAuth (next-auth v4) driving the Keycloak login.
- **Backend**: Spring Boot (Java 25, Gradle 9) exposing a single protected `GET /hello` endpoint.
- **Identity Provider**: Keycloak 26, importing a pre-configured `web` realm on startup.

The goal is to validate the full loop: a user logs in through Keycloak from the
Next.js app, receives a JWT access token, and uses it to call the protected
Spring Boot endpoint, which validates the token against Keycloak (signature,
issuer, expiry).

> **This is not a production system.** Secrets are local/dev-only and clearly
> marked as such. See [`PRD.md`](PRD.md) for full requirements and
> [`PLAN.md`](PLAN.md) for the implementation plan.

## Architecture

```
  ┌──────────────┐   1. Click "Login"            ┌──────────────┐
  │   Next.js    │ ────────────────────────────► │   Keycloak   │
  │  (frontend)  │   2. Redirect, authenticate    │   realm:     │
  │   :3000      │ ◄──────────────────────────── │   "web"      │
  │              │   3. Auth code → JWT tokens    │   :8081      │
  └──────┬───────┘                                └──────────────┘
         │  4. GET /hello with Bearer JWT (held in memory)
         ▼
  ┌──────────────┐   5. Validate JWT via JWKS    ┌──────────────┐
  │ Spring Boot  │ ─────── issuer / JWKS ───────► │   Keycloak   │
  │  (backend)   │ ◄──────────────────────────── │   (JWKS)     │
  │   :8080      │   6. 200 "Hello World, <user>" └──────────────┘
  └──────────────┘
```

| Component | Technology                      | Host port | Status            |
|-----------|---------------------------------|-----------|-------------------|
| Keycloak  | Keycloak 26 (dev mode)          | 8081      | ✅ Implemented (Step 1) |
| Backend   | Spring Boot 4.0 (Java 25)       | 8080      | ⏳ Pending (Step 2)     |
| Frontend  | Next.js (latest) + next-auth    | 3000      | ⏳ Pending (Step 3)     |

> This README documents only what is implemented. Run instructions for the
> backend and frontend are added as each step lands.

## Prerequisites

- **Docker** and **Docker Compose**.

## Running Keycloak (Step 1)

Start Keycloak (imports the `web` realm on first boot):

```bash
docker compose up -d keycloak   # start in the background
docker compose ps               # check status (waits for healthcheck)
docker compose logs -f keycloak # follow logs (Ctrl-C to stop following)
```

Stop it:

```bash
docker compose down             # stop and remove containers (realm re-imports on next up)
```

### URLs

| Endpoint               | URL                                                               | Expected |
|------------------------|-------------------------------------------------------------------|----------|
| Keycloak admin console | http://localhost:8081/admin                                       | `302` to console (login: `admin`/`admin`) |
| Realm `web`            | http://localhost:8081/realms/web                                  | `200` |
| OIDC discovery         | http://localhost:8081/realms/web/.well-known/openid-configuration | `200`, issuer `http://keycloak:8081/realms/web` |

### Verify

Confirm the realm imported and the issuer is correct:

```bash
# Realm reachable
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8081/realms/web        # -> 200

# Issuer in the discovery document
curl -s http://localhost:8081/realms/web/.well-known/openid-configuration \
  | grep -o '"issuer":"[^"]*"'                                                    # -> "issuer":"http://keycloak:8081/realms/web"
```

Get a token for the seed user (also proves the confidential client and password
work):

```bash
curl -s -X POST http://localhost:8081/realms/web/protocol/openid-connect/token \
  -d grant_type=password \
  -d client_id=nextjs-frontend \
  -d client_secret=nextjs-frontend-secret-dev \
  -d username=testuser \
  -d password=password | python3 -m json.tool
```

### Test credentials (dev-only)

| What            | Value      |
|-----------------|------------|
| Realm           | `web`      |
| Seed user       | `testuser` |
| Seed password   | `password` |
| Admin console   | `admin` / `admin` |

## How it works

- **Issuer / hostname strategy**: Keycloak listens on `8081` and the issuer is
  fixed to `http://keycloak:8081/realms/web` (`KC_HOSTNAME`). This single issuer
  will be reachable identically by the backend (over the Docker network, by
  service name) and, once the frontend exists, by the browser, so the `iss` claim
  is always consistent for discovery, JWKS, redirects, and validation.
- **Access tokens are short-lived (5 minutes)** with refresh tokens enabled
  (`accessTokenLifespan: 300` in the realm).

## Troubleshooting

- **Port 8081 already in use** → another process (or a previous Keycloak) holds
  the port. Stop it, or change `KC_PORT` in `.env`.
- **Realm edits not reflected** → the realm is imported only when the data is
  empty. Run `docker compose down` (removes the container) then `up` again to
  re-import `keycloak/realm-export.json`.

## License

Proof of concept, not licensed for production use.
