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
| Backend   | Spring Boot 4.0 (Java 25)       | 8080      | ✅ Implemented (Step 2) |
| Frontend  | Next.js (latest) + next-auth    | 3000      | ⏳ Pending (Step 3)     |

> This README documents only what is implemented. Run instructions for the
> frontend are added when that step lands.

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

### Get a token (Authorization Code + PKCE)

To obtain a token the way the real app will, run `scripts/auth-code-flow.mjs`. It
performs the **Authorization Code flow with PKCE** (the same flow next-auth uses
in Step 3): it starts a temporary server on the client's redirect URI, opens the
Keycloak login, and exchanges the returned `code` (plus the PKCE verifier and the
confidential client secret) for tokens.

> Requires the browser to reach Keycloak at `http://keycloak:8081`, so add
> `127.0.0.1 keycloak` to `/etc/hosts` first. Port `3000` must be free.
> No dependencies (Node 18+ only).

```bash
node scripts/auth-code-flow.mjs
# a browser opens -> log in as testuser / password
# the terminal prints the token response and decoded access-token claims:
#   iss: http://keycloak:8081/realms/web   preferred_username: testuser   lifespan: 300s
```

### Test credentials (dev-only)

| What            | Value      |
|-----------------|------------|
| Realm           | `web`      |
| Seed user       | `testuser` |
| Seed password   | `password` |
| Admin console   | `admin` / `admin` |

## Running the backend (Step 2)

The backend is a Spring Boot 4 (Java 25) OAuth2 resource server exposing a single
protected endpoint, `GET /hello`. It validates JWTs against Keycloak, so Keycloak
must be running.

```bash
docker compose up -d backend   # builds the image, waits for Keycloak to be healthy
```

### Endpoint

| Request                                   | Response |
|-------------------------------------------|----------|
| `GET /hello` with no token                | `401 Unauthorized` |
| `GET /hello` with an invalid/expired token| `401 Unauthorized` |
| `GET /hello` with a valid token           | `200` + `Hello World, <preferred_username>` |

### Verify

```bash
# No token -> 401
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8080/hello              # -> 401

# With a token (grab one from `node scripts/auth-code-flow.mjs`, then:)
curl -s http://localhost:8080/hello -H "Authorization: Bearer <access_token>"     # -> Hello World, testuser
```

### Run the tests

```bash
cd backend && ./gradlew test
```

Two layers run on JUnit 6 (requires JDK 25):

- **Controller slice test** (`HelloControllerTest`): mocks the JWT decoder, so it
  needs no Docker or live Keycloak. Covers `401` (no token) and `200` (mock JWT).
- **Integration test** (`HelloControllerIntegrationTest`): starts a real Keycloak
  via [Testcontainers](https://testcontainers.com/modules/keycloak/), imports the
  same `realm-export.json`, fetches a real signed token, and asserts the resource
  server validates it end to end. **Requires a running Docker engine.**

## How it works

- **Issuer / hostname strategy**: Keycloak listens on `8081` and the issuer is
  fixed to `http://keycloak:8081/realms/web` (`KC_HOSTNAME`). This single issuer
  will be reachable identically by the backend (over the Docker network, by
  service name) and, once the frontend exists, by the browser, so the `iss` claim
  is always consistent for discovery, JWKS, redirects, and validation.
- **Access tokens are short-lived (5 minutes)** with refresh tokens enabled
  (`accessTokenLifespan: 300` in the realm).
- **Backend JWT validation**: the resource server fetches the issuer's JWKS at
  startup and validates each token's signature, issuer, and expiry. No token (or
  an invalid one) yields `401`. CORS allows the `http://localhost:3000` origin and
  the `Authorization` header so the browser can call `/hello` in Step 3.

## Troubleshooting

- **Port 8081 already in use** → another process (or a previous Keycloak) holds
  the port. Stop it, or change `KC_PORT` in `.env`.
- **Realm edits not reflected** → the realm is imported only when the data is
  empty. Run `docker compose down` (removes the container) then `up` again to
  re-import `keycloak/realm-export.json`.

## License

Proof of concept, not licensed for production use.
