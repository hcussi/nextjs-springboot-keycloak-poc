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
| Frontend  | Next.js 16 + next-auth v4 + Tailwind | 3000 | ✅ Implemented (Step 3) |

## Prerequisites

- **Docker** and **Docker Compose**.
- **A `/etc/hosts` entry** (one-time, required for browser login). The token
  issuer is fixed to the `keycloak` hostname so the `iss` claim is identical for
  the browser and the backend. The browser must resolve that hostname to
  localhost:

  ```
  127.0.0.1 keycloak
  ```

  Without it, the redirect to Keycloak during login fails. This is the single
  most common point of failure.

## Quick start

With Docker running and the `/etc/hosts` entry set:

```bash
docker compose up -d --build
```

This starts all three services in order (Keycloak and the backend become healthy
before the frontend starts). Then open **http://localhost:3000**, click **Log in**,
sign in as `testuser` / `password`, and the home screen shows
**"Hello World, testuser"** fetched from the backend.

To verify the whole flow without a browser:

```bash
node scripts/e2e-login.mjs   # -> E2E PASSED: ... Hello World, testuser
```

The sections below document and verify each service individually.

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
  same `realm-export.json`, obtains a token through the real **Authorization Code
  + PKCE** flow (the same flow the frontend uses), and asserts the resource server
  validates it end to end. **Requires a running Docker engine.**

## Running the frontend / full stack (Step 3)

The frontend is a Next.js 16 (App Router, TypeScript, Tailwind) app using
next-auth v4 with the Keycloak provider. Bring up the whole stack with one
command (make sure the `/etc/hosts` entry above is set first):

```bash
docker compose up -d --build   # Keycloak, backend, and frontend
```

Then open **http://localhost:3000** and:

1. The **login screen** shows a single **Log in** button.
2. **Log in** redirects to Keycloak; sign in as `testuser` / `password`.
3. You return to the **home screen**, which automatically calls `GET /hello` and
   shows **"Hello World, testuser"**, with a **Log out** button.

Any failure in the login/auth flow (a Keycloak error redirect, a token-refresh
failure, or an unreachable API) is shown as a red **toast** in the top-right that
auto-dismisses after 5 seconds; multiple errors stack.

To smoke-test the whole flow without a browser, run the headless E2E check (it
logs in, establishes a session, and calls `/hello`):

```bash
node scripts/e2e-login.mjs   # -> E2E PASSED: ... Hello World, testuser
```

### Frontend development (outside Docker)

```bash
cd frontend
npm install --legacy-peer-deps   # next-auth v4 predates React 19 peer ranges
npm run dev                       # http://localhost:3000 (needs keycloak + backend up)
```

## How it works

- **Issuer / hostname strategy**: Keycloak listens on `8081` and the issuer is
  fixed to `http://keycloak:8081/realms/web` (`KC_HOSTNAME`). This single issuer
  is reachable identically by the backend (over the Docker network, by service
  name) and by the browser (via the `/etc/hosts` entry), so the `iss` claim is
  always consistent for discovery, JWKS, redirects, and validation.
- **Access tokens are short-lived (5 minutes)** with refresh tokens enabled
  (`accessTokenLifespan: 300` in the realm).
- **Backend JWT validation**: the resource server fetches the issuer's JWKS at
  startup and validates each token's signature, issuer, and expiry. No token (or
  an invalid one) yields `401`. CORS allows the `http://localhost:3000` origin and
  the `Authorization` header so the browser can call `/hello`.
- **Frontend session**: next-auth runs the Authorization Code + PKCE flow
  server-side (the confidential client secret stays on the Next.js server). The
  access token is kept in the next-auth session (in memory, not localStorage) and
  sent as a Bearer token to the backend. When the 5-minute token expires, a
  refresh callback silently renews it; if that fails, the UI shows an error toast.

## Security

A `security-reviewer` subagent (`.claude/agents/`) audited the auth surface and
its findings were applied. What the stack enforces:

- **Audience validation**: the backend requires the access token's `aud` to
  include `nextjs-frontend` (a Keycloak audience mapper sets it), so a token
  minted for another client is rejected, not just any signature-valid token.
- **PKCE enforced both sides**: the Keycloak client requires `S256`
  (`pkce.code.challenge.method`) and next-auth pins `checks: ["pkce", "state"]`.
- **Refresh token rotation**: `revokeRefreshToken` + `refreshTokenMaxReuse=0`, so
  a replayed refresh token is rejected.
- **Least privilege**: `fullScopeAllowed=false`; the client only gets its scopes.
- **Full logout**: signing out also ends the Keycloak SSO session (back-channel).
- **Short sessions**: `ssoSessionMaxLifespan` is 1 hour; access tokens 5 minutes.
- **No PII in logs**; confidential client secret stays server-side; access token
  in memory (not localStorage); CORS scoped to the one origin.

Still required before any non-local use (intentionally out of scope for this POC):
TLS everywhere (`sslRequired`, `KC_HTTP_ENABLED=false`), `KC_HOSTNAME_STRICT=true`,
real per-environment secrets (the committed ones are dev-only placeholders), and a
migration from next-auth v4 (maintenance mode) to Auth.js v5.

## Troubleshooting

- **Login redirect fails / Keycloak unreachable in the browser** → confirm the
  `127.0.0.1 keycloak` line is in `/etc/hosts`. This is the most common issue.
- **`/hello` returns 401 right after login** → the 5-minute access token may have
  expired; the refresh callback should renew it. A persistent error toast means
  refresh failed, sign in again.
- **Browser fetch to `/hello` blocked by CORS** → the backend must allow the
  `http://localhost:3000` origin and the `Authorization` header (it does by
  default in `SecurityConfig`).
- **Port already in use (8081 / 8080 / 3000)** → another process holds the port.
  Stop it, or change `KC_PORT` / `BACKEND_PORT` / `FRONTEND_PORT` in `.env`.
- **Realm edits not reflected** → the realm is imported only when Keycloak's data
  is empty. Run `docker compose down` then `up` again to re-import
  `keycloak/realm-export.json`.

## License

Proof of concept, not licensed for production use.
