# Next.js + Spring Boot + Keycloak: OAuth2/OIDC Proof of Concept

A proof of concept demonstrating an end-to-end OAuth2 / OpenID Connect flow across
three applications wired together with Docker Compose:

- **Frontend**: Next.js (App Router, TypeScript) with NextAuth (next-auth v4) driving the Keycloak login.
- **Backend**: Spring Boot (Java 25, Gradle 9) exposing a protected `GET /hello` and a step-up-gated `GET /server-details` endpoint.
- **Identity Provider**: Keycloak 26, importing a pre-configured `web` realm on startup.

The goal is to validate the full loop: a user logs in through Keycloak from the
Next.js app, receives a JWT access token, and uses it to call the protected
Spring Boot endpoint, which validates the token against Keycloak (signature,
issuer, expiry).

A second iteration adds **step-up authentication**: an elevated
`GET /server-details` endpoint that requires a TOTP second factor (`acr=pro`) on
top of the base login. A base token is refused with an RFC 9470 challenge, and the
frontend transparently re-authenticates at the higher level and retries.

> **This is not a production system.** Secrets are local/dev-only and clearly
> marked as such. See [`PRD.md`](PRD.md) / [`PLAN.md`](PLAN.md) for the base
> iteration and [`PRD-2.md`](PRD-2.md) / [`PLAN-2.md`](PLAN-2.md) for the step-up
> iteration.

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

To verify the whole flow without a browser, run the headless e2e suite (each
prints `E2E PASSED`):

```bash
node scripts/e2e-login.mjs             # base login -> /hello; /server-details refused (401 + step-up challenge)
node scripts/e2e-stepup.mjs            # step-up: OTP -> session acr=pro -> /server-details 200
node scripts/e2e-stepup-denied.mjs     # basicuser (no factor) is denied at step-up, no token issued
node scripts/e2e-stepup-bruteforce.mjs # brute-force locks the OTP factor at failureFactor
node scripts/e2e-stepup-refresh.mjs    # a refreshed elevated session stays acr=pro
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
| Seed user       | `testuser` (password + seeded TOTP, can reach `acr=pro`) |
| No-factor user  | `basicuser` (password only; denied at step-up) |
| Brute-force user| `bruteuser` (password + TOTP; used by the brute-force test) |
| Seed password   | `password` (all three users) |
| Admin console   | `admin` / `admin` |

### Step-up authentication: `basic` vs `pro` (Iteration 2, Step 1)

The realm can issue tokens at two assurance levels, mapped by the realm
attribute `acr.loa.map` = `{"basic":1,"pro":2}`:

| ACR (`acr` claim) | Level of Authentication | Factors required            |
|-------------------|-------------------------|-----------------------------|
| `basic`           | LoA 1                   | password                    |
| `pro`             | LoA 2                   | password **+ TOTP** (step-up) |

A normal login (no `acr` requested) yields `acr=basic` and is unchanged from
iteration 1. A client that requests `acr=pro` triggers a custom browser flow
(`browser-stepup`) whose conditional **Condition - Level of Authentication**
executions run the TOTP (`auth-otp-form`) step **only** when LoA 2 is requested.
The LoA-2 condition uses **max age 0**, so requesting `pro` always re-verifies the
second factor, even inside an existing `basic` SSO session (the base `Cookie`
execution cannot short-circuit it). The `acr` claim is emitted on the **access
token** (not only the ID token) via Keycloak's built-in `acr` client scope, which
is a default scope on `nextjs-frontend`, because the backend enforces on the
access token the browser forwards.

**Seed TOTP credential (dev-only).** `testuser` is pre-seeded with a TOTP
credential so the second factor can be completed non-interactively:

| What          | Value                                |
|---------------|--------------------------------------|
| Secret (raw)  | `stepupTOTPseedDEVonly1234567890AB`  |
| Algorithm     | HmacSHA1, 6 digits, 30s period       |

Keycloak uses the **raw UTF-8 bytes** of that secret string as the HMAC key, so a
standard RFC 6238 TOTP over those bytes produces codes Keycloak accepts. Compute
the current code with the helper (defaults to the seed above; pass a different
seed as an argument):

```bash
node scripts/totp.mjs            # -> current 6-digit code for testuser
node scripts/totp.mjs <seed>     # -> code for any raw-string seed
```

> ⚠️ **This TOTP seed is a second-factor secret, a different and higher risk
> class than the committed dev password.** It exists only so this throwaway realm
> is reproducible with one command. **Never reuse it for any account outside this
> POC realm.** Unlike a password, a leaked second-factor seed silently defeats the
> entire point of the second factor and cannot be meaningfully rotated away from
> without re-enrolling the credential. It is not for production, ever.

**Observe the `acr` claim.** Request `pro` via the OIDC `claims`/`acr_values`
parameters on the authorization request, complete the OTP step, then decode the
resulting **access** token: its `acr` is `pro` (a base login shows `basic`). A
`refresh_token` grant on an elevated session keeps `acr=pro` for the SSO session
lifetime without re-running OTP (the `max age: 0` re-challenge applies at the
authorization request, not per refresh).

With the full stack up, a headless smoke test drives the whole step-up flow
(next-auth sign-in with `acr_values=pro` -> Keycloak OTP form -> elevated session)
and asserts the resulting access token is `acr=pro`. It reuses `scripts/totp.mjs`
to compute the code:

```bash
node scripts/e2e-stepup.mjs   # -> E2E PASSED: step-up login -> OTP -> session with acr=pro
```

### DPoP sender-constrained tokens (Iteration 3, Step 1)

A third iteration binds the access token to a key the client holds, so a stolen
token is useless without the private key (**DPoP**, RFC 9449). See
[`PRD-3.md`](PRD-3.md) / [`PLAN-3.md`](PLAN-3.md).

Keycloak 26.6 ships DPoP as a generally available feature (no preview flag). The
`nextjs-frontend` client now sets **`dpop.bound.access.tokens: "true"`**, so:

- Every token request must carry a **DPoP proof** (a short-lived JWT signed with
  the client's key, sent in the `DPoP` header) or Keycloak rejects it.
- The issued access token carries a **`cnf.jkt`** claim equal to the SHA-256
  thumbprint of the client's public key.
- Being a **confidential** client, only the access token is DPoP-bound (the
  refresh token is protected by the client secret), but the `refresh_token` grant
  **still requires a proof** so the refreshed access token stays bound to the same
  key (measured, not assumed).

Only the Keycloak side lands in this step; the backend proof validation (Step 2)
and the frontend key + BFF proxy (Step 3) follow. A scratch check proves the IdP
behavior directly (no frontend needed), obtaining a bound token and asserting
`cnf.jkt`:

```bash
docker compose up -d keycloak --force-recreate   # re-import the realm
node scripts/dpop-verify.mjs                      # -> STEP 1 PASSED: cnf.jkt bound, unbound rejected
```

> Between this step and Step 3 the frontend and backend integration tests do not
> yet speak DPoP, so `scripts/e2e-login.mjs` and `./gradlew test` are expected to
> fail against the DPoP-requiring client until those steps land. This is the
> planned incremental order, not a regression.

## Running the backend (Step 2)

The backend is a Spring Boot 4 (Java 25) OAuth2 resource server exposing a base
protected endpoint, `GET /hello`, and an elevated `GET /server-details` that
requires step-up (`acr=pro`). It validates JWTs against Keycloak, so Keycloak
must be running.

```bash
docker compose up -d backend   # builds the image, waits for Keycloak to be healthy
```

### Endpoint

Tokens are now **DPoP-bound** (Iteration 3), so a protected call presents the
token under the `DPoP` scheme with a fresh proof: `Authorization: DPoP <token>`
plus a `DPoP: <proof>` header.

| Request                                              | Response |
|------------------------------------------------------|----------|
| `GET /hello` with no token                           | `401 Unauthorized` |
| `GET /hello` with an invalid/expired token           | `401 Unauthorized` |
| `GET /hello` `DPoP` scheme + valid proof             | `200` + `Hello World, <preferred_username>` |
| `GET /hello` with the bound token as **`Bearer`**    | `401` (RFC 9449 §7.1: a bound token can't be a bearer token) |
| `GET /hello` `DPoP` scheme, missing/replayed proof   | `401` (proof required; a reused `jti` is rejected) |
| `GET /server-details` with no/invalid token          | `401 Unauthorized` (ordinary challenge) |
| `GET /server-details` `basic` token + valid proof    | `401` + `WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="pro"` (RFC 9470 step-up) |
| `GET /server-details` `pro` token + valid proof      | `200` + JSON runtime details (app, version, JVM, uptime, profiles, hostname, time) |

`/server-details` maps the token's `acr` claim to an `ACR_<value>` authority and
requires `ACR_pro` (the required level is `app.security.stepup.acr`, default
`pro`, not a hardcoded literal). A valid but under-assured token gets the RFC 9470
`401` step-up challenge instead of a bare `403`, and `WWW-Authenticate` is exposed
via CORS so the browser `fetch` can read it. The payload carries no secrets,
tokens, or environment dumps.

**DPoP validation (Step 2).** Spring Security 7 auto-enables DPoP proof
validation once `DPoPProofJwtDecoderFactory` is on the classpath: it verifies the
proof (signature, `htm`/`htu`, `iat` freshness, `jti` replay via a built-in cache,
`ath`, and the `cnf.jkt` thumbprint match) and decodes the access token through
the *same* JWT authentication manager, so the existing issuer/audience and `acr`
step-up checks still apply to `DPoP`-scheme requests. Two guards keep a bound
token from being downgraded: the framework's own `BearerTokenAuthenticationFilter`
rejects a `cnf`-bound token presented as plain `Bearer` (RFC 9449 §7.1), and
`DpopBoundTokenValidator` additionally requires *every* accepted token to carry
`cnf.jkt`, so an unbound token is refused under any scheme and the guarantee does
not rest on Keycloak's client toggle alone. DPoP-proof failures are an
authentication-time `401`; the step-up challenge is an authorization-time `401`,
so the two never mask each other.

### Verify

```bash
# No token -> 401
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8080/hello              # -> 401

# A bare bearer token is now refused (tokens are DPoP-bound); a plain curl cannot
# mint a proof, so use the scripts to exercise the DPoP path end to end:
node scripts/dpop-verify.mjs   # Keycloak side: issues a bound token (cnf.jkt)
cd backend && ./gradlew test   # backend side: real DPoP calls against /hello + /server-details
```

### Run the tests

```bash
cd backend && ./gradlew test
```

Two layers run on JUnit 6 (requires JDK 25):

- **Controller slice tests** (`HelloControllerTest`, `ServerDetailsControllerTest`):
  mock the JWT decoder, so they need no Docker or live Keycloak.
  `ServerDetailsControllerTest` covers `401` (no token), the `401` step-up
  challenge for a `basic` token, and `200` + payload for a `pro` token;
  `HelloControllerTest` also asserts a `cnf`-bound token is refused under the
  `Bearer` scheme.
- **Integration tests** (`HelloControllerIntegrationTest`,
  `ServerDetailsControllerIntegrationTest`): start a real Keycloak via
  [Testcontainers](https://testcontainers.com/modules/keycloak/), import the same
  `realm-export.json`, and obtain real **DPoP-bound** tokens through the
  **Authorization Code + PKCE** flow (signing proofs with `DpopProofs` /
  `KeycloakAuthCodeClient`). They assert the happy DPoP path on `/hello` and
  `/server-details`, plus the negatives: a bound token used as `Bearer`, a `DPoP`
  request with no proof, and a replayed proof are each `401`. The server-details
  test drives the real OTP second factor to get a `pro` token, confirms a `basic`
  token still gets the step-up challenge, and asserts `app.security.stepup.acr` is
  a key in the realm's `acr.loa.map` (so a Keycloak rename fails the build rather
  than silently denying all access). **Requires a running Docker engine.**

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
3. You return to the **home screen**, which automatically calls the greeting
   endpoint through a **same-origin BFF proxy** (`GET /api/backend/hello`) and shows
   **"Hello World, testuser"**, with a **Log out** button. A small badge shows the
   current assurance level (`basic`).

**DPoP + BFF proxy (iteration 3).** The browser never holds the access token or the
DPoP key. next-auth runs a **DPoP-bound** token exchange server-side (the access
token is `cnf.jkt`-bound to a per-session ES256 key held in the Next.js server, not
the browser), and the browser reaches the backend only through same-origin
`/api/backend/*` routes that attach the token and a freshly signed DPoP proof
server-side. `session` exposes only the `acr` UI hint, never the token.

**Step-up (`GET /server-details`).** The home screen also has a **Load server
details** button:

4. Click **Load server details**. The browser calls `GET /api/backend/server-details`
   (the proxy forwards it to the backend under DPoP), and the base (`acr=basic`)
   session gets the `401` step-up challenge, relayed back through the proxy.
5. The app reads the required level from the `WWW-Authenticate` header (allow-listed
   against the known set before use), then re-authenticates via next-auth
   requesting `acr=pro`. **Keycloak prompts for the OTP** (compute the current code
   with `node scripts/totp.mjs`).
6. After the OTP you are redirected back, the app **auto-retries once** (a one-shot,
   time-bounded marker), the **server details render**, and the badge flips to
   `pro`. Already-elevated sessions skip straight to the details.
7. **Cancelling** the OTP shows an error **toast** and leaves the base session and
   `/hello` intact.

Any failure in the login/auth flow (a Keycloak error redirect, a token-refresh
failure, an unreachable API, or a not-completed step-up) is shown as a red
**toast** in the top-right that auto-dismisses after 5 seconds; multiple errors
stack. Enforcement is entirely server-side; `session.acr` is only a UI hint (badge
and skip-redundant-step-up), re-derived from the token on every refresh.

To smoke-test the DPoP + BFF flow without a browser:

```bash
node scripts/dpop-bff-verify.mjs   # login -> no token in session -> /hello via BFF;
                                    # step-up (OTP) -> pro -> /server-details 200 via BFF
```

> The older `scripts/e2e-login.mjs` / `e2e-stepup*.mjs` read the access token from
> the session and called the backend directly; with the token now server-side behind
> the BFF proxy they are being migrated to the proxy + DPoP in Step 4.

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

## Debug logging

A single `DEBUG` flag (off by default) turns on verbose, non-secret tracing of
the DPoP and step-up flow across the whole stack. It is a local developer aid,
not an audit log, and it **never** prints access/refresh tokens, the DPoP private
key, proof signatures, or the client secret; only material that is non-sensitive
by design is emitted (selected JWT claims such as `acr`/`aud`/`sub`, the public
`cnf.jkt` thumbprint, and a proof's `htm`/`htu`/`jti`/`iat` plus whether
`ath`/`nonce` are present). Keep it off outside debugging.

Enable it for the full Docker stack:

```bash
DEBUG=true docker compose up -d --build   # rebuild so the client bundle picks it up
docker compose logs -f backend frontend   # watch [dpop-debug] / [stepup-debug] lines
```

Or per component during local development:

```bash
# Frontend (server, SSR, and browser). One flag reaches all three JS runtimes;
# NEXT_PUBLIC_* is inlined at build time, so restart dev after changing it.
cd frontend && NEXT_PUBLIC_DEBUG=true npm run dev

# Backend (DPoP validation + step-up decisions), logged at INFO.
cd backend && DEBUG=true ./gradlew bootRun
```

What each side logs:

- **Backend** (`DEBUG`): `[dpop-debug]` when a token is accepted/rejected by the
  DPoP-bound check (`cnf.jkt`, `acr`, `aud`, `sub`) and on each `/hello` hit;
  `[stepup-debug]` when `/server-details` is challenged for a higher `acr` or
  served after the step-up gate passes.
- **Frontend** (`NEXT_PUBLIC_DEBUG`): `[dpop-debug][server|client][scope]` lines
  covering the token exchange and refresh (`auth`), key store put/get/evict
  (`keystore`), proof signing (`dpop`), the BFF proxy request/response and nonce
  retries (`bff`), SSR render (`ssr`), and the browser fetch, step-up, and session
  updates (`page`).

In Docker the frontend's browser logging needs `--build` because the client value
is inlined at build time; the server/SSR side also honors it at runtime.

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
- **Brute-force protection**: `bruteForceProtected` is on (`failureFactor` 10),
  so repeated bad password/OTP attempts get throttled and locked, which matters now
  that a 6-digit TOTP gates the elevated (`pro`) level.
- **Step-up needs a provisioned factor**: the `CONFIGURE_TOTP` required action is
  disabled, so a user without a second factor is denied at step-up ("credential
  setup required") rather than being allowed to self-enroll one inline. `acr=pro`
  therefore means a pre-provisioned factor was used.
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
