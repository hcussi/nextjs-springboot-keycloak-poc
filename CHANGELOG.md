# Changelog

All notable changes to this proof of concept are documented here.
This project is in active development; sections are added as each step lands.

## [0.2.0] - 2026-07-05

Step-up authentication: a second, higher-assurance level (`pro`) layered on top of
the base login (`basic`), so a more sensitive endpoint can demand a stronger proof
of identity than a plain password session. See [`PRD-2.md`](PRD-2.md) and
[`PLAN-2.md`](PLAN-2.md).

### Step-up authentication (Keycloak)

- **Two assurance levels.** A normal login yields `acr=basic`; requesting `acr=pro`
  runs a **TOTP second factor** on top of the password. The realm maps the levels
  (`acr.loa.map`) and a custom browser flow runs the OTP step only when `pro` is
  requested, re-challenging every time (so an existing `basic` session cannot slip
  through) while leaving base login unchanged.
- **Reproducible second factor.** The seed user `testuser` has a pre-seeded,
  dev-only TOTP so the whole flow runs headlessly; `scripts/totp.mjs` prints the
  current code.

### Backend API (Spring Boot)

- **New elevated `GET /server-details` endpoint.** Returns non-sensitive runtime
  facts (app, version, JVM, uptime, active profiles, hostname, time) and requires
  `acr=pro`; it deliberately exposes no secrets, tokens, or environment dumps.
- **Standards-based step-up challenge.** A valid but base-level token is refused
  with an RFC 9470 `401` (`insufficient_user_authentication`, `acr_values="pro"`)
  telling the client to re-authenticate at a higher level, rather than an opaque
  `403`. A missing or invalid token still gets the ordinary `401`. The required
  level is configuration, not a hardcoded value.
- **Tests.** Slice tests cover no-token, the base-token step-up challenge, and the
  `pro`-token success; a Testcontainers integration test completes the real OTP to
  obtain a `pro` token end to end.

### Frontend (Next.js)

- **Load server details, with transparent step-up.** A new button fetches
  `/server-details`; on the step-up challenge the app re-authenticates at `pro`
  (Keycloak prompts for the OTP), then **auto-retries once** and renders the
  details. An assurance-level badge shows `basic` vs `pro`. Cancelling the second
  factor shows a toast and leaves the base session and `/hello` intact.

### Security

- **Second factor must be pre-provisioned.** Inline self-enrollment of TOTP during
  step-up is disabled, so `pro` proves possession of an existing factor.
- **Brute-force protection enabled.** The OTP now gates the elevated level, so
  repeated bad codes lock the account temporarily.
- **Server-side enforcement.** The required `acr` is checked on the signed token in
  the backend; the challenge's requested level is allow-listed before use, and the
  frontend's level indicator is only a hint. The committed dev TOTP seed carries a
  distinct, loud not-for-production warning (a leaked second-factor seed is a higher
  risk class than a password).

### Tooling

- **Headless step-up e2e suite.** `scripts/e2e-stepup.mjs` (OTP to `acr=pro` to
  `/server-details`), `e2e-stepup-denied.mjs` (a factor-less user is denied),
  `e2e-stepup-bruteforce.mjs` (the OTP factor locks under brute force), and
  `e2e-stepup-refresh.mjs` (a refreshed elevated session stays `pro`).
  `e2e-login.mjs` also asserts a base session is challenged on `/server-details`.

### Documentation

- Step-up requirements (`PRD-2.md`) and plan (`PLAN-2.md`); a README step-up
  section (levels, the seed TOTP note, the endpoint table, the browser walkthrough)
  and a `CLAUDE.md` iteration pointer.

## [0.1.1] - 2026-06-30

### Security hardening

Findings from a security review of the auth surface, applied:

- **Audience validation.** The backend now requires the access token's `aud` to
  include this API, rejecting tokens minted for other clients in the realm (added
  a Keycloak audience mapper and an `AudienceValidator`).
- **PKCE enforced.** The Keycloak client requires PKCE (S256) and next-auth pins
  it, closing the gap where a code exchange without a verifier was accepted.
- **Refresh token rotation.** Refresh tokens are now single-use; a replayed token
  is rejected.
- **Least-privilege scopes.** The client no longer receives every realm scope.
- **Full logout.** Signing out now also ends the Keycloak SSO session, so the next
  login requires credentials again.
- **Shorter sessions** (SSO max lifespan 10h to 1h) and **no username in logs**.
- **Non-trivial dev admin password** (still dev-only).

### Added

- A read-only `security-reviewer` subagent and a project `CLAUDE.md`.

## [0.1.0] - 2026-06-30

Initial, feature-complete proof of concept: an end-to-end OAuth2 / OIDC login
across a Next.js frontend, a Spring Boot backend, and Keycloak, runnable with a
single command.

### Login and identity (Keycloak)

- **One-command identity provider.** Keycloak 26 starts with the `web` realm
  auto-imported: an OIDC client, 5-minute access tokens, refresh tokens, and a
  ready-to-use seed login (`testuser` / `password`). No manual realm setup.
- **Consistent token issuer.** Keycloak is fixed to a single issuer reachable
  identically by the browser and the backend, so token validation works the same
  everywhere.

### Frontend (Next.js)

- **Login screen.** A clean, minimalist page with a single Log in button that
  signs in through Keycloak (Authorization Code + PKCE via next-auth).
- **Home screen.** After signing in, the app shows who you are and automatically
  calls the protected `GET /hello`, displaying "Hello World, testuser", with a
  Log out button. The access token is held in memory and silently refreshed when
  the 5-minute token expires.
- **Stacking error toasts.** Any failure in the login/auth flow (a Keycloak error,
  a token-refresh failure, or an unreachable API) appears as a red toast that
  auto-dismisses after 5 seconds; multiple errors stack.

### Backend API (Spring Boot)

- **Protected `GET /hello` endpoint.** A Spring Boot 4 (Java 25) service that
  greets the logged-in user (`Hello World, <username>`), reading the name from
  the validated token.
- **Real token validation.** The backend verifies each request's JWT against
  Keycloak (signature, issuer, expiry). Requests with no token, or an invalid or
  expired one, are rejected with `401`. CORS allows the browser origin.
- **Automated tests.** JUnit 6 controller tests cover the unauthorized (`401`)
  and authorized (`200` + greeting) cases. A Testcontainers integration test
  spins up a real Keycloak, imports the same realm, obtains a token via the
  Authorization Code + PKCE flow, and validates it end to end.

### Orchestration and tooling

- **One-command full stack.** `docker compose up -d --build` runs all three
  services. Health checks plus `depends_on: condition: service_healthy` give a
  deterministic startup order: Keycloak and the backend are healthy before the
  frontend starts.
- **Helper scripts.** `scripts/auth-code-flow.mjs` runs the Authorization Code +
  PKCE flow against Keycloak and prints the decoded token; `scripts/e2e-login.mjs`
  is a headless smoke test of the whole login-to-`/hello` flow.

### Documentation

- Product requirements (`PRD.md`), implementation plan (`PLAN.md`), and a
  `README.md` with a quick start, prerequisites (including the `/etc/hosts`
  entry), test credentials, per-service verification, and troubleshooting.
