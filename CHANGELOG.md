# Changelog

All notable changes to this proof of concept are documented here.
This project is in active development; sections are added as each step lands.

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
