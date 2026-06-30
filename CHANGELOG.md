# Changelog

All notable changes to this proof of concept are documented here.
This project is in active development; sections are added as each step lands.

## [Unreleased]

### Added (Step 2: Backend API)

- **Protected `GET /hello` endpoint.** A Spring Boot 4 (Java 25) service that
  greets the logged-in user (`Hello World, <username>`), reading the name from
  the validated token. Run it with `docker compose up -d backend`.
- **Real token validation.** The backend verifies each request's JWT against
  Keycloak (signature, issuer, expiry). Requests with no token, or an invalid or
  expired one, are rejected with `401`. The Next.js origin is allowed through CORS
  so the browser can call it in Step 3.
- **Automated tests.** JUnit 6 controller tests cover the unauthorized (`401`)
  and authorized (`200` + greeting) cases. A Testcontainers integration test also
  spins up a real Keycloak, imports the same realm, and validates a real signed
  token end to end.

### Added (Step 1: Keycloak)

- **One-command identity provider.** `docker compose up -d keycloak` starts
  Keycloak 26 with the `web` realm auto-imported: an OIDC client for the
  frontend, 5-minute access tokens, refresh tokens, and a ready-to-use seed
  login (`testuser` / `password`). No manual realm setup.
- **Consistent token issuer.** Keycloak is fixed to a single issuer
  (`http://keycloak:8081/realms/web`) reachable identically by the browser and
  the backend, so token validation works the same everywhere.
- **Authorization Code + PKCE demo.** `node scripts/auth-code-flow.mjs` runs the
  real login flow end to end (the same one the app will use): it captures the
  authorization code on the client's redirect URI and exchanges it for tokens,
  then prints the decoded claims. Handy for trying the flow before the frontend
  exists.

### Documentation

- Added the product requirements (`PRD.md`) and the step-by-step implementation
  plan (`PLAN.md`), updated to the chosen stack: Spring Boot 4, Java 25, Lombok,
  JUnit 6 tests, and a Next.js + Tailwind frontend.
- Added a `README.md` with prerequisites, run and verify instructions, and the
  test credentials.

### Not yet available

- The Next.js login UI (Step 3) is planned but not implemented yet.
