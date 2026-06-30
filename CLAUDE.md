# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A proof-of-concept OAuth2/OIDC integration: a Next.js frontend logs in through
Keycloak and calls a protected Spring Boot endpoint that validates the JWT. See
`PRD.md` (requirements) and `PLAN.md` (build order, all four steps done).

## Commands

Backend (`backend/`, Spring Boot 4 / Java 25 / Gradle wrapper):

```bash
cd backend
./gradlew test                                   # all tests (integration test needs Docker)
./gradlew test --tests HelloControllerTest       # the mocked slice test only (no Docker)
./gradlew test --tests HelloControllerIntegrationTest   # Testcontainers Keycloak
./gradlew bootJar                                # build the jar
```

Frontend (`frontend/`, Next.js 16 / next-auth v4 / Tailwind):

```bash
cd frontend
npm install --legacy-peer-deps   # next-auth v4 predates React 19 peer ranges; this flag is required
npm run dev                      # http://localhost:3000 (needs keycloak + backend up)
npm run build                    # production build (standalone output)
npm run lint                     # eslint (flat config)
```

Full stack and end-to-end check:

```bash
docker compose up -d --build     # Keycloak + backend + frontend, health-gated startup
node scripts/e2e-login.mjs       # headless login -> session -> /hello smoke test
docker compose down              # stop (realm re-imports on next up)
```

## Architecture and non-obvious decisions

- **Single token issuer / the `/etc/hosts` trick.** The issuer is fixed to
  `http://keycloak:8081/realms/web` (`KC_HOSTNAME`) so the `iss` claim is
  identical whether validated by the backend (reaches Keycloak by Docker service
  name) or used by the browser. The browser only resolves that hostname if the
  developer adds `127.0.0.1 keycloak` to `/etc/hosts`. This is the most common
  failure point; do not "simplify" the issuer to `localhost`.
- **Confidential client + PKCE.** `nextjs-frontend` is a confidential client;
  next-auth runs the Authorization Code + PKCE flow server-side so the secret
  never reaches the browser. `directAccessGrantsEnabled` is off (no password
  grant). Keep it confidential unless intentionally switching to a public SPA model.
- **Token handling.** The access token lives in the next-auth session (in memory,
  not localStorage) and is refreshed by a callback when the 5-minute token expires.
- **Two backend test layers.** `HelloControllerTest` is a `@WebMvcTest` slice with
  a mocked `JwtDecoder` (fast, no Docker). `HelloControllerIntegrationTest` boots a
  real Keycloak via Testcontainers and runs the real auth-code flow
  (`KeycloakAuthCodeClient`). The realm file is copied onto the test classpath at
  build time (one source of truth, no duplicate).
- **Gradle version catalog.** Dependency/plugin versions live in
  `backend/gradle/libs.versions.toml`; Spring artifacts are versionless (managed by
  the Boot BOM).

## Conventions

- **Dev secrets are committed on purpose.** `.env`, `frontend/.env.local`, the
  realm client secret, and `NEXTAUTH_SECRET` are placeholder dev-only values, kept
  in the repo for one-command reproducibility (PRD NFR-4). They are clearly marked
  not-for-production; do not treat them as leaked credentials, but never use them
  anywhere real.
- **Single root `.gitignore`.** No per-directory `.gitignore` files; scaffolders
  (create-next-app) generate them, consolidate into the root one.
- **README tracks implementation.** Each build step updates `README.md` so it
  documents only what exists.

## Version gotchas (this stack is newer than most training data)

- **Spring Boot 4** moved test-slice annotations: `@WebMvcTest` /
  `@AutoConfigureMockMvc` are now in `org.springframework.boot.webmvc.test.autoconfigure`
  (add `spring-boot-starter-webmvc-test`). Use `@MockitoBean`, not `@MockBean`.
- **Testcontainers 2.0** renamed artifacts (`org.testcontainers:testcontainers-junit-jupiter`).
  The Keycloak module must be on the 4.x line (`com.github.dasniko:testcontainers-keycloak`).
- **Next.js 16**: Turbopack by default, async request APIs, route-handler `params`
  are Promises. Check `frontend/node_modules/next/dist/docs/` for the bundled docs.
