# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A proof-of-concept OAuth2/OIDC integration: a Next.js frontend logs in through
Keycloak and calls a protected Spring Boot endpoint that validates the JWT. See
`PRD.md` (requirements) and `PLAN.md` (build order, all four steps done).

Iteration 2 added **step-up authentication**: an elevated `GET /server-details`
endpoint that requires `acr=pro` (a TOTP second factor on top of the base login),
with an RFC 9470 challenge driving a transparent re-auth in the frontend. See
`PRD-2.md` / `PLAN-2.md` (all four steps done).

Iteration 3 added **DPoP sender-constrained access tokens** (RFC 9449): Keycloak
26.6 binds the access token to a per-session ES256 key (`cnf.jkt`), the backend
validates a DPoP proof on every resource call, and the browser reaches the backend
only through a same-origin BFF proxy that signs the proof server-side (the token
and key never leave the Next.js tier). See `PRD-3.md` / `PLAN-3.md` (all four steps
done).

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
docker compose up -d --build         # Keycloak + backend + frontend, health-gated startup
node scripts/e2e-login.mjs           # DPoP login -> /hello 200 + negatives (no-proof/wrong-key/Bearer/replay = 401)
node scripts/e2e-stepup.mjs          # step-up: OTP -> acr=pro + cnf.jkt -> /server-details 200 (testuser)
node scripts/e2e-stepup-denied.mjs   # negative: basicuser (no factor) denied at acr=pro
node scripts/e2e-stepup-bruteforce.mjs  # brute-force locks the OTP factor (bruteuser)
node scripts/e2e-stepup-refresh.mjs  # refresh keeps acr=pro and a stable cnf.jkt binding
node scripts/dpop-bff-verify.mjs     # browser path: login -> BFF proxy -> /hello, no token in browser
node scripts/totp.mjs                # current TOTP code for the step-up seed
docker compose down                  # stop (realm re-imports on next up)
```

Every e2e script above drives the real DPoP flow (obtains a `cnf.jkt`-bound token
and calls the backend under the `DPoP` scheme with a fresh proof); `e2e-login`
additionally asserts the leaked-token negatives, and `dpop-bff-verify` covers the
same-origin BFF proxy path the browser actually uses.

## Before committing

Not enforced by a hook (the e2e needs the full Docker stack healthy, so a hard
pre-commit gate would be flaky); treated as a required manual checklist instead:

1. **Run the security-reviewer subagent** over the pending diff (it is read-only
   and reports findings by severity). Especially required when the change touches
   auth, tokens, the Keycloak realm/flows, secrets, or CORS.
2. **Run the e2e suite green** against a running stack: `e2e-login.mjs`,
   `e2e-stepup.mjs`, `e2e-stepup-denied.mjs`, `e2e-stepup-bruteforce.mjs`, and
   `e2e-stepup-refresh.mjs` must all print `E2E PASSED`, and
   `cd backend && ./gradlew test` must pass. If the realm changed, re-import first
   (`docker compose up -d keycloak --force-recreate`) so the checks run against the
   committed file, not stale in-memory state.

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
  build time (one source of truth, no duplicate). The step-up tests mirror this
  (`ServerDetailsControllerTest` / `ServerDetailsControllerIntegrationTest`, the
  latter completing a real OTP to obtain a `pro` token).
- **Step-up (`acr=pro`) enforcement.** A custom Keycloak `browser-stepup` flow
  runs TOTP only when `acr=pro` is requested (LoA-2 condition with `max age 0`, so
  it always re-challenges); `acr` rides on the access token via the built-in `acr`
  client scope. The backend maps `acr` to an `ACR_<value>` authority and gates
  `/server-details` on `ACR_pro` (required level is `app.security.stepup.acr`, not
  hardcoded). A base token gets an RFC 9470 `401`
  (`insufficient_user_authentication`, `acr_values="pro"`) via
  `StepUpAccessDeniedHandler`, not a bare `403`; `WWW-Authenticate` is CORS-exposed
  so the browser can read it. `session.acr` in the frontend is a UI hint only;
  enforcement is server-side. The realm also disables self-service TOTP enrollment
  (`CONFIGURE_TOTP` off) and enables brute-force protection, since the OTP now
  gates the elevated level. Seed users: `testuser` (password + dev TOTP),
  `basicuser` (password only), `bruteuser` (for the brute-force test).
- **DPoP (`cnf.jkt`) sender-constraint.** Keycloak 26.6 (DPoP GA, no preview flag)
  binds the access token to a per-session ES256 key via the `nextjs-frontend`
  client attribute `dpop.bound.access.tokens=true`; the token carries `cnf.jkt` =
  the JWK thumbprint. The **same key signs both proof sites**: the token-endpoint
  proof (`htm=POST`, `htu`=token endpoint, no `ath`) and every resource proof
  (`htm`/`htu` of the backend call + `ath`=SHA-256 of the access token). Spring
  Security 7 **auto-enables** DPoP proof validation once `DPoPProofJwtDecoderFactory`
  is on the classpath (checks signature, `htm`/`htu`, `iat` window, `jti` replay via
  a built-in cache, `ath`, and the `cnf.jkt` match), decoding through the *same* JWT
  manager so the audience + acr checks still apply. A `cnf`-bound token can't be
  downgraded: the framework's `BearerTokenAuthenticationFilter` refuses it under
  `Bearer` (RFC 9449 §7.1), and `DpopBoundTokenValidator` refuses any token *lacking*
  `cnf.jkt` under any scheme, so the guarantee doesn't rest on the Keycloak toggle
  alone. The key lives **only in the Next.js server tier** (an in-memory key store
  keyed by an opaque ref that rides in the JWE cookie, never the raw key; see
  `frontend/src/lib/dpop.ts`, `dpopKeyStore.ts`, `bffProxy.ts`); the browser holds
  neither token nor key and reaches the backend only through the same-origin
  `/api/backend/*` BFF proxy, which signs the proof and relays the RFC 9470 step-up
  `401` unchanged. Nonces are handled reactively (retry once on `use_dpop_nonce`) but
  not mandated. Confidential-client nuance: the refresh-token grant still needs a
  proof so the refreshed access token keeps a stable `cnf.jkt`. The e2e scripts
  (`scripts/lib/dpop.mjs` + `node:crypto`) and the backend tests (`DpopProofs`,
  `KeycloakAuthCodeClient`) exercise all of this, including the leaked-token negatives.
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
