# PLAN: Next.js + Spring Boot + Keycloak OAuth2 POC

**Status:** Draft, for review
**Companion to:** [PRD.md](PRD.md)
**Date:** 2026-06-19

This plan turns the approved PRD into a concrete, ordered implementation guide.
It reflects the resolved decisions: **Gradle 9**, **Spring Boot 3.5.x / Java 25**,
**NextAuth.js (next-auth)** with a confidential Keycloak client, **Keycloak 26**
in dev mode, issuer standardized on the **`keycloak`** container hostname, ports
**3000 / 8080 / 8081**.

> No code is written yet. This document defines *what* will be built and *in what
> order*. Implementation begins only after this plan is approved.

---

## 1. Proposed repository layout

```
nextjs-springboot-keycloak-poc/
├── PRD.md
├── PLAN.md
├── README.md                      # run instructions + test creds (written last)
├── docker-compose.yml
├── .env                           # shared compose vars (ports, secrets, issuer)
├── keycloak/
│   └── realm-export.json          # "web" realm, imported on startup
├── backend/                       # Spring Boot (Java 25, Gradle 9)
│   ├── build.gradle
│   ├── settings.gradle
│   ├── gradle/wrapper/...          # Gradle 9 wrapper
│   ├── Dockerfile
│   └── src/main/java/com/poc/backend/
│       ├── BackendApplication.java
│       ├── config/SecurityConfig.java
│       └── web/HelloController.java
│   └── src/main/resources/application.yml
└── frontend/                      # Next.js (latest, App Router) + next-auth
    ├── package.json
    ├── next.config.ts
    ├── Dockerfile
    ├── .env.local                 # NEXTAUTH_URL, client id/secret, issuer, api url
    └── src/app/
        ├── page.tsx               # home page (login button OR hello result)
        ├── layout.tsx
        └── api/auth/[...nextauth]/route.ts   # NextAuth handler (Keycloak provider)
```

---

## 2. The issuer / hostname strategy (the critical detail)

This is the part that most commonly breaks. The token's `iss` claim must be
**identical** whether validated by the backend or used by the browser, and the
URL must be reachable by both.

**Approach:** make Keycloak reachable at `http://keycloak:8081` from *both*
sides.

- Keycloak runs on internal HTTP port **8081** (`KC_HTTP_PORT=8081`) and is
  published to the host as **8081** (`8081:8081`).
- `KC_HOSTNAME=http://keycloak:8081` and `KC_HOSTNAME_STRICT=false` so the
  issuer in tokens is `http://keycloak:8081/realms/web`.
- **Backend** (in a container) reaches it over the Docker network via the
  service name `keycloak` → works natively.
- **Browser** (on the host) reaches it only if `keycloak` resolves. The
  developer adds one line to `/etc/hosts`:
  ```
  127.0.0.1 keycloak
  ```
  Then `http://keycloak:8081` in the browser hits the published port. README
  will call this out as a required one-time setup step.

This keeps a single consistent issuer (`http://keycloak:8081/realms/web`) for
discovery, JWKS, browser redirects, and token validation.

---

## 3. Build order (incremental, each step verifiable)

### Step 1: Keycloak realm + Docker Compose skeleton

**Goal:** Keycloak 26 boots with the `web` realm pre-imported.

- Author `keycloak/realm-export.json` containing:
  - Realm `web`, enabled.
  - **Access token lifespan = 300s (5 min)** (`accessTokenLifespan`).
  - Refresh tokens enabled (default SSO session settings; documented).
  - **Client** `nextjs-frontend`:
    - Confidential (`publicClient: false`, `clientAuthenticatorType: client-secret`),
      with a fixed dev secret.
    - Standard flow enabled (Authorization Code).
    - `redirectUris`: `http://localhost:3000/api/auth/callback/keycloak`
    - `webOrigins`: `http://localhost:3000`
    - `post.logout.redirect.uris`: `http://localhost:3000`
  - **Seed user** `testuser` / password `password` (documented in README),
    email verified, enabled.
- Author `docker-compose.yml` with the `keycloak` service:
  - Image `quay.io/keycloak/keycloak:26.x`
  - Command `start-dev --import-realm`
  - Mount `./keycloak/realm-export.json` → `/opt/keycloak/data/import/realm-export.json`
  - Env: `KC_BOOTSTRAP_ADMIN_USERNAME/PASSWORD`, `KC_HTTP_PORT=8081`,
    `KC_HOSTNAME=http://keycloak:8081`, `KC_HOSTNAME_STRICT=false`
  - Ports `8081:8081`, plus a healthcheck on the realm endpoint.

**Verify:** `docker compose up keycloak` → admin console at
`http://localhost:8081`, realm `web` present with the client, 5-min token
lifespan, and seed user.

### Step 2: Spring Boot backend (resource server)

**Goal:** `GET /hello` protected by JWT validated against Keycloak.

- Generate Gradle 9 project (`build.gradle`, wrapper) targeting **Java 25**,
  **Spring Boot 3.5.x**. Dependencies:
  `spring-boot-starter-web`, `spring-boot-starter-oauth2-resource-server`.
- `application.yml`:
  ```yaml
  spring:
    security:
      oauth2:
        resourceserver:
          jwt:
            issuer-uri: http://keycloak:8081/realms/web
  ```
- `SecurityConfig.java`: `SecurityFilterChain` requiring authentication for
  `/hello`, enabling `oauth2ResourceServer().jwt()`, and a CORS config allowing
  `http://localhost:3000`.
- `HelloController.java`: `GET /hello` returns
  `"Hello World, <preferred_username>"` read from the JWT (`@AuthenticationPrincipal Jwt`).
- `Dockerfile` (multi-stage: Gradle build → JRE 25 runtime).
- Add `backend` service to compose: build context `./backend`, port `8080:8080`,
  `depends_on` keycloak (healthy), on the shared network.

**Verify:**
- `GET /hello` with no token → `401`.
- Obtain a token via Keycloak token endpoint (curl, direct grant or the seed
  user) → `GET /hello` with `Authorization: Bearer <token>` → `200` + greeting.

### Step 3: Next.js frontend with NextAuth

**Goal:** Home page → Login → Keycloak → back → auto-call `/hello`.

> **Reference:** [Keycloak Auth on Next.js 13.4 using NextAuth](https://dev.to/farisdurrani/keycloak-auth-on-nextjs-134-using-nextauth-57e0)
> confirms our baseline: `next-auth ^4.x` + `KeycloakProvider({ clientId,
> clientSecret, issuer })`, issuer = `${URL}/realms/${realm}`, route handler at
> `app/api/auth/[...nextauth]/route.ts` exporting `{ handler as GET, handler as
> POST }`, and a confidential client ("Client authentication" enabled). It does
> **not** cover surfacing the access token or token refresh, the two pieces our
> POC adds below (5-min token → refresh is mandatory).

- Scaffold latest Next.js (App Router, TypeScript).
- Install `next-auth` (v4, https://next-auth.js.org/) and configure the
  **Keycloak provider** in `src/app/api/auth/[...nextauth]/route.ts`:
  - `clientId: nextjs-frontend`, `clientSecret`, `issuer: http://keycloak:8081/realms/web`.
  - `jwt`/`session` callbacks to surface the **access token** into the session
    (held in the NextAuth session, used in-memory client-side; not written to
    localStorage).
  - Token-refresh callback using the refresh token when the 5-min access token
    expires.
- `src/app/page.tsx` (client component):
  - If unauthenticated → dummy home page + single **Login** button
    (`signIn("keycloak")`).
  - If authenticated → call `GET http://localhost:8080/hello` with the access
    token as a Bearer header and render the response; show a **Logout** button.
- `.env.local`: `NEXTAUTH_URL=http://localhost:3000`, `NEXTAUTH_SECRET`,
  `KEYCLOAK_CLIENT_ID/SECRET`, `KEYCLOAK_ISSUER=http://keycloak:8081/realms/web`,
  `NEXT_PUBLIC_API_URL=http://localhost:8080`.
- `Dockerfile` for Next.js; add `frontend` service to compose, port `3000:3000`,
  `depends_on` backend + keycloak.

**Verify (full E2E):** `http://localhost:3000` → Login → Keycloak login
(`testuser`/`password`) → redirected back → page shows
"Hello World, testuser" fetched from the backend.

### Step 4: Orchestration polish + README

- Healthchecks and `depends_on: condition: service_healthy` so startup ordering
  is deterministic.
- Single `.env` for shared compose values (ports, client secret, issuer).
- `README.md`: prerequisites (Docker, the `/etc/hosts` entry), `docker compose up`,
  test-user credentials, the URLs, and a troubleshooting note on the issuer/hosts
  requirement.

**Verify:** From a clean state, `docker compose up` brings the whole stack to the
passing E2E flow with no manual steps beyond the one-time `/etc/hosts` entry.

---

## 4. Acceptance mapping

Each PRD §7 acceptance criterion is covered by:

| PRD criterion                                  | Covered in |
|------------------------------------------------|------------|
| 1. `docker compose up` starts everything       | Step 4     |
| 2. `web` realm imported (client, 5-min, user)  | Step 1     |
| 3. Home page with Login button                 | Step 3     |
| 4. Login redirects to Keycloak                 | Step 3     |
| 5. Redirect back, session established          | Step 3     |
| 6. Auto-call `/hello`, show greeting           | Step 3     |
| 7. `/hello` without token → 401                | Step 2     |
| 8. `/hello` with invalid/expired token → 401   | Step 2     |

---

## 5. Risks / watch-items

- **Issuer mismatch**: mitigated by §2; the `/etc/hosts` entry is mandatory and
  must be documented prominently.
- **Keycloak 26 hostname options**: v26 changed hostname config; the exact env
  var set (`KC_HOSTNAME`, `KC_HOSTNAME_STRICT`) will be validated against the
  26.x docs during Step 1.
- **NextAuth token refresh**: the 5-min access token will expire during a
  session; the refresh-token callback must be implemented and tested, not just
  the happy-path login.
- **CORS**: backend must allow the `http://localhost:3000` origin and the
  `Authorization` header, or the browser fetch to `/hello` will fail.
- **Java 25 + Spring Boot compatibility**: confirm the chosen Spring Boot 3.5.x
  patch officially supports Java 25 at build time.

---

## 6. Deliverables checklist

- [ ] `keycloak/realm-export.json` (`web` realm, client, 5-min token, seed user)
- [ ] `docker-compose.yml` + `.env`
- [ ] `backend/` Spring Boot resource server (`GET /hello`)
- [ ] `frontend/` Next.js + next-auth (home/login + hello call)
- [ ] `README.md` (run instructions, creds, `/etc/hosts` note)

---

## 7. Next step

On approval of this plan, implementation proceeds **Step 1 → Step 4**, verifying
at each step before moving on.
