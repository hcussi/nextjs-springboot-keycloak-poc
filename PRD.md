# PRD: Next.js + Spring Boot + Keycloak OAuth2 Integration (Proof of Concept)

**Status:** Draft, for review
**Author:** hcussi@gmail.com
**Date:** 2026-06-19
**Type:** Proof of Concept (POC)

---

## 1. Overview

This project is a **proof of concept** demonstrating an end-to-end OAuth2 /
OpenID Connect (OIDC) authentication and authorization flow across three
applications wired together with Docker Compose:

1. **Frontend**: a Next.js application (latest version) that provides the
   user-facing UI and initiates the login flow.
2. **Backend**: a Spring Boot application (Java 25) that exposes a single
   protected REST endpoint.
3. **Identity Provider**: Keycloak 26, acting as the OAuth2 / OIDC
   authorization server that authenticates users and issues JWT tokens.

The goal is to validate the full loop: a user logs in through Keycloak from
the Next.js app, receives a JWT access token, and uses that token to call a
protected Spring Boot endpoint, which validates the token against Keycloak.

This is **not** a production system. The objective is to prove the integration
pattern works and to serve as a reference template.

---

## 2. Goals

- Demonstrate a working OIDC Authorization Code flow between a Next.js SPA and
  Keycloak.
- Demonstrate JWT-based protection of a Spring Boot REST endpoint using Spring
  Security as an OAuth2 Resource Server.
- Demonstrate that the Spring Boot backend validates JWT access tokens against
  Keycloak (signature, issuer, expiry).
- Demonstrate a fully reproducible, one-command local environment via Docker
  Compose, including a pre-configured Keycloak realm imported on startup.

### Non-Goals

- Production-grade security hardening (TLS everywhere, secret management, etc.).
- Persistent databases for the apps (only what Keycloak needs).
- Role-based / fine-grained authorization beyond "authenticated user".
- User self-registration, account management, password reset flows.
- Multi-environment deployment (staging / prod), CI/CD pipelines.

---

## 3. Architecture

### 3.1 Components

| Component  | Technology                        | Port (host) | Role                              |
|------------|-----------------------------------|-------------|-----------------------------------|
| Frontend   | Next.js (latest) + NextAuth.js    | 3000        | UI, initiates OIDC login          |
| Backend    | Spring Boot (Java 25)             | 8080        | Protected REST API (resource srv) |
| Keycloak   | Keycloak 26                       | 8081        | OIDC Authorization Server          |

### 3.2 High-level flow

```
  ┌──────────────┐      1. Click "Login"        ┌──────────────┐
  │              │ ───────────────────────────► │              │
  │   Next.js    │   2. Redirect to Keycloak    │   Keycloak   │
  │  (frontend)  │ ◄─────────────────────────── │   (realm:    │
  │              │   3. User authenticates       │    "web")    │
  │              │   4. Auth code → tokens (JWT) │              │
  └──────┬───────┘ ◄─────────────────────────── └──────────────┘
         │
         │  5. Call /hello with Bearer JWT (token held in memory)
         ▼
  ┌──────────────┐   6. Validate JWT signature  ┌──────────────┐
  │ Spring Boot  │      & claims against         │   Keycloak   │
  │  (backend)   │ ───── JWKS / issuer ────────► │   (JWKS)     │
  │ resource srv │ ◄──────────────────────────── │              │
  └──────────────┘   7. 200 OK "Hello World"     └──────────────┘
```

### 3.3 Network (Docker Compose)

All three services run on a shared Docker Compose network so they can resolve
each other by service name. A key consideration (see Open Questions) is the
**issuer URL mismatch**: the browser reaches Keycloak via `localhost:8081`,
while the backend container reaches it via the internal service hostname
(e.g. `http://keycloak:8080`). The realm/issuer configuration must be
consistent so token validation succeeds. The POC will standardize on a single
issuer URL reachable by both, using a hostname strategy documented in the plan.

---

## 4. Functional Requirements

### 4.1 Keycloak (Identity Provider)

- **FR-K1:** Run Keycloak 26 via Docker Compose.
- **FR-K2:** Import a realm named **`web`** automatically on container startup
  from a `realm-export.json` file mounted into the container.
- **FR-K3:** The `web` realm contains an OIDC **client** for the frontend
  application configured for the Authorization Code flow (public or
  confidential, see Open Questions; NextAuth typically uses a confidential
  client with a secret).
- **FR-K4:** The client is configured with a **valid redirect URI** pointing
  back to the Next.js application's NextAuth callback
  (e.g. `http://localhost:3000/api/auth/callback/keycloak`).
- **FR-K5:** Keycloak issues **JWT access tokens** for the realm.
- **FR-K6:** **Access token lifetime = 5 minutes.**
- **FR-K7:** **Refresh tokens are enabled** so the session can be refreshed
  without re-authenticating.
- **FR-K8:** At least one **seed test user** exists in the realm (credentials
  documented in the README) so the flow can be exercised immediately.

### 4.2 Backend (Spring Boot, Java 25)

- **FR-B1:** Spring Boot application built and run on **Java 25**.
- **FR-B2:** Expose a single endpoint **`GET /hello`** (the "Hello World"
  endpoint) returning a simple greeting payload.
- **FR-B3:** The endpoint is **protected**: it requires a valid OAuth2 JWT
  Bearer access token. Unauthenticated requests receive `401 Unauthorized`.
- **FR-B4:** Configure **Spring Security as an OAuth2 Resource Server** that
  validates JWTs against Keycloak using the realm's issuer URI / JWKS endpoint
  (signature, issuer, expiry validation).
- **FR-B5:** The endpoint may echo a claim from the token (e.g. `preferred_username`)
  to visibly prove the token was decoded, e.g. `"Hello World, <username>"`.
- **FR-B6:** CORS configured to allow the Next.js origin (`http://localhost:3000`)
  to call the API from the browser.

### 4.3 Frontend (Next.js, latest)

- **FR-F1:** Built on the **latest Next.js** version (App Router).
- **FR-F2:** A **Home page** rendered when the user is not authenticated,
  showing dummy/placeholder content and a single **Login** button only.
- **FR-F3:** Clicking **Login** redirects the user to **Keycloak** to
  authenticate (OIDC Authorization Code flow).
- **FR-F4:** Use the **NextAuth.js (Auth.js)** library with the **Keycloak
  provider** to manage the OIDC flow and the session.
- **FR-F5:** After successful authentication, the user is **redirected back**
  to the Next.js application and the session (including the JWT access token)
  is established.
- **FR-F6:** The **JWT access token is held in memory** (not persisted to
  localStorage) and used as a Bearer token to call the backend.
- **FR-F7:** After login completes, the app **calls the backend `GET /hello`
  endpoint** with the access token and displays the response on screen.
- **FR-F8:** A **Logout** action ends the session (and, ideally, the Keycloak
  SSO session).

### 4.4 Integration / Orchestration

- **FR-I1:** A single **`docker-compose.yml`** brings up all three services
  (frontend, backend, Keycloak) plus any dependency Keycloak needs.
- **FR-I2:** Service startup ordering / health checks ensure Keycloak is ready
  (realm imported) before the backend and frontend depend on it.
- **FR-I3:** All configuration (issuer URLs, client IDs/secrets, ports) is
  provided via environment variables / compose config so the stack is
  reproducible with `docker compose up`.

---

## 5. Non-Functional Requirements

- **NFR-1 (Reproducibility):** `docker compose up` from a clean checkout brings
  the entire stack to a working state with the `web` realm pre-configured.
- **NFR-2 (Documentation):** A README documents how to run the stack, the test
  user credentials, and how to exercise the flow.
- **NFR-3 (Simplicity):** Favor the smallest configuration that demonstrates the
  pattern; avoid unnecessary abstractions.
- **NFR-4 (Security posture for a POC):** Secrets are local/dev-only and clearly
  marked as not for production. Tokens are not logged.

---

## 6. Technology Stack (proposed)

| Layer        | Choice                                                        |
|--------------|---------------------------------------------------------------|
| Frontend     | Next.js (latest, App Router), React, NextAuth.js v5 (Auth.js) |
| Backend      | Spring Boot 3.5.x (latest supporting Java 25), Spring Security |
| Build (Java) | **Gradle 9**                                                  |
| Language     | Java 25 (backend), TypeScript (frontend)                      |
| Identity     | Keycloak 26                                                   |
| Orchestration| Docker Compose                                               |
| Keycloak DB  | **Dev mode** (`start-dev`, in-memory), no external DB        |

---

## 7. Acceptance Criteria

The POC is considered successful when:

1. `docker compose up` starts all three services with no manual steps.
2. Keycloak starts with the **`web`** realm already imported (visible in the
   admin console), with a configured client, 5-minute access token lifetime,
   refresh tokens enabled, and a seed user.
3. Visiting `http://localhost:3000` shows the **home page with a Login button**.
4. Clicking **Login** redirects to the Keycloak login screen.
5. After logging in with the seed user, the browser is **redirected back** to
   the Next.js app and a session is established.
6. The app **automatically calls `GET /hello`** with the JWT and displays the
   greeting (including the username claim).
7. Calling `GET /hello` **without** a token returns `401`.
8. Calling `GET /hello` with an **expired/invalid** token returns `401`.

---

## 8. Resolved Decisions (reviewed 2026-06-19)

1. **Build tool / version**: ✅ **Gradle 9** ("Gravel nine"), with **Spring
   Boot 3.5.x** (latest GA line supporting Java 25).
2. **Keycloak client type**: ✅ Use **NextAuth.js** (https://next-auth.js.org/)
   with its standard **confidential** Keycloak client (client secret held
   server-side in the Next.js route handler).
3. **Issuer URL strategy**: ✅ Standardize the issuer on the **`keycloak`
   container hostname**. Both the browser and the backend will resolve Keycloak
   at the same URL/port so the `iss` claim is consistent. Concretely: Keycloak
   listens on **8081** internally and is published as **8081**, the issuer is
   `http://keycloak:8081`, and the developer adds `127.0.0.1 keycloak` to
   `/etc/hosts` so the browser resolves the same hostname the backend uses over
   the Docker network. (Details in PLAN.md.)
4. **Keycloak persistence**: ✅ **Dev mode** (`start-dev`, in-memory). No
   external database.
5. **Ports**: ✅ Frontend `3000`, backend `8080`, Keycloak `8081` (host).
6. **Token usage**: Backend validates the **access token** (JWT) presented as
   the `Authorization: Bearer` credential for `/hello`.

---

## 9. Out of Scope (explicitly)

- Production TLS / certificates.
- Horizontal scaling, load balancing.
- Observability stack (metrics, tracing, centralized logging).
- Automated test suites beyond what's needed to prove the flow (may be added
  later if desired).

---

## 10. Next Step

Once this PRD is reviewed and approved (and the Open Questions in §8 are
answered), the next deliverable is **`PLAN.md`**, a step-by-step
implementation plan covering project scaffolding, Keycloak realm export,
Spring Security resource-server config, NextAuth/Keycloak wiring, and the
Docker Compose orchestration.

**No implementation will be done until the PRD and plan are approved.**
