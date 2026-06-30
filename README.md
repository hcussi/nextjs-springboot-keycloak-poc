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

## Status

🚧 **Planning complete, implementation in progress.** The repository currently
contains the planning documents (`PRD.md`, `PLAN.md`). Application code (Keycloak
realm, backend, frontend, Docker Compose) is being built per `PLAN.md`, Step 1 → Step 4.

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

| Component | Technology                     | Host port | Role                          |
|-----------|--------------------------------|-----------|-------------------------------|
| Frontend  | Next.js (latest) + next-auth   | 3000      | UI, initiates OIDC login      |
| Backend   | Spring Boot (Java 25, Gradle 9)| 8080      | Protected REST resource server|
| Keycloak  | Keycloak 26 (dev mode)         | 8081      | OIDC authorization server     |

## Prerequisites

- **Docker** and **Docker Compose**.
- **A `/etc/hosts` entry** (one-time, required). The JWT issuer is standardized on
  the `keycloak` container hostname so the `iss` claim is identical for the browser
  and the backend. The browser must resolve that hostname to localhost:

  ```
  127.0.0.1 keycloak
  ```

  Without this line the browser cannot reach Keycloak at `http://keycloak:8081`
  and login will fail. This is the single most common point of failure.

## Running the stack

From a clean checkout (once implementation is complete):

```bash
docker compose up
```

This starts all three services. Healthchecks ensure Keycloak is ready (realm
imported) before the backend and frontend come up.

Then open **http://localhost:3000**, click **Login**, and authenticate with the
seed user below. After login the app automatically calls `GET /hello` and displays
the greeting.

### URLs

| Service             | URL                          |
|---------------------|------------------------------|
| Frontend            | http://localhost:3000        |
| Backend `/hello`    | http://localhost:8080/hello  |
| Keycloak admin      | http://localhost:8081        |

### Test credentials (dev-only)

| What            | Value      |
|-----------------|------------|
| Realm           | `web`      |
| Seed user       | `testuser` |
| Seed password   | `password` |

Keycloak admin credentials are configured via Docker Compose environment variables.

## How it works

- **Issuer / hostname strategy**: Keycloak listens on `8081` internally and is
  published as `8081`. The issuer is `http://keycloak:8081/realms/web`. The backend
  reaches it over the Docker network by service name; the browser reaches the same
  hostname via the `/etc/hosts` entry above. A single consistent issuer is used for
  discovery, JWKS, browser redirects, and token validation.
- **Access tokens are short-lived (5 minutes)** and refresh tokens are enabled, so
  the frontend refreshes the session via NextAuth rather than forcing re-login.
- **The access token is held in memory** (not persisted to localStorage) and sent as
  a `Bearer` token to the backend.
- **The backend** runs as a Spring Security OAuth2 Resource Server: `GET /hello`
  requires a valid JWT. Requests without a token (or with an expired/invalid token)
  receive `401 Unauthorized`. CORS permits the `http://localhost:3000` origin and the
  `Authorization` header.

## Troubleshooting

- **Login redirect fails / Keycloak unreachable in the browser** → confirm the
  `127.0.0.1 keycloak` line is in `/etc/hosts`.
- **`/hello` returns 401 after login** → the access token may have expired (5-minute
  lifetime); confirm the NextAuth refresh flow is working.
- **Browser fetch to `/hello` blocked by CORS** → the backend must allow the
  `http://localhost:3000` origin and the `Authorization` header.

## License

Proof of concept, not licensed for production use.
