# PLAN (Iteration 4): Distributed DPoP Replay Protection (Redis `jti`, `iat` window, nonce)

**Status:** Approved, in progress
**Companion to:** [PRD-4.md](PRD-4.md)
**Builds on:** [PLAN.md](PLAN.md) (iteration 1), [PLAN-2.md](PLAN-2.md) (iteration 2), and [PLAN-3.md](PLAN-3.md) (iteration 3, DPoP), all complete
**Date:** 2026-08-02

This plan turns approved **PRD-4** into an ordered, verifiable implementation guide,
in the same incremental style as the prior plans. It reflects the resolved decisions
(PRD-4 §8): **Redis** for distributed `jti` replay, a **configurable symmetric `iat`
window** (default 60s) that also bounds the Redis `jti` TTL, an **HMAC self-validating
DPoP nonce on `/server-details` only**, a **fail-closed** posture when Redis is down,
and a **two-instance** distributed-replay e2e.

---

## 1. Context and the gap being closed

Iteration 3 made access tokens DPoP-bound and let Spring Security auto-validate the
proof. Replay protection there is the framework's **in-memory, per-JVM** `jti` cache
(`DPoPProofJwtDecoderFactory$JtiClaimValidator`, a static `LinkedHashMap`), and the
`iat` check is the framework's fixed **60s** `JwtIssuedAtValidator` clock skew (which
primarily bounds *future*-dating). In a multi-instance deployment a captured proof can
be replayed once per instance (iteration-3 security review, finding I-1). This
iteration closes that with a distributed Redis `jti` check, a configurable symmetric
`iat` window, and a server-issued nonce on the elevated endpoint, without regressing
any iteration 1 to 3 behavior.

## 2. Design decision: one post-authentication filter

All three new checks live in **one post-authentication servlet filter**
(`DpopReplayProtectionFilter`, a `OncePerRequestFilter`) placed **before**
`AuthorizationFilter`. Rationale, grounded in inspecting Spring Security 7.0.6:

- The DPoP provider is auto-registered by a **package-private**
  `DPoPAuthenticationConfigurer` that constructs `new DPoPAuthenticationProvider(am)`
  and registers it directly. There is **no `ObjectPostProcessor` seam** on the
  provider and no bean lookup for a custom `DPoPProofJwtDecoderFactory`, so cleanly
  replacing the framework's verifier (its in-memory `jti` cache / `iat` validator) is
  not supported; only fragile provider-ordering would do it.
- The nonce challenge must emit a `DPoP-Nonce` **response** header, which a proof
  *verifier* cannot do (it has no `HttpServletResponse`). A filter is required
  regardless.
- Putting `iat` + `jti` + nonce together in one filter is cohesive and unit-testable.
  The framework's own `htm`/`htu`/`ath`/signature/`cnf` checks, its in-memory `jti`
  cache, and its future-skew `iat` all remain as **defense-in-depth**. Our symmetric
  window is authoritative for staleness; our Redis check is authoritative for
  cross-instance replay (the two-instance e2e proves the framework's per-JVM cache is
  not what decides).

The filter runs only for authenticated requests that carried a `DPoP` proof. It
re-reads the request's `DPoP` header and parses claims (`jti`/`iat`/`nonce`) — no
signature re-verification, since the framework already authenticated the request using
that exact proof.

## 3. Configuration surface (new)

Added to `backend/src/main/resources/application.yml`, following the existing
`${ENV:default}` convention, backed by a new
`@ConfigurationProperties("app.security.dpop")` record `DpopProperties` (the first such
class; cleaner than several `@Value` reads for a related group):

```yaml
spring:
  data:
    redis:
      host: ${REDIS_HOST:localhost}
      port: ${REDIS_PORT:6379}
app:
  security:
    dpop:
      iat-window-seconds: ${DPOP_IAT_WINDOW_SECONDS:60}   # symmetric; also the Redis jti TTL
      nonce:
        paths: ${DPOP_NONCE_PATHS:/server-details}        # comma-separated
        ttl-seconds: ${DPOP_NONCE_TTL_SECONDS:60}
        secret: ${DPOP_NONCE_SECRET:<dev placeholder, committed like the others>}
```

---

## Step 1 — Redis + second backend + config plumbing

**Goal:** the stack has Redis and a second backend instance sharing it; the backend
compiles against `spring-data-redis` and reads the new config. No behavior change yet.

- `backend/build.gradle` (+ `gradle/libs.versions.toml`): add
  `spring-boot-starter-data-redis` (versionless, managed by the Boot BOM, consistent
  with the other Spring starters).
- `backend/src/main/resources/application.yml`: add the `spring.data.redis.*` and
  `app.security.dpop.*` blocks above.
- New `com.poc.backend.config.DpopProperties` (`@ConfigurationProperties`):
  `iatWindowSeconds`, nested `nonce { paths (List<String>), ttlSeconds, secret }`.
- `docker-compose.yml`:
  - New `redis` service: `image: redis:7-alpine`, on `poc-net`, healthcheck
    `redis-cli ping` → `PONG` (same interval/retries pattern as the others).
  - `backend`: add `SPRING_DATA_REDIS_HOST: redis`, `SPRING_DATA_REDIS_PORT: 6379`,
    the new `DPOP_*` env, and `depends_on: redis: condition: service_healthy`.
  - New `backend-2` service: identical `build: ./backend`, same env, its own
    `container_name: poc-backend-2`, port `${BACKEND2_PORT}:8080`, same healthcheck,
    `depends_on` keycloak + redis healthy. Exists so the distributed-replay e2e can hit
    two real JVMs sharing one Redis. Frontend still points only at `backend` (LB is a
    PRD non-goal).
- `.env`: add `REDIS_PORT=6379`, `BACKEND2_PORT=8082`, and `DPOP_NONCE_SECRET=<dev
  placeholder>` under the existing dev-secret banner.

**Verify:** `docker compose up -d --build` brings up keycloak + redis + backend +
backend-2 + frontend, all healthy; existing `node scripts/e2e-login.mjs` still
`E2E PASSED` (no filter yet, so no behavior change).

## Step 2 — Redis `jti` replay + configurable symmetric `iat` window

**Goal:** every DPoP request's `jti` is single-use across instances (Redis), and a
proof outside the symmetric `iat` window is rejected; Redis-down fails closed.

- New `com.poc.backend.dpop.JtiReplayStore` interface (`boolean firstUse(String jti,
  Duration ttl)`), so the `@WebMvcTest` slice can supply an in-memory fake and the app
  uses Redis. Primary impl `RedisJtiReplayStore`:
  `stringRedisTemplate.opsForValue().setIfAbsent("dpop:jti:" + jti, "1", ttl)` →
  `Boolean.TRUE.equals(result)` is first use; `false` is a replay. **Fail closed:** any
  exception (Redis unreachable) is caught and surfaced as a "store unavailable" signal
  → the filter answers **503**, never silently allowing (FR-B20 / NFR-13). Uses
  `StringRedisTemplate` (auto-configured by the starter).
- New `com.poc.backend.dpop.DpopReplayProtectionFilter extends OncePerRequestFilter`:
  1. No `DPoP` request header or no authenticated principal → `chain` through
     (unauthenticated / non-DPoP requests handled downstream as today).
  2. Parse the proof payload claims only (`jti`, `iat`, `nonce`) via Nimbus
     `SignedJWT.parse(...).getJWTClaimsSet()` (already a transitive dep), no re-verify.
  3. **`iat` window:** reject if `|now - iat| > iatWindowSeconds` → `401`
     `invalid_dpop_proof`.
  4. **Redis `jti`:** `firstUse(jti, Duration.ofSeconds(iatWindowSeconds))`; `false` →
     `401` `invalid_dpop_proof` (replay); store-unavailable → `503`.
  5. (nonce added in Step 3.)
  - A small helper writes the `WWW-Authenticate: DPoP error="invalid_dpop_proof"` +
    JSON body, mirroring `StepUpAccessDeniedHandler`'s shape.
- `SecurityConfig.securityFilterChain`: `.addFilterBefore(dpopReplayProtectionFilter,
  AuthorizationFilter.class)`. Injected as a bean so Redis/props/nonce-service wire in.
  This placement guarantees the proof is already authenticated and runs **before** the
  `ACR_pro` authorization check.

**Test-slice note:** `HelloControllerTest` (`@WebMvcTest`) has no Redis. A
`@TestConfiguration` supplies an in-memory `JtiReplayStore` and a real
`DpopNonceService` so the filter loads; the existing mocked-`JwtDecoder` slice keeps
working.

**Verify:** existing `e2e-login.mjs` same-instance replay still `401`; `cd backend &&
./gradlew test` green.

## Step 3 — HMAC self-validating nonce on `/server-details`

**Goal:** `/server-details` requires a fresh server nonce (issued on challenge, echoed
in the proof); `/hello` never does; nonce precedes the step-up check.

- New `com.poc.backend.dpop.DpopNonceService` (PRD-4 §8.4 design), stateless HMAC:
  - `issue()`: `payload = random(16) || int64BE(now + ttlSeconds)`; `mac =
    HMAC-SHA256(secret, payload)`; `nonce = base64url(payload || mac)`.
  - `validate(nonce)`: base64url-decode, split, **constant-time** MAC compare
    (`MessageDigest.isEqual`), check expiry `> now`. Reusable within its lifetime
    (acceptable per §8.4 — the distributed `jti` cache + `iat` window still block
    whole-proof replay). No Redis (any instance verifies with the shared secret).
- `DpopReplayProtectionFilter`, after the `iat`/`jti` checks: if the request path is in
  `dpop.nonce.paths`, read the proof's `nonce` claim and `validate(...)`.
  Missing/expired/invalid → **`401`** with `DPoP-Nonce: <issue()>` **and**
  `WWW-Authenticate: DPoP error="use_dpop_nonce"`. Valid → continue. Because this runs
  before `AuthorizationFilter`, the nonce challenge precedes the RFC 9470 `acr`
  step-up challenge (FR-B19 / PRD-4 §3.3). `/hello` is not in the path set → never
  challenged, single round trip preserved (NFR-14).
- `SecurityConfig.corsConfigurationSource`: add `DPoP-Nonce` to `setExposedHeaders`
  (alongside `WWW-Authenticate`) and `DPoP` to `setAllowedHeaders`, for correctness
  (the browser reaches the backend via the same-origin BFF today, so this is
  belt-and-suspenders, but keeps the direct-call contract honest).

**Frontend (FR-F16):** no code change needed — `bffProxy.ts` / `dpopBackendFetch`
already retries once on `401` + `DPoP-Nonce` + `use_dpop_nonce` (PRD-3 FR-F15; the
comment there explicitly anticipates this iteration).

**Verify:** `/server-details` with a valid pro proof and no nonce → `401` +
`DPoP-Nonce` + `use_dpop_nonce`; retry with the nonce → `200`. `/hello` never returns
`use_dpop_nonce`.

## Step 4 — e2e coverage, backend tests, docs, release

**New headless e2e scripts** (copy the `cfg` + cookie-jar `go()` + `getCode()` /
`getProCode()` + `exchangeCode()` scaffolding from `e2e-login.mjs` / `e2e-stepup.mjs`;
reuse `scripts/lib/dpop.mjs`):

- `scripts/lib/dpop.mjs`: add an optional `iat` param to `signProof({..., iat})`
  (default now) so the window test can backdate a proof. Backward-compatible.
- `scripts/e2e-dpop-replay-distributed.mjs` (FR-I9a): obtain a bound token, build
  **one** `/hello` resource proof, call instance A (`API_URL`, 8080) → `200`; replay
  the **same** proof against instance B (`API_URL_2`, 8082) → `401`
  `invalid_dpop_proof`.
- `scripts/e2e-dpop-iat-window.mjs` (FR-I9b): sign a `/hello` proof with `iat = now -
  iatWindow - 10` → `401`; a fresh proof → `200`.
- `scripts/e2e-dpop-nonce.mjs` (FR-I9c): pro token → `/server-details` with valid
  proof, no nonce → `401` + `DPoP-Nonce` + `use_dpop_nonce`; retry echoing the nonce →
  `200`. Assert `/hello` with no nonce → `200` (never challenged).

**Backend tests:** add a Redis Testcontainer (`GenericContainer<>("redis:7-alpine")`
exposing 6379, via the existing `testcontainers-junit-jupiter`; no new dep) with
`@DynamicPropertySource` for `spring.data.redis.host/port`. Extend
`ServerDetailsControllerIntegrationTest` for the nonce challenge + retry and a
Redis-backed replay assertion. Add `DpopNonceServiceTest` (unit) and a
`DpopReplayProtectionFilter` slice/unit test.

**Docs:** update `CLAUDE.md` (commands: new e2e scripts + Redis in the stack; the DPoP
architecture note; the "Before committing" e2e checklist), `README.md` (Redis + second
backend, the new knobs and defaults), and `CHANGELOG.md` (0.4.0 entry).

**Release:** ships as a new **minor** version (`0.4.0`, continuing the 0.2.0 step-up /
0.3.0 DPoP line). After merge and green acceptance checks, cut a new GitHub minor
release tagged `v0.4.0` from the `CHANGELOG.md` 0.4.0 notes. Done only on the user's
go-ahead (never auto-tag/push).

**Verify (full acceptance, PRD-4 §6):**
1. `docker compose up -d --build` → keycloak + redis + backend + backend-2 + frontend
   all healthy.
2. `e2e-login`, `e2e-stepup`, `e2e-stepup-denied`, `e2e-stepup-bruteforce`,
   `e2e-stepup-refresh`, `dpop-bff-verify` → all `E2E PASSED` (no regression).
3. `e2e-dpop-replay-distributed`, `e2e-dpop-iat-window`, `e2e-dpop-nonce` → all
   `E2E PASSED`.
4. `cd backend && ./gradlew test` → green (Keycloak + Redis Testcontainers).
5. Fail-secure spot check: `docker compose stop redis`, then a DPoP call is refused
   (`503`), not served.
6. Run the **security-reviewer** subagent over the diff (auth/token/proof change).
7. On the user's go-ahead, cut the `v0.4.0` GitHub minor release.

## Files touched (summary)

- New: `backend/src/main/java/com/poc/backend/dpop/DpopReplayProtectionFilter.java`,
  `JtiReplayStore.java`, `RedisJtiReplayStore.java`, `DpopNonceService.java`;
  `backend/src/main/java/com/poc/backend/config/DpopProperties.java`;
  `scripts/e2e-dpop-replay-distributed.mjs`, `scripts/e2e-dpop-iat-window.mjs`,
  `scripts/e2e-dpop-nonce.mjs`.
- Edited: `backend/build.gradle`, `backend/gradle/libs.versions.toml`,
  `backend/src/main/resources/application.yml`,
  `backend/src/main/java/com/poc/backend/config/SecurityConfig.java`;
  `docker-compose.yml`, `.env`; `scripts/lib/dpop.mjs`; integration/unit tests;
  `CLAUDE.md`, `README.md`, `CHANGELOG.md`.

## Open choices (defaulted)

- Fail-closed status = **503** (store unreachable is infra, avoids client re-auth
  loops); `401` is an acceptable alternative and also satisfies §6.6.
- `DpopProperties` as `@ConfigurationProperties` (first in the repo) vs several
  `@Value` reads — went with the properties record for the grouped nonce config.
