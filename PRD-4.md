# PRD (Iteration 4): Distributed DPoP Replay Protection (Redis `jti`, `iat` window, nonce)

**Status:** Draft, for review
**Author:** hcussi@gmail.com
**Date:** 2026-07-08
**Type:** Proof of Concept (POC), iteration 4
**Builds on:** [PRD-3.md](PRD-3.md) (iteration 3, DPoP)

> **Dependency:** this iteration hardens the DPoP proof validation introduced in
> iteration 3 and assumes it is in place. The client-side nonce handling reuses the
> reactive `use_dpop_nonce` retry already specified for the frontend BFF proxy
> (PRD-3 FR-F15), so the new work is almost entirely backend + orchestration.

---

## 1. Overview

Iteration 3 made access tokens DPoP-bound and had the resource server validate the
proof (signature, `typ`, `htm`/`htu`, `iat`, `jti`, `ath`, `cnf.jkt`). Replay
protection there relies on Spring Security's **built-in, in-memory `jti` cache**,
which is **per-JVM**: it is not shared across backend replicas and does not survive
a restart (flagged in the iteration-3 security review, finding I-1). In a
multi-instance deployment a captured proof can therefore be replayed **once per
instance**, and the `iat` freshness window is a framework default rather than a
tuned, documented value.

Iteration 4 closes those gaps and adds one extra defense on the most sensitive
endpoint:

1. **Distributed `jti` replay protection.** Proof `jti` uniqueness is enforced in
   **Redis** (an atomic set-if-absent with a TTL), so a proof is single-use across
   **all** backend instances, not just within one JVM.
2. **Configurable `iat` freshness window.** The acceptable proof age becomes a
   configuration value (**default 60s**, symmetric), and it also bounds how long a
   `jti` must be remembered in Redis.
3. **Server-issued DPoP nonce on `/server-details` only.** The elevated endpoint
   additionally requires a fresh, server-chosen **`DPoP-Nonce`**, so a client
   cannot present a pre-computed proof: the server hands out a nonce and the proof
   must echo it. `/hello` is unchanged (no nonce, no extra round trip).

This remains a POC and a reference template, not a production system. All prior
Non-Goals (PRD.md §2, PRD-2.md §2, PRD-3.md §2) still apply, extended in §2 below.

---

## 2. Goals

- Enforce **`jti` uniqueness in Redis** for every DPoP proof, so replay is refused
  consistently across horizontally scaled backend instances (RFC 9449 replay
  protection, made distributed).
- Make the **`iat` acceptance window configurable** (default **60s**, symmetric
  past/future) via a single property, and derive the Redis `jti` TTL from it so the
  two never disagree.
- Require a **server-issued DPoP nonce on `/server-details`** (and only there): a
  proof without a valid, unexpired nonce is answered with a `DPoP-Nonce` header and
  the `use_dpop_nonce` error; the retried proof carrying that nonce is accepted.
- Ship **Redis in `docker compose`** so the whole thing stays reproducible with one
  command (PRD.md NFR-1), and add headless e2e coverage for distributed replay, the
  `iat` window, and the nonce challenge.
- Preserve **all iteration 1 to 3 behavior** with no regression: base login,
  `/hello` (still no nonce), the RFC 9470 step-up, and DPoP binding all keep working.

### Non-Goals (in addition to prior PRDs)

- A DPoP nonce on **`/hello`** or on the **Keycloak token endpoint** (the IdP side
  is unchanged from iteration 3; token-request nonces stay reactive only).
- **Redis HA / clustering / persistence tuning.** A single dev Redis is fine for the
  POC; production topology is out of scope.
- Replacing the framework's other proof checks (`typ`/`htm`/`htu`/`ath`/signature/
  `cnf`) or the mandatory-`cnf.jkt` validator from iteration 3. Those stay.
- Rate limiting, anomaly/risk scoring, or per-user nonce policies.
- Changing the token/refresh lifetimes or the key model (per-session ES256 key,
  server-tier, from iteration 3).

---

## 3. Architecture delta

Same services as before plus one new dependency. What changes:

### 3.1 New component

| Component | Technology | Port (host) | Role |
|-----------|------------|-------------|------|
| Redis     | Redis 7 (dev, in-memory) | 6379 | Shared store for DPoP `jti` replay keys |

The backend connects to Redis over the compose network (service name), health-gated
like the other services. This is the first shared datastore the apps use; it exists
purely to make the **`jti` replay decision cross-instance**. Nonces are **not**
stored in Redis: they are HMAC-signed and self-validating (§8.4), so any instance
verifies them without shared state.

### 3.2 Replay protection becomes distributed

```
  DPoP proof arrives (already signature/typ/htm/htu/ath/cnf verified as in iter 3)
     │
     ├─ iat within ± window (default 60s)?  ── no ──►  401 invalid_dpop_proof
     │                                                  (stale/early proof)
     │  yes
     ▼
  Redis: SET dpop:jti:<jti> "1" NX EX <window>
     │
     ├─ key already existed  ── replay ──►  401 invalid_dpop_proof
     │
     └─ key set (first use)  ──►  proof accepted
```

The `jti` key TTL equals the `iat` window: a proof is only acceptable while its
`iat` is fresh, and its `jti` only needs to be remembered for exactly that long
(after which the `iat` check rejects any replay anyway). This keeps Redis bounded
and the two checks consistent.

### 3.3 Nonce on the elevated endpoint

`/server-details` gains a nonce requirement layered on top of the existing DPoP +
step-up checks. The precedence is deliberate:

```
  GET /server-details  (DPoP proof, no nonce yet)
     │  proof valid but no/def stale nonce
     ▼
  401  DPoP-Nonce: <fresh nonce>   +  WWW-Authenticate: DPoP error="use_dpop_nonce"
     │
  client re-signs the proof with `nonce` = that value, retries
     ▼
  proof + valid nonce  ──►  now authorization runs:
     ├─ acr < pro  ──►  401 insufficient_user_authentication (RFC 9470 step-up, iter 2)
     └─ acr = pro  ──►  200 + server details
```

Nonce validation is **authentication-time** (part of proof acceptance), so it
precedes the **authorization-time** step-up check. A base-level client hitting
`/server-details` may therefore see the nonce challenge first and the step-up
challenge second; both are handled by the client's existing reactive retries
(PRD-3 FR-F15 nonce retry, PRD-2/PRD-3 step-up). `/hello` never issues a nonce, so
it keeps its single round trip.

### 3.4 Configuration surface

| Property | Default | Meaning |
|----------|---------|---------|
| `app.security.dpop.iat-window-seconds` | `60` | Symmetric proof-age tolerance; also the Redis `jti` TTL |
| `app.security.dpop.nonce.paths` | `/server-details` | Endpoints that require a server-issued nonce |
| `app.security.dpop.nonce.ttl-seconds` | `60` | Nonce validity lifetime |
| `app.security.dpop.nonce.secret` | dev placeholder | HMAC key that signs/verifies the self-validating nonce (dev-only, committed like the other placeholder secrets) |
| `spring.data.redis.host` / `.port` | `redis` / `6379` | Redis connection |

Nothing is hardcoded; the required-nonce path set is config so the pattern is
transferable, consistent with how iteration 2 externalized the required `acr`. The
nonce HMAC key follows the repo's dev-secret convention (committed placeholder,
clearly not for production).

---

## 4. Functional Requirements (iteration 4)

Numbered to continue PRD-3.md §4 without collision.

### 4.1 Backend (Spring Boot)

- **FR-B15:** DPoP proof `jti` uniqueness is enforced in **Redis** via an atomic
  set-if-absent with expiry. A `jti` already present within the window is a replay
  and yields **`401`** (`invalid_dpop_proof`), regardless of which backend instance
  handled the first request. This replaces reliance on the framework's per-JVM
  in-memory cache for replay decisions.
- **FR-B16:** The proof **`iat` is validated against a configurable symmetric
  window**, `app.security.dpop.iat-window-seconds` (**default 60**). A proof whose
  `iat` is older or further in the future than the window is rejected `401`. The
  Redis `jti` TTL is set to this same window.
- **FR-B17:** **`/server-details` requires a valid server-issued DPoP nonce.** A
  proof with no nonce, or an expired/unrecognized nonce, is answered with **`401`**,
  a **`DPoP-Nonce`** response header carrying a fresh nonce, and a
  `WWW-Authenticate: DPoP error="use_dpop_nonce"` challenge. A proof echoing a
  valid, unexpired nonce passes this check. **`/hello` never requires a nonce.**
- **FR-B18:** Nonces are **HMAC-signed and self-validating** (§8.4): any backend
  instance issues and verifies them with the shared `app.security.dpop.nonce.secret`
  key, with no per-nonce shared state. They are time-limited
  (`app.security.dpop.nonce.ttl-seconds`, default 60) and reusable within that
  lifetime; whole-proof replay is still prevented by the distributed `jti` cache
  (FR-B15) and the `iat` window (FR-B16).
- **FR-B19:** The nonce requirement composes correctly with the existing checks:
  nonce validation is authentication-time and therefore **precedes** the RFC 9470
  `acr` step-up authorization check, and it does not weaken the DPoP proof, audience,
  or `cnf.jkt` validation from iteration 3.
- **FR-B20:** **Redis-unavailability posture is explicit and fail-secure by
  default:** if Redis cannot be reached, DPoP-protected requests are refused (fail
  closed) rather than silently falling back to per-instance memory, so replay
  protection cannot be quietly downgraded. (Posture confirmed in §8.)

### 4.2 Integration / Orchestration

- **FR-I8:** `docker-compose` adds a **Redis** service and a **second backend
  instance** (§8.7), both health-gated; the backends share Redis and Keycloak and
  read their connections from env/config. `docker compose up` from a clean checkout
  yields a stack where distributed replay protection and the `/server-details`
  nonce work with no manual steps.
- **FR-I9:** The headless **e2e suite** is extended to cover: (a) **distributed
  replay across two instances** (a proof used once against backend A is rejected
  when replayed against backend B), (b) the **`iat` window** (a proof backdated
  beyond the window is rejected), and (c) the **nonce challenge on
  `/server-details`** (first call → `use_dpop_nonce` + `DPoP-Nonce`; retry with the
  nonce → success), while `/hello` needs no nonce.

### 4.3 Frontend (Next.js)

- **FR-F16:** The BFF proxy's reactive nonce handling (PRD-3 FR-F15) is exercised
  for `/server-details`: on a `use_dpop_nonce` challenge it retries once with the
  supplied `DPoP-Nonce`, then proceeds (including through any subsequent step-up).
  No new client mechanism is introduced; this iteration only ensures the elevated
  path drives it.

---

## 5. Non-Functional Requirements (carryover + additions)

All prior NFRs still hold. Additionally:

- **NFR-11 (Distributed correctness):** replay protection holds across **N backend
  instances**, not just within a single JVM, and survives a single instance
  restart (state lives in Redis).
- **NFR-12 (Configurable freshness):** the `iat` window and nonce TTL are
  configuration with documented defaults (60s), not hardcoded literals.
- **NFR-13 (Fail-secure):** loss of the replay/nonce store fails closed (FR-B20);
  the system never silently degrades to weaker, per-instance protection.
- **NFR-14 (No regression):** every iteration 1 to 3 acceptance criterion still
  passes; `/hello` keeps its single round trip and gains no nonce latency.

---

## 6. Acceptance Criteria (iteration 4)

In addition to all prior acceptance criteria (which must still pass):

1. `docker compose up` from a clean checkout brings up the stack **including Redis**
   (health-gated), and DPoP-protected calls work end to end.
2. A DPoP-bound call to `/hello` and (after step-up) `/server-details` still
   succeeds with a valid, fresh proof.
3. **Distributed replay:** replaying a proof (same `jti`) is rejected `401` on the
   second use, and the decision is backed by Redis (verifiable: the `jti` key
   exists, and a second instance rejects it too).
4. **`iat` window:** a proof whose `iat` is outside `app.security.dpop.iat-window-seconds`
   (default 60s) is rejected `401`; a proof within it is accepted. Changing the
   property changes the boundary.
5. **Nonce on `/server-details`:** the first call with a valid proof but no nonce
   returns `401` with a `DPoP-Nonce` header and `use_dpop_nonce`; retrying with that
   nonce proceeds (to `200` for a `pro` token, or to the RFC 9470 step-up for a
   `basic` one). `/hello` never returns `use_dpop_nonce`.
6. **Fail-secure:** with Redis down, DPoP-protected requests are refused rather than
   accepted with weaker protection.
7. The headless e2e exercises criteria 3 to 5 and prints `E2E PASSED`; `cd backend
   && ./gradlew test` passes.

---

## 7. Technology / stack notes

Net-new mechanics to validate during planning (this stack is newer than most
training data, so nothing is assumed without confirming against the shipped
versions):

- **Overriding Spring Security's DPoP `jti` validation.** Spring Security 7's DPoP
  support installs a built-in in-memory `JtiClaimValidator`/`JtiCache` inside
  `DPoPProofJwtDecoderFactory`, and the resource-server DPoP support is
  auto-wired (there is no `.dpop()` DSL in 7.0.6). Injecting a **Redis-backed** `jti`
  validator therefore means supplying a custom `JwtDecoderFactory<DPoPProofContext>`
  to the `DPoPAuthenticationProvider` (it exposes `setDPoPProofVerifierFactory`),
  which likely requires configuring the DPoP authentication provider explicitly
  rather than relying solely on auto-wiring. The exact hook is confirmed in PLAN-4.
- **No built-in resource-server nonce.** The iteration-3 review confirmed the RS
  side never itself requires `use_dpop_nonce`; nonce **issuance and validation are
  custom** (a small filter/validator scoped to the configured paths, emitting the
  `DPoP-Nonce` header and the `use_dpop_nonce` error, and checking the proof's
  `nonce` claim). The nonce is an **HMAC-signed, self-validating** token (§8.4):
  `base64url(random || expiry)` plus an HMAC over it with the server key, so any
  instance verifies it with no shared state and no Redis dependency. Design in
  PLAN-4.
- **Redis access** via `spring-boot-starter-data-redis` (Lettuce). The `jti` check
  is a single atomic `SET key value NX EX <ttl>` (the only Redis usage; nonces are
  stateless).
- **`iat` window** maps to a configured `JwtTimestampValidator`/`JwtIssuedAtValidator`
  (or a small custom validator) with the property-driven duration; confirm the
  framework validator honors a symmetric window or supply one.

---

## 8. Resolved Decisions (confirmed 2026-07-08)

1. **`jti` replay store: ✅ Redis (distributed).** Proof `jti` uniqueness is
   enforced in Redis so replay protection is cross-instance, not per-JVM.
2. **`iat` check: ✅ configurable window, default 60s** (symmetric), which also
   bounds the Redis `jti` TTL.
3. **Nonce scope: ✅ `/server-details` only.** The elevated endpoint requires a
   server-issued DPoP nonce; `/hello` does not.
4. **Nonce design: ✅ (A) HMAC-signed, self-validating nonce.** The nonce is
   `base64url(random || expiry)` signed with a server-held HMAC key; any backend
   instance validates it statelessly (no Redis for nonces), which is why Redis
   holds only `jti` keys (§3.1). It is **reusable within its short lifetime**
   (default 60s), which is acceptable because each proof still carries a unique
   `jti` (blocked by the distributed replay cache) and a fresh `iat` window, so the
   practical replay exposure is negligible. The stronger Redis-stored single-use
   nonce is deliberately not chosen, to avoid an extra round trip on every elevated
   call and to keep nonce validity independent of Redis availability.
5. **Redis-down posture: ✅ fail closed** (FR-B20/NFR-13). If Redis is unreachable,
   the `jti` replay check cannot run, so DPoP-protected requests are refused rather
   than falling back to weaker per-instance memory. (Stateless nonce validation
   would still function, but the request is rejected at the replay check anyway, so
   protection never silently degrades.)
6. **`iat` window: ✅ ±60s symmetric.** Equal tolerance past and future, one
   `iat-window-seconds` property; the Redis `jti` TTL equals it.
7. **Distributed-replay e2e: ✅ two real backend instances.** Compose runs a second
   backend instance sharing the same Redis and Keycloak; the e2e uses a proof once
   against instance A and replays it against instance B, asserting B rejects it, so
   the cross-instance property is genuinely demonstrated (not just inferred from a
   Redis key). Asserting the `jti` key in Redis is kept as the minimum fallback if
   the two-instance setup proves impractical during PLAN-4.

---

## 9. Next step

On approval of this PRD, I will write **`PLAN-4.md`**: an ordered, verifiable
implementation plan in the same incremental style as the prior plans, covering the
Redis service and the second backend instance, the Redis-backed `jti` validator and
configurable `iat` window on the DPoP proof path, the HMAC self-validating nonce
issuance/validation filter scoped to `/server-details`, the fail-secure posture, and
the e2e + README updates.

**No implementation will be done until PRD-4 and PLAN-4 are approved.**
