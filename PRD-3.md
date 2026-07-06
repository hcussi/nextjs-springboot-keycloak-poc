# PRD (Iteration 3): DPoP Sender-Constrained Access Tokens

**Status:** Draft, for review
**Author:** hcussi@gmail.com
**Date:** 2026-07-06
**Type:** Proof of Concept (POC), iteration 3
**Builds on:** [PRD.md](PRD.md) (iteration 1) and [PRD-2.md](PRD-2.md) (iteration 2), both complete

---

## 1. Overview

Iterations 1 and 2 use **bearer** access tokens: whoever holds the token can use
it. If a token leaks (XSS, a logged `Authorization` header, a compromised proxy),
the thief can replay it against the backend until it expires.

Iteration 3 makes the tokens **sender-constrained** with **DPoP** (Demonstrating
Proof-of-Possession at the Application Layer, **RFC 9449**). The frontend generates
an asymmetric **key pair**, and on every token request and every API call it
**signs a short-lived DPoP proof JWT** with the private key and attaches it in a
`DPoP` header. Keycloak binds the issued access token to the public key's
thumbprint (a `cnf.jkt` claim), and the backend (Spring Security resource server)
rejects any request whose DPoP proof does not match the key the token is bound to.
A stolen token is then useless without the private key.

This is additive and orthogonal to what already exists: the Authorization Code +
PKCE flow, the confidential `nextjs-frontend` client, JWT validation
(issuer/signature/expiry/audience), and the iteration-2 **step-up** (`acr=pro`)
protection on `/server-details` all keep working exactly as before, now on top of
DPoP-bound tokens instead of bearer tokens.

This remains a POC and a reference template, not a production system. All prior
Non-Goals (PRD.md §2, PRD-2.md §2) still apply, extended in §2 below.

---

## 2. Goals

- Enable **DPoP in Keycloak** (generally available on the bumped **26.6** image,
  see §7) and require **DPoP-bound access tokens** for the `nextjs-frontend`
  client, so the issued access token carries a `cnf.jkt` confirmation claim.
- Have the **frontend generate an ECDSA (`ES256`) key pair per session**, sign a
  fresh **DPoP proof** for each token request and each backend call, and attach it
  in the `DPoP` header, sending the access token with the `DPoP`
  authorization scheme (not `Bearer`).
- Have the **backend** (Spring Boot 4 / Spring Security 7 resource server)
  **validate the DPoP proof** against the token's `cnf.jkt` and the request
  (method/URI/`ath` access-token hash), rejecting mismatched or missing proofs.
- Keep the whole thing **reproducible via `docker compose up`**, including the
  bumped Keycloak image and the client DPoP toggle in the imported realm,
  consistent with PRD.md NFR-1.
- Preserve **all iteration-1 and iteration-2 behavior** with no regression: base
  login, `/hello`, the RFC 9470 step-up challenge, and `acr=pro` on
  `/server-details`.

### Non-Goals (in addition to PRD.md §2 and PRD-2.md §2)

- Making the **refresh token** DPoP-bound. With a confidential client Keycloak
  binds only the **access token**; the refresh token is protected by the client
  secret (see §3.5). Public-client refresh-token binding is out of scope.
- **Mandatory DPoP nonces.** We do **not** configure mandatory `DPoP-Nonce`
  challenges (confirmed §8.4). The frontend still handles a server-issued nonce
  reactively (retry once on `use_dpop_nonce`) in case Keycloak or the backend
  demands one, but nonces are not required by our config.
- **Hardware-backed / attested keys**, key escrow, or cross-device key sync.
- Replacing PKCE, the audience check, or step-up. DPoP stacks on top of them, it
  does not replace any of them.
- Binding tokens for any client other than `nextjs-frontend`.

---

## 3. Architecture delta

Same three services and the same single-issuer / `/etc/hosts` strategy as before
(PRD.md §3, PRD-2.md §3). What changes:

### 3.1 What DPoP adds to the loop

```
  Frontend                                 Keycloak                Backend
  ────────                                 ────────                ───────
  generate ES256 key pair (per session)
     │
     │  1. token request (auth-code / refresh)
     │     + DPoP: <proof signed by private key>
     ├──────────────────────────────────────►│
     │                                       │ validate proof,
     │  2. access token with                 │ compute jwk thumbprint,
     │     cnf.jkt = thumbprint(pubkey)      │ embed as cnf.jkt
     │◄───────────────────────────────────── │
     │
     │  3. GET /server-details
     │     Authorization: DPoP <access-token>
     │     DPoP: <fresh proof, htm/htu/ath = hash(token)>
     ├────────────────────────────────────────────────────────────►│
     │                                                             │ validate JWT
     │                                                             │ (iss/sig/exp/aud/acr)
     │                                                             │ AND DPoP proof:
     │                                                             │  key == cnf.jkt,
     │                                                             │  htm/htu match,
     │                                                             │  ath == hash(token)
     │  4. 200 + server details  (or 401 if proof missing/mismatched)
     │◄─────────────────────────────────────────────────────────── │
```

### 3.2 Where the key lives (the critical detail)

Iteration 1's critical detail was the single-issuer `/etc/hosts` trick; iteration
2's was that one login must yield two assurance levels. **Iteration 3's critical
detail is that a single private key must sign both the token-endpoint proof and
the resource-endpoint proof**, because the access token is bound (`cnf.jkt`) at the
token endpoint and that same binding is checked at the resource endpoint.

In this stack the **token exchange happens server-side inside next-auth** (the
confidential client's secret never reaches the browser, per CLAUDE.md). Therefore
the entity that signs the token-request proof is the **Next.js server**, and for
the resource-request proof to match, it must be signed by the **same key**.

**Decision (confirmed, §8.1): the key lives in the Next.js server tier behind a
thin BFF proxy.** The Next.js app generates and holds the ES256 key per session,
signs the DPoP proof for the Keycloak token exchange, and proxies backend calls
through a **server-side route handler** that attaches a fresh resource proof. The
browser stops calling the backend directly and stops holding the access token at
all: a net security improvement, and "the frontend generates/signs/attaches" is
satisfied at the Next.js application tier. The rejected alternative (a
non-extractable WebCrypto key in the browser) would require abandoning the
confidential client and moving token handling into the browser, contradicting the
established architecture (CLAUDE.md, PRD.md Decision §8.2); it is out of scope.

Either way the key pair is **generated by the frontend**, is **per-session**, and
its **private key is never sent to Keycloak or the backend**: only DPoP proofs
(signed assertions) and the public JWK (inside each proof header) cross the wire.

### 3.3 Request format change

| Aspect                | Before (bearer)                     | After (DPoP)                                    |
|-----------------------|-------------------------------------|-------------------------------------------------|
| Authorization scheme  | `Authorization: Bearer <token>`     | `Authorization: DPoP <token>`                   |
| Extra header          | none                                | `DPoP: <proof-jwt>` on every request            |
| Access token claim    | no `cnf`                            | `cnf.jkt = <base64url SHA-256 of public JWK>`   |
| Proof body            | n/a                                 | `htm`, `htu`, `iat`, `jti`, and `ath` on resource calls |

### 3.4 Endpoint protection map (unchanged levels, now DPoP-checked)

| Endpoint              | Auth level (iter 2)   | Iteration-3 addition                              |
|-----------------------|-----------------------|---------------------------------------------------|
| `GET /hello`          | LoA 1 (authenticated) | token must be DPoP-bound; valid proof required     |
| `GET /server-details` | LoA 2 (`acr=pro`)      | token must be DPoP-bound; valid proof required     |

A missing/invalid **JWT** still returns the ordinary `401`. A missing/invalid
**DPoP proof** on a DPoP-bound token also returns `401` (with an
`error="invalid_dpop_proof"` / `use_dpop_nonce` challenge as applicable). The
iteration-2 step-up `401` (`insufficient_user_authentication`, RFC 9470) is
unchanged and independent; a request can be well-formed for DPoP yet still be
challenged for insufficient `acr`.

### 3.5 Refresh and confidential-client nuance

Keycloak binds **only the access token** for a **confidential** client; the
refresh token is bound to the client credentials instead. On refresh, the Next.js
server still attaches a DPoP proof so the **new** access token is bound to the same
key, keeping the session's key stable across the 5-minute refresh cycle. The exact
proof requirements on the refresh call are confirmed against the Keycloak 26.6 docs
in PLAN-3, not assumed.

---

## 4. Functional Requirements (iteration 3)

Numbered to continue PRD-2.md §4 without collision.

### 4.1 Keycloak

- **FR-K13:** The Keycloak image is bumped to **26.6**, where DPoP is a
  **generally available** feature (no preview flag needed). The bump is pinned in
  compose/env so the stack is reproducible.
- **FR-K14:** The `nextjs-frontend` client is configured to **require DPoP-bound
  access tokens** (`dpop.bound.access.tokens = true` / "Require DPoP bound
  tokens"), shipped inside the imported realm export.
- **FR-K15:** Issued access tokens for the client carry a **`cnf.jkt`** confirmation
  claim equal to the SHA-256 thumbprint of the frontend's public key.
- **FR-K16:** The token endpoint **rejects a token request without a valid DPoP
  proof** for this client, and the base login / `/hello` flow still completes when
  a valid proof is supplied (no regression to iteration 1).

### 4.2 Backend (Spring Boot)

- **FR-B11:** The resource server **accepts the `DPoP` authorization scheme** and
  reads the `DPoP` proof header, in addition to (or instead of) `Bearer`.
- **FR-B12:** For a DPoP-bound token, the backend **validates the DPoP proof**:
  proof signature, `typ=dpop+jwt`, `htm`/`htu` match the actual request, `iat`
  freshness, and that the proof's public key thumbprint **equals the token's
  `cnf.jkt`** and the `ath` claim **equals the hash of the presented access
  token**. A missing/mismatched proof yields `401`.
- **FR-B13:** All existing JWT validation (issuer, signature, expiry, **audience**)
  and the **iteration-2 `acr` step-up** enforcement on `/server-details`
  (RFC 9470 challenge) continue to apply, unchanged, on top of DPoP.
- **FR-B14:** Because the backend is now called **server-side via the BFF proxy**
  (Decision A), the browser no longer calls the backend directly, so the existing
  CORS config does not need a DPoP-related relaxation. If any direct browser call
  is retained, CORS must allow the `DPoP` request header; this is called out so the
  proxy boundary is not accidentally bypassed.

### 4.3 Frontend (Next.js)

- **FR-F12:** The frontend **generates an ES256 key pair per session in the
  Next.js server tier** (Decision A) and holds the private key **server-side only**
  (in-memory, not in the browser, localStorage, or on disk). The private key is
  never exposed to the browser, Keycloak, or the backend; only signed DPoP proofs
  and the public JWK cross the wire. The browser drives the flow through the app's
  own server routes and never holds the access token or the key.
- **FR-F13:** The Next.js server **signs a fresh DPoP proof** (unique `jti`,
  current `iat`, correct `htm`/`htu`) for **every token request** to Keycloak
  (auth-code exchange and refresh) and attaches it in the `DPoP` header.
- **FR-F14:** The **BFF proxy route** (Decision A) **signs a fresh DPoP proof
  including `ath`** (the access-token hash) for **every backend call** it makes on
  the browser's behalf, and sends the token with the `DPoP` authorization scheme.
- **FR-F15:** If a token or resource endpoint returns a **`DPoP-Nonce`
  challenge** (`use_dpop_nonce`), the frontend **retries once** with the supplied
  nonce embedded in the proof. Other DPoP failures surface via the existing
  **sonner error toasts** without breaking the session.

### 4.4 Integration / Orchestration

- **FR-I6:** The bumped **26.6** image and the client's DPoP toggle ship **inside
  the compose/env config and the imported realm**, so `docker compose up` from a
  clean checkout yields a stack that requires and validates DPoP with no manual
  Keycloak console steps.
- **FR-I7:** The headless **e2e suite** is extended to cover DPoP: it generates a
  key pair, obtains a DPoP-bound token (asserting `cnf.jkt` is present), calls
  `/hello` and (after step-up) `/server-details` with valid proofs, and asserts a
  **negative case**: the same token replayed **without a valid DPoP proof** (or
  with a proof signed by a different key) is **rejected `401`**. Existing
  `e2e-login`, `e2e-stepup*` scripts keep passing (adapted to DPoP).

---

## 5. Non-Functional Requirements (carryover + additions)

All PRD.md §5 and PRD-2.md §5 NFRs still hold. Additionally:

- **NFR-7 (No regression):** Every iteration-1 (PRD.md §7) and iteration-2
  (PRD-2.md §6) acceptance criterion still passes. DPoP is additive.
- **NFR-8 (Sender-constrained):** A valid access token **replayed without the
  matching private key** must be rejected by the backend. This is the core
  security property and is asserted by an e2e negative test (FR-I7).
- **NFR-9 (Key hygiene):** Private keys and DPoP proofs are **never logged**; the
  private key never leaves the frontend tier and is never persisted to
  localStorage or disk (in-memory per session, consistent with PRD.md FR-F6 token
  handling).

---

## 6. Acceptance Criteria (iteration 3)

In addition to PRD.md §7 and PRD-2.md §6 (which must still pass):

1. `docker compose up` from a clean checkout brings up **Keycloak 26.6** with the
   `nextjs-frontend` client set to **require DPoP-bound tokens** (visible in the
   admin console); DPoP is GA on this image, so no preview flag is needed.
2. After login, the issued access token contains a **`cnf.jkt`** claim (verifiable
   by decoding the token in the e2e).
3. `GET /hello` succeeds when called with the token under the **`DPoP` scheme plus
   a valid proof**, and returns the greeting.
4. `GET /server-details` still triggers the **step-up** at LoA 1, and after
   completing TOTP succeeds when called with a **valid DPoP proof** on the elevated
   token.
5. The **same valid token replayed with no DPoP proof, or a proof signed by a
   different key, is rejected `401`** (the sender-constraint holds).
6. A missing/invalid **JWT** still returns an ordinary `401`; the iteration-2
   RFC 9470 step-up challenge is unchanged.
7. In the browser, the full flow (login, `/hello`, step-up, `/server-details`)
   works end to end with DPoP, and DPoP failures show an **error toast** without
   breaking the session.
8. The extended e2e suite exercises criteria 2 through 5 headlessly and prints
   `E2E PASSED`; `cd backend && ./gradlew test` passes.

---

## 7. Technology / stack notes

No new runtime services. Net-new mechanics to validate during planning (consistent
with the "version gotchas" caution, since this stack is newer than most training
data):

- **Keycloak is bumped 26.3 → 26.6, where DPoP is generally available.** DPoP was a
  _preview_ feature in 26.3 (needed `--features=dpop`) and became a fully supported
  feature in **26.4**, so on **26.6** no feature flag is required. Per-client
  control is the **"Require DPoP bound tokens"** capability toggle
  (`dpop.bound.access.tokens`); a realm-wide `dpop-bind-enforcer` client-policy
  executor exists but is not needed here. Exact realm-export JSON shape is confirmed
  in PLAN-3 against the Keycloak 26.6 docs. **The version bump is not free**: the
  pinned image in `.env` (`KEYCLOAK_IMAGE`), the Testcontainers Keycloak used by the
  backend integration tests, the e2e scripts, and the docs (`README.md`,
  `CLAUDE.md`) all reference the current version and must be revisited and re-run
  green as part of this iteration (tracked in §8.2 and PLAN-3).
- **Spring Security 7 (Spring Boot 4) resource-server DPoP.** Resource-server DPoP
  proof validation shipped in Spring Security 6.5 and is present in 7.x; it is
  enabled on the resource server (`oauth2ResourceServer(o -> o.jwt(...)` plus DPoP
  support, via `DPoPAuthenticationProvider` / `DPoPProofJwtDecoderFactory`). The
  exact DSL wiring, and its interaction with the existing custom `JwtDecoder`,
  audience validator, `acr` authority converter, and `StepUpAccessDeniedHandler`,
  is confirmed against the shipped version in PLAN-3, not assumed from older docs.
- **next-auth v4 DPoP.** next-auth v4 has **no built-in DPoP support**, so the
  proof signing is added around it: a custom key-pair generator, a DPoP proof
  signer (e.g. via the `jose` library already implied by the JWT handling), and
  hooks on the Keycloak provider's token request plus the backend call path. The
  precise integration point (provider `token` request override vs a custom HTTP
  layer, and the BFF proxy route under Decision A) is confirmed in PLAN-3.
- **Reference docs:** Keycloak DPoP (<https://www.keycloak.org/securing-apps/dpop>),
  Spring Security resource-server DPoP
  (<https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/dpop-tokens.html>),
  RFC 9449.

---

## 8. Resolved Decisions (confirmed 2026-07-06)

1. **Key location / architecture shape: ✅ (A) Next.js server tier + BFF proxy.**
   The ES256 key pair is generated and held server-side per session; the browser
   never holds the access token or the key and reaches the backend only through the
   app's server-side proxy route. The browser-held non-extractable-key + public
   client alternative is rejected (it would contradict the confidential-client
   architecture, CLAUDE.md / PRD.md §8.2).
2. **Keycloak version: ✅ bump to 26.6 (DPoP GA, no preview flag).** This supersedes
   the original "enable the preview feature" framing. The bump touches the pinned
   image (`.env`), the Testcontainers-based backend integration tests, the e2e
   scripts, and the docs (`README.md`, `CLAUDE.md`); **all tests are revisited and
   re-run green, and the docs are updated** to 26.6 as part of this iteration
   (PLAN-3 sequences this).
3. **DPoP algorithm: ✅ ES256 (ECDSA P-256).**
4. **DPoP nonce enforcement: ✅ do not mandate nonces.** Handle a server-issued
   `DPoP-Nonce` challenge reactively (retry once on `use_dpop_nonce`), but do not
   configure mandatory nonces on Keycloak or the backend.
5. **e2e coverage: ✅ full.** Assert both the positive DPoP-bound success and the
   negative "valid token without a matching proof is rejected `401`" (NFR-8).

---

## 9. Next step

On approval of this PRD, I will write **`PLAN-3.md`**: an ordered, verifiable
implementation plan in the same incremental style as PLAN.md and PLAN-2.md,
covering the Keycloak **26.6** bump and client DPoP toggle in the realm, the
Next.js server-tier key-pair generation + proof signing + BFF proxy, backend
resource-server DPoP validation preserving audience/step-up, revisiting and
re-running all existing tests (backend `./gradlew test` + the e2e scripts) green,
and updating the docs (`README.md`, `CLAUDE.md`).

**No implementation will be done until PRD-3 and PLAN-3 are approved.**
