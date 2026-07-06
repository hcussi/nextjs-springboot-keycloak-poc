# PLAN (Iteration 3): DPoP Sender-Constrained Access Tokens

**Status:** Draft, for review
**Companion to:** [PRD-3.md](PRD-3.md)
**Builds on:** [PLAN.md](PLAN.md) (iteration 1) and [PLAN-2.md](PLAN-2.md) (iteration 2), both complete
**Date:** 2026-07-06

This plan turns approved **PRD-3** into an ordered, verifiable implementation
guide, in the same incremental style as PLAN.md and PLAN-2.md. It reflects the
resolved decisions (PRD-3 §8): **(A)** the ES256 key pair lives in the **Next.js
server tier** behind a **BFF proxy**, Keycloak is on **26.6** (DPoP GA, no preview
flag), proofs are **ES256**, **nonces are handled reactively but not mandated**,
and e2e coverage is **full** (positive bind + negative replay).

> The Keycloak **26.6** bump (PRD-3 §8.2) is already done and verified green, so
> this plan starts from the DPoP wiring itself. No further code is written until
> this plan is approved, then it proceeds Step 1 → Step 4, verifying at each step.
> Iteration-1 and iteration-2 behavior must keep passing throughout (PRD-3 NFR-7),
> which for this iteration means the e2e scripts are **migrated to DPoP**, not left
> untouched: once the client requires DPoP, a bearer call is meant to fail.

---

## 1. Repository layout delta

Everything reuses the iteration-1/2 layout. Net changes:

```
nextjs-springboot-keycloak-poc/
├── PRD-3.md / PLAN-3.md                       # this iteration's docs
├── keycloak/realm-export.json                 # EXTENDED: nextjs-frontend
│                                              #   dpop.bound.access.tokens = true
├── backend/src/main/java/com/poc/backend/
│   └── config/SecurityConfig.java             # EXTENDED: DPoP proof validation on
│                                              #   the resource server (DPoP scheme),
│                                              #   preserving aud + acr step-up
├── backend/src/test/java/com/poc/backend/
│   ├── support/KeycloakAuthCodeClient.java    # EXTENDED: sign DPoP proof on the
│   │                                          #   token request; call with DPoP scheme
│   ├── support/DpopProofs.java (NEW)          # test helper: ES256 keypair + proof JWT
│   ├── web/HelloControllerTest.java           # EXTENDED: DPoP-bound token + proof cases
│   ├── web/ServerDetailsControllerTest.java   # EXTENDED: same, on the elevated path
│   └── web/*IntegrationTest.java              # EXTENDED: real DPoP end to end
├── frontend/src/lib/
│   ├── auth.ts                                # EXTENDED: per-session ES256 key in the
│   │                                          #   encrypted JWT; DPoP on token exchange
│   │                                          #   + refresh; stop exposing accessToken
│   └── dpop.ts (NEW)                          # server-only: keygen + proof signing (jose)
├── frontend/src/app/api/backend/
│   ├── hello/route.ts (NEW)                   # BFF proxy: sign proof, forward as DPoP
│   └── server-details/route.ts (NEW)          # BFF proxy: same; relays 401 + WWW-Auth
├── frontend/src/app/page.tsx                  # EXTENDED: call same-origin proxy routes,
│                                              #   not the backend directly; no token in browser
├── frontend/src/types/next-auth.d.ts          # EXTENDED: drop accessToken from Session;
│                                              #   private JWK on the server-side JWT only
├── scripts/lib/dpop.mjs (NEW)                 # shared: keypair + proof (node:crypto)
└── scripts/e2e-*.mjs, totp.mjs                # EXTENDED: DPoP on every token/resource call
                                               #   + a negative replay-without-proof assertion
```

---

## 2. The DPoP mechanics (the critical detail)

Iteration 1's critical detail was the single-issuer `/etc/hosts` trick (still in
force); iteration 2's was that one login yields two assurance levels. **Iteration
3's critical detail is that one private key must sign both the token-endpoint proof
and the resource-endpoint proof**, and in this stack the token exchange happens
**server-side inside next-auth**, so the key and the token must live server-side.
Three sub-problems fall out of that, and they drive the whole build order.

**(a) One key, two proof sites, one owner.** Keycloak binds the access token at the
token endpoint (`cnf.jkt = thumbprint(pubkey)`); the backend re-checks that binding
at the resource endpoint. The same key must therefore sign the token-request proof
(`htm=POST`, `htu=token endpoint`, no `ath`) and every resource-request proof
(`htm`/`htu` of the backend call, plus `ath = base64url(SHA-256(access token))`).
Decision A puts that key in the **Next.js server tier**.

**(b) Where the key is stored across a stateless next-auth session.** next-auth v4
uses a **stateless encrypted JWT** (JWE) session cookie, `httpOnly`, decryptable
only server-side with `NEXTAUTH_SECRET`. The plan stores the **private JWK inside
that server-side JWT** (via the `jwt` callback), so it is per-session, never
reaches browser JS, and is available to both the refresh path and the proxy routes
through `getToken({ req })`. The key is generated **once per session** and reused
until logout. It is never placed in the `session` object returned to the client.

**(c) Binding the very first token (the sharp edge).** The key must exist and sign
a proof **before** next-auth's authorization-code → token exchange, but in v4 that
exchange is performed inside the Keycloak provider, and the `jwt` callback (where
we would persist the key) runs **after** it. This is the one genuinely
version-sensitive piece. The intended approach:

- Generate the ES256 key and attach the DPoP proof by **customizing the Keycloak
  provider's `token` request** (next-auth v4 provider `token: { request }` /
  `token: { url }` hook), performing the POST with the `DPoP` header ourselves and
  handling a `use_dpop_nonce` retry, then hand the key to the `jwt` callback so it
  lands in the JWE. The exact hook shape and how the generated JWK is threaded into
  the `jwt` callback are **confirmed against the bundled next-auth v4 first** (a
  short spike at the top of Step 3).
- **Fallback if the provider hook cannot carry the key:** pre-generate the key in a
  server-side authorization step and pass **`dpop_jkt`** (the thumbprint) as an
  authorization parameter so Keycloak binds the code to it, persisting the JWK in a
  short-lived `httpOnly` cookie keyed to the OAuth `state`, then complete the token
  exchange in a code path we own. Chosen only if the spike shows the primary hook
  is infeasible; recorded, not silently swapped.

Everything downstream (refresh, resource calls) is in code paths we already own and
is straightforward: the existing `refreshAccessToken` fetch and the new proxy
routes just add a signed `DPoP` header.

**Request shape after this iteration.** Browser → same-origin Next.js proxy route
(cookie session, no token); proxy → backend with `Authorization: DPoP <token>` and
`DPoP: <fresh proof>`. The browser never holds the access token or the key. The
RFC 9470 step-up `401` (and its `WWW-Authenticate: ... acr_values="pro"`) is
**relayed unchanged by the proxy** to the browser so the existing step-up UX still
triggers.

> The exact Keycloak 26.6 client attribute key (`dpop.bound.access.tokens`), the
> Spring Security 7 DPoP DSL (`DPoPAuthenticationProvider` /
> `DPoPProofJwtDecoderFactory` and how it composes with the existing custom
> `JwtDecoder`, `AudienceValidator`, and acr converter), and the next-auth v4 token
> hook are all validated against the shipped versions during the steps below,
> consistent with PLAN.md's "this stack is newer than most training data" caution.
> Nothing here assumes an API from older docs without confirming it.

---

## 3. Build order (incremental, each step verifiable)

> **Documentation convention (unchanged):** each step ends by updating `README.md`
> to document only what exists so far. Step 4 is the consolidation pass and adds the
> `CLAUDE.md` iteration pointer.

Order rationale: turn on the requirement at the IdP first (Step 1), make the
resource server enforce it (Step 2), then move the client to satisfy it (Step 3).
Between Step 1 and Step 3 the browser flow is temporarily red by design (the client
does not yet send proofs); the e2e is migrated in Step 4. Each step is still
independently verifiable with scratch scripts.

### Step 1: Keycloak — require DPoP-bound tokens for `nextjs-frontend`

**Goal:** the token endpoint issues **DPoP-bound** access tokens (with `cnf.jkt`)
for `nextjs-frontend` and rejects a token request that lacks a valid proof.

- In `keycloak/realm-export.json`, on the `nextjs-frontend` client `attributes`, add
  **`dpop.bound.access.tokens: "true"`** (the internal key behind the "Require DPoP
  bound tokens" capability toggle; confirm the exact attribute key against a 26.6
  admin-console export, since attribute spellings have drifted across versions).
  Keep `publicClient: false` (confidential, unchanged) and everything else intact.
- No realm feature flag is needed on 26.6 (DPoP is GA). Confirm the compose/env has
  nothing DPoP-specific to add.
- **Confidential-client refresh nuance (measure, do not assume, PRD-3 §3.5):** with
  a confidential client Keycloak binds only the **access token**; the refresh token
  is protected by the client secret. Record whether the token endpoint still
  **requires a DPoP proof on the `refresh_token` grant** to bind the new access
  token (expected: yes) so Step 3's refresh path matches reality.

**Update `README.md`:** a short "DPoP" note: what sender-constrained means, that
`nextjs-frontend` now requires DPoP-bound tokens on 26.6 (no preview flag), and how
to observe `cnf.jkt`.

**Verify (scratch script, no app):** using a tiny node/`node:crypto` snippet (seed
for the reusable `scripts/lib/dpop.mjs`):
- A token request **without** a DPoP proof for this client is **rejected**.
- A token request **with** a valid ES256 proof (correct `htu`/`htm`/`typ=dpop+jwt`,
  public `jwk` in the header) succeeds and the decoded access token carries
  **`cnf.jkt`** equal to the JWK SHA-256 thumbprint.
- If Keycloak answers a token request with `use_dpop_nonce` + a `DPoP-Nonce` header,
  the retry embedding that nonce succeeds (records whether nonces are in play at
  all; we do not mandate them, PRD-3 §8.4).
- Reconfirm the step-up path: a `pro` (OTP) token request with a proof still yields
  `acr=pro` **and** `cnf.jkt` together.

### Step 2: Backend — validate the DPoP proof on the resource server

**Goal:** `/hello` and `/server-details` accept the **`DPoP`** authorization scheme
and require a valid proof bound to the token's `cnf.jkt`; a DPoP-bound token
presented **without** a matching proof is rejected `401`. Audience validation and
the iteration-2 acr step-up are preserved.

- **`SecurityConfig.java`:** enable Spring Security 7 resource-server **DPoP** proof
  validation so the `DPoP` scheme is accepted and the proof is checked
  (`DPoPAuthenticationProvider` + `DPoPProofJwtDecoderFactory`, wired through the
  `oauth2ResourceServer` DSL). Confirm the exact DSL against the shipped version
  (the reference shows resource-server DPoP support; the enabling call is validated,
  not copied from memory).
  - **Compose with what already exists, do not regress it.** The custom `JwtDecoder`
    bean (issuer/signature/expiry + `AudienceValidator`) and the acr→`ACR_pro`
    `JwtAuthenticationConverter` must keep applying to the DPoP-bound token. DPoP
    adds proof↔token binding on top of, not instead of, JWT validation. Verify the
    `cnf.jkt`/`ath`/`htm`/`htu` checks and the audience+acr checks all run for a
    single request.
  - **Interplay with `StepUpAccessDeniedHandler` (order matters).** A `basic`
    DPoP-bound token with a **valid** proof hitting `/server-details` must still get
    the RFC 9470 `insufficient_user_authentication` `401` (not a DPoP error), while
    a token with a **missing/invalid** proof must get the DPoP `401`
    (`invalid_dpop_proof` / `use_dpop_nonce` as applicable). Confirm which handler
    wins in each case and that both `WWW-Authenticate` challenges are well-formed.
  - **CORS:** the browser no longer calls the backend directly (Decision A), so no
    DPoP-related CORS relaxation is required; leave the existing config. Note in a
    comment that the proxy boundary is intentional so a future direct call is not
    added without also exposing/allowing the right headers.
- **Test helper `support/DpopProofs.java` (NEW):** generate an EC P-256 key and mint
  a DPoP proof JWT (Nimbus JOSE, already on the resource-server classpath): `typ`,
  `jwk`, `htm`, `htu`, `iat`, `jti`, and `ath` when a token is supplied. Reused by
  both slice and integration tests.
- **`support/KeycloakAuthCodeClient.java`:** the real auth-code flow now targets a
  DPoP-requiring client, so it must **sign a proof on the token request** (and on
  refresh if Step 1 showed it is required) and call the endpoints with the **`DPoP`**
  scheme + a per-request proof. This is what keeps the integration tests real.
- **Slice tests (`@WebMvcTest`, mocked decoder):** extend `HelloControllerTest` and
  `ServerDetailsControllerTest` for: DPoP-bound token **with** a valid proof → `200`
  (and `pro` still `200` on `/server-details`); DPoP-bound token **without** a proof
  or with a proof signed by a **different** key → `401`; `basic`+valid proof on
  `/server-details` → RFC 9470 `401` step-up (unchanged).
- **Integration tests:** drive the real DPoP flow via the updated
  `KeycloakAuthCodeClient` (bound token → `/hello` `200`; OTP → `pro` bound token →
  `/server-details` `200`; **replay without proof → `401`**). Keep the existing
  assertion that the config `acr` matches the realm `acr.loa.map`.

**Update `README.md`:** note the endpoints now require the `DPoP` scheme + proof;
document the `401` a bare bearer replay gets.

**Verify:** `./gradlew test` green (slice + integration on Keycloak 26.6). With a
scratch DPoP-bound token from Step 1: `/hello` and `/server-details` succeed **only**
when accompanied by a valid proof; a bearer replay (no proof) → `401`; a proof
signed by a different key → `401`; `basic`+proof on `/server-details` → RFC 9470
step-up `401`.

### Step 3: Frontend — server-tier key, DPoP on token exchange/refresh, BFF proxy

**Goal:** the Next.js server generates and holds the ES256 key, DPoP-binds the token
at exchange and refresh, and the browser reaches the backend only through
proof-signing proxy routes. The step-up UX still works. The browser never holds the
token or the key.

- **Spike first (the §2(c) risk):** confirm the next-auth v4 token-request hook can
  attach a DPoP proof and thread the generated JWK into the `jwt` callback; if not,
  switch to the `dpop_jkt` fallback. Do this before building the rest of the step so
  the persistence mechanism is known.
- **`lib/dpop.ts` (NEW, server-only):** ES256 keypair generation and DPoP proof
  signing via `jose` (already implied by the JWT work). Functions: `generateKeypair()`
  → `{ privateJwk, publicJwk }`; `signProof({ privateJwk, htm, htu, nonce?, accessToken? })`
  → proof JWT (adds `ath` when `accessToken` is given). Mark the module
  `import "server-only"` so it can never be bundled to the browser.
- **`lib/auth.ts`:**
  - On initial sign-in, ensure a **per-session ES256 keypair** exists and store the
    **private JWK on the server-side JWT** (the JWE). Never copy it into `session`.
  - Attach the DPoP proof to the **token exchange** (via the Step-3 spike outcome)
    and to the existing **`refreshAccessToken`** fetch (`htu` = token endpoint,
    `htm = POST`, plus a one-shot `use_dpop_nonce` retry). Keep the same key across
    refresh so `cnf.jkt` stays stable for the session.
  - **Stop exposing the access token to the browser.** Remove `session.accessToken`
    from the `session` callback (and from `next-auth.d.ts`); keep deriving
    `session.acr` (UI hint only, still fine to expose). Confirm nothing client-side
    reads `accessToken` after the page rewrite below.
- **BFF proxy routes** `app/api/backend/hello/route.ts` and
  `app/api/backend/server-details/route.ts` (NEW, server-side):
  - Read the token + private JWK server-side via `getToken({ req })` (never trust a
    client-supplied token).
  - Sign a fresh proof (`htm=GET`, `htu` = the backend URL, `ath` = hash of the
    token) and forward to the backend with `Authorization: DPoP <token>` +
    `DPoP: <proof>`. On a backend `use_dpop_nonce`, retry once with the nonce.
  - **Relay** the backend status and body, and **pass through the `WWW-Authenticate`
    header** on a `401` so the browser can still see the RFC 9470 step-up challenge.
    The proxy is same-origin, so the browser can read it without CORS gymnastics.
  - Use the server-side backend base URL (Docker service name), not the browser
    `NEXT_PUBLIC_API_URL`, since the fetch now originates in the Next.js container.
- **`page.tsx`:** call the **same-origin proxy routes** (`/api/backend/hello`,
  `/api/backend/server-details`) instead of `${API_URL}/...`, and stop reading
  `session.accessToken`. The step-up logic is unchanged in spirit: a `401` with
  `insufficient_user_authentication` (now relayed by the proxy) still triggers
  `beginStepUp`, and the one-shot retry marker still drives the auto-retry. The acr
  allow-list, toasts, and `LevelBadge` are untouched.

**Update `README.md`:** document the BFF proxy (browser → Next.js → backend), that
the token/key never reach the browser, and that step-up still prompts TOTP.

**Verify (browser E2E):** log in (`testuser`) → `/hello` renders via the proxy →
**Load server details** → TOTP prompt → back → details render, `LevelBadge` flips to
`pro`. In devtools, confirm the browser makes only **same-origin** calls and no
access token or private key appears in any client-visible response, storage, or the
`session`. Cancelling TOTP still toasts and leaves `/hello` working.

### Step 4: Full headless e2e (positive + negative) + orchestration/README polish

**Goal:** every e2e script exercises the real DPoP flow, including the negative
replay case (NFR-8), and the docs are consolidated.

- **`scripts/lib/dpop.mjs` (NEW, dependency-free, `node:crypto`):** ES256 keypair +
  DPoP proof signing (matching Keycloak/Spring exactly: `typ=dpop+jwt`, `jwk`,
  `htm`, `htu`, `iat`, `jti`, `ath`, optional `nonce`), plus the JWK SHA-256
  thumbprint helper. Shared by all scripts and the Step-1 scratch check.
- **Migrate the existing scripts** (`e2e-login`, `e2e-stepup`, `e2e-stepup-denied`,
  `e2e-stepup-bruteforce`, `e2e-stepup-refresh`, and `totp.mjs`/`auth-code-flow.mjs`
  as needed): every **token request** (auth-code + refresh) and every **resource
  call** attaches a DPoP proof under the `DPoP` scheme; assert the issued token has
  **`cnf.jkt`**. Handle a `use_dpop_nonce` retry if Step 1 found nonces active.
- **Add the negative assertion (NFR-8):** in `e2e-login`, take a valid DPoP-bound
  token and call the backend **(a)** with no `DPoP` proof and **(b)** with a proof
  signed by a **different** key; assert both are **`401`**. This is the property the
  whole iteration exists to demonstrate.
- The step-up scripts keep proving `acr=pro` and the refresh script keeps proving
  `acr` survives refresh, now additionally proving `cnf.jkt` is present and stable
  across refresh.
- **Finalize `README.md`:** consolidation pass so run instructions, the DPoP section,
  the BFF-proxy description, the endpoint table (now `DPoP` scheme), and the e2e list
  are accurate end to end.
- **`CLAUDE.md`:** add the `PRD-3.md` / `PLAN-3.md` pointer under "What this is" and a
  DPoP note in the architecture section (server-tier key + BFF proxy, `cnf.jkt`
  binding, DPoP scheme, 26.6 GA). Update the "before committing" checklist to run the
  migrated e2e set.

**Verify:** from a clean state, `docker compose up -d --build`, then all e2e scripts
print `E2E PASSED` (including the negative replay), and `cd backend && ./gradlew test`
is green. Re-import the realm first if it changed (`docker compose up -d keycloak
--force-recreate`) so checks run against the committed file.

---

## 4. Acceptance mapping (PRD-3 §6)

| PRD-3 criterion                                                    | Covered in |
|-------------------------------------------------------------------|------------|
| 1. Clean `up`: KC 26.6, client requires DPoP-bound tokens          | Step 1     |
| 2. Issued access token carries `cnf.jkt`                           | Steps 1,4  |
| 3. `/hello` succeeds under `DPoP` scheme + valid proof             | Steps 2,3  |
| 4. Step-up still works; `/server-details` `pro` + proof → `200`    | Steps 2,3  |
| 5. Valid token replayed w/o matching proof → `401` (NFR-8)         | Steps 2,4  |
| 6. Missing/invalid JWT → ordinary `401`; RFC 9470 unchanged        | Step 2     |
| 7. Browser flow end to end; DPoP failure toasts, session intact    | Step 3     |
| 8. Headless e2e covers 2–5; `./gradlew test` green                 | Step 4     |
| NFR-7 no regression (iteration-1/2 criteria still pass)            | all steps  |

---

## 5. Risks / watch-items

- **Token-exchange binding in next-auth v4 (the top risk).** Attaching a DPoP proof
  to the first token request and persisting the generated key across a stateless JWE
  session is the one piece not in code we already own. **Spike it first (Step 3),**
  with the `dpop_jkt` fallback ready. Everything else (refresh, proxy) is
  straightforward because we control those fetches.
- **Private key must never reach the browser.** It lives only in the `httpOnly` JWE
  and in `server-only` modules/route handlers. Guard against leaking it via the
  `session` object, a client component, or a serialized prop. A devtools check in
  Step 3's verify is a required gate, not optional.
- **Spring Security 7 DPoP DSL is unverified from memory.** The exact enabling call
  and its composition with the existing custom `JwtDecoder`/`AudienceValidator`/acr
  converter are confirmed against the shipped version in Step 2, not copied from
  older docs. Confirm both the proof checks and the audience/acr checks run for one
  request.
- **Handler precedence on `/server-details`.** DPoP proof failure vs RFC 9470
  step-up must each return the right `401` challenge. Test both a valid-proof/`basic`
  token (expect step-up `401`) and a no-proof token (expect DPoP `401`).
- **The e2e is red between Step 1 and Step 3 by design.** Requiring DPoP at the IdP
  before the client sends proofs breaks bearer calls intentionally; do not "fix" it
  by loosening the client. It goes green when Step 3 lands and is asserted in Step 4.
- **Confidential-client refresh proof.** Whether the `refresh_token` grant needs a
  proof is measured in Step 1 and matched in Step 3; getting it wrong silently
  breaks the 5-minute refresh (session drops mid-use).
- **DPoP `iat` clock skew.** Keycloak and Spring allow a small proof-freshness
  window; the e2e and integration proofs must use current time. If Docker clock skew
  ever bites, it surfaces as intermittent `401`s. Noted; not expected locally.
- **Nonce handling is reactive only (PRD-3 §8.4).** We retry once on
  `use_dpop_nonce` but do not mandate nonces. If a future hardening step enables
  mandatory nonces, the proxy and token paths already have the retry hook.
- **`ath` and per-request proofs.** Each resource call needs a **fresh** proof with
  the correct `ath`; reusing one across two calls (or omitting `ath`) is a `401`.
  The proxy signs per request.
- **Residual POC limitations (unchanged).** DPoP raises token-theft resistance but
  the realm/session lifetimes, dev secrets, and the committed TOTP seed from
  iteration 2 are still dev-only; this iteration does not change those trade-offs.

---

## 6. Deliverables checklist

- [ ] `keycloak/realm-export.json`: `nextjs-frontend` `dpop.bound.access.tokens=true`
      (confirmed attribute key), still confidential
- [ ] `backend/` resource-server DPoP proof validation composed with existing
      `JwtDecoder`/`AudienceValidator`/acr converter + correct handler precedence vs
      RFC 9470 step-up
- [ ] `backend/` tests: `DpopProofs` helper, updated `KeycloakAuthCodeClient` (signs
      proofs), slice + integration cases incl. **replay-without-proof → 401**
- [ ] `frontend/` `lib/dpop.ts` (server-only), `lib/auth.ts` (per-session key in JWE,
      DPoP on exchange + refresh, drop `session.accessToken`), `next-auth.d.ts`
- [ ] `frontend/` BFF proxy routes (`/api/backend/hello`, `/api/backend/server-details`)
      signing proofs, relaying `WWW-Authenticate`; `page.tsx` calls same-origin proxies
- [ ] `scripts/lib/dpop.mjs` + all e2e scripts migrated to DPoP, incl. the negative
      replay assertion (NFR-8)
- [ ] `README.md` (DPoP + BFF section, endpoint table under `DPoP` scheme) +
      `CLAUDE.md` iteration pointer and architecture note

---

## 7. Next step

On approval of this plan, implementation proceeds **Step 1 → Step 4**, verifying at
each step (spiking the next-auth token-exchange binding at the top of Step 3, and
running the migrated e2e set + `./gradlew test` as the no-regression guard) before
moving on.

**No implementation will be done until PRD-3 and PLAN-3 are approved.**
