# PLAN (Iteration 2): Step-Up Authentication for `/server-details`

**Status:** Implemented (all four steps done)
**Companion to:** [PRD-2.md](PRD-2.md)
**Builds on:** [PLAN.md](PLAN.md) (iteration 1, complete)
**Date:** 2026-07-01

This plan turns approved **PRD-2** into an ordered, verifiable implementation
guide, in the same incremental style as PLAN.md. It reflects the resolved
decisions (PRD-2 §8): elevated factor = **TOTP**, ACR levels = **`basic`** (LoA 1)
/ **`pro`** (LoA 2) mapped via `acr.loa.map`, and **full headless e2e coverage**
(the script computes the TOTP).

> Implementation proceeded Step 1 → Step 4, verifying at each step; all four steps
> are now complete. Iteration-1 behavior kept passing throughout (PRD-2 NFR-5).

---

## 1. Repository layout delta

Everything reuses the iteration-1 layout. Net changes:

```
nextjs-springboot-keycloak-poc/
├── PRD-2.md / PLAN-2.md                    # this iteration's docs
├── keycloak/realm-export.json             # EXTENDED: acr.loa.map, OTP policy,
│                                          #   custom browser flow, seed TOTP cred
├── backend/src/main/java/com/poc/backend/
│   ├── config/SecurityConfig.java         # EXTENDED: /server-details rule,
│   │                                      #   acr->authority converter, RFC 9470
│   │                                      #   challenge handler, CORS expose hdr
│   ├── config/StepUpAccessDeniedHandler.java   # NEW: emits RFC 9470 401 challenge
│   ├── web/ServerDetailsController.java    # NEW: GET /server-details
│   └── web/dto/ServerDetails.java          # NEW: response record
├── backend/src/test/java/com/poc/backend/
│   ├── web/ServerDetailsControllerTest.java        # NEW: slice test (acr cases)
│   └── web/ServerDetailsControllerIntegrationTest.java  # NEW: real step-up (opt.)
├── frontend/src/app/page.tsx               # EXTENDED: server-details + step-up
├── frontend/src/lib/auth.ts                # EXTENDED: surface `acr` into session
├── frontend/src/types/next-auth.d.ts       # EXTENDED: acr on Session/JWT
└── scripts/e2e-login.mjs                   # EXTENDED: TOTP + full step-up flow
```

---

## 2. The step-up mechanics (the critical detail)

Iteration 1's critical detail was the single-issuer / `/etc/hosts` trick (still in
force). Iteration 2's critical detail is that **the same login must be able to
produce two different assurance levels**, gated by what the client asks for, and
the elevated one must actually re-challenge even inside an existing session.

**ACR ↔ LoA map (realm level).** The realm carries
`acr.loa.map = {"basic":1,"pro":2}`. When a client requests `acr=pro` (LoA 2),
Keycloak must run the TOTP factor; the resulting token's `acr` claim is `pro`. A
normal login (no acr requested) yields `basic`.

**Conditional flow keyed on LoA.** A custom browser flow uses the
**Condition - Level of Authentication** authenticator so that:
- the **password** step satisfies LoA 1 (`basic`), and
- the **OTP** step runs **only when LoA 2 (`pro`) is requested**.

This is what keeps `/hello` (base login) unchanged while `/server-details` can
demand more. The `Cookie` execution stays `ALTERNATIVE` so an existing SSO session
satisfies LoA 1 without re-login; the LoA-2 conditional still forces OTP on
step-up. The Condition-LoA **max age is set to 0** so requesting `pro` always
re-verifies the factor rather than silently reusing a stale elevation (important
for a believable demo and for the e2e to be deterministic).

**Standards-based challenge (RFC 9470).** When a valid but LoA-1 token hits
`/server-details`, the backend returns **`401`** with
`WWW-Authenticate: Bearer error="insufficient_user_authentication",
error_description="...", acr_values="pro"` (not a bare `403`). The frontend reads
`acr_values` from that header and re-runs login requesting `pro`.

> The exact Keycloak 26 wiring (Condition-LoA execution requirements, the
> `acr.loa.map` attribute key, the seed user's `otp` credential JSON shape and
> secret encoding) and the exact Spring Security 7 / next-auth v4 APIs are
> validated against the shipped versions during the steps below, consistent with
> PLAN.md's "this stack is newer than most training data" caution. Nothing here
> assumes an API from older docs without confirming it.

---

## 3. Build order (incremental, each step verifiable)

> **Documentation convention (unchanged):** each step ends by updating
> `README.md` to document only what exists so far. Step 4 is the consolidation
> pass and adds the `CLAUDE.md` iteration pointer.

### Step 1: Keycloak step-up configuration (realm export)

**Goal:** the imported `web` realm can issue both `basic` and `pro` tokens, with
TOTP as the elevated factor, and the seed user can complete `pro` non-interactively.

Extend `keycloak/realm-export.json` (single source of truth, still imported on
startup) with:

- **`attributes.acr.loa.map`** = `{"basic":1,"pro":2}` (realm level; also mirrored
  on the `nextjs-frontend` client attributes if required by 26.x, to be confirmed).
- **`acr` as an access-token claim (do not assume it is automatic).** By default
  OIDC puts `acr` in the **ID token**; the backend enforces on the **access token**
  the frontend forwards as a Bearer credential (same as `HelloController` reading
  `preferred_username` from the access token today, which works only because of
  scope/mapper config, not automatically). Add/confirm a protocol mapper or client
  scope on `nextjs-frontend` so `acr` is emitted in the **access token**. If this
  is missed the `pro` authority is never granted to any token and every
  `/server-details` call is challenged forever (fail-closed but fully broken).
- **OTP policy** pinned so codes are reproducible: `otpPolicyType: "totp"`,
  `otpPolicyAlgorithm: "HmacSHA1"`, `otpPolicyDigits: 6`, `otpPolicyPeriod: 30`,
  `otpPolicyLookAheadWindow: 1`.
- A **custom top-level browser flow** (e.g. alias `browser-stepup`) in
  `authenticationFlows`, with `authenticatorConfig` for the Condition-LoA
  executions:
  - `Cookie` (ALTERNATIVE)
  - `Identity Provider Redirector` (ALTERNATIVE)
  - `stepup-forms` subflow (ALTERNATIVE):
    - Conditional subflow **LoA 1**: `conditional-level-of-authentication`
      (config: level `1`, max age default) → `auth-username-password-form` (REQUIRED)
    - Conditional subflow **LoA 2**: `conditional-level-of-authentication`
      (config: level `2`, **max age `0`**) → `auth-otp-form` (REQUIRED)
  - Bind it: realm `"browserFlow": "browser-stepup"`.
- The **seed user's TOTP credential**, pre-seeded with a **known secret** so the
  e2e can compute codes: add an `otp` credential to `testuser` with `secretData`
  (the shared secret) and `credentialData` (`{"subType":"totp","digits":6,
  "period":30,"algorithm":"HmacSHA1"}`). The chosen secret and its encoding are
  documented in the README as dev-only and reused verbatim by the e2e in Step 4.
  - **A committed TOTP seed is a different risk class than a committed password.**
    The README/`CLAUDE.md` note must carry a distinct, loud warning (not folded
    into the generic `.env`/`NEXTAUTH_SECRET` dev-secret line): this seed must
    never be reused for any account outside this throwaway realm, because unlike a
    password a leaked second-factor seed defeats the whole point of the second
    factor and cannot be meaningfully rotated away from without re-enrolling the
    credential.

**Update `README.md`:** a "Step-up authentication" section: what `basic`/`pro`
mean, that `testuser` has a pre-seeded TOTP secret (value documented, dev-only),
and how to observe the `acr` claim.

**Verify:**
- `docker compose up keycloak` → admin console shows `browser-stepup` bound, the
  Condition-LoA executions, the OTP policy, and `testuser` with an OTP credential.
- A normal login (no acr) still works and yields a token with `acr=basic`
  (inspect via `scripts/auth-code-flow.mjs` or the token endpoint).
- **`acr` is present on the access token** (not only the ID token). Decode the
  access token and confirm the `acr` claim is there; if absent, the mapper/scope
  from the bullet above is missing.
- **Step-up from an existing LoA-1 SSO session (the single most safety-critical
  check).** With a live `basic` session (SSO cookie present), request
  `acr_values=pro` and confirm: (a) the **OTP form is forced** rather than the
  `Cookie` execution short-circuiting the flow, (b) the resulting token has
  `acr=pro`, and (c) if OTP is **skipped or fails, no token with `acr=pro` is
  ever issued**. If the flow lets a `basic` cookie yield a `pro` token without
  OTP, the entire step-up control is a no-op.
- **Refresh behavior of an elevated session.** After obtaining a `pro` token,
  run the `refresh_token` grant and record what `acr` the refreshed access token
  carries (expected: Keycloak preserves the SSO session's achieved LoA, so it
  stays `pro` for the session lifetime without re-running OTP; see §5). This is a
  measured fact, not an assumption baked into the frontend.
- **Regression:** the iteration-1 `node scripts/e2e-login.mjs` still passes
  (base login → `/hello`), since base login is unchanged.

### Step 2: Backend `/server-details` + acr enforcement + RFC 9470 challenge

**Goal:** `GET /server-details` requires `acr=pro`; a LoA-1 token gets a proper
step-up `401`; a LoA-2 token gets the payload. `/hello` untouched.

- **`web/dto/ServerDetails.java`** (record) and **`ServerDetailsController.java`**:
  `GET /server-details` returns JSON with app name/version, JVM version, uptime /
  start time, active Spring profiles, hostname, server time (via `Environment`,
  `RuntimeMXBean`, `BuildProperties` if present). **No secrets/tokens/env dumps**
  (PRD-2 §3.4).
- **`SecurityConfig.java`** changes:
  - A `JwtAuthenticationConverter` that maps the `acr` claim to an authority
    (e.g. `acr=pro` → `ACR_pro`).
  - Authorization rules: `/hello` → `authenticated()` (as today);
    `/server-details` → requires the `pro` authority; everything else as today.
  - **Externalize the required `acr`, do not hardcode `"pro"`.** Follow the
    existing `app.security.jwt.audience` pattern (`application.yml` +
    `@Value` in `SecurityConfig`): add `app.security.stepup.acr` (default `pro`)
    so the required level is config, not a buried string literal. An integration
    test should assert this value is consistent with the realm's `acr.loa.map`
    so a Keycloak rename (`pro` → something) surfaces as a failing test rather
    than a silent total-denial of `/server-details`.
  - **`StepUpAccessDeniedHandler`** wired via
    `oauth2ResourceServer(...).accessDeniedHandler(...)` (and/or the resource
    server's bearer-token error handling): when an authenticated-but-insufficient
    principal is denied on `/server-details`, respond **`401`** with the RFC 9470
    `insufficient_user_authentication` challenge carrying `acr_values="pro"`,
    instead of the default `403`. A missing/invalid token keeps the ordinary
    resource-server `401`.
  - **CORS:** add `WWW-Authenticate` to `setExposedHeaders(...)` so the browser
    `fetch` can read the challenge; keep the existing allowed origin/methods.
- **Tests (`@WebMvcTest` slice, mocked `JwtDecoder`, same pattern as
  `HelloControllerTest`):** `ServerDetailsControllerTest` asserting:
  - no token → `401`;
  - token with `acr=basic` → `401` **and** the `WWW-Authenticate` header contains
    `insufficient_user_authentication` and `acr_values="pro"`;
  - token with `acr=pro` → `200` and a sane payload shape.
- **Optional integration test** (`ServerDetailsControllerIntegrationTest`, real
  Keycloak via Testcontainers): extend `KeycloakAuthCodeClient` to complete the
  OTP form (computing TOTP from the known secret) and request `acr=pro`, then
  assert the real `pro` token yields `200`. Feasibility depends on the client
  driving the OTP step; if it proves heavy, the real step-up is instead covered by
  the Step 4 e2e and this integration test is scoped to the `basic` → `401`
  challenge. (Decision recorded during implementation, not silently dropped.)

**Update `README.md`:** add `/server-details` to the endpoint table with its
`401` (no token), `401` step-up (basic token), `200` (pro token) behavior.

**Verify:**
- `./gradlew test --tests ServerDetailsControllerTest` green.
- With a **basic** token from Step 1: `GET /server-details` → `401` +
  `WWW-Authenticate: ... insufficient_user_authentication ... acr_values="pro"`.
- With a **pro** token: `GET /server-details` → `200` + payload.
- `GET /hello` unchanged; `HelloControllerTest` still green.

### Step 3: Frontend step-up + auto-retry

**Goal:** from the home screen, "Load server details" triggers the fetch; a step-up
challenge transparently re-authenticates at `pro` and retries; failures toast.

- **`page.tsx`:** add a **"Load server details"** button and a panel that renders
  the returned details (mirroring the existing `/hello` card styling). On click:
  - `fetch(`${API_URL}/server-details`, { Authorization: Bearer <token> })`.
  - On `200`: render the details.
  - On `401` with `insufficient_user_authentication` in `WWW-Authenticate`: parse
    the required `acr_values`, **allow-list it against the known set (`"pro"`)
    before use** (never forward arbitrary header content into a redirect
    parameter, the transport is plain HTTP and the header is attacker-rewritable
    on-path), then initiate **step-up** via next-auth `signIn` with that acr.
    Prefer the OIDC **`claims` essential-acr** form
    (`{"id_token":{"acr":{"essential":true,"values":["pro"]}}}`) over a bare
    `acr_values` hint where next-auth v4 supports passing it through, since per
    OIDC Core `acr_values` is only a hint while an essential `claims` request is
    the binding channel (exact plumbing confirmed against the bundled version).
    Persist a **one-shot, time-bounded** "retry server-details after step-up"
    marker (callbackUrl query flag or `sessionStorage`), **cleared immediately on
    use**, so it cannot replay a stale auto-retry against a later unrelated
    navigation; after the redirect back the app auto-retries the fetch and renders
    the result.
  - On other errors / a cancelled or failed step-up: **sonner error toast**
    (reusing the existing `TOAST_DURATION` pattern), leaving the base session and
    `/hello` intact (PRD-2 FR-F11).
- **`auth.ts` + `next-auth.d.ts`:** surface the token's `acr` into the session so
  the UI can tell `basic` from `pro` and avoid a redundant step-up if already
  elevated. **Derive `acr` by decoding the access token on every `jwt` callback
  pass (including after `refreshAccessToken`), not once at initial sign-in.** If
  it is cached only when `account` is present, a `session.acr === "pro"` can go
  stale after a refresh that returns a different level, making the UI skip a
  step-up it still needs (a redundant challenge loop, not a bypass, since the
  backend re-checks the real claim, but avoidable). Enforcement stays server-side
  regardless; `session.acr` is a UI hint only.
- Confirm CORS: the browser can only read `WWW-Authenticate` because Step 2 added
  it to exposed headers.

**Update `README.md`:** document the server-details UI and the step-up prompt in
the E2E walkthrough (the user completes TOTP on second-factor).

**Verify (browser E2E):** log in (`testuser`/`password`) → `/hello` shows as
today → click **Load server details** → Keycloak prompts for the **OTP** →
enter the current code → redirected back → server details render, and the session
token now has `acr=pro`. Cancelling the OTP shows a toast and keeps `/hello`
working.

### Step 4: Full headless e2e + orchestration/README polish

**Goal:** `scripts/e2e-login.mjs` covers the whole step-up flow with no browser,
and the docs are consolidated.

- Extend `scripts/e2e-login.mjs` (keep it dependency-free; TOTP via `node:crypto`):
  1. Base login → session → `GET /hello` (existing assertions).
  2. `GET /server-details` with the **basic** access token → assert `401` and that
     `WWW-Authenticate` contains `insufficient_user_authentication` and
     `acr_values="pro"`.
  3. **Step up:** re-run the next-auth sign-in requesting `acr=pro` (append the acr
     authorization param the same way `signIn` does in Step 3), follow to the
     Keycloak **OTP form**, compute the current TOTP from the **known seed secret**
     (HMAC-SHA1, 6 digits, 30s, matching the realm OTP policy), submit it, follow
     the callback so next-auth mints the elevated session.
  4. Read the session, `GET /server-details` with the **pro** token → assert `200`
     and the expected payload fields.
  5. **Refresh assertion:** force a token refresh of the elevated session and
     assert the refreshed access token's `acr` matches what Step 1 measured
     (documents the real refresh behavior rather than assuming it).
  6. Print `E2E PASSED` covering base + step-up.
- A tiny **TOTP helper** in the script (or `scripts/lib/totp.mjs`) implementing the
  standard TOTP so codes match Keycloak exactly.
- **Finalize `README.md`:** consolidation pass so the run instructions, the
  step-up section, the seed TOTP secret note, and the endpoint table are accurate
  end to end, including the `node scripts/e2e-login.mjs` step-up smoke test.
- **`CLAUDE.md`:** add a one-line pointer under "What this is" so the iteration
  trail is discoverable (`PRD-2.md` / `PLAN-2.md` = step-up iteration), and note
  `/server-details` + the step-up decisions in the architecture section.

**Verify:** from a clean state, `docker compose up --build` then
`node scripts/e2e-login.mjs` passes the full base + step-up flow with no manual
steps beyond the one-time `/etc/hosts` entry. `./gradlew test` green.

---

## 4. Acceptance mapping (PRD-2 §6)

| PRD-2 criterion                                             | Covered in |
|------------------------------------------------------------|------------|
| 1. Clean `up`: realm has acr map + step-up flow + TOTP user | Step 1     |
| 2. `/hello` still returns greeting at base level            | Steps 1–2  |
| 3. `/server-details` + basic token → `401` step-up challenge| Step 2     |
| 4. `/server-details` + no/invalid token → ordinary `401`    | Step 2     |
| 5. Browser: server-details at LoA 1 prompts second factor   | Steps 1,3  |
| 6. After OTP, auto-retry succeeds; token `acr=pro`          | Step 3     |
| 7. Cancel/fail step-up → toast, base session intact         | Step 3     |
| 8. Headless e2e exercises criteria 2–6                      | Step 4     |
| NFR-5 no regression (iteration-1 §7 still passes)           | all steps  |

---

## 5. Risks / watch-items

- **TOTP reproducibility.** The seed user's OTP `secretData`/encoding and the realm
  OTP policy (algorithm/digits/period) must match exactly what the e2e computes, or
  codes won't validate. Pin all three and share one secret; validate the exact
  Keycloak 26 `otp` credential JSON shape during Step 1.
- **Condition-LoA semantics.** The exact requirement settings for the Condition-LoA
  executions and the `acr.loa.map` attribute key changed across Keycloak versions;
  confirm against the 26.x step-up docs. Max age 0 on the LoA-2 condition is what
  forces a real re-challenge inside an existing session.
- **Base-login regression.** The custom flow must leave LoA-1 login (and thus
  `/hello`) byte-for-byte behaviorally unchanged. The iteration-1 e2e is the guard;
  run it after Step 1.
- **Spring Security 7 has no turnkey RFC 9470 emitter (assume so until confirmed).**
  The `insufficient_user_authentication` `401` is produced by a custom
  access-denied/bearer-error handler; verify the exact hook on the shipped version
  rather than copying an older API.
- **next-auth v4 per-request acr.** Passing `acr_values`/`claims` dynamically
  through `signIn` (not just static provider config) and getting the new `acr` into
  the session needs confirmation against the bundled next-auth v4; the whole-page
  redirect means the retry must be resumed via a persisted marker.
- **CORS exposed header.** If `WWW-Authenticate` is not in `exposedHeaders`, the
  browser fetch cannot read the challenge and step-up never triggers.
- **`acr` must be on the access token.** Enforcement reads the Bearer access
  token; if `acr` is only in the ID token the `pro` authority is never granted and
  `/server-details` is challenged forever. Add the mapper/scope in Step 1 and
  assert `acr` on the access token in Step 1's verify.
- **Elevated session stays elevated across refresh (accepted POC limitation).**
  Keycloak's `refresh_token` grant is expected to keep minting `acr=pro` for the
  SSO session lifetime (`ssoSessionMaxLifespan: 3600`, `ssoSessionIdleTimeout:
  1800`) without re-running OTP, so `max age: 0` only forces a fresh OTP at the
  authorization-request boundary, not per token use, and a leaked `pro` token/
  refresh token is reusable for up to that window. This is accepted per PRD-2 §2
  non-goals (no session-lifetime re-prompt policy) but must not be assumed to
  auto-downgrade; Step 1/Step 4 measure the actual refreshed `acr`.
- **`max age: 0` is a demo-determinism choice, revisit before real use.** A real
  deployment would use a non-zero max age (re-verify OTP only if the last
  elevation is older than N minutes) to avoid step-up fatigue.
- **OTP brute-force.** Adding a guessable 6-digit factor (`digits: 6`,
  `lookAheadWindow: 1`) is new attack surface; a real deployment should enable
  Keycloak realm brute-force protection (`bruteForceProtected`). Not a regression
  from iteration 1, noted for the record.
- **No sender-constraining / replay protection.** A leaked `pro` bearer token is
  as replayable as a `basic` one for its `accessTokenLifespan` (300s). RFC 9470
  raises assurance of *who* authenticated, not token-theft resistance; a real
  deployment guarding something genuinely sensitive would add DPoP/mTLS on top of
  the `acr` check. Accepted for the POC.

---

## 6. Deliverables checklist

- [x] `keycloak/realm-export.json`: `acr.loa.map`, OTP policy, `browser-stepup`
      flow (+ Condition-LoA config), seed `testuser` TOTP credential, protocol
      mapper/scope putting `acr` on the **access** token
- [x] `backend/` `GET /server-details` + DTO
- [x] `backend/` acr enforcement (required `acr` externalized as config, not
      hardcoded) + RFC 9470 `StepUpAccessDeniedHandler` + CORS exposed
      `WWW-Authenticate`
- [x] `backend/` `ServerDetailsControllerTest` (no token / basic → 401 challenge /
      pro → 200); integration test asserting config `acr` matches realm `acr.loa.map`
- [x] `frontend/` server-details UI + step-up (allow-listed acr, one-shot retry
      marker) + auto-retry + error toasts; `acr` derived fresh per `jwt` pass
- [x] `scripts/e2e-login.mjs` extended with TOTP + full step-up + refresh-acr assertion
- [x] `README.md` (step-up section, **distinct loud TOTP-seed warning**, endpoint
      table) + `CLAUDE.md` iteration pointer

---

## 7. Next step

On approval of this plan, implementation proceeds **Step 1 → Step 4**, verifying at
each step (and re-running the iteration-1 e2e as the no-regression guard) before
moving on.

**No implementation will be done until PRD-2 and PLAN-2 are approved.**
