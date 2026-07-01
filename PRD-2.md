# PRD (Iteration 2): Step-Up Authentication for `/server-details`

**Status:** Draft, for review
**Author:** hcussi@gmail.com
**Date:** 2026-07-01
**Type:** Proof of Concept (POC), iteration 2
**Builds on:** [PRD.md](PRD.md) (iteration 1, complete)

---

## 1. Overview

Iteration 1 proved a single-assurance flow: log in through Keycloak, receive a
JWT, call the protected `GET /hello`. Iteration 2 adds **step-up authentication**
(also called incremental authorization / Level of Authentication, LoA).

A new backend endpoint **`GET /server-details`** returns runtime information about
the backend process. It is protected at a **higher assurance level** than
`/hello`: a normal logged-in session is **not** sufficient. When the user tries
to reach it with only the base-level session, the backend rejects the call with a
**step-up challenge**, the frontend transparently re-authenticates the user at the
higher level with Keycloak, and the retry succeeds.

The base level (LoA 1) is the existing username/password login. The elevated
level (LoA 2) requires a second, stronger authentication step configured in
Keycloak. This iteration wires that second level end to end: Keycloak flow +
`acr` claim, backend enforcement + RFC 9470 challenge, frontend step-up + retry.

This remains a POC and a reference template, not a production system. The prior
Non-Goals (PRD.md §2) still apply, extended in §2 below.

---

## 2. Goals

- Demonstrate a working **OIDC step-up** flow: two endpoints on the same backend
  with two different required assurance levels, driven by the token's **`acr`**
  (Authentication Context Class Reference) claim.
- Configure **Keycloak** with an ACR-to-LoA mapping and a **conditional
  authentication flow** that enforces a stronger factor only when the elevated
  level is requested (so the base `/hello` login is unchanged).
- Have the **backend** enforce the required `acr` on `/server-details` and, when
  it is missing/insufficient, return a standards-based **step-up challenge**
  (`WWW-Authenticate: Bearer error="insufficient_user_authentication"`, per
  RFC 9470) rather than a bare `403`.
- Have the **frontend** react to that challenge by re-running the OIDC flow with
  the requested `acr_values`, then automatically **retry** the call and display
  the result.
- Keep the whole thing **reproducible via `docker compose up`**, including the
  step-up configuration in the imported realm, consistent with PRD.md NFR-1.

### Non-Goals (in addition to PRD.md §2)

- Full MFA **enrollment UX** (guided TOTP/WebAuthn setup screens). The seed
  user's second factor is pre-provisioned in the realm (see Open Decisions).
- WebAuthn / passkeys, hardware tokens, or SMS/email OTP delivery.
- Risk-based / adaptive step-up (device fingerprint, geo, anomaly scoring).
- Per-role or per-scope authorization. Access is still "authenticated at the
  required level," not role-based.
- Remembering the elevated level across sessions or enforcing a max-age re-prompt
  policy beyond what the demo needs.

---

## 3. Architecture delta

Same three services and the same single-issuer / `/etc/hosts` strategy as
iteration 1 (PRD.md §3, PLAN.md §2). What changes:

### 3.1 Assurance levels

| Level | Meaning                 | How Keycloak satisfies it        | `acr` in token |
|-------|-------------------------|----------------------------------|----------------|
| LoA 1 | Base login              | username + password (as today)   | `"basic"`      |
| LoA 2 | Stepped-up login        | password **plus TOTP**           | `"pro"`        |

Keycloak maps these named `acr` values to LoA numbers via the realm's
`acr_loa_map` (e.g. `{"basic":1,"pro":2}`). Decisions resolved in §8.

### 3.2 Endpoint protection map

| Endpoint              | Required level | On insufficient auth                     |
|-----------------------|----------------|------------------------------------------|
| `GET /hello`          | LoA 1          | `401` (no/invalid token), as today       |
| `GET /server-details` | LoA 2          | `401` **step-up challenge** (RFC 9470)    |

### 3.3 Step-up flow

```
  Frontend (already logged in at LoA 1)
     │  1. GET /server-details  (Bearer LoA-1 token)
     ▼
  Backend  ── acr = "basic", endpoint needs "pro" ──►  reject
     │  2. 401 + WWW-Authenticate: Bearer error="insufficient_user_authentication",
     │        acr_values="pro"
     ▼
  Frontend reads the required acr_values, re-runs OIDC login
     │  3. Authorization request with acr_values=pro (claims param)
     ▼
  Keycloak  ── conditional flow triggers the 2nd factor ──►  user completes it
     │  4. New tokens, acr = "pro"
     ▼
  Frontend  5. retry GET /server-details (Bearer LoA-2 token)  ──►  200 + server details
```

### 3.4 `/server-details` payload

`GET /server-details` returns backend runtime info, for example (final field list
in PLAN-2): app name/version, JVM version, uptime/start time, active Spring
profiles, hostname, server time. **No secrets, tokens, env values, or
credentials** are included (NFR carryover from PRD.md NFR-4). The point is to have
a plausibly "sensitive" endpoint worth protecting more strongly, not to leak
anything.

---

## 4. Functional Requirements (iteration 2)

Numbered to continue PRD.md §4 without collision.

### 4.1 Keycloak

- **FR-K9:** The `web` realm defines an **`acr_loa_map`** mapping the chosen
  `acr` values to LoA numbers (base and elevated).
- **FR-K10:** The realm's browser authentication flow includes a **conditional
  subflow keyed on Level of Authentication** so the **second factor is required
  only when LoA 2 is requested**. Base login (LoA 1) behavior is unchanged: the
  iteration-1 login and `/hello` flow must still pass exactly as before.
- **FR-K11:** The `nextjs-frontend` client is configured so the elevated level
  can be requested via **`acr_values` / the `claims` parameter** and so the
  issued token carries the resulting **`acr`** claim.
- **FR-K12:** The **seed user** can complete the elevated level in a fully
  scripted/reproducible way (second factor pre-provisioned in the realm export,
  see Open Decisions), so no manual enrollment is needed on first run.

### 4.2 Backend (Spring Boot)

- **FR-B7:** Expose **`GET /server-details`** returning backend runtime info
  (see §3.4) as JSON.
- **FR-B8:** `/server-details` requires a valid JWT **whose `acr` claim meets or
  exceeds the elevated level**. A valid LoA-1 token is authenticated but **not**
  authorized for this endpoint.
- **FR-B9:** When the token is valid but the level is insufficient, respond with
  a **step-up challenge** per **RFC 9470**: HTTP `401` with
  `WWW-Authenticate: Bearer error="insufficient_user_authentication",
  error_description="...", acr_values="<required>"`. A missing/invalid token
  still returns the ordinary `401` unauthorized.
- **FR-B10:** `/hello` behavior is **unchanged** (still LoA 1). CORS must expose
  the `WWW-Authenticate` response header to the browser so the frontend can read
  the required `acr_values`.

### 4.3 Frontend (Next.js)

- **FR-F9:** From the authenticated home screen, the user can trigger a call to
  **`/server-details`** (e.g. a "Load server details" button).
- **FR-F10:** On a **step-up challenge** (`401` +
  `insufficient_user_authentication`), the frontend reads the required
  `acr_values` and **re-initiates the OIDC login requesting that level** (passing
  `acr_values` / `claims` through next-auth), then **retries** the call and
  renders the returned server details.
- **FR-F11:** Step-up **failures** (user cancels the second factor, refresh at the
  elevated level fails, etc.) surface as the existing **sonner error toasts**;
  the app returns cleanly to the authenticated home state without breaking the
  existing session.

### 4.4 Integration / Orchestration

- **FR-I4:** All step-up configuration ships **inside the imported realm** and via
  existing env/compose config, so `docker compose up` from a clean checkout yields
  a stack where the step-up flow works with no manual Keycloak console steps.
- **FR-I5:** The headless **e2e check** (`scripts/e2e-login.mjs`) is extended to
  cover step-up: base login → `/hello` succeeds, `/server-details` at LoA 1 is
  challenged, step-up completes, `/server-details` at LoA 2 succeeds. (Feasibility
  depends on the second-factor choice, see Open Decisions.)

---

## 5. Non-Functional Requirements (carryover + additions)

All PRD.md §5 NFRs still hold. Additionally:

- **NFR-5 (No regression):** The iteration-1 acceptance criteria (PRD.md §7) must
  still pass unchanged. Step-up is additive.
- **NFR-6 (Standards-based challenge):** The insufficient-level response follows
  RFC 9470 rather than an ad-hoc contract, so the pattern is transferable.

---

## 6. Acceptance Criteria (iteration 2)

In addition to PRD.md §7 (which must still pass):

1. `docker compose up` from a clean checkout brings up a stack where the realm
   already contains the ACR/LoA map and the conditional step-up flow (visible in
   the admin console), with the seed user able to complete the elevated level.
2. Logged in at the base level, `GET /hello` still returns the greeting.
3. `GET /server-details` with a **LoA-1** token returns **`401`** with a
   `WWW-Authenticate: Bearer error="insufficient_user_authentication"` header
   carrying the required `acr_values`.
4. `GET /server-details` with **no/invalid** token returns an ordinary `401`.
5. In the browser, triggering server details while at LoA 1 causes a **step-up
   prompt** (the second factor) at Keycloak.
6. After completing the second factor, the app **automatically retries** and
   displays the server details, and the token now carries the elevated `acr`.
7. Cancelling or failing the second factor shows an **error toast** and leaves the
   base session intact (still able to use `/hello`).
8. The extended `scripts/e2e-login.mjs` exercises criteria 2 through 6 headlessly
   (subject to the second-factor decision in §8).

---

## 7. Technology / stack notes

No new runtime services. Net-new mechanics to validate during planning
(consistent with PRD.md "version gotchas" caution, since this stack is newer than
most training data):

- **Keycloak step-up**: the `acr_loa_map` realm attribute and the
  "Conditional - Level of Authentication" authenticator in the browser flow.
  Exact realm-export JSON shape to be confirmed against the Keycloak 26 docs in
  PLAN-2.
- **Spring Security (Boot 4 / Security 7) step-up**: enforcing an `acr` claim and
  emitting the RFC 9470 `insufficient_user_authentication` challenge. The exact
  API (authorization manager + a custom entry point / `BearerTokenError`, or any
  built-in step-up support) is to be confirmed against the shipped Spring Security
  version in PLAN-2, not assumed from older docs.
- **next-auth v4 step-up**: passing `acr_values` / the OIDC `claims` parameter
  through the Keycloak provider and forcing a fresh authorization (not silently
  reusing the LoA-1 session), plus surfacing the new `acr` into the session. To be
  confirmed in PLAN-2.

---

## 8. Resolved Decisions (confirmed 2026-07-01)

1. **Elevated (LoA 2) factor: ✅ TOTP.** LoA 1 = username + password, LoA 2 =
   password + TOTP. The seed user's TOTP credential is **pre-seeded in the realm
   export with a known secret** so the flow is reproducible and the headless e2e
   can compute the code.
2. **ACR naming: ✅ named levels** `basic` (LoA 1) and `pro` (LoA 2), mapped via
   `acr_loa_map` = `{"basic":1,"pro":2}`. The frontend requests `pro` on step-up.
3. **e2e coverage: ✅ full.** `scripts/e2e-login.mjs` computes the TOTP and
   completes the elevated flow end to end (base login → `/hello`, LoA-1 challenge
   on `/server-details`, step-up, LoA-2 success).

---

## 9. Next step

On your answers to §8 and approval of this PRD, I will write **`PLAN-2.md`**: an
ordered, verifiable implementation plan (realm step-up config, backend endpoint +
`acr` enforcement + RFC 9470 challenge, frontend step-up + retry, e2e + README
updates), in the same incremental style as PLAN.md.

**No implementation will be done until PRD-2 and PLAN-2 are approved.**
