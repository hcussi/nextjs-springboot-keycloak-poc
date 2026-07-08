# PRD (Iteration 5): Browser-Key React SPA with WebCrypto + IndexedDB DPoP

**Status:** Draft, for review
**Author:** hcussi@gmail.com
**Date:** 2026-07-08
**Type:** Proof of Concept (POC), iteration 5
**Builds on:** [PRD-3.md](PRD-3.md) (DPoP), with [PRD-2.md](PRD-2.md) (step-up) and
[PRD-4.md](PRD-4.md) (distributed replay / nonce) as compatible layers

> **Dependency:** targets the same Spring Boot resource server and Keycloak realm.
> It requires the iteration-3 DPoP backend to be in place, and interoperates with
> the iteration-2 step-up and (if present) the iteration-4 nonce on
> `/server-details`.

---

## 1. Overview

Every frontend so far has been the **Next.js** app, where the confidential client
and the DPoP key live in the **server tier** and the browser reaches the backend
through a BFF proxy (PRD-3 Decision A). PRD-3 §8.1 explicitly recorded the
alternative it did **not** build: a **public client with a non-extractable key in
the browser**. Iteration 5 builds exactly that, as a **separate, additional
frontend**, to demonstrate the other end of the DPoP key-custody spectrum.

The new app is a **plain React SPA (Vite + React + TypeScript, no Next.js)** that:

1. Generates a **non-extractable ECDSA P-256 key pair in the browser** with the
   **WebCrypto** API and persists it in **IndexedDB**. The raw private key never
   exists in JavaScript and can never be exported, not even by the app itself.
2. **Builds and signs each DPoP proof in the browser** with that key (via
   `crypto.subtle.sign`), rather than handing signing to a server tier. This is the
   "build the DPoP header differently" goal: client-side WebCrypto signing with a
   non-extractable IndexedDB key, in contrast to the Next.js server signing an
   in-memory JWK with `jose`.
3. Runs the OIDC **Authorization Code + PKCE** flow as a **public client** (no
   secret) directly from the browser, DPoP-binding the token at the token endpoint,
   then calls the backend **directly** with `Authorization: DPoP <token>` and a
   fresh proof (no BFF proxy, because the SPA legitimately holds the key and token).

The existing Next.js app is **not replaced**; the two coexist as reference
implementations of the two custody models, both talking to the same backend and
realm. This remains a POC, not a production system; all prior Non-Goals still apply.

---

## 2. Goals

- Stand up a **new React SPA** (Vite, TypeScript, no Next.js, no next-auth) served
  as static assets, as an additional frontend for the same backend/realm.
- Generate a **non-extractable ES256 key pair via WebCrypto** and store it in
  **IndexedDB**, so the private key is never exportable and survives reloads while
  never being readable by script.
- **Construct DPoP proofs client-side**, signing with the IndexedDB key, for every
  token request (auth-code exchange and refresh) and every backend call (`ath`
  bound), including reactive `use_dpop_nonce` handling for `/server-details`.
- Add a **public, DPoP-required Keycloak client** (`spa-frontend`) and let the SPA
  complete base login and step-up (`acr=pro`) fully in the browser.
- Have the **backend accept the SPA** (its audience and its cross-origin DPoP
  calls) without weakening any existing check.
- Keep the whole thing **reproducible via `docker compose up`** (the SPA is a new
  service) and covered by a headless **browser** e2e (WebCrypto/IndexedDB need a
  real browser).
- Preserve **all prior behavior**: the Next.js app, `/hello`, step-up, DPoP binding,
  and (if present) the iteration-4 nonce all keep working unchanged.

### Non-Goals (in addition to prior PRDs)

- **Replacing the Next.js frontend.** Both stay; this is an additional app.
- A **confidential client or BFF proxy** for the SPA. The point of this iteration is
  browser custody, so the SPA is a public client with no server tier of its own.
- **Server-side rendering**, a Node backend-for-frontend, or sharing a session/cookie
  with the Next.js app.
- **Persisting the access token** to storage. The token stays in memory; only the
  non-extractable key handle lives in IndexedDB.
- Making XSS harmless (see the threat model, §3.5): non-extractable keys stop key
  *exfiltration*, not in-page misuse while the app is live.
- Changing Keycloak's realm-level flows, or the backend's DPoP/step-up logic beyond
  audience acceptance and CORS.

---

## 3. Architecture delta

Same backend and Keycloak realm; a new frontend and the config to let it in.

### 3.1 New component

| Component | Technology | Port (host) | Role |
|-----------|------------|-------------|------|
| SPA frontend | React + Vite + TypeScript, static (nginx) | 3100 | Public OIDC client; browser-held DPoP key |

The SPA is built to static assets and served by a small static server. It coexists
with the Next.js frontend (still on 3000); both call the backend and Keycloak.

### 3.2 Key custody: WebCrypto + IndexedDB

- The key pair is created with
  `crypto.subtle.generateKey({name:"ECDSA", namedCurve:"P-256"}, /*extractable*/ false, ["sign"])`.
  The **private** `CryptoKey` is **non-extractable**; the **public** `CryptoKey`
  is exportable (public keys carry no secret) so the app can derive the public JWK
  and its RFC 7638 thumbprint for the proof header and `cnf.jkt` comparison.
- Both `CryptoKey` handles are stored in **IndexedDB**. A non-extractable
  `CryptoKey` can be structured-cloned into IndexedDB and reloaded later as an
  opaque handle: usable for `sign`, never readable as bytes. This is what makes the
  key survive reloads without ever being exfiltratable.
- The key is generated **per login** (§8.6): created at login and reused across
  reloads within the session, then cleared from IndexedDB on explicit logout, so a
  later login mints a fresh key and a freshly bound token.

### 3.3 Building the DPoP proof in the browser

Each proof is assembled and signed in the browser:

```
  header  { typ:"dpop+jwt", alg:"ES256", jwk: <public JWK from IndexedDB key> }
  payload { jti, htm, htu, iat, [ath], [nonce] }
  signature = base64url( crypto.subtle.sign({name:"ECDSA", hash:"SHA-256"},
                                            privateKey /* from IndexedDB */, signingInput) )
```

`crypto.subtle.sign` returns the raw R||S (IEEE P-1363) signature that JOSE ES256
expects. `ath` (base64url SHA-256 of the access token) is added on resource calls;
`nonce` is added on a `use_dpop_nonce` retry. This mirrors, byte for byte, the
proofs the backend already validates (iteration 3), but the signer is the browser's
non-extractable key rather than a server-side `jose` key.

### 3.4 Token and request flow (public client, direct calls)

```
  SPA (browser)                         Keycloak                 Backend
  ─────────────                         ────────                 ───────
  generate/load non-extractable key (IndexedDB)
     │ 1. auth-code + PKCE (public client, no secret), acr_values as needed
     ├───────────────────────────────────►│
     │ 2. token request + DPoP proof (browser-signed)
     ├───────────────────────────────────►│  binds token: cnf.jkt = thumbprint
     │ 3. access token (+ DPoP-bound refresh token, public client)
     │◄─────────────────────────────────── │
     │ 4. GET /hello  (Authorization: DPoP <token>, DPoP: <fresh proof, ath>)
     ├──────────────────────────────────────────────────────────►│  validates proof
     │ 5. 200 (or 401 use_dpop_nonce on /server-details → retry with nonce,
     │        or 401 step-up → re-auth with acr=pro)
     │◄────────────────────────────────────────────────────────── │
```

For a **public** client Keycloak DPoP-binds **both** the access and the refresh
token, so the SPA's **refresh** requests also carry a proof (unlike the confidential
Next.js client, where only the access token is bound).

### 3.5 Threat model (state it precisely, do not oversell)

- **What the browser key buys:** the private key is **non-extractable** and stored
  as an opaque IndexedDB handle, so **even an XSS attacker cannot exfiltrate it**.
  A stolen access token is useless without the key (sender-constrained), and the
  key cannot be copied out to be used elsewhere. This is strictly stronger against
  *token/key exfiltration* than a public client without DPoP, and it is the property
  the Next.js server-tier model could not offer to the browser.
- **What it does not buy:** an XSS payload running **inside the live page** can still
  call `crypto.subtle.sign` with the non-extractable key and make authenticated
  requests **while the page is open**. DPoP + non-extractable keys reduce token theft
  to "attacker must operate from within the compromised origin, in real time," not to
  zero. The access token also lives in page memory. This is the honest boundary and
  must be documented, not glossed.

### 3.6 Backend and Keycloak deltas

- **Keycloak:** a new **public** client `spa-frontend` (PKCE required, DPoP required,
  no secret, redirect URIs + web origins for `http://localhost:3100`), plus an
  audience mapper so its tokens carry an `aud` the backend accepts.
- **Backend:** accept the SPA's **audience** (make the accepted audience a
  configurable set rather than a single value) and allow the SPA **origin** through
  CORS with the `DPoP` request header, exposing `WWW-Authenticate` and (iteration 4)
  `DPoP-Nonce`. No change to DPoP proof validation, step-up, or the mandatory
  `cnf.jkt` check.

---

## 4. Functional Requirements (iteration 5)

Numbered to continue prior PRDs; the SPA uses a new **FR-S** prefix.

### 4.1 Keycloak

- **FR-K17:** A new **public** client `spa-frontend` exists in the `web` realm:
  standard flow + PKCE (S256) **required**, **DPoP-bound tokens required**
  (`dpop.bound.access.tokens=true`), **no client secret**, direct-access grants off,
  redirect URIs and web origins scoped to `http://localhost:3100`, and an audience
  mapper putting a backend-accepted value in the access token's `aud`.

### 4.2 SPA frontend (new app)

- **FR-S1:** A React + Vite + TypeScript SPA (no Next.js, no next-auth) builds to
  static assets and is served on `http://localhost:3100`.
- **FR-S2:** On first use the SPA **generates a non-extractable ES256 key pair via
  WebCrypto** and stores the `CryptoKey` handles in **IndexedDB**; the private key is
  never exportable and never leaves the browser.
- **FR-S3:** The SPA runs OIDC **Authorization Code + PKCE** as a public client and
  attaches a **browser-signed DPoP proof** to the token request, obtaining a
  DPoP-bound token whose `cnf.jkt` equals the key's thumbprint.
- **FR-S4:** The SPA **signs a fresh DPoP proof in the browser for every backend
  call** (`htm`/`htu`, and `ath` = hash of the access token) and calls the backend
  with the `DPoP` authorization scheme.
- **FR-S5:** The SPA handles **step-up**: on the RFC 9470
  `insufficient_user_authentication` challenge from `/server-details`, it re-runs the
  OIDC flow with `acr_values=pro`, then retries and renders the result.
- **FR-S6:** The SPA handles the **`use_dpop_nonce` challenge** (iteration 4, on
  `/server-details`) by retrying once with the supplied `DPoP-Nonce` embedded in the
  proof.
- **FR-S7:** The SPA **refreshes** the access token using the DPoP-bound refresh
  token with a browser-signed proof (public client: refresh is bound too), keeping
  the same key. The access token is held **in memory only**; IndexedDB holds only the
  key handle, never the token.
- **FR-S8:** **Logout** clears the SPA session and the IndexedDB key (and ends the
  Keycloak SSO session), so a subsequent login mints a fresh key and token. Errors
  (failed step-up, unreachable API, refused proof) surface as visible, non-fatal UI
  messages.

### 4.3 Backend (Spring Boot)

- **FR-B21:** The resource server accepts the **SPA's audience**: the accepted
  audience becomes a configurable **set** (still including the existing value), so a
  token minted for `spa-frontend` is validated without weakening the check for any
  single client.
- **FR-B22:** **CORS** allows the SPA origin (`http://localhost:3100`) to call the
  backend with the `DPoP` request header, and exposes `WWW-Authenticate` and (if
  iteration 4 is present) `DPoP-Nonce`, so the browser can read the challenges. The
  existing origins/behavior are unchanged.

### 4.4 Integration / Orchestration

- **FR-I10:** `docker-compose` adds the **SPA** as a health-gated static service on
  `3100`, configured (issuer, client id, backend URL) via build-time env, so
  `docker compose up` from a clean checkout brings up both frontends and the SPA
  DPoP flow works with no manual steps (beyond the existing `/etc/hosts` entry).
- **FR-I11:** A headless **browser** e2e (Playwright, since WebCrypto/IndexedDB need
  a real browser) drives the SPA: login → key in IndexedDB (non-extractable) →
  `/hello` under DPoP → step-up on `/server-details` → success, plus a negative
  (a token without the matching proof is refused). Existing node e2e for the Next.js
  app keep passing.

---

## 5. Non-Functional Requirements (carryover + additions)

All prior NFRs still hold. Additionally:

- **NFR-15 (Key non-exfiltration):** the SPA's private key is non-extractable and
  never leaves the browser; no code path exports it, logs it, or writes token/key
  bytes to storage. An automated check asserts the IndexedDB key is non-extractable.
- **NFR-16 (Honest threat model):** the docs state precisely what the browser-key
  model defends (token/key exfiltration) and what it does not (in-page XSS misuse
  while live), per §3.5.
- **NFR-17 (Coexistence / no regression):** the Next.js frontend and all backend
  behavior continue to work unchanged; the two frontends are independent.

---

## 6. Acceptance Criteria (iteration 5)

In addition to all prior acceptance criteria (which must still pass):

1. `docker compose up` from a clean checkout serves the SPA on `http://localhost:3100`
   alongside the Next.js app, backend, and Keycloak (and Redis if iteration 4 is in).
2. Logging into the SPA generates a **non-extractable** ES256 key in **IndexedDB**
   (verifiable: the stored `CryptoKey` has `extractable === false`) and yields a
   token whose `cnf.jkt` equals the key's thumbprint.
3. `GET /hello` from the SPA succeeds under the `DPoP` scheme with a
   browser-signed proof.
4. `GET /server-details` triggers step-up in the SPA; after completing the second
   factor (and the `use_dpop_nonce` retry when iteration 4 is present), it returns
   the details.
5. A token captured from the SPA and replayed **without** the (non-extractable) key
   is refused `401` (the sender-constraint holds), and the key cannot be exported
   from IndexedDB.
6. The Next.js frontend still works end to end; nothing about it changed.
7. The Playwright SPA e2e prints `E2E PASSED`, and `cd backend && ./gradlew test`
   passes.

---

## 7. Technology / stack notes

Net-new mechanics to validate during planning (this stack is newer than most
training data; confirm against shipped versions, do not assume):

- **WebCrypto non-extractable keys in IndexedDB.** Confirm the target browsers
  structured-clone a non-extractable `CryptoKey` into IndexedDB and reload it as a
  usable signing handle (well supported in current Chromium/Firefox; the Playwright
  e2e is the guard). Public-key export for the JWK/thumbprint is via
  `crypto.subtle.exportKey("jwk", publicKey)`.
- **DPoP proof assembly in the browser.** ES256 signing yields the raw R||S
  signature JOSE needs; base64url everything, strip query/fragment from `htu`. The
  proof must match the backend validators bit for bit (iteration 3).
- **Public client + DPoP in Keycloak.** For a public client Keycloak binds **both**
  access and refresh tokens; the SPA's refresh call needs a proof. PKCE is mandatory
  (no secret). Confirm the exact `spa-frontend` realm-export JSON shape against
  Keycloak 26.6.
- **OIDC + DPoP library.** **`oidc-client-ts`** (§8.5): its `IndexedDbDPoPStore`
  generates and stores the non-extractable ES256 key in IndexedDB and its
  `dpopProof(url, user)` builds resource-request proofs, so the SPA gets the exact
  browser-key model without hand-rolling crypto. Two items to verify against the
  pinned version in the PLAN-5 spike: DPoP-bound **refresh** for a public client, and
  the **`use_dpop_nonce` retry** on `/server-details`; `oidc-spa` (automatic nonce)
  and `oauth4webapi` (native `DPoP-Nonce`) are the fallbacks if needed.
- **Backend audience as a set.** Extending `AudienceValidator` / the config from a
  single audience to a set is a small change; confirm it keeps rejecting tokens whose
  `aud` matches none of the accepted values.
- **Browser e2e.** Playwright is available; it is required here because the node
  scripts cannot exercise WebCrypto/IndexedDB.

---

## 8. Resolved Decisions (confirmed 2026-07-08)

1. **New app, React SPA, no Next.js: ✅.** A separate Vite + React + TypeScript SPA,
   additional to (not replacing) the Next.js frontend.
2. **Browser-held key via WebCrypto + IndexedDB: ✅.** Non-extractable ES256 key,
   stored as an opaque IndexedDB handle; the private key never leaves the browser.
3. **DPoP proof built and signed in the browser: ✅**, with the IndexedDB key, for
   every token request and backend call.
4. **Public client + direct backend calls (no BFF): ✅.** The SPA is a public OIDC
   client and calls the backend directly under the `DPoP` scheme.
5. **OIDC + DPoP client library: ✅ `oidc-client-ts` (primary), evaluated against
   the alternatives.** This supersedes the earlier "hand-rolled PKCE" note: rolling
   our own re-implements exactly what a good library already does, and the subtle
   parts (base64url, raw R‖S ES256, `htu` normalization, nonce retry, `ath`) are
   precisely where hand-rolled crypto goes wrong.

   | Option | DPoP + browser-key fit | Verdict |
   |--------|------------------------|---------|
   | **`oidc-client-ts`** (authts) | Native DPoP with an **`IndexedDbDPoPStore`** that generates and stores a **non-extractable** `CryptoKeyPair` in IndexedDB (exactly the PRD-5 key model, `extractable:false`), `bind_authorization_code` token binding, and `UserManager.dpopProof(url, user)` for resource-request proofs, on a mature PKCE/session/silent-renew base. | **Chosen.** Verifiably realizes the non-extractable IndexedDB key model (FR-S2 / NFR-15) without hand-rolling crypto; established, focused SPA OIDC library. |
   | **`oidc-spa`** | Transparent `fetch`/`XHR` interceptors that auto-attach the proof and **handle `use_dpop_nonce` tracking/retry automatically** (closes gaps (a)/(b) below); framework-agnostic. But its docs do **not** confirm a non-extractable WebCrypto key in IndexedDB, and `mode:"auto"` falls back to Bearer when the RS lacks DPoP. | **Strong alternative.** If the PLAN-5 spike confirms non-extractable IndexedDB keys and a DPoP-required (non-fallback) mode, reconsider as primary, since it also solves nonce + refresh out of the box. |
   | **`oauth4webapi`** (panva) | Low-level, browser-native, first-class DPoP with a `CryptoKeyPair` and built-in `DPoP-Nonce` handling, by the `jose`/`openid-client` author. More manual flow wiring. | **Fallback.** Best for maximal control, or if `oidc-client-ts`'s nonce/refresh handling proves insufficient. |
   | **Keycloak JS adapter (`keycloak-js`)** | **No DPoP support** (keycloak/keycloak#30874 open); would force hand-rolling the whole DPoP layer anyway. | **Rejected.** |

   Two gaps to close in the PLAN-5 spike, both because the docs are silent on them:
   **(a) public-client refresh binding** (Keycloak binds the refresh token for public
   clients, so the refresh request needs a proof; confirm `oidc-client-ts` signs it,
   else wrap it), and **(b) the `use_dpop_nonce` retry** on `/server-details`
   (iteration 4; confirm a nonce can be threaded through `dpopProof`, else add a
   one-shot retry wrapper). If either is unpleasant, `oidc-spa` (automatic) or
   `oauth4webapi` (native nonce) is the escape hatch.
6. **Key lifetime: ✅ per-login.** The key is generated at login and cleared from
   IndexedDB on logout, so each login mints a fresh key and a freshly bound token;
   it survives reloads within a session but is not a persistent per-profile key.
7. **Backend audience: ✅ configurable set.** The resource server accepts a set of
   audiences (adding `spa-frontend`) rather than a single value, still rejecting a
   token whose `aud` matches none.
8. **SPA e2e: ✅ full Playwright coverage** (login, non-extractable-key assertion,
   `/hello` under DPoP, step-up on `/server-details`, and a negative replay).

---

## 9. Next step

On approval of this PRD, I will write **`PLAN-5.md`**: an ordered, verifiable
implementation plan (the `spa-frontend` public Keycloak client; the Vite React app
with `oidc-client-ts` non-extractable IndexedDB key management and browser DPoP
proof signing (spiking refresh + nonce first, §8.5); step-up, nonce, and refresh; the
backend audience-set and CORS changes; the compose SPA service; and the full
Playwright e2e + README updates), in the same incremental style as the prior plans.

**No implementation will be done until PRD-5 and PLAN-5 are approved.**
