#!/usr/bin/env node
// Headless e2e for the iteration-4 DPoP nonce on /server-details (PRD-4 FR-B17/
// FR-B19, acceptance §6.5). With a DPoP-bound token:
//   - /server-details with a valid proof but NO nonce -> 401 with a DPoP-Nonce
//     header and WWW-Authenticate: DPoP error="use_dpop_nonce".
//   - retrying with that nonce passes the nonce check; because this token is a
//     BASIC token, authorization then applies and returns the RFC 9470 step-up
//     challenge (proving the nonce check is authentication-time and precedes the
//     acr step-up authorization check).
//   - /hello with no nonce -> 200 (the nonce is never required there).
//
// Prereq: the stack is up (`docker compose up -d --build`) and `/etc/hosts` has
// `127.0.0.1 keycloak`. Seed user testuser / password.
//
// Usage:  node scripts/e2e-dpop-nonce.mjs
//   KEYCLOAK_BASE (default http://keycloak:8081), API_URL (default http://localhost:8080)

import { signProof } from "./lib/dpop.mjs";
import { getBasicBoundToken } from "./lib/keycloak-login.mjs";

const assert = (cond, msg) => { if (!cond) throw new Error(msg); };

// One-shot GET with a freshly signed proof; `nonce` is echoed when provided.
function call(url, token, key, nonce) {
  return fetch(url, {
    method: "GET",
    headers: {
      authorization: `DPoP ${token}`,
      DPoP: signProof({ privateKey: key.privateKey, publicJwk: key.publicJwk, htm: "GET", htu: url, accessToken: token, nonce }),
    },
  });
}

async function main() {
  const { token, key, claims, cfg } = await getBasicBoundToken();
  console.log(`bound token: acr=${claims.acr}  cnf.jkt=${claims.cnf?.jkt}`);
  assert(claims.acr === "basic", `expected a basic token, got acr=${claims.acr}`);

  const sdUrl = `${cfg.api}/server-details`;

  // 1) No nonce -> use_dpop_nonce challenge with a fresh DPoP-Nonce.
  const challenge = await call(sdUrl, token, key);
  const nonce = challenge.headers.get("dpop-nonce");
  const wwwAuth = challenge.headers.get("www-authenticate") ?? "";
  console.log(`GET /server-details (no nonce) -> ${challenge.status}: ${wwwAuth} (DPoP-Nonce: ${nonce ? "present" : "absent"})`);
  assert(challenge.status === 401, `expected 401 nonce challenge, got ${challenge.status}`);
  assert(wwwAuth.includes("use_dpop_nonce"), `missing use_dpop_nonce in WWW-Authenticate: ${wwwAuth}`);
  assert(nonce, "missing DPoP-Nonce response header on the challenge");

  // 2) Retry with the nonce -> nonce accepted; a BASIC token now hits the step-up.
  const retried = await call(sdUrl, token, key, nonce);
  const retryAuth = retried.headers.get("www-authenticate") ?? "";
  console.log(`GET /server-details (with nonce) -> ${retried.status}: ${retryAuth}`);
  assert(retried.status === 401, `expected 401 step-up after the nonce, got ${retried.status}`);
  assert(!retryAuth.includes("use_dpop_nonce"), `nonce was not accepted (still use_dpop_nonce): ${retryAuth}`);
  assert(
    retryAuth.includes("insufficient_user_authentication") && retryAuth.includes('acr_values="pro"'),
    `expected the RFC 9470 step-up challenge after the nonce, got: ${retryAuth}`,
  );

  // 3) /hello never requires a nonce -> single round trip, 200.
  const hello = await call(`${cfg.api}/hello`, token, key);
  console.log(`GET /hello (no nonce) -> ${hello.status}`);
  assert(hello.status === 200, `expected /hello 200 with no nonce, got ${hello.status}`);
  assert(!(hello.headers.get("www-authenticate") ?? "").includes("use_dpop_nonce"), "/hello unexpectedly issued a nonce challenge");

  console.log(`\nE2E PASSED: /server-details requires a DPoP nonce (use_dpop_nonce -> retry -> step-up); /hello needs none`);
}

main().catch((err) => {
  console.error("E2E FAILED:", err.message);
  process.exit(1);
});
