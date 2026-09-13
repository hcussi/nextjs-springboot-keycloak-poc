#!/usr/bin/env node
// Headless e2e for the iteration-4 configurable DPoP iat freshness window (PRD-4
// FR-B16, acceptance §6.4). With a DPoP-bound token, a resource proof whose `iat`
// is backdated beyond the window is rejected 401 (invalid_dpop_proof), while a
// fresh proof is accepted 200. This exercises the symmetric window the framework's
// default check does not enforce for stale proofs.
//
// Prereq: the stack is up (`docker compose up -d --build`) and `/etc/hosts` has
// `127.0.0.1 keycloak`. Seed user testuser / password.
//
// Usage:  node scripts/e2e-dpop-iat-window.mjs
//   API_URL (default http://localhost:8080)
//   DPOP_IAT_WINDOW_SECONDS (default 60) must match the backend's configured window.

import { signProof } from "./lib/dpop.mjs";
import { getBasicBoundToken } from "./lib/keycloak-login.mjs";

const assert = (cond, msg) => { if (!cond) throw new Error(msg); };
const WINDOW = Number(process.env.DPOP_IAT_WINDOW_SECONDS ?? 60);

// GET /hello with a proof whose iat is `iat` (epoch seconds); omit for "now".
function callHello(url, token, key, iat) {
  return fetch(url, {
    method: "GET",
    headers: {
      authorization: `DPoP ${token}`,
      DPoP: signProof({ privateKey: key.privateKey, publicJwk: key.publicJwk, htm: "GET", htu: url, accessToken: token, iat }),
    },
  });
}

async function main() {
  const { token, key, claims, cfg } = await getBasicBoundToken();
  console.log(`bound token: acr=${claims.acr}  cnf.jkt=${claims.cnf?.jkt}  (iat window=${WINDOW}s)`);
  const helloUrl = `${cfg.api}/hello`;

  // 1) A proof backdated beyond the window is stale -> 401 invalid_dpop_proof.
  const staleIat = Math.floor(Date.now() / 1000) - WINDOW - 10;
  const stale = await callHello(helloUrl, token, key, staleIat);
  const staleAuth = stale.headers.get("www-authenticate") ?? "";
  console.log(`GET /hello (iat backdated ${WINDOW + 10}s) -> ${stale.status}: ${staleAuth}`);
  assert(stale.status === 401, `expected 401 for a stale proof, got ${stale.status}`);
  assert(staleAuth.includes("invalid_dpop_proof"), `expected invalid_dpop_proof challenge, got: ${staleAuth}`);

  // 2) A fresh proof (iat = now) is within the window -> 200.
  const fresh = await callHello(helloUrl, token, key);
  console.log(`GET /hello (fresh iat) -> ${fresh.status}`);
  assert(fresh.status === 200, `expected 200 for a fresh proof, got ${fresh.status}`);

  console.log(`\nE2E PASSED: DPoP iat window (${WINDOW}s) rejects a stale proof (401) and accepts a fresh one (200)`);
}

main().catch((err) => {
  console.error("E2E FAILED:", err.message);
  process.exit(1);
});
