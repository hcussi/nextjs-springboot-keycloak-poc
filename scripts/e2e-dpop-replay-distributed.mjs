#!/usr/bin/env node
// Headless e2e for DISTRIBUTED DPoP replay protection across two backend instances
// (PRD-4 FR-B15/FR-I9a, acceptance §6.3). A single proof is used once against
// instance A (200), then the SAME proof (same jti) is replayed against instance B,
// a different JVM sharing the same Redis, and must be refused 401. This proves the
// replay decision is cross-instance (Redis), not the framework's per-JVM in-memory
// cache (which on B would be empty and would let the replay through).
//
// The two instances are reached on different host ports, but a DPoP proof's `htu`
// must match the resource URL. Spring builds the compared URL from
// request.getRequestURL(), i.e. from the Host header, so both calls send the SAME
// Host (instance A's authority); the proof's htu therefore matches on both, and it
// is genuinely the jti replay check (not an htu mismatch) that refuses B.
//
// Prereq: `docker compose up -d --build` (brings up backend + backend-2 + redis)
// and `/etc/hosts` has `127.0.0.1 keycloak`. Seed user testuser / password.
//
// Usage:  node scripts/e2e-dpop-replay-distributed.mjs
//   API_URL   (instance A, default http://localhost:8080)
//   API_URL_2 (instance B, default http://localhost:8082)

import http from "node:http";
import { signProof } from "./lib/dpop.mjs";
import { getBasicBoundToken } from "./lib/keycloak-login.mjs";

const assert = (cond, msg) => { if (!cond) throw new Error(msg); };

const A = new URL(process.env.API_URL ?? "http://localhost:8080");
const B = new URL(process.env.API_URL_2 ?? "http://localhost:8082");

// GET <target>/hello sending instance A's Host header and a verbatim proof, so both
// instances reconstruct the same htu. Returns { status, wwwAuth }.
function callHello(target, hostHeader, token, proof) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: target.hostname,
        port: target.port,
        path: "/hello",
        method: "GET",
        headers: { Host: hostHeader, authorization: `DPoP ${token}`, DPoP: proof },
      },
      (res) => {
        res.resume();
        res.on("end", () => resolve({ status: res.statusCode, wwwAuth: res.headers["www-authenticate"] ?? "" }));
      },
    );
    req.on("error", reject);
    req.end();
  });
}

async function main() {
  const { token, key, claims } = await getBasicBoundToken();
  console.log(`bound token: acr=${claims.acr}  cnf.jkt=${claims.cnf?.jkt}`);
  console.log(`instance A = ${A.host}   instance B = ${B.host}`);

  // One proof, signed for instance A's URL (htu); both calls send Host: A.host.
  const proof = signProof({
    privateKey: key.privateKey,
    publicJwk: key.publicJwk,
    htm: "GET",
    htu: `${A.origin}/hello`,
    accessToken: token,
  });

  // 1) First use against instance A -> 200 (consumes the jti in shared Redis).
  const first = await callHello(A, A.host, token, proof);
  console.log(`GET A /hello (first use)   -> ${first.status}`);
  assert(first.status === 200, `expected the first use on instance A to succeed, got ${first.status}`);

  // 2) Replay the SAME proof against instance B -> 401 invalid_dpop_proof, because
  //    the jti is already recorded in the shared store (a different JVM catches it).
  const replay = await callHello(B, A.host, token, proof);
  console.log(`GET B /hello (replayed jti) -> ${replay.status}: ${replay.wwwAuth}`);
  assert(replay.status === 401, `expected the cross-instance replay to be refused, got ${replay.status}`);
  assert(replay.wwwAuth.includes("invalid_dpop_proof"), `expected invalid_dpop_proof, got: ${replay.wwwAuth}`);

  console.log(`\nE2E PASSED: a proof used on instance A is refused when replayed on instance B (distributed Redis jti)`);
}

main().catch((err) => {
  console.error("E2E FAILED:", err.message);
  process.exit(1);
});
