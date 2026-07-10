#!/usr/bin/env node
// Headless end-to-end check of the base login + DPoP (RFC 9449) flow against a
// running stack. Iteration 3 sender-constrains the access token: the client now
// requires a DPoP proof at the token endpoint, and the backend requires a matching
// proof on every resource call. So this script drives the Authorization Code +
// PKCE flow DIRECTLY against Keycloak with its own ES256 key (the way next-auth
// does server-side), obtains a `cnf.jkt`-bound token, and calls the protected
// GET /hello under the `DPoP` scheme.
//
// It then proves the properties this whole iteration exists to demonstrate
// (PRD-3 §6.5/§6.9, NFR-8): a leaked bound token is useless without the key.
// Taking the same valid token, the backend must reject a call that is
//   (a) missing the DPoP proof,           (b) signed by a DIFFERENT key,
//   (c) presented under the `Bearer` scheme, or
//   (d) a verbatim replay of a valid proof (same `jti`)  -> all 401.
//
// The browser never does any of this (it goes through the same-origin BFF proxy,
// covered by dpop-bff-verify.mjs); this script talks to Keycloak/the backend
// directly so it can hold the token+key and exercise the negative paths.
//
// Prereq: the stack is up (`docker compose up -d --build`) and `/etc/hosts` has
// `127.0.0.1 keycloak`. Seed user testuser / password.
//
// Usage:  node scripts/e2e-login.mjs
//   KEYCLOAK_BASE (default http://keycloak:8081), API_URL (default http://localhost:8080)
//   USERNAME / PASSWORD (default testuser / password)

import crypto from "node:crypto";
import { generateKeyPair, jwkThumbprint, signProof, base64url } from "./lib/dpop.mjs";

const cfg = {
  authBase: process.env.KEYCLOAK_BASE ?? "http://keycloak:8081",
  realm: process.env.KEYCLOAK_REALM ?? "web",
  clientId: process.env.KEYCLOAK_CLIENT_ID ?? "nextjs-frontend",
  clientSecret: process.env.KEYCLOAK_CLIENT_SECRET ?? "nextjs-frontend-secret-dev",
  redirectUri: "http://localhost:3000/api/auth/callback/keycloak",
  api: process.env.API_URL ?? "http://localhost:8080",
  username: process.env.USERNAME ?? "testuser",
  password: process.env.PASSWORD ?? "password",
};

const realmBase = `${cfg.authBase}/realms/${cfg.realm}`;
const authEndpoint = `${realmBase}/protocol/openid-connect/auth`;
const tokenEndpoint = `${realmBase}/protocol/openid-connect/token`;

// Per-host cookie jar so Keycloak's SSO session survives across the flow's redirects.
const jars = new Map();
function jarFor(url) {
  const host = new URL(url).host;
  if (!jars.has(host)) jars.set(host, new Map());
  return jars.get(host);
}
async function go(url, { method = "GET", body, headers = {} } = {}) {
  const jar = jarFor(url);
  const cookie = [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
  const res = await fetch(url, {
    method,
    body,
    headers: { ...headers, ...(cookie ? { cookie } : {}) },
    redirect: "manual",
  });
  for (const setCookie of res.headers.getSetCookie?.() ?? []) {
    const [pair] = setCookie.split(";");
    const eq = pair.indexOf("=");
    if (eq > 0) {
      const value = pair.slice(eq + 1).trim();
      if (value) jar.set(pair.slice(0, eq).trim(), value);
    }
  }
  return res;
}

const form = (obj) => new URLSearchParams(obj).toString();
const formAction = (html) =>
  html.match(/action="([^"]*login-actions\/authenticate[^"]*)"/)?.[1]?.replace(/&amp;/g, "&");
const decodeJwt = (jwt) => JSON.parse(Buffer.from(jwt.split(".")[1], "base64url").toString("utf8"));

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

// Drive the auth-code flow directly against Keycloak and return { code,
// codeVerifier }. The redirect to redirectUri is captured (not followed) to read
// the code straight off the Location header.
async function getCode() {
  const codeVerifier = base64url(crypto.randomBytes(32));
  const codeChallenge = base64url(crypto.createHash("sha256").update(codeVerifier).digest());
  const state = base64url(crypto.randomBytes(16));
  let res = await go(`${authEndpoint}?${form({
    response_type: "code",
    client_id: cfg.clientId,
    redirect_uri: cfg.redirectUri,
    scope: "openid profile email",
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  })}`);

  for (let i = 0; i < 8; i++) {
    const loc = res.headers.get("location");
    if (res.status === 302 && loc) {
      const redirect = new URL(loc, cfg.redirectUri);
      const code = redirect.searchParams.get("code");
      if (code) {
        // Verify Keycloak echoed back our OAuth state (CSRF defense on the flow).
        const returnedState = redirect.searchParams.get("state");
        if (returnedState !== state) throw new Error(`OAuth state mismatch: sent ${state}, got ${returnedState}`);
        return { code, codeVerifier };
      }
      res = await go(loc); // intermediate redirect, follow it
      continue;
    }
    if (res.status === 200) {
      const action = formAction(await res.text());
      if (!action) throw new Error("no login form action in Keycloak page");
      res = await go(action, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: form({ username: cfg.username, password: cfg.password, credentialId: "" }),
      });
      continue;
    }
    throw new Error(`unexpected status ${res.status} while obtaining a code`);
  }
  throw new Error("did not obtain an authorization code");
}

// Exchange the code at the token endpoint with a DPoP proof (htm=POST, htu=token
// endpoint, no ath). Retries once on a use_dpop_nonce challenge; we do not mandate
// nonces but handle them if Keycloak asks (PRD-3 §8.4).
async function exchangeCode({ code, codeVerifier, key }, nonce) {
  const headers = { "Content-Type": "application/x-www-form-urlencoded" };
  if (key) {
    headers["DPoP"] = signProof({
      privateKey: key.privateKey,
      publicJwk: key.publicJwk,
      htm: "POST",
      htu: tokenEndpoint,
      nonce,
    });
  }
  const res = await fetch(tokenEndpoint, {
    method: "POST",
    headers,
    body: form({
      grant_type: "authorization_code",
      code,
      redirect_uri: cfg.redirectUri,
      client_id: cfg.clientId,
      client_secret: cfg.clientSecret,
      code_verifier: codeVerifier,
    }),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok && key && !nonce && json.error === "use_dpop_nonce") {
    const serverNonce = res.headers.get("dpop-nonce");
    if (serverNonce) return exchangeCode({ code, codeVerifier, key }, serverNonce);
  }
  return { res, json };
}

// Call a backend endpoint the way the BFF proxy does: `Authorization: DPoP <token>`
// plus a fresh proof. The options let the negative cases deviate deliberately:
//   scheme    - override "DPoP" (e.g. "Bearer" for the downgrade test)
//   proofKey  - sign the proof with a DIFFERENT key than the one bound in cnf.jkt
//   omitProof - send no DPoP header at all
//   proof     - reuse a verbatim proof string (same jti) for the replay test
async function callBackend(path, { token, key, scheme = "DPoP", proofKey, omitProof = false, proof } = {}) {
  const url = `${cfg.api}${path}`;
  const headers = { authorization: `${scheme} ${token}` };
  if (!omitProof) {
    const signer = proofKey ?? key;
    headers["DPoP"] = proof ?? signProof({
      privateKey: signer.privateKey,
      publicJwk: signer.publicJwk,
      htm: "GET",
      htu: url,
      accessToken: token,
    });
  }
  return fetch(url, { method: "GET", headers });
}

async function main() {
  const key = generateKeyPair();
  const thumbprint = jwkThumbprint(key.publicJwk);
  console.log(`DPoP key thumbprint (jkt): ${thumbprint}`);

  // 1) Base login -> DPoP-bound access token. Assert it is sender-constrained to
  //    exactly our key (cnf.jkt == our JWK thumbprint) and is a base (acr=basic) token.
  const bound = await exchangeCode({ ...(await getCode()), key });
  assert(bound.res.ok, `token exchange failed: ${JSON.stringify(bound.json)}`);
  const token = bound.json.access_token;
  const claims = decodeJwt(token);
  console.log(`access token: acr=${claims.acr}  cnf.jkt=${claims.cnf?.jkt}`);
  assert(claims.cnf?.jkt === thumbprint, `token not bound to our key (cnf.jkt=${claims.cnf?.jkt})`);
  assert(claims.acr === "basic", `expected acr=basic for a base login, got ${claims.acr}`);

  // 2) GET /hello under the DPoP scheme with a valid proof -> 200 greeting.
  const hello = await callBackend("/hello", { token, key });
  const helloText = await hello.text();
  console.log(`GET /hello (DPoP + valid proof) -> ${hello.status}: ${helloText}`);
  assert(hello.status === 200 && helloText === `Hello World, ${cfg.username}`, "valid DPoP call to /hello did not return the greeting");

  // 3) Negative assertions (NFR-8): the SAME valid bound token must be refused when
  //    the proof is missing / wrong-key / downgraded to Bearer / replayed verbatim.
  const noProof = await callBackend("/hello", { token, key, omitProof: true });
  console.log(`GET /hello (no proof)        -> ${noProof.status}`);
  assert(noProof.status === 401, `expected 401 without a DPoP proof, got ${noProof.status}`);

  const wrongKey = await callBackend("/hello", { token, key, proofKey: generateKeyPair() });
  console.log(`GET /hello (wrong-key proof) -> ${wrongKey.status}`);
  assert(wrongKey.status === 401, `expected 401 for a proof signed by a different key, got ${wrongKey.status}`);

  const bearer = await callBackend("/hello", { token, key, scheme: "Bearer", omitProof: true });
  console.log(`GET /hello (Bearer scheme)   -> ${bearer.status}`);
  assert(bearer.status === 401, `expected 401 for a cnf-bound token under Bearer (RFC 9449 §7.1), got ${bearer.status}`);

  // Replay: one proof, two calls. The first consumes the jti (200); the verbatim
  // second must hit the backend's jti replay cache and be refused (401).
  const replayProof = signProof({
    privateKey: key.privateKey,
    publicJwk: key.publicJwk,
    htm: "GET",
    htu: `${cfg.api}/hello`,
    accessToken: token,
  });
  const replay1 = await callBackend("/hello", { token, key, proof: replayProof });
  const replay2 = await callBackend("/hello", { token, key, proof: replayProof });
  console.log(`GET /hello (same jti twice)  -> ${replay1.status}, then ${replay2.status}`);
  assert(replay1.status === 200, `expected the first proof use to succeed, got ${replay1.status}`);
  assert(replay2.status === 401, `expected the replayed proof (same jti) to be refused, got ${replay2.status}`);

  // 4) /server-details at base level: no token -> ordinary 401; a valid-proof basic
  //    token -> RFC 9470 step-up 401 (authentication succeeds, authorization does not).
  const sdNoToken = await fetch(`${cfg.api}/server-details`);
  console.log(`GET /server-details (no token) -> ${sdNoToken.status}`);
  assert(sdNoToken.status === 401, `expected 401 without a token, got ${sdNoToken.status}`);

  const sdBasic = await callBackend("/server-details", { token, key });
  const challenge = sdBasic.headers.get("www-authenticate") ?? "";
  console.log(`GET /server-details (basic + valid proof) -> ${sdBasic.status}: ${challenge}`);
  assert(sdBasic.status === 401, `expected 401 step-up for a basic token, got ${sdBasic.status}`);
  assert(
    challenge.includes("insufficient_user_authentication") && challenge.includes('acr_values="pro"'),
    `missing RFC 9470 step-up challenge in WWW-Authenticate: ${challenge}`,
  );

  console.log(`\nE2E PASSED: DPoP-bound base login -> /hello 200; leaked token refused (no-proof / wrong-key / Bearer / replay = 401); /server-details step-up 401`);
}

main().catch((err) => {
  console.error("E2E FAILED:", err.message);
  process.exit(1);
});
