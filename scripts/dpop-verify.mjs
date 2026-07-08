#!/usr/bin/env node
// Step 1 scratch verification (PLAN-3): proves Keycloak now issues DPoP-bound
// (RFC 9449) access tokens for `nextjs-frontend` and rejects an unbound token
// request. It talks DIRECTLY to Keycloak (not through the frontend, which does
// not sign proofs until Step 3), driving the Authorization Code + PKCE flow like
// a browser and reading the `code` straight off the redirect.
//
// Checks:
//   1. Token request WITHOUT a DPoP proof -> rejected (the client requires DPoP).
//   2. Token request WITH a valid ES256 proof -> 200, and the access token carries
//      `cnf.jkt` == the JWK SHA-256 thumbprint (bound to exactly our key).
//   3. Step-up: request acr=pro, complete OTP, exchange with a proof -> the token
//      is BOTH acr=pro AND cnf.jkt-bound.
//   4. Refresh (confidential client): measures whether the refresh_token grant
//      needs a proof and whether the refreshed access token stays bound.
//
// Prereq: stack up with the current realm (`docker compose up -d keycloak
// --force-recreate`) and `/etc/hosts` has `127.0.0.1 keycloak`. Seed testuser.
//
// Usage:  node scripts/dpop-verify.mjs
//
// DEV-ONLY: uses the placeholder client secret and the throwaway TOTP seed.

import crypto from "node:crypto";
import { generateKeyPair, jwkThumbprint, signProof, base64url } from "./lib/dpop.mjs";
import { totp, secondsLeft, DEFAULT_SEED } from "./totp.mjs";

const cfg = {
  authBase: process.env.KEYCLOAK_BASE ?? "http://keycloak:8081",
  realm: process.env.KEYCLOAK_REALM ?? "web",
  clientId: process.env.KEYCLOAK_CLIENT_ID ?? "nextjs-frontend",
  clientSecret: process.env.KEYCLOAK_CLIENT_SECRET ?? "nextjs-frontend-secret-dev",
  redirectUri: "http://localhost:3000/api/auth/callback/keycloak",
  username: process.env.USERNAME ?? "testuser",
  password: process.env.PASSWORD ?? "password",
  secret: process.env.TOTP_SECRET ?? DEFAULT_SEED,
};

const realmBase = `${cfg.authBase}/realms/${cfg.realm}`;
const authEndpoint = `${realmBase}/protocol/openid-connect/auth`;
const tokenEndpoint = `${realmBase}/protocol/openid-connect/token`;

// Per-host cookie jar so Keycloak's SSO session survives across requests.
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
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function freshCode() {
  if (secondsLeft() < 3) await sleep((secondsLeft() + 1) * 1000);
  return totp(cfg.secret);
}

// Drive the auth-code flow directly against Keycloak and return { code,
// codeVerifier }. Handles the login form and, when acr=pro is requested, the OTP
// form. The redirect to redirectUri is captured (not followed) to read the code.
async function getCode({ acr } = {}) {
  const codeVerifier = base64url(crypto.randomBytes(32));
  const codeChallenge = base64url(crypto.createHash("sha256").update(codeVerifier).digest());
  const state = base64url(crypto.randomBytes(16));
  const params = {
    response_type: "code",
    client_id: cfg.clientId,
    redirect_uri: cfg.redirectUri,
    scope: "openid profile email",
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  };
  if (acr) params.acr_values = acr;

  let res = await go(`${authEndpoint}?${form(params)}`);

  for (let i = 0; i < 8; i++) {
    const loc = res.headers.get("location");
    if (res.status === 302 && loc) {
      const code = new URL(loc, cfg.redirectUri).searchParams.get("code");
      if (code) return { code, codeVerifier };
      res = await go(loc); // some intermediate redirect, follow it
      continue;
    }
    if (res.status === 200) {
      const html = await res.text();
      const action = formAction(html);
      if (!action) throw new Error("no login/OTP form action in Keycloak page");
      if (/name="otp"/.test(html)) {
        res = await submitOtp(action);
      } else {
        res = await go(action, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: form({ username: cfg.username, password: cfg.password, credentialId: "" }),
        });
      }
      continue;
    }
    throw new Error(`unexpected status ${res.status} while obtaining a code`);
  }
  throw new Error("did not obtain an authorization code");
}

// Submit the TOTP, retrying across window rollovers, until Keycloak redirects.
async function submitOtp(action) {
  for (let attempt = 1; attempt <= 3; attempt++) {
    const code = await freshCode();
    const res = await go(action, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: form({ otp: code, login: "Sign In" }),
    });
    if (res.status === 302) return res;
    action = formAction(await res.text()) ?? action;
    if (attempt < 3) await sleep((secondsLeft() + 1) * 1000);
  }
  throw new Error("OTP was not accepted after retries");
}

// Exchange a code at the token endpoint, optionally with a DPoP proof. Retries
// once on a use_dpop_nonce challenge (we do not mandate nonces, but handle them).
async function exchangeCode({ code, codeVerifier, key }) {
  const body = {
    grant_type: "authorization_code",
    code,
    redirect_uri: cfg.redirectUri,
    client_id: cfg.clientId,
    client_secret: cfg.clientSecret,
    code_verifier: codeVerifier,
  };
  return tokenRequest(body, key);
}

async function tokenRequest(body, key, nonce) {
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
  const res = await fetch(tokenEndpoint, { method: "POST", headers, body: form(body) });
  const json = await res.json().catch(() => ({}));
  if (!res.ok && key && !nonce && json.error === "use_dpop_nonce") {
    const serverNonce = res.headers.get("dpop-nonce");
    if (serverNonce) return tokenRequest(body, key, serverNonce);
  }
  return { res, json };
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

async function main() {
  const key = generateKeyPair();
  const thumbprint = jwkThumbprint(key.publicJwk);
  console.log(`DPoP key thumbprint (jkt): ${thumbprint}`);

  // 1) No-proof token request is rejected (the client requires DPoP).
  const { code: c1, codeVerifier: v1 } = await getCode();
  const noProof = await exchangeCode({ code: c1, codeVerifier: v1, key: null });
  console.log(`1) token exchange WITHOUT proof -> HTTP ${noProof.res.status} (${noProof.json.error ?? "ok"})`);
  assert(!noProof.res.ok, "expected the unbound token request to be REJECTED, but it succeeded");

  // 2) Proof-backed token request succeeds and is bound to our key.
  const { code: c2, codeVerifier: v2 } = await getCode();
  const bound = await exchangeCode({ code: c2, codeVerifier: v2, key });
  console.log(`2) token exchange WITH proof -> HTTP ${bound.res.status}`);
  assert(bound.res.ok, `expected the bound token request to succeed: ${JSON.stringify(bound.json)}`);
  const claims = decodeJwt(bound.json.access_token);
  console.log(`   access token acr=${claims.acr}  cnf.jkt=${claims.cnf?.jkt}`);
  assert(claims.cnf?.jkt === thumbprint, `cnf.jkt (${claims.cnf?.jkt}) != our thumbprint (${thumbprint})`);

  // 3) Step-up: acr=pro AND cnf.jkt together.
  const { code: c3, codeVerifier: v3 } = await getCode({ acr: "pro" });
  const pro = await exchangeCode({ code: c3, codeVerifier: v3, key });
  assert(pro.res.ok, `expected the pro token request to succeed: ${JSON.stringify(pro.json)}`);
  const proClaims = decodeJwt(pro.json.access_token);
  console.log(`3) step-up token -> acr=${proClaims.acr}  cnf.jkt=${proClaims.cnf?.jkt ? "present" : "MISSING"}`);
  assert(proClaims.acr === "pro", `expected acr=pro, got ${proClaims.acr}`);
  assert(proClaims.cnf?.jkt === thumbprint, "pro token is not bound to our key");

  // 4) Refresh behavior of a confidential client (measure, do not assume).
  const refreshNoProof = await tokenRequest(
    { grant_type: "refresh_token", refresh_token: bound.json.refresh_token, client_id: cfg.clientId, client_secret: cfg.clientSecret },
    null,
  );
  const refreshProof = await tokenRequest(
    { grant_type: "refresh_token", refresh_token: bound.json.refresh_token, client_id: cfg.clientId, client_secret: cfg.clientSecret },
    key,
  );
  console.log(`4) refresh WITHOUT proof -> HTTP ${refreshNoProof.res.status} (${refreshNoProof.json.error ?? "ok"})`);
  console.log(`   refresh WITH proof    -> HTTP ${refreshProof.res.status}`);
  if (refreshProof.res.ok) {
    const refreshed = decodeJwt(refreshProof.json.access_token);
    console.log(`   refreshed access token cnf.jkt=${refreshed.cnf?.jkt ? "present (stable)" : "MISSING"}`);
    assert(refreshed.cnf?.jkt === thumbprint, "refreshed token lost/changed its DPoP binding");
  }
  const refreshNeedsProof = !refreshNoProof.res.ok && refreshProof.res.ok;
  console.log(`   => confidential-client refresh ${refreshNeedsProof ? "REQUIRES" : "does NOT require"} a DPoP proof`);

  console.log(`\nSTEP 1 PASSED: DPoP-bound tokens issued (cnf.jkt), unbound requests rejected.`);
}

main().catch((err) => {
  console.error(`\nSTEP 1 FAILED: ${err.message}`);
  process.exit(1);
});
