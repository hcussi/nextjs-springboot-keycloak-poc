#!/usr/bin/env node
// Headless check that an elevated (acr=pro), DPoP-bound session stays both elevated
// AND sender-constrained across a token refresh. This is a Keycloak (IdP) behavior,
// so it drives the Authorization Code + PKCE flow directly with its own ES256 key,
// completes the OTP second factor, then runs the refresh_token grant and asserts
// the refreshed access token is still acr=pro and still bound to the SAME key
// (cnf.jkt unchanged).
//
// It documents PLAN-2 §5 (accepted POC limitation): the refresh grant preserves
// the SSO session's achieved LoA for the session lifetime without re-running OTP.
// Iteration 3 adds the DPoP dimension: a confidential client binds the access
// token, so the refresh must carry a proof to mint a fresh bound token, and the
// binding must stay stable so the BFF's per-session key keeps working across the
// 5-minute refresh (PRD-3 §3.5). Measured here rather than assumed.
//
// A dedicated script (not folded into e2e-stepup.mjs) because a single OTP avoids
// Keycloak's one-time code reuse protection rejecting a second submission in the
// same 30s window.
//
// Prereq: Keycloak up (`docker compose up -d keycloak`) and `/etc/hosts` has
// `127.0.0.1 keycloak`.
//
// Usage:  node scripts/e2e-stepup-refresh.mjs
//   KEYCLOAK_BASE (default http://keycloak:8081), USERNAME/PASSWORD, TOTP_SECRET

import crypto from "node:crypto";
import { generateKeyPair, jwkThumbprint, signProof, base64url } from "./lib/dpop.mjs";
import { totp, secondsLeft, DEFAULT_SEED } from "./totp.mjs";

const cfg = {
  // Must be the `keycloak` hostname (the single-issuer trick, reachable from the
  // host via `/etc/hosts`): the issuer is fixed to keycloak:8081, so pointing this
  // at localhost would break issuer validation and the DPoP proof `htu`. Aligned
  // with the other direct-flow scripts, which all default here.
  authBase: process.env.KEYCLOAK_BASE ?? "http://keycloak:8081",
  realm: process.env.KEYCLOAK_REALM ?? "web",
  clientId: process.env.KEYCLOAK_CLIENT_ID ?? "nextjs-frontend",
  clientSecret: process.env.KEYCLOAK_CLIENT_SECRET ?? "nextjs-frontend-secret-dev",
  redirectUri: "http://localhost:3000/api/auth/callback/keycloak",
  username: process.env.USERNAME ?? "testuser",
  password: process.env.PASSWORD ?? "password",
  secret: process.env.TOTP_SECRET ?? DEFAULT_SEED,
};
const ACR = "pro";

const realmBase = `${cfg.authBase}/realms/${cfg.realm}`;
const authEndpoint = `${realmBase}/protocol/openid-connect/auth`;
const tokenEndpoint = `${realmBase}/protocol/openid-connect/token`;

const form = (obj) => new URLSearchParams(obj).toString();
const formAction = (h) => h.match(/action="([^"]*login-actions\/authenticate[^"]*)"/)?.[1]?.replace(/&amp;/g, "&");
const decodeJwt = (jwt) => JSON.parse(Buffer.from(jwt.split(".")[1], "base64url").toString("utf8"));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

// A TOTP code with comfortable validity left. If the window is about to roll
// (<3s), wait for the next one so the code stays valid through submission.
async function freshCode() {
  if (secondsLeft() < 3) await sleep((secondsLeft() + 1) * 1000);
  return totp(cfg.secret);
}

// Submit the OTP, retrying across 30s window rollovers until Keycloak redirects.
// Retrying is necessary because a run right after e2e-stepup.mjs would otherwise
// resubmit the same window's code, which Keycloak's one-time-code reuse protection
// rejects; on a rejection we wait for a genuinely new code.
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

const jar = new Map();
function absorb(res) {
  for (const sc of res.headers.getSetCookie?.() ?? []) {
    const [pair] = sc.split(";");
    const eq = pair.indexOf("=");
    if (eq > 0) {
      const v = pair.slice(eq + 1).trim();
      if (v) jar.set(pair.slice(0, eq).trim(), v);
    }
  }
}
async function go(url, opts = {}) {
  const res = await fetch(url, {
    redirect: "manual",
    ...opts,
    headers: { ...(opts.headers || {}), ...(jar.size ? { cookie: [...jar].map(([k, v]) => `${k}=${v}`).join("; ") } : {}) },
  });
  absorb(res);
  return res;
}

// A token-endpoint request (auth-code or refresh) carrying a DPoP proof (htm=POST,
// htu=token endpoint). Retries once on a use_dpop_nonce challenge.
async function tokenRequest(params, key, nonce) {
  const res = await fetch(tokenEndpoint, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      DPoP: signProof({ privateKey: key.privateKey, publicJwk: key.publicJwk, htm: "POST", htu: tokenEndpoint, nonce }),
    },
    body: new URLSearchParams(params),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok && !nonce && json.error === "use_dpop_nonce") {
    const serverNonce = res.headers.get("dpop-nonce");
    if (serverNonce) return tokenRequest(params, key, serverNonce);
  }
  return json;
}

// Authorization Code + PKCE with acr_values=pro, completing the OTP form, then a
// DPoP-bound token exchange. Returns the token set.
async function stepUpTokens(key) {
  const verifier = base64url(crypto.randomBytes(32));
  const challenge = base64url(crypto.createHash("sha256").update(verifier).digest());
  const state = base64url(crypto.randomBytes(8));
  const authUrl = `${authEndpoint}?` + form({
    response_type: "code", client_id: cfg.clientId, redirect_uri: cfg.redirectUri, scope: "openid",
    state, code_challenge: challenge, code_challenge_method: "S256",
    acr_values: ACR,
  });
  let res = await go(authUrl);
  res = await go(formAction(await res.text()), {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form({ username: cfg.username, password: cfg.password, credentialId: "" }),
  });
  let location = res.headers.get("location");
  if (!location) {
    const html = await res.text();
    if (!/name="otp"/.test(html)) throw new Error("expected the OTP form for a pro step-up");
    res = await submitOtp(formAction(html));
    location = res.headers.get("location");
  }
  if (!location?.startsWith(cfg.redirectUri)) throw new Error(`no code redirect: HTTP ${res.status} -> ${location}`);
  const redirect = new URL(location);
  // Verify Keycloak echoed back our OAuth state (CSRF defense on the flow).
  const returnedState = redirect.searchParams.get("state");
  if (returnedState !== state) throw new Error(`OAuth state mismatch: sent ${state}, got ${returnedState}`);
  const code = redirect.searchParams.get("code");
  const tok = await tokenRequest({
    grant_type: "authorization_code", code, redirect_uri: cfg.redirectUri,
    client_id: cfg.clientId, client_secret: cfg.clientSecret, code_verifier: verifier,
  }, key);
  if (!tok.access_token || !tok.refresh_token) throw new Error(`token exchange failed: ${JSON.stringify(tok)}`);
  return tok;
}

async function main() {
  const key = generateKeyPair();
  const thumbprint = jwkThumbprint(key.publicJwk);
  console.log(`DPoP key thumbprint (jkt): ${thumbprint}`);

  const tok = await stepUpTokens(key);
  const first = decodeJwt(tok.access_token);
  console.log(`step-up token: acr=${first.acr}  cnf.jkt=${first.cnf?.jkt}`);
  assert(first.acr === ACR, `expected acr=${ACR} after OTP, got ${first.acr}`);
  assert(first.cnf?.jkt === thumbprint, `step-up token not bound to our key (cnf.jkt=${first.cnf?.jkt})`);

  const refreshed = await tokenRequest({
    grant_type: "refresh_token", refresh_token: tok.refresh_token,
    client_id: cfg.clientId, client_secret: cfg.clientSecret,
  }, key);
  if (!refreshed.access_token) throw new Error(`refresh failed: ${JSON.stringify(refreshed)}`);
  const second = decodeJwt(refreshed.access_token);
  console.log(`refreshed token: acr=${second.acr}  cnf.jkt=${second.cnf?.jkt}`);
  assert(second.acr === ACR, `refresh did not preserve elevation: expected ${ACR}, got ${second.acr}`);
  assert(second.cnf?.jkt === thumbprint, `refresh lost/changed the DPoP binding (cnf.jkt=${second.cnf?.jkt})`);

  console.log(`\nE2E PASSED: step-up refresh preserves acr=${second.acr} and a stable DPoP binding (cnf.jkt) for the session lifetime`);
}

main().catch((err) => {
  console.error("E2E FAILED:", err.message);
  process.exit(1);
});
