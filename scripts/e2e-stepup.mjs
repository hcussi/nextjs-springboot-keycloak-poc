#!/usr/bin/env node
// Headless end-to-end check of the STEP-UP (acr=pro) flow with DPoP against a
// running stack. It drives the Authorization Code + PKCE flow DIRECTLY against
// Keycloak with its own ES256 key, requesting `acr_values=pro` so Keycloak forces
// the TOTP second factor, completes the OTP, and obtains an access token that is
// BOTH elevated (acr=pro) AND DPoP-bound (cnf.jkt). It then calls the elevated
// GET /server-details under the `DPoP` scheme and asserts it unlocks.
//
// Iteration 3 sender-constrains the token, so the token exchange carries a DPoP
// proof and every resource call carries a fresh proof bound to the token. This
// complements scripts/e2e-login.mjs (base login) and scripts/e2e-stepup-denied.mjs
// (a user without a second factor is refused).
//
// Prereq: the stack is up (`docker compose up -d --build`) and `/etc/hosts` has
// `127.0.0.1 keycloak`. Seed user testuser / password with the dev TOTP seed.
//
// Usage:  node scripts/e2e-stepup.mjs
//   KEYCLOAK_BASE (default http://keycloak:8081), API_URL (default http://localhost:8080)
//   USERNAME / PASSWORD (default testuser / password)
//   TOTP_SECRET  (default: the dev seed baked into scripts/totp.mjs)

import crypto from "node:crypto";
import { generateKeyPair, jwkThumbprint, signProof, base64url } from "./lib/dpop.mjs";
import { totp, secondsLeft, DEFAULT_SEED } from "./totp.mjs";

const cfg = {
  authBase: process.env.KEYCLOAK_BASE ?? "http://keycloak:8081",
  realm: process.env.KEYCLOAK_REALM ?? "web",
  clientId: process.env.KEYCLOAK_CLIENT_ID ?? "nextjs-frontend",
  clientSecret: process.env.KEYCLOAK_CLIENT_SECRET ?? "nextjs-frontend-secret-dev",
  redirectUri: "http://localhost:3000/api/auth/callback/keycloak",
  api: process.env.API_URL ?? "http://localhost:8080",
  username: process.env.USERNAME ?? "testuser",
  password: process.env.PASSWORD ?? "password",
  secret: process.env.TOTP_SECRET ?? DEFAULT_SEED,
};
const ACR = "pro";

const realmBase = `${cfg.authBase}/realms/${cfg.realm}`;
const authEndpoint = `${realmBase}/protocol/openid-connect/auth`;
const tokenEndpoint = `${realmBase}/protocol/openid-connect/token`;

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

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

// A TOTP code with comfortable validity left: if the current window is about to
// roll (<3s), wait for the next one so the code stays valid through submission.
async function freshCode() {
  if (secondsLeft() < 3) await sleep((secondsLeft() + 1) * 1000);
  return totp(cfg.secret);
}

// Submit the TOTP, retrying across 30s window rollovers, until Keycloak redirects
// to the callback. Recomputing inside the same window would resubmit the same
// rejected code, so on a rejection we wait for the next window first.
async function submitOtp(action) {
  for (let attempt = 1; attempt <= 3; attempt++) {
    const code = await freshCode();
    console.log(`OTP attempt ${attempt}: submitting ${code}`);
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

// Drive the auth-code flow directly against Keycloak with acr_values=pro. Handles
// the password form and the OTP second factor. Returns { code, codeVerifier }.
async function getProCode() {
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
    acr_values: ACR,
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
      res = await go(loc);
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

// Exchange the code with a DPoP proof (htm=POST, htu=token endpoint), retrying
// once on a use_dpop_nonce challenge.
async function exchangeCode({ code, codeVerifier, key }, nonce) {
  const headers = {
    "Content-Type": "application/x-www-form-urlencoded",
    DPoP: signProof({
      privateKey: key.privateKey,
      publicJwk: key.publicJwk,
      htm: "POST",
      htu: tokenEndpoint,
      nonce,
    }),
  };
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
  if (!res.ok && !nonce && json.error === "use_dpop_nonce") {
    const serverNonce = res.headers.get("dpop-nonce");
    if (serverNonce) return exchangeCode({ code, codeVerifier, key }, serverNonce);
  }
  return { res, json };
}

// Call a backend endpoint under the DPoP scheme with a fresh, token-bound proof.
async function callBackend(path, { token, key }) {
  const url = `${cfg.api}${path}`;
  return fetch(url, {
    method: "GET",
    headers: {
      authorization: `DPoP ${token}`,
      DPoP: signProof({
        privateKey: key.privateKey,
        publicJwk: key.publicJwk,
        htm: "GET",
        htu: url,
        accessToken: token,
      }),
    },
  });
}

async function main() {
  const key = generateKeyPair();
  const thumbprint = jwkThumbprint(key.publicJwk);
  console.log(`DPoP key thumbprint (jkt): ${thumbprint}`);

  // 1) Step-up login -> OTP -> elevated + bound token (acr=pro AND cnf.jkt).
  const bound = await exchangeCode({ ...(await getProCode()), key });
  assert(bound.res.ok, `token exchange failed: ${JSON.stringify(bound.json)}`);
  const token = bound.json.access_token;
  const claims = decodeJwt(token);
  console.log(`access token: acr=${claims.acr}  cnf.jkt=${claims.cnf?.jkt}`);
  assert(claims.acr === ACR, `expected acr=${ACR}, got acr=${claims.acr}`);
  assert(claims.cnf?.jkt === thumbprint, `elevated token not bound to our key (cnf.jkt=${claims.cnf?.jkt})`);

  // 2) The elevated bound token unlocks /server-details (the endpoint the UI calls).
  const sd = await callBackend("/server-details", { token, key });
  const details = await sd.json().catch(() => ({}));
  console.log(`GET /server-details (pro + DPoP proof) -> ${sd.status} (application: ${details.application})`);
  assert(sd.status === 200 && details.application, `elevated DPoP token failed on /server-details (HTTP ${sd.status})`);

  // 3) Sanity: still a valid bound token for the base endpoint too.
  const hello = await callBackend("/hello", { token, key });
  console.log(`GET /hello (pro + DPoP proof) -> ${hello.status}`);
  assert(hello.status === 200, `elevated token failed on /hello (HTTP ${hello.status})`);

  console.log(`\nE2E PASSED: step-up login -> OTP -> acr=${claims.acr} + cnf.jkt bound token -> /server-details 200 under DPoP`);
}

main().catch((err) => {
  console.error("E2E FAILED:", err.message);
  process.exit(1);
});
