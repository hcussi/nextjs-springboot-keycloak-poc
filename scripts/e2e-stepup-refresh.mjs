#!/usr/bin/env node
// Headless check that an elevated (acr=pro) session stays elevated across a token
// refresh. This is a Keycloak (IdP) behavior, so it drives the Authorization Code
// + PKCE flow directly, completes the OTP second factor, then runs the
// refresh_token grant and asserts the refreshed access token is still acr=pro.
//
// It documents PLAN-2 §5 (accepted POC limitation): the refresh grant preserves
// the SSO session's achieved LoA for the session lifetime without re-running OTP,
// so `max age: 0` on the step-up condition only forces a fresh OTP at the
// authorization request, not per token use. Measured here rather than assumed.
//
// A dedicated script (not folded into e2e-stepup.mjs) because next-auth keeps the
// refresh token server-side, and because a single OTP avoids Keycloak's one-time
// code reuse protection rejecting a second submission in the same 30s window.
//
// Prereq: Keycloak up (`docker compose up -d keycloak`) and `/etc/hosts` has
// `127.0.0.1 keycloak`.
//
// Usage:  node scripts/e2e-stepup-refresh.mjs
//   KC (default http://localhost:8081), USERNAME/PASSWORD, TOTP_SECRET

import crypto from "node:crypto";
import { totp, DEFAULT_SEED } from "./totp.mjs";

const KC = process.env.KC ?? "http://localhost:8081";
const REALM = "web";
const CLIENT = "nextjs-frontend";
const SECRET = process.env.KEYCLOAK_CLIENT_SECRET ?? "nextjs-frontend-secret-dev";
const REDIRECT = "http://localhost:3000/api/auth/callback/keycloak";
const USER = process.env.USERNAME ?? "testuser";
const PASS = process.env.PASSWORD ?? "password";
const TOTP_SECRET = process.env.TOTP_SECRET ?? DEFAULT_SEED;
const ACR = "pro";
const realmBase = `${KC}/realms/${REALM}`;

const b64url = (b) => b.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const decode = (jwt) => JSON.parse(Buffer.from(jwt.split(".")[1], "base64url").toString("utf8"));
const formAction = (h) => h.match(/action="([^"]*login-actions\/authenticate[^"]*)"/)?.[1]?.replace(/&amp;/g, "&");

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
const tokenRequest = (params) =>
  fetch(`${realmBase}/protocol/openid-connect/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(params),
  }).then((r) => r.json());

// Authorization Code + PKCE with acr_values=pro, completing the OTP form.
async function stepUpTokens() {
  const verifier = b64url(crypto.randomBytes(32));
  const challenge = b64url(crypto.createHash("sha256").update(verifier).digest());
  const authUrl = `${realmBase}/protocol/openid-connect/auth?` + new URLSearchParams({
    response_type: "code", client_id: CLIENT, redirect_uri: REDIRECT, scope: "openid",
    state: b64url(crypto.randomBytes(8)), code_challenge: challenge, code_challenge_method: "S256",
    acr_values: ACR,
  });
  let res = await go(authUrl);
  res = await go(formAction(await res.text()), {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ username: USER, password: PASS, credentialId: "" }),
  });
  let location = res.headers.get("location");
  if (!location) {
    const html = await res.text();
    if (!/name="otp"/.test(html)) throw new Error("expected the OTP form for a pro step-up");
    res = await go(formAction(html), {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ otp: totp(TOTP_SECRET), login: "Sign In" }),
    });
    location = res.headers.get("location");
  }
  if (!location?.startsWith(REDIRECT)) throw new Error(`no code redirect: HTTP ${res.status} -> ${location}`);
  const code = new URL(location).searchParams.get("code");
  const tok = await tokenRequest({
    grant_type: "authorization_code", code, redirect_uri: REDIRECT,
    client_id: CLIENT, client_secret: SECRET, code_verifier: verifier,
  });
  if (!tok.access_token || !tok.refresh_token) throw new Error(`token exchange failed: ${JSON.stringify(tok)}`);
  return tok;
}

async function main() {
  const tok = await stepUpTokens();
  const acr1 = decode(tok.access_token).acr;
  console.log(`step-up token acr: ${acr1}`);
  if (acr1 !== ACR) throw new Error(`expected acr=${ACR} after OTP, got ${acr1}`);

  const refreshed = await tokenRequest({
    grant_type: "refresh_token", refresh_token: tok.refresh_token,
    client_id: CLIENT, client_secret: SECRET,
  });
  if (!refreshed.access_token) throw new Error(`refresh failed: ${JSON.stringify(refreshed)}`);
  const acr2 = decode(refreshed.access_token).acr;
  console.log(`refreshed token acr: ${acr2}`);
  if (acr2 !== ACR) throw new Error(`refresh did not preserve elevation: expected ${ACR}, got ${acr2}`);

  console.log(`\nE2E PASSED: step-up refresh preserves acr=${acr2} for the session lifetime`);
}

main().catch((err) => {
  console.error("E2E FAILED:", err.message);
  process.exit(1);
});
