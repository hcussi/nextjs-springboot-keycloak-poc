#!/usr/bin/env node
// Headless negative test for step-up: a user WITHOUT a second factor must NOT be
// able to reach acr=pro. `basicuser` (username + password only, no OTP) requests
// `acr_values=pro`; because self-service TOTP enrollment is disabled in the realm
// (CONFIGURE_TOTP required action off), Keycloak denies the step-up with "Cannot
// login, credential setup required" instead of letting the user enroll a factor
// inline. This asserts that failure path and that NO authorization code (hence no
// token, elevated or otherwise) is ever issued.
//
// It drives the Authorization Code + PKCE flow DIRECTLY against Keycloak (like the
// other iteration-3 e2e scripts): the denial happens at the authorization step,
// before any token exchange, so DPoP does not enter into it. Complements
// scripts/e2e-stepup.mjs (the positive path for testuser, who has a provisioned
// TOTP factor).
//
// Prereq: the stack is up (`docker compose up -d --build`) and `/etc/hosts` has
// `127.0.0.1 keycloak`.
//
// Usage:  node scripts/e2e-stepup-denied.mjs
//   KEYCLOAK_BASE (default http://keycloak:8081)
//   USERNAME / PASSWORD (default basicuser / password)

import crypto from "node:crypto";
import { base64url } from "./lib/dpop.mjs";

const cfg = {
  authBase: process.env.KEYCLOAK_BASE ?? "http://keycloak:8081",
  realm: process.env.KEYCLOAK_REALM ?? "web",
  clientId: process.env.KEYCLOAK_CLIENT_ID ?? "nextjs-frontend",
  redirectUri: "http://localhost:3000/api/auth/callback/keycloak",
  username: process.env.USERNAME ?? "basicuser",
  password: process.env.PASSWORD ?? "password",
};
const ACR = "pro";

const realmBase = `${cfg.authBase}/realms/${cfg.realm}`;
const authEndpoint = `${realmBase}/protocol/openid-connect/auth`;

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

async function main() {
  // 1) Begin the auth-code flow directly, requesting LoA 2 (acr=pro).
  const codeVerifier = base64url(crypto.randomBytes(32));
  const codeChallenge = base64url(crypto.createHash("sha256").update(codeVerifier).digest());
  const state = base64url(crypto.randomBytes(16));
  const authUrl = `${authEndpoint}?${form({
    response_type: "code",
    client_id: cfg.clientId,
    redirect_uri: cfg.redirectUri,
    scope: "openid profile email",
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    acr_values: ACR,
  })}`;

  // 2) Login page -> submit basicuser credentials.
  const loginAction = formAction(await (await go(authUrl)).text());
  if (!loginAction) throw new Error("login form action not found");
  const res = await go(loginAction, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form({ username: cfg.username, password: cfg.password, credentialId: "" }),
  });

  // 3) Assert the step-up was DENIED, not elevated: no redirect to the callback
  //    (no authorization code), no OTP/enrollment form, and a denial page.
  const location = res.headers.get("location");
  const html = res.status === 200 || res.status >= 400 ? await res.text() : "";

  if (location?.includes("/api/auth/callback/keycloak")) {
    throw new Error("SECURITY: basicuser reached the callback (an authorization code was issued) without a second factor");
  }
  if (/name="otp"/.test(html)) {
    throw new Error("basicuser was shown an OTP/enrollment form; self-service enrollment should be disabled");
  }
  const denied = /credential setup required/i.test(html) || /We are sorry/i.test(html);
  if (!denied) {
    throw new Error(`expected a step-up denial page, got HTTP ${res.status}: ${html.slice(0, 200)}`);
  }

  console.log(`step-up denied for ${cfg.username} (no second factor): HTTP ${res.status}, "credential setup required"`);
  console.log(`\nE2E PASSED: step-up correctly denied, no authorization code (hence no acr=pro token) issued`);
}

main().catch((err) => {
  console.error("E2E FAILED:", err.message);
  process.exit(1);
});
