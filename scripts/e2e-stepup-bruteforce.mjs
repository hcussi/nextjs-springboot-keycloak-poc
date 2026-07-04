#!/usr/bin/env node
// Headless test that Keycloak's brute-force protection guards the step-up (OTP)
// factor. Using a dedicated `bruteuser` (password + seeded OTP) so it never locks
// out `testuser`, it drives the step-up flow and submits RANDOM wrong OTP codes
// in fresh, spaced sessions. After `failureFactor` failures Keycloak temporarily
// disables the account, at which point the password step stops reaching the OTP
// form and returns a generic "Invalid username or password" even for the correct
// password. Lock detection is read straight from the flow responses; the admin
// REST API is used only to reset the counter before and after (so the test is
// repeatable and leaves `bruteuser` unlocked).
//
// Prereq: Keycloak up (`docker compose up -d keycloak`) and `/etc/hosts` has
// `127.0.0.1 keycloak`. Runs ~20s (failures must be spaced past the realm
// `quickLoginCheckMilliSeconds` or Keycloak collapses them into one).
//
// Usage:  node scripts/e2e-stepup-bruteforce.mjs
//   KC (default http://localhost:8081)
//   KEYCLOAK_ADMIN_USERNAME / KEYCLOAK_ADMIN_PASSWORD (dev defaults match .env)

import crypto from "node:crypto";

const KC = process.env.KC ?? "http://localhost:8081";
const REALM = "web";
const CLIENT = "nextjs-frontend";
const REDIRECT = "http://localhost:3000/api/auth/callback/keycloak";
const USER = "bruteuser";
const PASS = "password";
const ADMIN_USER = process.env.KEYCLOAK_ADMIN_USERNAME ?? "admin";
// Dev-only admin password (matches .env; override via env for a real setup).
const ADMIN_PW = process.env.KEYCLOAK_ADMIN_PASSWORD ?? "94e4d551eb822834cfc9660f68fc3dd9";
const SPACING_MS = 1300; // must exceed realm quickLoginCheckMilliSeconds (1000)

const realmBase = `${KC}/realms/${REALM}`;
const b64 = (b) => b.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const action = (h) => h.match(/action="([^"]*login-actions\/authenticate[^"]*)"/)?.[1]?.replace(/&amp;/g, "&");
const feedback = (h) => h.match(/kc-feedback-text[^>]*>([\s\S]*?)</)?.[1]?.replace(/\s+/g, " ").trim();

// --- admin helpers (each refreshes the token, so a slow test can't expire it) ---
let USER_ID;
async function adminToken() {
  const r = await fetch(`${KC}/realms/master/protocol/openid-connect/token`, {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: "admin-cli", username: ADMIN_USER, password: ADMIN_PW, grant_type: "password" }),
  });
  if (!r.ok) throw new Error(`admin login failed (${r.status}); set KEYCLOAK_ADMIN_PASSWORD?`);
  return (await r.json()).access_token;
}
async function adminGet(path) {
  const token = await adminToken();
  const r = await fetch(`${KC}/admin/realms/${REALM}${path}`, { headers: { authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error(`admin GET ${path} -> ${r.status}`);
  return r.json();
}
async function resolveUserId() {
  const u = await adminGet(`/users?username=${USER}&exact=true`);
  if (!u[0]) throw new Error(`${USER} not found in realm (re-import the realm?)`);
  USER_ID = u[0].id;
}
async function bfReset() {
  const token = await adminToken();
  const r = await fetch(`${KC}/admin/realms/${REALM}/attack-detection/brute-force/users/${USER_ID}`, {
    method: "DELETE", headers: { authorization: `Bearer ${token}` } });
  if (!r.ok && r.status !== 204) throw new Error(`brute-force reset -> ${r.status}`);
}
const bfStatus = () => adminGet(`/attack-detection/brute-force/users/${USER_ID}`);

// One fresh authorize -> password -> OTP. When the account is locked, the flow
// stops at the password step (reachedOtp=false). Returns the stage and feedback.
async function attempt(otp) {
  const jar = new Map();
  const absorb = (r) => { for (const sc of r.headers.getSetCookie?.() ?? []) { const [p] = sc.split(";"); const eq = p.indexOf("="); if (eq > 0) { const val = p.slice(eq + 1).trim(); if (val) jar.set(p.slice(0, eq).trim(), val); } } };
  const go = (u, o = {}) => fetch(u, { redirect: "manual", ...o, headers: { ...(o.headers || {}), ...(jar.size ? { cookie: [...jar].map(([k, v]) => `${k}=${v}`).join("; ") } : {}) } }).then((r) => { absorb(r); return r; });
  const v = b64(crypto.randomBytes(32)), c = b64(crypto.createHash("sha256").update(v).digest());
  const url = `${realmBase}/protocol/openid-connect/auth?` + new URLSearchParams({ response_type: "code", client_id: CLIENT, redirect_uri: REDIRECT, scope: "openid", state: "x", code_challenge: c, code_challenge_method: "S256", acr_values: "pro" });
  let r = await go(url); let h = await r.text();
  r = await go(action(h), { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ username: USER, password: PASS, credentialId: "" }) });
  h = r.status === 200 ? await r.text() : "";
  if (!/name="otp"/.test(h)) return { reachedOtp: false, feedback: feedback(h) };
  r = await go(action(h), { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ otp, login: "Sign In" }) });
  h = r.status === 200 ? await r.text() : "";
  return { reachedOtp: true, feedback: feedback(h) };
}

async function main() {
  await resolveUserId();
  const realm = await adminGet("");
  const failureFactor = realm.failureFactor ?? 10;
  if (!realm.bruteForceProtected) throw new Error("bruteForceProtected is OFF on the realm; brute-force test is meaningless");
  console.log(`brute-force ON, failureFactor=${failureFactor}; resetting ${USER} counter`);
  await bfReset();
  const st0 = await bfStatus();
  if (st0.numFailures !== 0 || st0.disabled) throw new Error(`reset failed: ${JSON.stringify(st0)}`);

  try {
    // Submit random wrong OTPs. Count how many actually reach (and fail) the OTP
    // step; the account should lock exactly after `failureFactor` of them, after
    // which the password step is refused (correct password, generic message).
    let otpFailures = 0;
    let lockFeedback = null;
    const maxAttempts = failureFactor + 3;
    for (let i = 1; i <= maxAttempts; i++) {
      const wrong = String(crypto.randomInt(0, 1_000_000)).padStart(6, "0");
      const a = await attempt(wrong);
      if (a.reachedOtp) {
        otpFailures++;
        console.log(`  attempt ${String(i).padStart(2)}: otp=${wrong} reached OTP -> "${a.feedback ?? ""}"`);
        await sleep(SPACING_MS);
      } else {
        lockFeedback = a.feedback;
        console.log(`  attempt ${String(i).padStart(2)}: password step REFUSED -> "${a.feedback ?? ""}" (account locked)`);
        break;
      }
    }

    if (lockFeedback === null) throw new Error(`account never locked after ${maxAttempts} wrong OTPs (brute-force not enforced on the OTP step)`);
    if (otpFailures !== failureFactor) throw new Error(`locked after ${otpFailures} OTP failures, expected failureFactor ${failureFactor}`);
    if (!/invalid username or password/i.test(lockFeedback)) throw new Error(`expected a locked-out response, got "${lockFeedback}"`);
    console.log(`locked after ${otpFailures} failed OTPs (= failureFactor); correct password then refused with "${lockFeedback}"`);
  } finally {
    // Always unlock (fresh admin token inside bfReset), even if an assertion threw,
    // so bruteuser stays reusable and the suite stays repeatable.
    await bfReset();
    const st = await bfStatus();
    console.log(`cleanup: brute-force reset (numFailures=${st.numFailures}, disabled=${st.disabled})`);
  }

  console.log(`\nE2E PASSED: brute-force locks the OTP factor at failureFactor and refuses the locked account`);
}

main().catch((err) => {
  console.error("E2E FAILED:", err.message);
  process.exit(1);
});
