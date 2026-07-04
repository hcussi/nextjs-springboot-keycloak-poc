#!/usr/bin/env node
// Headless negative test for step-up: a user WITHOUT a second factor must NOT be
// able to reach acr=pro. `basicuser` (username + password only, no OTP) requests
// `acr_values=pro`; because self-service TOTP enrollment is disabled in the realm
// (CONFIGURE_TOTP required action off), Keycloak denies the step-up with
// "Cannot login, credential setup required" instead of letting the user enroll a
// factor inline. This asserts that failure path and that NO elevated session is
// minted.
//
// Complements scripts/e2e-stepup.mjs (the positive path for testuser, who has a
// provisioned TOTP factor).
//
// Prereq: the stack is up (`docker compose up -d --build`) and `/etc/hosts` has
// `127.0.0.1 keycloak`.
//
// Usage:  node scripts/e2e-stepup-denied.mjs
//   FRONTEND_URL (default http://localhost:3000)
//   USERNAME / PASSWORD (default basicuser / password)

const FRONT = process.env.FRONTEND_URL ?? "http://localhost:3000";
const USERNAME = process.env.USERNAME ?? "basicuser";
const PASSWORD = process.env.PASSWORD ?? "password";
const ACR = "pro";

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
  // 1) CSRF + begin sign-in -> authorize redirect (next-auth sets state + PKCE).
  const csrf = await (await go(`${FRONT}/api/auth/csrf`)).json();
  const signin = await go(`${FRONT}/api/auth/signin/keycloak`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form({ csrfToken: csrf.csrfToken, callbackUrl: `${FRONT}/` }),
  });
  let authorizeUrl = signin.headers.get("location");
  if (!authorizeUrl) throw new Error(`no authorize redirect (HTTP ${signin.status})`);
  authorizeUrl += (authorizeUrl.includes("?") ? "&" : "?") + form({ acr_values: ACR });

  // 2) Login page -> submit basicuser credentials.
  const loginAction = formAction(await (await go(authorizeUrl)).text());
  if (!loginAction) throw new Error("login form action not found");
  const res = await go(loginAction, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form({ username: USERNAME, password: PASSWORD, credentialId: "" }),
  });

  // 3) Assert the step-up was DENIED, not elevated.
  const location = res.headers.get("location");
  const html = res.status === 200 || res.status >= 400 ? await res.text() : "";

  if (location?.includes("/api/auth/callback/keycloak")) {
    throw new Error("SECURITY: basicuser reached the callback (a token was issued) without a second factor");
  }
  if (/name="otp"/.test(html)) {
    throw new Error("basicuser was shown an OTP/enrollment form; self-service enrollment should be disabled");
  }
  const denied = /credential setup required/i.test(html) || /We are sorry/i.test(html);
  if (!denied) {
    throw new Error(`expected a step-up denial page, got HTTP ${res.status}: ${html.slice(0, 200)}`);
  }

  // 4) And no next-auth session/token should exist.
  const session = await (await go(`${FRONT}/api/auth/session`)).json();
  if (session?.accessToken) {
    throw new Error("SECURITY: a session with an access token exists after a denied step-up");
  }

  console.log(`step-up denied for ${USERNAME} (no second factor): HTTP ${res.status}, "credential setup required"`);
  console.log(`\nE2E PASSED: step-up correctly denied, no acr=pro token issued`);
}

main().catch((err) => {
  console.error("E2E FAILED:", err.message);
  process.exit(1);
});
