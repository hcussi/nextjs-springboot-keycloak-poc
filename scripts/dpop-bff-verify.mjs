#!/usr/bin/env node
// Step 3 verification (PLAN-3): the Next.js frontend now holds the DPoP key in the
// server tier and calls the backend through a same-origin BFF proxy. This drives
// next-auth login headlessly (like e2e-login), then exercises the proxy:
//
//   1. session does NOT expose the access token (only the acr UI hint).
//   2. GET /api/backend/hello -> 200 greeting (proxy attached the DPoP token+proof).
//   3. GET /api/backend/server-details -> 401 with the RFC 9470 step-up challenge
//      relayed through the proxy (base session is acr=basic).
//
// Prereq: full stack up (`docker compose up -d --build`) and `/etc/hosts` has
// `127.0.0.1 keycloak`. Seed user testuser / password.

import { totp, secondsLeft, DEFAULT_SEED } from "./totp.mjs";

const FRONT = process.env.FRONTEND_URL ?? "http://localhost:3000";
const USERNAME = process.env.USERNAME ?? "testuser";
const PASSWORD = process.env.PASSWORD ?? "password";
const SECRET = process.env.TOTP_SECRET ?? DEFAULT_SEED;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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

async function main() {
  // 1) next-auth sign-in -> Keycloak authorize.
  const csrf = await (await go(`${FRONT}/api/auth/csrf`)).json();
  const signin = await go(`${FRONT}/api/auth/signin/keycloak`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form({ csrfToken: csrf.csrfToken, callbackUrl: `${FRONT}/` }),
  });
  const authorizeUrl = signin.headers.get("location");
  if (!authorizeUrl) throw new Error(`no authorize redirect (HTTP ${signin.status})`);

  // 2) Keycloak login form -> submit credentials.
  const loginHtml = await (await go(authorizeUrl)).text();
  const action = loginHtml
    .match(/action="([^"]*login-actions\/authenticate[^"]*)"/)?.[1]
    ?.replace(/&amp;/g, "&");
  if (!action) throw new Error("login form action not found");
  const afterLogin = await go(action, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form({ username: USERNAME, password: PASSWORD, credentialId: "" }),
  });
  const callbackUrl = afterLogin.headers.get("location");
  if (!callbackUrl?.includes("/api/auth/callback/keycloak")) {
    throw new Error(`expected callback redirect, got HTTP ${afterLogin.status} -> ${callbackUrl}`);
  }

  // 3) Hit the callback -> next-auth runs the DPoP-bound token exchange, sets session.
  const callback = await go(callbackUrl);
  if (callback.status !== 302) throw new Error(`callback did not redirect (HTTP ${callback.status})`);

  // 4) Session must NOT contain the access token (browser never holds it).
  const session = await (await go(`${FRONT}/api/auth/session`)).json();
  console.log("session keys:", Object.keys(session).join(", "), "| acr:", session.acr);
  if (session.accessToken) throw new Error("session exposed accessToken to the browser (should be server-side only)");
  if (session.acr !== "basic") throw new Error(`expected acr=basic, got ${session.acr}`);

  // 5) Proxy: /hello via same-origin BFF (no Authorization header from the client).
  const hello = await go(`${FRONT}/api/backend/hello`);
  const helloText = await hello.text();
  console.log(`GET /api/backend/hello -> ${hello.status}: ${helloText}`);
  if (hello.status !== 200 || helloText !== `Hello World, ${USERNAME}`) {
    throw new Error("BFF /hello did not return the greeting");
  }

  // 6) Proxy: /server-details at base level -> relayed RFC 9470 step-up 401.
  const details = await go(`${FRONT}/api/backend/server-details`);
  const challenge = details.headers.get("www-authenticate") ?? "";
  console.log(`GET /api/backend/server-details -> ${details.status}: ${challenge}`);
  if (details.status !== 401) throw new Error(`expected 401 step-up, got ${details.status}`);
  if (!challenge.includes("insufficient_user_authentication") || !challenge.includes('acr_values="pro"')) {
    throw new Error(`step-up challenge not relayed through the proxy: ${challenge}`);
  }

  // 7) Step-up phase: a fresh login requesting acr=pro, complete OTP, then the
  //    elevated (pro) DPoP-bound token must succeed on /server-details via the proxy.
  jars.clear();
  const csrf2 = await (await go(`${FRONT}/api/auth/csrf`)).json();
  const signin2 = await go(`${FRONT}/api/auth/signin/keycloak`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form({ csrfToken: csrf2.csrfToken, callbackUrl: `${FRONT}/` }),
  });
  let authorize2 = signin2.headers.get("location");
  authorize2 += (authorize2.includes("?") ? "&" : "?") + form({ acr_values: "pro" });
  const loginHtml2 = await (await go(authorize2)).text();
  const action2 = loginHtml2.match(/action="([^"]*login-actions\/authenticate[^"]*)"/)?.[1]?.replace(/&amp;/g, "&");
  let res = await go(action2, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form({ username: USERNAME, password: PASSWORD, credentialId: "" }),
  });
  // Password step returns the OTP form (HTTP 200); submit a fresh TOTP.
  if (res.status === 200) {
    let html = await res.text();
    for (let attempt = 1; attempt <= 3; attempt++) {
      if (secondsLeft() < 3) await sleep((secondsLeft() + 1) * 1000);
      const otpAction = html.match(/action="([^"]*login-actions\/authenticate[^"]*)"/)?.[1]?.replace(/&amp;/g, "&");
      res = await go(otpAction, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: form({ otp: totp(SECRET), login: "Sign In" }),
      });
      if (res.status === 302) break;
      html = await res.text();
      if (attempt < 3) await sleep((secondsLeft() + 1) * 1000);
    }
  }
  const cb2 = res.headers.get("location");
  if (!cb2?.includes("/api/auth/callback/keycloak")) throw new Error(`step-up: no callback redirect (HTTP ${res.status})`);
  await go(cb2);
  const session2 = await (await go(`${FRONT}/api/auth/session`)).json();
  console.log("step-up session acr:", session2.acr);
  if (session2.acr !== "pro") throw new Error(`expected acr=pro after OTP, got ${session2.acr}`);
  const details2 = await go(`${FRONT}/api/backend/server-details`);
  const body2 = await details2.json().catch(() => ({}));
  console.log(`GET /api/backend/server-details (pro) -> ${details2.status} (application: ${body2.application})`);
  if (details2.status !== 200 || !body2.application) throw new Error("elevated DPoP token failed on /server-details via BFF");

  console.log(`\nSTEP 3 PASSED: DPoP token via BFF; no token in browser; /hello 200; step-up relayed; pro -> /server-details 200`);
}

main().catch((err) => {
  console.error(`\nSTEP 3 FAILED: ${err.message}`);
  process.exit(1);
});
