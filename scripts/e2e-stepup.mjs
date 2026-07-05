#!/usr/bin/env node
// Headless end-to-end check of the STEP-UP (acr=pro) flow against a running
// stack: drives next-auth + Keycloak like a browser, but requests `acr_values=pro`
// so Keycloak forces the TOTP second factor. It computes the code from the seed
// (reusing scripts/totp.mjs), submits it, establishes the elevated session, and
// asserts the resulting access token carries `acr=pro`.
//
// This complements scripts/e2e-login.mjs (base login -> acr=basic). The full
// step-up e2e including /server-details lands in Step 4; this focuses on proving
// the OTP challenge and the elevated acr.
//
// Prereq: the stack is up (`docker compose up -d --build`) and `/etc/hosts` has
// `127.0.0.1 keycloak`. Seed user testuser / password with the dev TOTP seed.
//
// Usage:  node scripts/e2e-stepup.mjs
//   FRONTEND_URL (default http://localhost:3000)
//   API_URL      (default http://localhost:8080)
//   USERNAME / PASSWORD (default testuser / password)
//   TOTP_SECRET  (default: the dev seed baked into scripts/totp.mjs)

import { totp, secondsLeft, DEFAULT_SEED } from "./totp.mjs";

const FRONT = process.env.FRONTEND_URL ?? "http://localhost:3000";
const API = process.env.API_URL ?? "http://localhost:8080";
const USERNAME = process.env.USERNAME ?? "testuser";
const PASSWORD = process.env.PASSWORD ?? "password";
const SECRET = process.env.TOTP_SECRET ?? DEFAULT_SEED;
const ACR = "pro";

// Cookies are tracked per host (next-auth's localhost cookies stay separate from
// Keycloak's), and redirects are followed manually.
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

// A TOTP code with comfortable validity left: if the current window is about to
// roll (<3s), wait for the next one so the code stays valid through submission.
async function freshCode() {
  if (secondsLeft() < 3) await sleep((secondsLeft() + 1) * 1000);
  return totp(SECRET);
}

async function main() {
  // 1) CSRF token for the sign-in POST.
  const csrf = await (await go(`${FRONT}/api/auth/csrf`)).json();

  // 2) Begin sign-in -> 302 to the Keycloak authorize URL (next-auth sets state + PKCE).
  const signin = await go(`${FRONT}/api/auth/signin/keycloak`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form({ csrfToken: csrf.csrfToken, callbackUrl: `${FRONT}/` }),
  });
  let authorizeUrl = signin.headers.get("location");
  if (!authorizeUrl) throw new Error(`no authorize redirect (HTTP ${signin.status})`);

  // Ask Keycloak for LoA 2. Appending acr_values does not disturb next-auth's
  // state/PKCE (validated from its own cookie on callback), it only tells
  // Keycloak to run the step-up flow.
  authorizeUrl += (authorizeUrl.includes("?") ? "&" : "?") + form({ acr_values: ACR });

  // 3) Keycloak login page -> extract the form action.
  const loginHtml = await (await go(authorizeUrl)).text();
  const loginAction = formAction(loginHtml);
  if (!loginAction) throw new Error("login form action not found");

  // 4) Submit credentials. With acr=pro requested, Keycloak responds with the OTP
  //    form (HTTP 200) rather than redirecting straight to the callback.
  let res = await go(loginAction, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form({ username: USERNAME, password: PASSWORD, credentialId: "" }),
  });

  let location = res.headers.get("location");
  if (res.status === 200) {
    let html = await res.text();
    if (!/name="otp"/.test(html)) throw new Error("expected the OTP form after password, but did not get it (is acr=pro forcing step-up?)");

    // 5) Submit the TOTP. A code submitted right at a 30s rotation boundary can be
    //    rejected; to make this deterministic we never submit a code with under 3s
    //    of validity left, and on a rejection we wait for the next window so the
    //    retry uses a genuinely different code (recomputing within the same window
    //    would just resubmit the same rejected code).
    let accepted = false;
    for (let attempt = 1; attempt <= 3 && !accepted; attempt++) {
      const otpAction = formAction(html);
      const code = await freshCode();
      console.log(`OTP attempt ${attempt}: submitting ${code}`);
      res = await go(otpAction, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: form({ otp: code, login: "Sign In" }),
      });
      location = res.headers.get("location");
      if (res.status === 302 && location) { accepted = true; break; }
      html = await res.text(); // rejected -> wait for a new window, then retry
      if (attempt < 3) await sleep((secondsLeft() + 1) * 1000);
    }
    if (!accepted) throw new Error("OTP was not accepted after retries");
  } else if (res.status !== 302) {
    throw new Error(`unexpected status after password: ${res.status}`);
  }

  if (!location?.includes("/api/auth/callback/keycloak")) {
    throw new Error(`expected callback redirect, got HTTP ${res.status} -> ${location}`);
  }

  // 6) Hit the callback -> next-auth exchanges the code and sets the session.
  const callback = await go(location);
  if (callback.status !== 302) throw new Error(`callback did not redirect (HTTP ${callback.status})`);

  // 7) Read the session and assert the access token was elevated to acr=pro.
  const session = await (await go(`${FRONT}/api/auth/session`)).json();
  if (!session?.accessToken) throw new Error(`no session/accessToken: ${JSON.stringify(session)}`);
  const claims = decodeJwt(session.accessToken);
  console.log("session.user:", JSON.stringify(session.user));
  console.log(`access-token acr: ${claims.acr}`);
  if (claims.acr !== ACR) throw new Error(`expected acr=${ACR}, got acr=${claims.acr}`);

  // 8) Sanity: the elevated token is a valid bearer for the base endpoint too.
  const hello = await fetch(`${API}/hello`, { headers: { authorization: `Bearer ${session.accessToken}` } });
  const text = await hello.text();
  console.log(`GET /hello -> ${hello.status}: ${text}`);
  if (hello.status !== 200) throw new Error("elevated token failed on /hello");

  console.log(`\nE2E PASSED: step-up login -> OTP -> session with acr=${claims.acr}`);
}

main().catch((err) => {
  console.error("E2E FAILED:", err.message);
  process.exit(1);
});
