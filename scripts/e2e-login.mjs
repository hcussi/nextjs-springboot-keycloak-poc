#!/usr/bin/env node
// Headless end-to-end check of the full login flow against a running stack:
// drives next-auth + Keycloak like a browser (Authorization Code + PKCE),
// establishes a session, then calls the protected GET /hello and asserts the
// greeting. Useful as a smoke test without opening a browser.
//
// Prereq: the stack is up (`docker compose up -d --build`) and `/etc/hosts` has
// `127.0.0.1 keycloak`. Seed user testuser / password.
//
// Usage:  node scripts/e2e-login.mjs
//   FRONTEND_URL (default http://localhost:3000)
//   API_URL      (default http://localhost:8080)
//   USERNAME / PASSWORD (default testuser / password)

const FRONT = process.env.FRONTEND_URL ?? "http://localhost:3000";
const API = process.env.API_URL ?? "http://localhost:8080";
const USERNAME = process.env.USERNAME ?? "testuser";
const PASSWORD = process.env.PASSWORD ?? "password";

// Cookies are tracked per host (the browser keeps next-auth's localhost cookies
// separate from Keycloak's), and redirects are followed manually.
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
  // 1) CSRF token for the sign-in POST.
  const csrf = await (await go(`${FRONT}/api/auth/csrf`)).json();

  // 2) Begin sign-in -> 302 to the Keycloak authorize URL.
  const signin = await go(`${FRONT}/api/auth/signin/keycloak`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form({ csrfToken: csrf.csrfToken, callbackUrl: `${FRONT}/` }),
  });
  const authorizeUrl = signin.headers.get("location");
  if (!authorizeUrl) throw new Error(`no authorize redirect (HTTP ${signin.status})`);

  // 3) Keycloak login page -> extract the form action.
  const loginHtml = await (await go(authorizeUrl)).text();
  const action = loginHtml
    .match(/action="([^"]*login-actions\/authenticate[^"]*)"/)?.[1]
    ?.replace(/&amp;/g, "&");
  if (!action) throw new Error("login form action not found");

  // 4) Submit credentials -> 302 back to the next-auth callback with the code.
  const afterLogin = await go(action, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form({ username: USERNAME, password: PASSWORD, credentialId: "" }),
  });
  const callbackUrl = afterLogin.headers.get("location");
  if (!callbackUrl?.includes("/api/auth/callback/keycloak")) {
    throw new Error(`expected callback redirect, got HTTP ${afterLogin.status} -> ${callbackUrl}`);
  }

  // 5) Hit the callback -> next-auth exchanges the code and sets the session.
  const callback = await go(callbackUrl);
  if (callback.status !== 302) throw new Error(`callback did not redirect (HTTP ${callback.status})`);

  // 6) Read the session (exposes accessToken via the session callback).
  const session = await (await go(`${FRONT}/api/auth/session`)).json();
  if (!session?.accessToken) throw new Error(`no session/accessToken: ${JSON.stringify(session)}`);
  console.log("session.user:", JSON.stringify(session.user));

  // 7) Call the protected endpoint the way the browser does.
  const hello = await fetch(`${API}/hello`, {
    headers: { authorization: `Bearer ${session.accessToken}` },
  });
  const text = await hello.text();
  console.log(`GET /hello -> ${hello.status}: ${text}`);
  if (hello.status !== 200 || text !== `Hello World, ${USERNAME}`) {
    throw new Error("unexpected /hello result");
  }
  console.log(`\nE2E PASSED: login -> session -> ${text}`);
}

main().catch((err) => {
  console.error("E2E FAILED:", err.message);
  process.exit(1);
});
