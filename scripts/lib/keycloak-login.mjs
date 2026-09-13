// Shared login helper for the iteration-4 DPoP e2e scripts. Drives the
// Authorization Code + PKCE flow directly against Keycloak (the way next-auth does
// server-side) with a per-session ES256 key, and returns a `cnf.jkt`-bound access
// token plus that key. The older e2e scripts inline this scaffolding; the newer
// ones share it here to stay focused on the behavior under test.
//
// DEV-ONLY tooling. Keys are ephemeral; the client secret is the committed dev value.

import crypto from "node:crypto";
import { generateKeyPair, jwkThumbprint, signProof, base64url } from "./dpop.mjs";

export function loginConfig() {
  return {
    authBase: process.env.KEYCLOAK_BASE ?? "http://keycloak:8081",
    realm: process.env.KEYCLOAK_REALM ?? "web",
    clientId: process.env.KEYCLOAK_CLIENT_ID ?? "nextjs-frontend",
    clientSecret: process.env.KEYCLOAK_CLIENT_SECRET ?? "nextjs-frontend-secret-dev",
    redirectUri: "http://localhost:3000/api/auth/callback/keycloak",
    api: process.env.API_URL ?? "http://localhost:8080",
    username: process.env.USERNAME ?? "testuser",
    password: process.env.PASSWORD ?? "password",
  };
}

export const decodeJwt = (jwt) =>
  JSON.parse(Buffer.from(jwt.split(".")[1], "base64url").toString("utf8"));

const form = (obj) => new URLSearchParams(obj).toString();
const formAction = (html) =>
  html.match(/action="([^"]*login-actions\/authenticate[^"]*)"/)?.[1]?.replace(/&amp;/g, "&");

// Per-host cookie jar so Keycloak's SSO session survives the flow's redirects.
function makeGo() {
  const jars = new Map();
  const jarFor = (url) => {
    const host = new URL(url).host;
    if (!jars.has(host)) jars.set(host, new Map());
    return jars.get(host);
  };
  return async function go(url, { method = "GET", body, headers = {} } = {}) {
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
  };
}

async function getCode(cfg, go) {
  const realmBase = `${cfg.authBase}/realms/${cfg.realm}`;
  const authEndpoint = `${realmBase}/protocol/openid-connect/auth`;
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
  })}`);

  for (let i = 0; i < 8; i++) {
    const loc = res.headers.get("location");
    if (res.status === 302 && loc) {
      const redirect = new URL(loc, cfg.redirectUri);
      const code = redirect.searchParams.get("code");
      if (code) {
        if (redirect.searchParams.get("state") !== state) throw new Error("OAuth state mismatch");
        return { code, codeVerifier };
      }
      res = await go(loc);
      continue;
    }
    if (res.status === 200) {
      const action = formAction(await res.text());
      if (!action) throw new Error("no login form action in Keycloak page");
      res = await go(action, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: form({ username: cfg.username, password: cfg.password, credentialId: "" }),
      });
      continue;
    }
    throw new Error(`unexpected status ${res.status} while obtaining a code`);
  }
  throw new Error("did not obtain an authorization code");
}

async function exchangeCode(cfg, { code, codeVerifier, key }, nonce) {
  const tokenEndpoint = `${cfg.authBase}/realms/${cfg.realm}/protocol/openid-connect/token`;
  const res = await fetch(tokenEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      DPoP: signProof({ privateKey: key.privateKey, publicJwk: key.publicJwk, htm: "POST", htu: tokenEndpoint, nonce }),
    },
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
    if (serverNonce) return exchangeCode(cfg, { code, codeVerifier, key }, serverNonce);
  }
  return { res, json };
}

/**
 * Logs in as the base (acr=basic) seed user and returns a DPoP-bound token.
 * @returns {Promise<{ token: string, key: object, thumbprint: string, claims: object, cfg: object }>}
 */
export async function getBasicBoundToken(cfg = loginConfig()) {
  const key = generateKeyPair();
  const thumbprint = jwkThumbprint(key.publicJwk);
  const go = makeGo();
  const bound = await exchangeCode(cfg, { ...(await getCode(cfg, go)), key });
  if (!bound.res.ok) throw new Error(`token exchange failed: ${JSON.stringify(bound.json)}`);
  const token = bound.json.access_token;
  return { token, key, thumbprint, claims: decodeJwt(token), cfg };
}
