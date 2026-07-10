#!/usr/bin/env node
// Demonstrates the OAuth2 Authorization Code flow (with PKCE, S256) against the
// `web` realm, using the existing confidential `nextjs-frontend` client.
//
// It spins up a temporary HTTP server on the client's registered redirect URI
// (http://localhost:3000/api/auth/callback/keycloak), opens the Keycloak login
// page, captures the `code` from the redirect, and exchanges it (code +
// code_verifier + client_secret) for tokens. This is the same flow next-auth
// performs in Step 3; the password grant in the README is only a CLI shortcut.
//
// Iteration 3: the `nextjs-frontend` client requires DPoP-bound tokens, so the
// exchange also generates an ES256 key and signs a DPoP proof (RFC 9449) on the
// token request; the demo prints the access token's `cnf.jkt` binding.
//
// Requirements (all already satisfied in this repo's dev setup):
//   - Keycloak running:           docker compose up -d keycloak
//   - /etc/hosts has:             127.0.0.1 keycloak   (browser must reach keycloak:8081)
//   - Port 3000 free              (frontend not running yet)
//   - Node 18+                    (built-in fetch / crypto)
//
// Usage:  node scripts/auth-code-flow.mjs
//
// DEV-ONLY: uses the placeholder client secret from .env. Not for production.

import http from "node:http";
import crypto from "node:crypto";
import { exec } from "node:child_process";
import { generateKeyPair, jwkThumbprint, signProof } from "./lib/dpop.mjs";

// One ES256 key for this run; signs the DPoP proof and is what cnf.jkt binds to.
const dpopKey = generateKeyPair();

const cfg = {
  // Single issuer host, reachable identically by browser (via /etc/hosts) and
  // by this script. Matches KEYCLOAK_ISSUER in .env.
  authBase: process.env.KEYCLOAK_BASE ?? "http://keycloak:8081",
  realm: process.env.KEYCLOAK_REALM ?? "web",
  clientId: process.env.KEYCLOAK_CLIENT_ID ?? "nextjs-frontend",
  clientSecret: process.env.KEYCLOAK_CLIENT_SECRET ?? "nextjs-frontend-secret-dev",
  redirectUri: "http://localhost:3000/api/auth/callback/keycloak",
  callbackPort: 3000,
  callbackPath: "/api/auth/callback/keycloak",
  scope: "openid profile email",
  timeoutMs: 120_000,
};

const realmBase = `${cfg.authBase}/realms/${cfg.realm}`;
const authEndpoint = `${realmBase}/protocol/openid-connect/auth`;
const tokenEndpoint = `${realmBase}/protocol/openid-connect/token`;

const base64url = (buf) =>
  buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

// --- PKCE + CSRF state ---
const codeVerifier = base64url(crypto.randomBytes(32));
const codeChallenge = base64url(crypto.createHash("sha256").update(codeVerifier).digest());
const state = base64url(crypto.randomBytes(16));

const authUrl =
  `${authEndpoint}?` +
  new URLSearchParams({
    response_type: "code",
    client_id: cfg.clientId,
    redirect_uri: cfg.redirectUri,
    scope: cfg.scope,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  }).toString();

function decodeJwtPayload(jwt) {
  try {
    const payload = jwt.split(".")[1];
    return JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

async function exchangeCodeForTokens(code, nonce) {
  const res = await fetch(tokenEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      // DPoP proof for the token request (htm=POST, htu=token endpoint, no ath).
      DPoP: signProof({
        privateKey: dpopKey.privateKey,
        publicJwk: dpopKey.publicJwk,
        htm: "POST",
        htu: tokenEndpoint,
        nonce,
      }),
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: cfg.redirectUri,
      client_id: cfg.clientId,
      client_secret: cfg.clientSecret, // required: confidential client
      code_verifier: codeVerifier, // PKCE proof
    }),
  });
  const body = await res.json();
  // Retry once if Keycloak demands a nonce (we do not mandate nonces, but handle it).
  if (!res.ok && !nonce && body.error === "use_dpop_nonce") {
    const serverNonce = res.headers.get("dpop-nonce");
    if (serverNonce) return exchangeCodeForTokens(code, serverNonce);
  }
  if (!res.ok) {
    throw new Error(`Token exchange failed (${res.status}): ${JSON.stringify(body)}`);
  }
  return body;
}

function htmlResponse(res, status, message) {
  res.writeHead(status, { "Content-Type": "text/html; charset=utf-8" });
  res.end(`<!doctype html><html><body style="font-family:sans-serif;padding:2rem">
    <h2>${message}</h2><p>You can close this tab and return to the terminal.</p></body></html>`);
}

function waitForCallback() {
  return new Promise((resolve, reject) => {
    const server = http.createServer(async (req, res) => {
      const url = new URL(req.url, `http://localhost:${cfg.callbackPort}`);
      if (url.pathname !== cfg.callbackPath) {
        res.writeHead(404).end();
        return;
      }
      const error = url.searchParams.get("error");
      if (error) {
        htmlResponse(res, 400, `Login error: ${error}`);
        server.close();
        reject(new Error(`Authorization error: ${error} - ${url.searchParams.get("error_description") ?? ""}`));
        return;
      }
      const code = url.searchParams.get("code");
      const returnedState = url.searchParams.get("state");
      if (returnedState !== state) {
        htmlResponse(res, 400, "State mismatch (possible CSRF).");
        server.close();
        reject(new Error(`State mismatch: expected ${state}, got ${returnedState}`));
        return;
      }
      htmlResponse(res, 200, "Authorization code received.");
      server.close();
      resolve(code);
    });

    server.on("error", reject);
    server.listen(cfg.callbackPort, () => {
      console.log(`\nListening for the redirect on ${cfg.redirectUri}\n`);
      console.log("Open this URL in your browser and log in as testuser / password:\n");
      console.log(`  ${authUrl}\n`);
      // Best-effort auto-open (macOS `open`, Linux `xdg-open`).
      const opener = process.platform === "darwin" ? "open" : "xdg-open";
      exec(`${opener} "${authUrl}"`, () => {});
    });

    setTimeout(() => {
      server.close();
      reject(new Error(`Timed out after ${cfg.timeoutMs / 1000}s waiting for login.`));
    }, cfg.timeoutMs).unref();
  });
}

async function main() {
  console.log("=== Authorization Code + PKCE demo ===");
  console.log(`Authorize endpoint: ${authEndpoint}`);
  console.log(`Token endpoint:     ${tokenEndpoint}`);
  console.log(`PKCE code_challenge (S256): ${codeChallenge}`);

  const code = await waitForCallback();
  console.log(`\nReceived code: ${code.slice(0, 12)}... exchanging for tokens...\n`);

  const tokens = await exchangeCodeForTokens(code);
  const access = decodeJwtPayload(tokens.access_token);

  console.log("=== Token response ===");
  console.log(`token_type:    ${tokens.token_type}`);
  console.log(`expires_in:    ${tokens.expires_in}s`);
  console.log(`scope:         ${tokens.scope}`);
  console.log(`refresh_token: ${tokens.refresh_token ? "present" : "absent"}`);
  if (access) {
    console.log("\n=== Decoded access token claims ===");
    console.log(`iss:                ${access.iss}`);
    console.log(`preferred_username: ${access.preferred_username}`);
    console.log(`lifespan (exp-iat):  ${access.exp - access.iat}s`);
    const boundOk = access.cnf?.jkt === jwkThumbprint(dpopKey.publicJwk);
    console.log(`cnf.jkt (DPoP-bound): ${access.cnf?.jkt} ${boundOk ? "(matches our key)" : "(MISMATCH!)"}`);
  }
  console.log("\nDone. Authorization Code + PKCE flow succeeded.");
}

main().catch((err) => {
  console.error(`\nERROR: ${err.message}`);
  process.exit(1);
});
