import "server-only";

import { getToken } from "next-auth/jwt";
import type { NextRequest } from "next/server";

import { debug, describeToken } from "./debug";
import { signDpopProof } from "./dpop";
import { getDpopKey } from "./dpopKeyStore";

// Server-side backend base URL (Docker service name in compose, localhost in dev).
// The browser never learns it; it only ever calls the same-origin proxy routes.
const BACKEND_URL = process.env.BACKEND_URL ?? "http://localhost:8080";

/**
 * Backend-for-frontend proxy (PRD-3 Decision A). The browser calls a same-origin
 * `/api/backend/*` route with only its session cookie; this reads the DPoP-bound
 * access token and the per-session key server-side, signs a fresh proof, and
 * forwards the call to the backend under the `DPoP` scheme. The access token and
 * the private key never reach the browser.
 *
 * Requests and responses are relayed through a strict header allow-list: the
 * browser's incoming headers (notably its `Cookie`) are never forwarded to the
 * backend, and only status, body, `Content-Type`, and `WWW-Authenticate` come back
 * (so the browser can still read the RFC 9470 step-up challenge). The token is only
 * ever taken from the verified session, never from a client-supplied header.
 */
export async function proxyToBackend(req: NextRequest, path: string): Promise<Response> {
  const token = await getToken({ req });
  const accessToken = token?.accessToken;
  const key = getDpopKey(token?.dpopKeyRef);

  debug("bff", `proxy ${path}`, {
    hasToken: Boolean(accessToken),
    hasKey: Boolean(key),
    acr: token?.acr,
    dpop: token?.dpop,
    ...(accessToken ? describeToken(accessToken) : {}),
  });

  if (!accessToken || !key) {
    debug("bff", `proxy ${path}: no session token/key -> 401`);
    return new Response(null, { status: 401 });
  }

  return dpopBackendFetch(`${BACKEND_URL}${path}`, accessToken, key);
}

async function dpopBackendFetch(
  url: string,
  accessToken: string,
  key: NonNullable<ReturnType<typeof getDpopKey>>,
  nonce?: string,
): Promise<Response> {
  const proof = await signDpopProof({ key, htm: "GET", htu: url, accessToken, nonce });
  debug("bff", `-> backend GET ${url}`, { scheme: "DPoP", nonce: nonce ? "present" : "absent" });
  const backendResponse = await fetch(url, {
    method: "GET",
    headers: { Authorization: `DPoP ${accessToken}`, DPoP: proof },
    cache: "no-store",
  });

  debug("bff", `<- backend ${backendResponse.status} for GET ${url}`, {
    wwwAuthenticate: backendResponse.headers.get("WWW-Authenticate") ?? "(none)",
    dpopNonce: backendResponse.headers.get("DPoP-Nonce") ? "present" : "absent",
  });

  // Retry once if the backend demands a DPoP nonce (forward-compatible with the
  // iteration-4 nonce on /server-details); we do not mandate nonces ourselves.
  if (backendResponse.status === 401 && !nonce) {
    const serverNonce = backendResponse.headers.get("DPoP-Nonce");
    const challenge = backendResponse.headers.get("WWW-Authenticate") ?? "";
    if (serverNonce && challenge.includes("use_dpop_nonce")) {
      debug("bff", `retrying GET ${url} with DPoP nonce`);
      return dpopBackendFetch(url, accessToken, key, serverNonce);
    }
  }

  const headers = new Headers();
  const contentType = backendResponse.headers.get("Content-Type");
  if (contentType) headers.set("Content-Type", contentType);
  const wwwAuthenticate = backendResponse.headers.get("WWW-Authenticate");
  if (wwwAuthenticate) headers.set("WWW-Authenticate", wwwAuthenticate);

  return new Response(await backendResponse.arrayBuffer(), {
    status: backendResponse.status,
    headers,
  });
}
