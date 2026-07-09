import type { NextAuthOptions } from "next-auth";
import type { JWT } from "next-auth/jwt";
import KeycloakProvider from "next-auth/providers/keycloak";

import { debug, describeToken } from "@/lib/debug";
import { generateDpopKeyPair, signDpopProof } from "@/lib/dpop";
import { deleteDpopKey, getDpopKey, putDpopKey } from "@/lib/dpopKeyStore";

const KEYCLOAK_ISSUER = process.env.KEYCLOAK_ISSUER!;
const CLIENT_ID = process.env.KEYCLOAK_CLIENT_ID!;
const CLIENT_SECRET = process.env.KEYCLOAK_CLIENT_SECRET!;
const TOKEN_ENDPOINT = `${KEYCLOAK_ISSUER}/protocol/openid-connect/token`;

/**
 * Reads the `acr` (assurance level) claim from an access token. Used only as a
 * UI hint (basic vs pro); real enforcement is server-side in the backend. It is
 * re-derived whenever the access token changes (sign-in and refresh), never
 * cached from a stale token.
 */
function acrOf(accessToken?: string): string | undefined {
  if (!accessToken) return undefined;
  try {
    const payload = JSON.parse(Buffer.from(accessToken.split(".")[1], "base64url").toString("utf8"));
    return typeof payload.acr === "string" ? payload.acr : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Whether the access token is DPoP sender-constrained, i.e. carries a `cnf.jkt`
 * confirmation claim (RFC 9449). Derived from the real token (not hardcoded), so it
 * reflects the actual binding; UI hint only, like `acr`.
 */
function dpopBoundOf(accessToken?: string): boolean {
  if (!accessToken) return false;
  try {
    const payload = JSON.parse(Buffer.from(accessToken.split(".")[1], "base64url").toString("utf8"));
    return typeof payload?.cnf?.jkt === "string" && payload.cnf.jkt.length > 0;
  } catch {
    return false;
  }
}

/**
 * POSTs to Keycloak's token endpoint with a DPoP proof, retrying once if Keycloak
 * answers with a `use_dpop_nonce` challenge. Used for the refresh grant (the
 * confidential client still needs a proof on refresh so the new access token stays
 * bound to the same key).
 */
async function dpopTokenFetch(body: URLSearchParams, keyRef: string | undefined, nonce?: string): Promise<Response> {
  const key = getDpopKey(keyRef);
  if (!key) throw new Error("Missing DPoP key for token request");
  const proof = await signDpopProof({ key, htm: "POST", htu: TOKEN_ENDPOINT, nonce });
  debug("auth", "token endpoint request (DPoP)", {
    grant: body.get("grant_type"),
    nonce: nonce ? "present" : "absent",
  });
  const response = await fetch(TOKEN_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", DPoP: proof },
    body,
  });
  if (response.status === 400 && !nonce) {
    const serverNonce = response.headers.get("DPoP-Nonce");
    const cloned = await response.clone().json().catch(() => ({}));
    if (serverNonce && cloned.error === "use_dpop_nonce") {
      debug("auth", "token endpoint asked for DPoP nonce; retrying once");
      return dpopTokenFetch(body, keyRef, serverNonce);
    }
  }
  return response;
}

/**
 * Uses the DPoP-bound refresh token to get a new access token when the 5-minute one
 * expires, keeping the same key so `cnf.jkt` stays stable. On failure, tags the
 * token with an error the UI surfaces as a toast.
 */
async function refreshAccessToken(token: JWT): Promise<JWT> {
  try {
    if (!token.refreshToken) {
      throw new Error("Missing refresh token");
    }
    const response = await dpopTokenFetch(
      new URLSearchParams({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        grant_type: "refresh_token",
        refresh_token: token.refreshToken,
      }),
      token.dpopKeyRef,
    );
    const refreshed = await response.json();
    if (!response.ok) {
      throw refreshed;
    }
    debug("auth", "access token refreshed", describeToken(refreshed.access_token));
    return {
      ...token,
      accessToken: refreshed.access_token,
      accessTokenExpires: Date.now() + refreshed.expires_in * 1000,
      refreshToken: refreshed.refresh_token ?? token.refreshToken,
      acr: acrOf(refreshed.access_token),
      dpop: dpopBoundOf(refreshed.access_token),
      error: undefined,
    };
  } catch {
    debug("auth", "access token refresh FAILED");
    return { ...token, error: "RefreshAccessTokenError" };
  }
}

export const authOptions: NextAuthOptions = {
  providers: [
    KeycloakProvider({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      issuer: KEYCLOAK_ISSUER,
      // Send PKCE (S256) and state; Keycloak enforces PKCE on this client.
      checks: ["pkce", "state"],
      // Custom token exchange so the access token is DPoP-bound at issuance. We
      // generate a per-session ES256 key, let openid-client (which next-auth hands
      // us) sign the token-request proof and handle any nonce, then stash the key
      // server-side and thread only an opaque reference through to the jwt callback.
      token: {
        async request({ client, params, checks, provider }) {
          const key = await generateDpopKeyPair();
          const tokenSet = await client.callback(provider.callbackUrl, params, checks, {
            DPoP: key.privateKey,
          });
          const dpopKeyRef = putDpopKey(key);
          debug("auth", "authorization-code token exchange (DPoP-bound)", {
            dpopKeyRef,
            ...describeToken(tokenSet.access_token),
          });
          return { tokens: { ...tokenSet, dpopKeyRef } };
        },
      },
    }),
  ],
  callbacks: {
    async jwt({ token, account }) {
      // Initial sign in: capture tokens and the DPoP key reference from the account.
      if (account) {
        token.accessToken = account.access_token;
        token.refreshToken = account.refresh_token;
        token.accessTokenExpires = account.expires_at
          ? account.expires_at * 1000
          : Date.now() + 300 * 1000;
        token.dpopKeyRef = account.dpopKeyRef as string | undefined;
        token.acr = acrOf(account.access_token);
        token.dpop = dpopBoundOf(account.access_token);
        debug("auth", "jwt callback: initial sign-in", { acr: token.acr, dpop: token.dpop });
        return token;
      }
      // Still valid (refresh 10s early to avoid edge races).
      if (token.accessTokenExpires && Date.now() < token.accessTokenExpires - 10_000) {
        debug("auth", "jwt callback: token still valid", { acr: token.acr, dpop: token.dpop });
        return token;
      }
      // Expired: try to refresh (with a DPoP proof).
      debug("auth", "jwt callback: token expired, refreshing");
      return refreshAccessToken(token);
    },
    async session({ session, token }) {
      // The access token is NOT exposed to the browser: it stays in the server-side
      // JWT and is used only by the /api/backend/* proxy routes. Only UI hints here.
      session.acr = token.acr;
      session.dpop = token.dpop;
      session.error = token.error;
      debug("auth", "session callback: exposing UI hints", {
        acr: token.acr,
        dpop: token.dpop,
        error: token.error ?? "(none)",
      });
      return session;
    },
  },
  events: {
    // Back-channel logout plus DPoP-key eviction: ending the next-auth session also
    // ends the Keycloak SSO session and drops the per-session key from the store.
    async signOut({ token }) {
      debug("auth", "signOut: evicting DPoP key and ending Keycloak session");
      deleteDpopKey(token.dpopKeyRef);
      if (!token?.refreshToken) return;
      try {
        await fetch(`${KEYCLOAK_ISSUER}/protocol/openid-connect/logout`, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET,
            refresh_token: token.refreshToken,
          }),
        });
      } catch {
        // Best-effort: the local session is cleared regardless.
      }
    },
  },
};
