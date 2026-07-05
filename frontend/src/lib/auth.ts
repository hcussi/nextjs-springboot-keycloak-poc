import type { NextAuthOptions } from "next-auth";
import type { JWT } from "next-auth/jwt";
import KeycloakProvider from "next-auth/providers/keycloak";

const KEYCLOAK_ISSUER = process.env.KEYCLOAK_ISSUER!;
const CLIENT_ID = process.env.KEYCLOAK_CLIENT_ID!;
const CLIENT_SECRET = process.env.KEYCLOAK_CLIENT_SECRET!;

/**
 * Reads the `acr` (assurance level) claim from an access token. Used only as a
 * UI hint (basic vs pro); real enforcement is server-side in the backend. It is
 * re-derived whenever the access token changes (sign-in and refresh), never
 * cached from a stale token, so the hint can't lie after a refresh that returns
 * a different level.
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
 * Uses the refresh token to get a new access token when the 5-minute one
 * expires. On failure, tags the token with an error the UI surfaces as a toast.
 */
async function refreshAccessToken(token: JWT): Promise<JWT> {
  try {
    if (!token.refreshToken) {
      throw new Error("Missing refresh token");
    }
    const response = await fetch(`${KEYCLOAK_ISSUER}/protocol/openid-connect/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        grant_type: "refresh_token",
        refresh_token: token.refreshToken,
      }),
    });
    const refreshed = await response.json();
    if (!response.ok) {
      throw refreshed;
    }
    return {
      ...token,
      accessToken: refreshed.access_token,
      accessTokenExpires: Date.now() + refreshed.expires_in * 1000,
      refreshToken: refreshed.refresh_token ?? token.refreshToken,
      // Re-derive the level from the refreshed token, not the pre-refresh one.
      acr: acrOf(refreshed.access_token),
      error: undefined,
    };
  } catch {
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
    }),
  ],
  callbacks: {
    async jwt({ token, account }) {
      // Initial sign in: capture tokens from Keycloak.
      if (account) {
        token.accessToken = account.access_token;
        token.refreshToken = account.refresh_token;
        token.accessTokenExpires = account.expires_at
          ? account.expires_at * 1000
          : Date.now() + 300 * 1000;
        token.acr = acrOf(account.access_token);
        return token;
      }
      // Still valid (refresh 10s early to avoid edge races).
      if (token.accessTokenExpires && Date.now() < token.accessTokenExpires - 10_000) {
        return token;
      }
      // Expired: try to refresh.
      return refreshAccessToken(token);
    },
    async session({ session, token }) {
      session.accessToken = token.accessToken;
      session.acr = token.acr;
      session.error = token.error;
      return session;
    },
  },
  events: {
    // Back-channel logout: ending the next-auth session also ends the Keycloak
    // SSO session, so the next "Log in" requires credentials again.
    async signOut({ token }) {
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
