import "next-auth";
import "next-auth/jwt";

declare module "next-auth" {
  interface Session {
    // NOTE: the access token is intentionally NOT exposed to the browser (PRD-3
    // Decision A). The browser calls same-origin /api/backend/* proxy routes that
    // attach the DPoP-bound token server-side. Only UI hints live here.
    // Assurance level from the access token (e.g. "basic" / "pro"). UI hint only.
    acr?: string;
    error?: string;
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    // Server-side only (httpOnly, encrypted). Never surfaced to the client session.
    accessToken?: string;
    refreshToken?: string;
    accessTokenExpires?: number;
    // Opaque reference to the per-session DPoP key held in the server-side store.
    dpopKeyRef?: string;
    acr?: string;
    error?: string;
  }
}
