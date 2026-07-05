import "next-auth";
import "next-auth/jwt";

declare module "next-auth" {
  interface Session {
    accessToken?: string;
    // Assurance level from the access token (e.g. "basic" / "pro"). UI hint only.
    acr?: string;
    error?: string;
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    accessToken?: string;
    refreshToken?: string;
    accessTokenExpires?: number;
    acr?: string;
    error?: string;
  }
}
