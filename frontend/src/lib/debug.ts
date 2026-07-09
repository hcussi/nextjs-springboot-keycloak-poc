// Universal debug logging for the DPoP / step-up flow. OFF by default.
//
// A single flag, NEXT_PUBLIC_DEBUG, controls every JS runtime at once:
//   - the Node server  (BFF proxy, next-auth token/refresh callbacks),
//   - SSR              (server components rendered on the server), and
//   - the browser      (client components).
// NEXT_PUBLIC_* is inlined into the client bundle at build time and is also
// readable via process.env on the server, so one variable reaches all three.
//
// This is a developer aid, not an audit log. It NEVER prints secrets: access and
// refresh tokens, the DPoP private key, proof signatures, and the client secret
// are redacted. Only material that is non-sensitive by design is emitted, e.g.
// selected JWT claims (acr, aud, exp, sub), the public cnf.jkt thumbprint, and a
// proof's htm/htu/jti/iat plus the mere presence of ath/nonce. Keep it OFF
// outside local debugging.

const ENABLED =
  process.env.NEXT_PUBLIC_DEBUG === "true" || process.env.NEXT_PUBLIC_DEBUG === "1";

/** Whether debug logging is enabled. Callers can guard expensive work with this. */
export function debugEnabled(): boolean {
  return ENABLED;
}

// "server" covers both the Node request handlers and SSR (both have no window);
// the scope argument distinguishes them (e.g. "bff", "auth", "ssr", "page").
function runtime(): string {
  return typeof window === "undefined" ? "server" : "client";
}

/**
 * Logs a namespaced debug line when NEXT_PUBLIC_DEBUG is set, otherwise a no-op.
 * `scope` names the code path (e.g. "auth", "bff", "page", "ssr"); `fields` is an
 * optional structured payload (pass only redacted/non-secret values).
 */
export function debug(scope: string, message: string, fields?: Record<string, unknown>): void {
  if (!ENABLED) return;
  const prefix = `[dpop-debug][${runtime()}][${scope}]`;
  if (fields && Object.keys(fields).length > 0) {
    console.log(prefix, message, fields);
  } else {
    console.log(prefix, message);
  }
}

/** Redact a token/proof/secret to a short, non-reconstructable fingerprint. */
export function redact(value: string | undefined | null): string {
  if (!value) return "(none)";
  return `${value.slice(0, 6)}…(${value.length} chars)`;
}

function decodeJwtPart(part: string | undefined): Record<string, unknown> | undefined {
  if (!part) return undefined;
  try {
    const b64 = part.replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    const json =
      typeof atob === "function"
        ? atob(padded)
        : Buffer.from(padded, "base64").toString("utf8");
    return JSON.parse(json);
  } catch {
    return undefined;
  }
}

/**
 * Non-secret summary of an access token: the token itself is redacted and only
 * selected claims are surfaced (acr, the public cnf.jkt thumbprint, aud, exp,
 * sub). Safe to log when debugging.
 */
export function describeToken(token: string | undefined): Record<string, unknown> {
  if (!token) return { token: "(none)" };
  const payload = decodeJwtPart(token.split(".")[1]);
  return {
    token: redact(token),
    acr: payload?.acr,
    jkt: (payload?.cnf as { jkt?: string } | undefined)?.jkt,
    aud: payload?.aud,
    exp: payload?.exp,
    sub: payload?.sub,
  };
}

/**
 * Non-secret summary of a DPoP proof: header typ/alg and payload htm/htu/jti/iat,
 * plus whether ath and nonce are present. The signature is never logged.
 */
export function describeProof(proof: string | undefined): Record<string, unknown> {
  if (!proof) return { proof: "(none)" };
  const [h, p] = proof.split(".");
  const header = decodeJwtPart(h);
  const payload = decodeJwtPart(p);
  return {
    typ: header?.typ,
    alg: header?.alg,
    htm: payload?.htm,
    htu: payload?.htu,
    jti: payload?.jti,
    iat: payload?.iat,
    ath: payload?.ath ? "present" : "absent",
    nonce: payload?.nonce ? "present" : "absent",
  };
}
