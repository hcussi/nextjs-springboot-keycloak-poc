// Shared DPoP (RFC 9449) helpers for the e2e / scratch scripts. Dependency-free:
// ES256 (ECDSA P-256) key generation and DPoP proof signing over node:crypto,
// producing proofs Keycloak and the Spring resource server accept verbatim.
//
// A DPoP proof is a JWT with:
//   header  { typ: "dpop+jwt", alg: "ES256", jwk: <public key> }
//   payload { jti, htm, htu, iat, [nonce], [ath] }
// signed with the private key. `htu` is the target URL with any query/fragment
// stripped; `ath` (base64url SHA-256 of the access token) is included only on
// resource requests. See PLAN-3 Step 1/Step 4.
//
// DEV-ONLY tooling. Keys are ephemeral, generated per run, never persisted.

import crypto from "node:crypto";

export const base64url = (buf) => Buffer.from(buf).toString("base64url");

// SHA-256 of a string, base64url (used for the DPoP `ath` access-token hash).
export const sha256b64url = (str) =>
  base64url(crypto.createHash("sha256").update(str).digest());

// A fresh per-session ES256 key pair. Returns the KeyObjects plus the public JWK
// (the exact object embedded in every proof header).
export function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });
  const publicJwk = publicKey.export({ format: "jwk" });
  return { publicKey, privateKey, publicJwk };
}

// RFC 7638 JWK thumbprint (SHA-256, base64url) of an EC public JWK. This is the
// value Keycloak embeds as the access token's `cnf.jkt`, so the e2e can assert
// the token is bound to exactly this key.
export function jwkThumbprint(jwk) {
  // Members in lexicographic order, no whitespace, only the required fields.
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return base64url(crypto.createHash("sha256").update(canonical).digest());
}

// Sign a DPoP proof for one request. `accessToken` adds the `ath` claim (resource
// calls); `nonce` is echoed back when a server answered with `use_dpop_nonce`.
export function signProof({ privateKey, publicJwk, htm, htu, nonce, accessToken }) {
  const header = {
    typ: "dpop+jwt",
    alg: "ES256",
    // Only the required EC members, in the canonical order.
    jwk: { crv: publicJwk.crv, kty: publicJwk.kty, x: publicJwk.x, y: publicJwk.y },
  };
  const payload = {
    jti: crypto.randomUUID(),
    htm,
    htu: htu.split(/[?#]/)[0], // strip query/fragment per RFC 9449
    iat: Math.floor(Date.now() / 1000),
  };
  if (nonce) payload.nonce = nonce;
  if (accessToken) payload.ath = sha256b64url(accessToken);

  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`;
  // JOSE needs the raw R||S signature (ieee-p1363), not Node's default DER.
  const signature = crypto.sign("sha256", Buffer.from(signingInput), {
    key: privateKey,
    dsaEncoding: "ieee-p1363",
  });
  return `${signingInput}.${base64url(signature)}`;
}
