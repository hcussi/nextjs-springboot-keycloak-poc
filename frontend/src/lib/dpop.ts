import "server-only";

import { createHash, randomUUID } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { base64url, exportJWK, generateKeyPair, SignJWT } from "jose";
import type { JWK } from "jose";

import { debug, debugEnabled, describeProof } from "./debug";
import type { DpopKey } from "./dpopKeyStore";

/**
 * Generates a per-session ES256 (P-256) key pair for DPoP. The private key stays a
 * Node key object in this process; the public JWK is derived for the proof header.
 */
export async function generateDpopKeyPair(): Promise<DpopKey> {
  const { privateKey, publicKey } = await generateKeyPair("ES256");
  const publicJwk = await exportJWK(publicKey);
  debug("dpop", "generated ES256 DPoP key pair", { kty: publicJwk.kty, crv: publicJwk.crv });
  return { privateKey: privateKey as KeyObject, publicJwk };
}

/** base64url SHA-256 of the access token, for the DPoP `ath` claim on resource calls. */
function accessTokenHash(accessToken: string): string {
  return base64url.encode(createHash("sha256").update(accessToken).digest());
}

/**
 * Signs a DPoP proof (RFC 9449) for one request. `accessToken` adds the `ath`
 * binding (resource calls); `nonce` is echoed on a `use_dpop_nonce` retry. Only the
 * required EC members go in the embedded JWK, and `htu` is stripped of any
 * query/fragment, so the proof matches what Keycloak and the Spring resource server
 * validate.
 */
export async function signDpopProof(opts: {
  key: DpopKey;
  htm: string;
  htu: string;
  nonce?: string;
  accessToken?: string;
}): Promise<string> {
  const { key, htm, htu, nonce, accessToken } = opts;
  const { kty, crv, x, y } = key.publicJwk;

  const payload: Record<string, unknown> = { htm, htu: htu.split(/[?#]/)[0] };
  if (nonce) payload.nonce = nonce;
  if (accessToken) payload.ath = accessTokenHash(accessToken);

  const proof = await new SignJWT(payload)
    .setProtectedHeader({ typ: "dpop+jwt", alg: "ES256", jwk: { kty, crv, x, y } as JWK })
    .setJti(randomUUID())
    .setIssuedAt()
    .sign(key.privateKey);
  if (debugEnabled()) {
    debug("dpop", "signed DPoP proof", describeProof(proof));
  }
  return proof;
}
