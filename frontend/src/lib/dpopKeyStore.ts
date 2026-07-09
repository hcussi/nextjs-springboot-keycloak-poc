import "server-only";

import type { KeyObject } from "node:crypto";
import { randomUUID } from "node:crypto";
import type { JWK } from "jose";

import { debug } from "./debug";

/**
 * Per-session DPoP key material, held only in the Next.js server process.
 */
export type DpopKey = { privateKey: KeyObject; publicJwk: JWK };

/**
 * Server-side key store (PRD-3 Decision A). The raw ES256 private key never leaves
 * this process: the encrypted next-auth session cookie carries only an opaque
 * reference (a random id), which the token-exchange, refresh, and BFF-proxy code
 * paths resolve back to the key here.
 *
 * Attached to `globalThis` so it survives dev HMR module reloads. A full process
 * restart still clears it, which forces a re-login: the accepted POC limitation of
 * an in-memory store (a real deployment would use a shared server-side secret
 * store). It is never a persistent, multi-instance store.
 */
const store: Map<string, DpopKey> =
  ((globalThis as typeof globalThis & { __dpopKeyStore?: Map<string, DpopKey> })
    .__dpopKeyStore ??= new Map());

/** Store a key and return the opaque reference to place in the session JWT. */
export function putDpopKey(key: DpopKey): string {
  const ref = randomUUID();
  store.set(ref, key);
  debug("keystore", "stored DPoP key", { ref, size: store.size });
  return ref;
}

/** Resolve a reference back to its key, or undefined if not present (e.g. after a restart). */
export function getDpopKey(ref: string | undefined): DpopKey | undefined {
  const key = ref ? store.get(ref) : undefined;
  debug("keystore", "resolved DPoP key", { ref: ref ?? "(none)", hit: Boolean(key), size: store.size });
  return key;
}

/** Evict a key on logout so it does not outlive the session. */
export function deleteDpopKey(ref: string | undefined): void {
  if (ref) {
    store.delete(ref);
    debug("keystore", "evicted DPoP key", { ref, size: store.size });
  }
}
