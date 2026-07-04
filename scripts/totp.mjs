#!/usr/bin/env node
// Compute the current TOTP code for the step-up (acr=pro) second factor.
//
// Keycloak validates TOTP over the RAW UTF-8 bytes of the seed stored in the
// user's `otp` credential (secretData.value), using the realm OTP policy
// (HmacSHA1, 6 digits, 30s period). This reproduces that so you can complete the
// OTP form manually, or feed a code into a script.
//
// As a CLI:
//   node scripts/totp.mjs                 # uses the committed dev seed
//   node scripts/totp.mjs <seed>          # any raw-string seed
//   TOTP_SECRET=<seed> node scripts/totp.mjs
//
// As a module:
//   import { totp, DEFAULT_SEED } from "./totp.mjs";
//   totp(DEFAULT_SEED); // -> "123456"
//
// Options (env / opts, defaults match keycloak/realm-export.json OTP policy):
//   TOTP_DIGITS=6  TOTP_PERIOD=30  TOTP_ALGO=sha1
//
// DEV-ONLY: the default seed is the throwaway realm's dev secret. Never reuse it.

import crypto from "node:crypto";
import { pathToFileURL } from "node:url";

// Dev-only seed for `testuser`, matching keycloak/realm-export.json.
export const DEFAULT_SEED = "stepupTOTPseedDEVonly1234567890AB";

// RFC 6238 / RFC 4226. The secret is used as raw UTF-8 bytes (Keycloak's default).
export function totp(seed, { digits = 6, period = 30, algo = "sha1", forTime = Date.now() } = {}) {
  const counter = Math.floor(forTime / 1000 / period);
  const buf = Buffer.alloc(8);
  buf.writeBigInt64BE(BigInt(counter));
  const hmac = crypto.createHmac(algo, Buffer.from(seed, "utf8")).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const bin =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(bin % 10 ** digits).padStart(digits, "0");
}

// Seconds remaining in the current TOTP window.
export function secondsLeft(period = 30) {
  return period - (Math.floor(Date.now() / 1000) % period);
}

// --- CLI entry point (only when run directly, not when imported) ---
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const secret = process.argv[2] ?? process.env.TOTP_SECRET ?? DEFAULT_SEED;
  const digits = Number(process.env.TOTP_DIGITS ?? 6);
  const period = Number(process.env.TOTP_PERIOD ?? 30);
  const algo = (process.env.TOTP_ALGO ?? "sha1").toLowerCase();
  const code = totp(secret, { digits, period, algo });

  // When piped (not a TTY), print only the code so it composes with other tools.
  if (!process.stdout.isTTY) {
    process.stdout.write(code + "\n");
  } else {
    console.log(`TOTP: ${code}  (valid ~${secondsLeft(period)}s, ${digits} digits / ${period}s / ${algo})`);
  }
}
