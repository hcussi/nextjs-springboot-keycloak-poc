import type { NextRequest } from "next/server";

import { proxyToBackend } from "@/lib/bffProxy";

// Same-origin BFF proxy for the elevated endpoint. A step-up (RFC 9470) or nonce
// (RFC 9449) challenge from the backend is relayed to the browser unchanged.
export async function GET(req: NextRequest): Promise<Response> {
  return proxyToBackend(req, "/server-details");
}
