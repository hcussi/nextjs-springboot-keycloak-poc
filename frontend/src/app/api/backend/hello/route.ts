import type { NextRequest } from "next/server";

import { proxyToBackend } from "@/lib/bffProxy";

// Same-origin BFF proxy for the protected greeting: the browser calls this with
// only its session cookie; the server attaches the DPoP-bound token and proof.
export async function GET(req: NextRequest): Promise<Response> {
  return proxyToBackend(req, "/hello");
}
