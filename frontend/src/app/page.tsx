"use client";

import { getSession, signIn, signOut, useSession } from "next-auth/react";
import { useCallback, useEffect, useRef, useState } from "react";
import { toast } from "sonner";

const TOAST_DURATION = 5000;

// Solid accent primary: keyline + subtle hover lift/press instead of a heavy drop
// shadow, with a crisp focus-visible ring on the dark canvas.
const PRIMARY_BTN =
  "inline-flex w-full items-center justify-center gap-2 rounded-xl bg-accent px-4 py-2.5 " +
  "text-sm font-semibold text-canvas shadow-[0_0_0_1px_rgba(53,224,200,0.5)] transition duration-150 " +
  "hover:-translate-y-0.5 hover:shadow-[0_8px_24px_-8px_rgba(53,224,200,0.7)] " +
  "active:translate-y-0 active:shadow-[0_0_0_1px_rgba(53,224,200,0.5)] " +
  "focus:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-canvas " +
  "disabled:cursor-not-allowed disabled:opacity-60 disabled:hover:translate-y-0 disabled:hover:shadow-[0_0_0_1px_rgba(53,224,200,0.5)]";

// Quiet secondary (log out): hairline keyline, muted text, faint hover fill.
const SECONDARY_BTN =
  "inline-flex w-full items-center justify-center rounded-xl border border-hairline px-4 py-2.5 " +
  "text-sm font-medium text-muted transition hover:bg-white/5 hover:text-ink " +
  "focus:outline-none focus-visible:ring-2 focus-visible:ring-white/20 focus-visible:ring-offset-2 focus-visible:ring-offset-canvas";

// Assurance levels this client is willing to request. The required level comes
// from the backend's WWW-Authenticate challenge, which travels over plain HTTP
// and is rewritable on-path, so we allow-list it before forwarding it into a
// redirect parameter rather than trusting arbitrary header content.
const KNOWN_ACRS = ["pro"];

// One-shot marker (sessionStorage) so that after the whole-page step-up redirect
// we retry the fetch exactly once. Cleared immediately on use and time-bounded so
// it can't replay a stale retry against a later unrelated navigation.
const STEPUP_MARKER = "stepup:retry-server-details";
const STEPUP_MARKER_TTL = 5 * 60 * 1000;

type ServerDetails = {
  application: string;
  version: string;
  javaVersion: string;
  startTime: string;
  uptimeMillis: number;
  activeProfiles: string[];
  hostname: string;
  serverTime: string;
};

export default function Home() {
  const { data: session, status } = useSession();
  const [greeting, setGreeting] = useState<string | null>(null);
  // Whether the initial /hello call has settled (resolved or failed). Loading is
  // derived from this rather than a setState in the effect, which avoids a
  // synchronous setState during the effect (react-hooks/set-state-in-effect).
  const [helloSettled, setHelloSettled] = useState(false);
  const [serverDetails, setServerDetails] = useState<ServerDetails | null>(null);
  const [detailsLoading, setDetailsLoading] = useState(false);
  const refreshErrorShown = useRef(false);

  const acr = session?.acr;
  const dpop = session?.dpop;
  const helloLoading = status === "authenticated" && !helloSettled;

  // Fetch /server-details. `allowStepUp` gates whether a step-up challenge starts
  // a re-authentication: true for an explicit user action, false for the one-shot
  // retry after a redirect (so a cancelled/failed step-up toasts instead of
  // bouncing the user through Keycloak again in a loop).
  const loadServerDetails = useCallback(
    async (allowStepUp: boolean) => {
      setDetailsLoading(true);
      try {
        // Same-origin BFF proxy: the DPoP-bound token and proof are attached
        // server-side, so no Authorization header is set here. backendFetch
        // transparently refreshes an expired session and retries once.
        const res = await backendFetch("/api/backend/server-details");
        if (res.ok) {
          setServerDetails(await res.json());
          return;
        }
        // Readable only because the backend exposes WWW-Authenticate via CORS.
        const challenge = res.headers.get("WWW-Authenticate") ?? "";
        const isStepUp =
          res.status === 401 && challenge.includes("insufficient_user_authentication");
        if (isStepUp && allowStepUp) {
          const required = parseAcrValues(challenge);
          if (required && KNOWN_ACRS.includes(required)) {
            beginStepUp(required);
            return; // navigates away to Keycloak
          }
        }
        if (isStepUp) {
          toast.error("Additional verification was not completed.", { duration: TOAST_DURATION });
        } else {
          toast.error(`Could not load server details (HTTP ${res.status}).`, { duration: TOAST_DURATION });
        }
      } catch (err) {
        toast.error(`Could not reach the API: ${(err as Error).message}`, { duration: TOAST_DURATION });
      } finally {
        setDetailsLoading(false);
      }
    },
    [],
  );

  // Surface login errors that NextAuth reports via the ?error= callback redirect.
  // A cancelled step-up returns here too; clear the retry marker so we don't then
  // auto-retry (which would double-toast).
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const error = params.get("error");
    if (error) {
      clearStepUpMarker();
      toast.error(`Login failed: ${prettifyAuthError(error)}`, { duration: TOAST_DURATION });
      window.history.replaceState({}, "", window.location.pathname);
    }
  }, []);

  // Surface token-refresh failures (the 5-minute access token could not be renewed).
  useEffect(() => {
    if (session?.error === "RefreshAccessTokenError" && !refreshErrorShown.current) {
      refreshErrorShown.current = true;
      toast.error("Your session expired. Please sign in again.", { duration: TOAST_DURATION });
    }
  }, [session?.error]);

  // Once authenticated, automatically call the protected greeting endpoint via the
  // same-origin BFF proxy (which attaches the DPoP-bound token server-side).
  useEffect(() => {
    if (status !== "authenticated") return;
    let active = true;
    backendFetch("/api/backend/hello")
      .then(async (res) => {
        if (!res.ok) throw new Error(`API responded ${res.status}`);
        return res.text();
      })
      .then((text) => {
        if (active) setGreeting(text);
      })
      .catch((err: Error) => {
        if (active) toast.error(`Could not reach the API: ${err.message}`, { duration: TOAST_DURATION });
      })
      .finally(() => {
        if (active) setHelloSettled(true);
      });
    return () => {
      active = false;
    };
  }, [status]);

  // After a step-up redirect, retry the server-details fetch exactly once. The
  // marker is consumed (cleared) before the retry so it can't replay. The fetch
  // is deferred to a microtask so its loading setState doesn't run synchronously
  // inside the effect.
  useEffect(() => {
    if (status !== "authenticated") return;
    const ts = consumeStepUpMarker();
    if (ts !== null && Date.now() - ts <= STEPUP_MARKER_TTL) {
      queueMicrotask(() => void loadServerDetails(false));
    }
  }, [status, loadServerDetails]);

  if (status === "loading") {
    return (
      <Centered>
        <Spinner />
      </Centered>
    );
  }

  if (status !== "authenticated") {
    return (
      <Centered>
        <Card>
          <div className="flex items-center gap-3">
            <BrandMark />
            <span className="font-mono text-[11px] font-medium uppercase tracking-[0.22em] text-accent">
              Secure access
            </span>
          </div>
          <h1 className="mt-7 text-3xl font-semibold tracking-tight text-ink">Welcome</h1>
          <p className="mt-2 text-sm leading-relaxed text-muted">
            Sign in with Keycloak to access the protected greeting.
          </p>
          <button onClick={() => signIn("keycloak")} className={`mt-8 ${PRIMARY_BTN}`}>
            <LockGlyph className="h-4 w-4" />
            Continue with Keycloak
          </button>
          <div className="mt-6 border-t border-hairline pt-4">
            <p className="text-center font-mono text-[11px] tracking-wide text-muted">
              Protected by Keycloak · OIDC
            </p>
          </div>
        </Card>
      </Centered>
    );
  }

  const displayName = session.user?.name ?? session.user?.email ?? "there";

  return (
    <Centered>
      <Card>
        <div className="flex items-center justify-between gap-3">
          <div>
            <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted">Signed in as</p>
            <p className="mt-1 text-lg font-medium text-ink">{displayName}</p>
          </div>
          <div className="flex flex-col items-end gap-1.5">
            <LevelBadge acr={acr} />
            <DpopBadge enabled={dpop} />
          </div>
        </div>

        <div className="mt-6 rounded-xl border border-hairline bg-white/[0.03] px-4 py-6 text-center">
          {helloLoading ? (
            <Spinner />
          ) : (
            <p className="text-lg font-semibold text-ink">{greeting ?? "—"}</p>
          )}
          <p className="mt-2 font-mono text-[11px] text-muted">response from GET /hello</p>
        </div>

        <div className="mt-6 border-t border-hairline pt-6">
          <div className="flex items-center justify-between gap-3">
            <p className="text-sm font-medium text-ink">Server details</p>
            <span className="font-mono text-[11px] text-muted">requires step-up (pro)</span>
          </div>

          {serverDetails ? (
            <ServerDetailsPanel details={serverDetails} />
          ) : (
            <p className="mt-3 text-xs leading-relaxed text-muted">
              Loading these prompts a second factor if you are not already elevated.
            </p>
          )}

          <button
            onClick={() => loadServerDetails(true)}
            disabled={detailsLoading}
            className={`mt-4 ${PRIMARY_BTN}`}
          >
            {detailsLoading ? "Loading…" : serverDetails ? "Reload server details" : "Load server details"}
          </button>
        </div>

        <button onClick={() => signOut({ callbackUrl: "/" })} className={`mt-6 ${SECONDARY_BTN}`}>
          Log out
        </button>
      </Card>
    </Centered>
  );
}

// Requests a step-up re-authentication at the given (allow-listed) acr. Uses the
// OIDC `claims` essential-acr form as the binding channel, plus `acr_values` as
// the compatibility hint. A one-shot marker lets us auto-retry the fetch on
// return. This navigates the whole page away to Keycloak.
function beginStepUp(acr: string) {
  try {
    sessionStorage.setItem(STEPUP_MARKER, String(Date.now()));
  } catch {
    // sessionStorage unavailable: the step-up still works, only the auto-retry is lost.
  }
  signIn(
    "keycloak",
    { callbackUrl: "/" },
    {
      claims: JSON.stringify({ id_token: { acr: { essential: true, values: [acr] } } }),
      acr_values: acr,
    },
  );
}

// Calls a same-origin BFF proxy route. The proxy uses the access token from the
// session cookie as-is (getToken does not refresh it), so once the 5-minute token
// expires the backend answers 401 with an invalid_token challenge. On any 401 that
// is NOT a step-up challenge, force a next-auth session refresh (which runs the
// DPoP refresh callback and rewrites the cookie) and retry once. A step-up 401 is
// returned unchanged for the caller to drive the re-authentication.
async function backendFetch(path: string): Promise<Response> {
  const res = await fetch(path);
  if (res.status === 401 && !isStepUpChallenge(res)) {
    await getSession();
    return fetch(path);
  }
  return res;
}

function isStepUpChallenge(res: Response): boolean {
  return (res.headers.get("WWW-Authenticate") ?? "").includes("insufficient_user_authentication");
}

function parseAcrValues(challenge: string): string | null {
  return challenge.match(/acr_values="?([^",\s]+)"?/i)?.[1] ?? null;
}

function consumeStepUpMarker(): number | null {
  let raw: string | null = null;
  try {
    raw = sessionStorage.getItem(STEPUP_MARKER);
  } catch {
    return null;
  }
  if (raw === null) return null;
  clearStepUpMarker();
  const ts = Number(raw);
  return Number.isFinite(ts) ? ts : null;
}

function clearStepUpMarker() {
  try {
    sessionStorage.removeItem(STEPUP_MARKER);
  } catch {
    // ignore
  }
}

// The assurance badge is the visual payoff of the step-up: it flips from a quiet
// neutral (basic) to a glowing teal "unlocked" state (pro). The color change is
// eased so the transition reads when the badge updates after step-up.
function LevelBadge({ acr }: { acr?: string }) {
  const isPro = acr === "pro";
  return (
    <span
      className={
        "inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 font-mono text-xs font-medium transition-colors duration-500 " +
        (isPro
          ? "bg-accent/10 text-accent ring-1 ring-accent/40 shadow-[0_0_14px_-2px_rgba(53,224,200,0.55)]"
          : "bg-white/5 text-muted ring-1 ring-hairline")
      }
      title={`assurance level (acr): ${acr ?? "unknown"}`}
    >
      <span
        className={
          "h-1.5 w-1.5 rounded-full transition-colors duration-500 " +
          (isPro ? "bg-accent" : "bg-muted")
        }
      />
      {acr ?? "—"}
    </span>
  );
}

// Companion to LevelBadge: shows that the session's access token is DPoP
// sender-constrained (cnf.jkt present). Reflects the real token binding surfaced
// via session.dpop, not a hardcoded flag. Falls back to a quiet "bearer" pill if
// the token is ever unbound, mirroring the basic/pro visual language.
function DpopBadge({ enabled }: { enabled?: boolean }) {
  return (
    <span
      className={
        "inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 font-mono text-xs font-medium transition-colors duration-500 " +
        (enabled
          ? "bg-accent/10 text-accent ring-1 ring-accent/40 shadow-[0_0_14px_-2px_rgba(53,224,200,0.55)]"
          : "bg-white/5 text-muted ring-1 ring-hairline")
      }
      title={
        enabled
          ? "Access token is DPoP sender-constrained (RFC 9449): bound to a key held server-side"
          : "Bearer token (not sender-constrained)"
      }
    >
      <ShieldGlyph className="h-3 w-3" />
      {enabled ? "DPoP" : "bearer"}
    </span>
  );
}

// Small shield-check mark for the DPoP badge.
function ShieldGlyph({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" className={className} aria-hidden="true">
      <path
        d="M12 2.5 5 5.2v5.6c0 4.3 2.9 8.1 7 9.2 4.1-1.1 7-4.9 7-9.2V5.2L12 2.5Z"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
      <path
        d="m9 11.6 2.1 2.1L15 9.9"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function ServerDetailsPanel({ details }: { details: ServerDetails }) {
  const rows: [string, string][] = [
    ["Application", `${details.application} ${details.version}`],
    ["Java", details.javaVersion],
    ["Host", details.hostname],
    ["Profiles", details.activeProfiles.length ? details.activeProfiles.join(", ") : "(none)"],
    ["Uptime", formatUptime(details.uptimeMillis)],
    ["Server time", new Date(details.serverTime).toLocaleString()],
  ];
  return (
    <dl className="mt-3 divide-y divide-hairline rounded-xl border border-hairline bg-white/[0.03] px-4">
      {rows.map(([label, value]) => (
        <div key={label} className="flex justify-between gap-3 py-2 text-sm">
          <dt className="text-muted">{label}</dt>
          <dd className="text-right font-mono text-ink">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

function formatUptime(ms: number): string {
  const totalSeconds = Math.floor(ms / 1000);
  const h = Math.floor(totalSeconds / 3600);
  const m = Math.floor((totalSeconds % 3600) / 60);
  const s = totalSeconds % 60;
  return [h ? `${h}h` : null, m ? `${m}m` : null, `${s}s`].filter(Boolean).join(" ");
}

function Centered({ children }: { children: React.ReactNode }) {
  return <main className="flex flex-1 items-center justify-center p-6">{children}</main>;
}

// Lit surface: translucent panel + backdrop blur over the glowing canvas, a
// hairline border, and a 1px inset top highlight so it reads as a lit surface
// rather than a flat box. Enters with a fade + rise.
function Card({ children }: { children: React.ReactNode }) {
  return (
    <div className="animate-card-in w-full max-w-sm rounded-2xl border border-hairline bg-surface/85 p-8 shadow-[0_24px_60px_-20px_rgba(0,0,0,0.7),inset_0_1px_0_0_rgba(255,255,255,0.06)] backdrop-blur-xl">
      {children}
    </div>
  );
}

function Spinner() {
  return (
    <span
      className="mx-auto block h-6 w-6 animate-spin rounded-full border-2 border-white/15 border-t-accent"
      role="status"
      aria-label="loading"
    />
  );
}

// Minimal shield-with-lock brand mark: gives the login card identity and nods at
// the assurance concept without importing an icon set.
function BrandMark() {
  return (
    <span className="inline-flex h-9 w-9 items-center justify-center rounded-xl border border-hairline bg-accent/10 text-accent shadow-[inset_0_1px_0_0_rgba(255,255,255,0.08)]">
      <svg viewBox="0 0 24 24" fill="none" className="h-5 w-5" aria-hidden="true">
        <path
          d="M12 2.5 5 5.2v5.6c0 4.3 2.9 8.1 7 9.2 4.1-1.1 7-4.9 7-9.2V5.2L12 2.5Z"
          stroke="currentColor"
          strokeWidth="1.4"
          strokeLinejoin="round"
        />
        <path
          d="M9.6 11.2v-1.3a2.4 2.4 0 0 1 4.8 0v1.3"
          stroke="currentColor"
          strokeWidth="1.4"
          strokeLinecap="round"
        />
        <rect x="8.6" y="11.2" width="6.8" height="4.6" rx="1" fill="currentColor" />
      </svg>
    </span>
  );
}

function LockGlyph({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" className={className} aria-hidden="true">
      <rect x="5" y="10.5" width="14" height="9" rx="2" fill="currentColor" />
      <path
        d="M8 10.5V8a4 4 0 0 1 8 0v2.5"
        stroke="currentColor"
        strokeWidth="1.7"
        strokeLinecap="round"
      />
    </svg>
  );
}

function prettifyAuthError(code: string): string {
  switch (code) {
    case "OAuthSignin":
    case "OAuthCallback":
      return "could not complete sign-in with Keycloak";
    case "AccessDenied":
      return "access denied";
    case "Configuration":
      return "auth is misconfigured";
    default:
      return code;
  }
}
