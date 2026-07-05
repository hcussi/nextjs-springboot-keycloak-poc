"use client";

import { signIn, signOut, useSession } from "next-auth/react";
import { useCallback, useEffect, useRef, useState } from "react";
import { toast } from "sonner";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";
const TOAST_DURATION = 5000;

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
  // The access token whose /hello request has settled (resolved or failed).
  // Loading is derived from this rather than a setState in the effect, which
  // avoids a synchronous setState during the effect (react-hooks/set-state-in-effect).
  const [settledToken, setSettledToken] = useState<string | null>(null);
  const [serverDetails, setServerDetails] = useState<ServerDetails | null>(null);
  const [detailsLoading, setDetailsLoading] = useState(false);
  const refreshErrorShown = useRef(false);

  const accessToken = session?.accessToken;
  const acr = session?.acr;
  const helloLoading =
    status === "authenticated" && !!accessToken && settledToken !== accessToken;

  // Fetch /server-details. `allowStepUp` gates whether a step-up challenge starts
  // a re-authentication: true for an explicit user action, false for the one-shot
  // retry after a redirect (so a cancelled/failed step-up toasts instead of
  // bouncing the user through Keycloak again in a loop).
  const loadServerDetails = useCallback(
    async (allowStepUp: boolean) => {
      if (!accessToken) return;
      setDetailsLoading(true);
      try {
        const res = await fetch(`${API_URL}/server-details`, {
          headers: { Authorization: `Bearer ${accessToken}` },
        });
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
    [accessToken],
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

  // Once authenticated, automatically call the protected greeting endpoint.
  useEffect(() => {
    if (status !== "authenticated" || !accessToken) return;
    let active = true;
    fetch(`${API_URL}/hello`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    })
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
        if (active) setSettledToken(accessToken);
      });
    return () => {
      active = false;
    };
  }, [status, accessToken]);

  // After a step-up redirect, retry the server-details fetch exactly once. The
  // marker is consumed (cleared) before the retry so it can't replay. The fetch
  // is deferred to a microtask so its loading setState doesn't run synchronously
  // inside the effect.
  useEffect(() => {
    if (status !== "authenticated" || !accessToken) return;
    const ts = consumeStepUpMarker();
    if (ts !== null && Date.now() - ts <= STEPUP_MARKER_TTL) {
      queueMicrotask(() => void loadServerDetails(false));
    }
  }, [status, accessToken, loadServerDetails]);

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
          <h1 className="text-2xl font-semibold tracking-tight text-slate-900">Welcome</h1>
          <p className="mt-2 text-sm text-slate-500">
            Sign in with Keycloak to access the protected greeting.
          </p>
          <button
            onClick={() => signIn("keycloak")}
            className="mt-8 w-full rounded-xl bg-indigo-600 px-4 py-2.5 text-sm font-medium text-white shadow-sm transition hover:bg-indigo-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:ring-offset-2"
          >
            Log in
          </button>
        </Card>
      </Centered>
    );
  }

  const displayName = session.user?.name ?? session.user?.email ?? "there";

  return (
    <Centered>
      <Card>
        <div className="flex items-center justify-between">
          <div>
            <p className="text-xs uppercase tracking-wide text-slate-400">Signed in as</p>
            <p className="mt-1 text-lg font-medium text-slate-900">{displayName}</p>
          </div>
          <LevelBadge acr={acr} />
        </div>

        <div className="mt-6 rounded-xl border border-slate-100 bg-slate-50 px-4 py-6 text-center">
          {helloLoading ? (
            <Spinner />
          ) : (
            <p className="text-lg font-semibold text-slate-800">{greeting ?? "—"}</p>
          )}
          <p className="mt-2 text-xs text-slate-400">response from GET /hello</p>
        </div>

        <div className="mt-6 border-t border-slate-100 pt-6">
          <div className="flex items-center justify-between">
            <p className="text-sm font-medium text-slate-700">Server details</p>
            <span className="text-xs text-slate-400">requires step-up (pro)</span>
          </div>

          {serverDetails ? (
            <ServerDetailsPanel details={serverDetails} />
          ) : (
            <p className="mt-3 text-xs text-slate-400">
              Loading these prompts a second factor if you are not already elevated.
            </p>
          )}

          <button
            onClick={() => loadServerDetails(true)}
            disabled={detailsLoading}
            className="mt-4 w-full rounded-xl bg-indigo-600 px-4 py-2.5 text-sm font-medium text-white shadow-sm transition hover:bg-indigo-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {detailsLoading ? "Loading…" : serverDetails ? "Reload server details" : "Load server details"}
          </button>
        </div>

        <button
          onClick={() => signOut({ callbackUrl: "/" })}
          className="mt-6 w-full rounded-xl border border-slate-300 px-4 py-2.5 text-sm font-medium text-slate-700 transition hover:bg-slate-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-slate-400 focus-visible:ring-offset-2"
        >
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

function LevelBadge({ acr }: { acr?: string }) {
  const isPro = acr === "pro";
  return (
    <span
      className={
        "rounded-full px-2.5 py-1 text-xs font-medium " +
        (isPro ? "bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200" : "bg-slate-100 text-slate-500")
      }
      title={`assurance level (acr): ${acr ?? "unknown"}`}
    >
      {acr ?? "—"}
    </span>
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
    <dl className="mt-3 divide-y divide-slate-100 rounded-xl border border-slate-100 bg-slate-50 px-4">
      {rows.map(([label, value]) => (
        <div key={label} className="flex justify-between gap-3 py-2 text-sm">
          <dt className="text-slate-500">{label}</dt>
          <dd className="text-right font-medium text-slate-800">{value}</dd>
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

function Card({ children }: { children: React.ReactNode }) {
  return (
    <div className="w-full max-w-sm rounded-2xl bg-white p-8 shadow-lg shadow-slate-200/60 ring-1 ring-slate-100">
      {children}
    </div>
  );
}

function Spinner() {
  return (
    <span
      className="mx-auto block h-6 w-6 animate-spin rounded-full border-2 border-slate-300 border-t-indigo-600"
      role="status"
      aria-label="loading"
    />
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
