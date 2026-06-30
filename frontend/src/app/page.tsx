"use client";

import { signIn, signOut, useSession } from "next-auth/react";
import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";
const TOAST_DURATION = 5000;

export default function Home() {
  const { data: session, status } = useSession();
  const [greeting, setGreeting] = useState<string | null>(null);
  // The access token whose /hello request has settled (resolved or failed).
  // Loading is derived from this rather than a setState in the effect, which
  // avoids a synchronous setState during the effect (react-hooks/set-state-in-effect).
  const [settledToken, setSettledToken] = useState<string | null>(null);
  const refreshErrorShown = useRef(false);

  const accessToken = session?.accessToken;
  const helloLoading =
    status === "authenticated" && !!accessToken && settledToken !== accessToken;

  // Surface login errors that NextAuth reports via the ?error= callback redirect.
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const error = params.get("error");
    if (error) {
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

  // Once authenticated, automatically call the protected endpoint.
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
        <p className="text-xs uppercase tracking-wide text-slate-400">Signed in as</p>
        <p className="mt-1 text-lg font-medium text-slate-900">{displayName}</p>

        <div className="mt-6 rounded-xl border border-slate-100 bg-slate-50 px-4 py-6 text-center">
          {helloLoading ? (
            <Spinner />
          ) : (
            <p className="text-lg font-semibold text-slate-800">{greeting ?? "—"}</p>
          )}
          <p className="mt-2 text-xs text-slate-400">response from GET /hello</p>
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
