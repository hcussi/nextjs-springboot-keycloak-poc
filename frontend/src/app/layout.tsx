import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { Toaster } from "sonner";

import { debug } from "@/lib/debug";

import { Providers } from "./providers";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "OAuth2 POC",
  description: "Next.js + Spring Boot + Keycloak OAuth2 proof of concept",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  // Runs during server-side rendering; confirms the DEBUG flag reaches the SSR runtime.
  debug("ssr", "rendering root layout");
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col">
        {/* Mounted before the app on purpose: sonner delivers a toast only to
            subscribers that exist when toast() is called and never replays earlier
            ones, so the Toaster must subscribe before any page effect (e.g. the
            session-expiry or ?error toast fired on mount) runs, or that toast is
            lost. richColors styles error toasts red; toasts stack and each
            auto-hides after the per-toast duration (5s) set at the call site. */}
        <Toaster position="top-right" richColors closeButton />
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
