import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ThreatLocker Email Alert Generator",
  description: "Web fork with Supabase authentication and per-user instances."
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
