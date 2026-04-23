"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";

type Props = {
  email: string;
  configuredKeys: {
    virusTotal: boolean;
    abuseIpDb: boolean;
    proxyCheck: boolean;
  };
};

export function ApiKeysForm({ email, configuredKeys }: Props) {
  const router = useRouter();
  const [virusTotal, setVirusTotal] = useState("");
  const [abuseIpDb, setAbuseIpDb] = useState("");
  const [proxyCheck, setProxyCheck] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState(
    "These keys are required once per user account before the workspace opens."
  );
  const [isPending, startTransition] = useTransition();

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setStatus("Saving your API keys...");

    const response = await fetch("/api/user-api-keys", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        virusTotal,
        abuseIpDb,
        proxyCheck
      })
    });

    const payload = (await response.json()) as { error?: string };
    if (!response.ok) {
      setError(payload.error ?? "Unable to save API keys.");
      setStatus("Your keys were not saved.");
      return;
    }

    setStatus("Keys saved. Opening your workspace...");
    startTransition(() => {
      router.replace("/app");
      router.refresh();
    });
  }

  return (
    <main className="page-shell">
      <div className="auth-grid">
        <section className="hero-panel">
          <span className="hero-kicker">API Setup</span>
          <h1>Your first login needs the enrichment keys.</h1>
          <p>
            The app uses your personal VirusTotal, AbuseIPDB, and proxycheck.io keys to enrich
            template tokens on demand. Until all three are saved for <strong>{email}</strong>, the
            workspace stays locked.
          </p>

          <div className="hero-list">
            <div className="hero-item">
              VirusTotal: {configuredKeys.virusTotal ? "already configured" : "required"}
            </div>
            <div className="hero-item">
              AbuseIPDB: {configuredKeys.abuseIpDb ? "already configured" : "required"}
            </div>
            <div className="hero-item">
              proxycheck.io: {configuredKeys.proxyCheck ? "already configured" : "required"}
            </div>
          </div>
        </section>

        <section className="card stack">
          <div>
            <h2>Save API Keys</h2>
            <p className="muted">{status}</p>
          </div>

          {error ? <div className="danger">{error}</div> : null}

          <form className="stack" onSubmit={handleSubmit}>
            <div className="field">
              <label htmlFor="virus-total-key">VirusTotal API Key</label>
              <input
                id="virus-total-key"
                autoComplete="off"
                required
                type="password"
                value={virusTotal}
                onChange={(event) => setVirusTotal(event.target.value)}
              />
            </div>

            <div className="field">
              <label htmlFor="abuseipdb-key">AbuseIPDB API Key</label>
              <input
                id="abuseipdb-key"
                autoComplete="off"
                required
                type="password"
                value={abuseIpDb}
                onChange={(event) => setAbuseIpDb(event.target.value)}
              />
            </div>

            <div className="field">
              <label htmlFor="proxycheck-key">proxycheck.io API Key</label>
              <input
                id="proxycheck-key"
                autoComplete="off"
                required
                type="password"
                value={proxyCheck}
                onChange={(event) => setProxyCheck(event.target.value)}
              />
            </div>

            <button className="button" disabled={isPending} type="submit">
              Save and Continue
            </button>
          </form>
        </section>
      </div>
    </main>
  );
}
