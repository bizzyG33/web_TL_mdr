import { SignInPanel } from "@/components/sign-in-panel";

export function AuthShell() {
  return (
    <main className="page-shell">
      <div className="auth-grid">
        <section className="hero-panel">
          <span className="hero-kicker">ThreatLocker Access Gateway</span>
          <h1>Move the alert generator onto the web without dropping identity control.</h1>
          <p>
            This landing page is the only entry into the web remake. Supabase backs account
            creation and login, `@threatlocker.com` is enforced at the edge and in the UI, and
            every user must complete TOTP before the application opens.
          </p>

          <div className="hero-list">
            <div className="hero-item">
              Corporate email restriction is enforced during account creation, during sign-in, and
              again on protected routes.
            </div>
            <div className="hero-item">
              TOTP MFA is required to finish first-time access and is checked again on every login.
            </div>
            <div className="hero-item">
              The authenticated app instance stays isolated per user through Supabase-backed state
              and route protection.
            </div>
          </div>
        </section>

        <SignInPanel />
      </div>
    </main>
  );
}
