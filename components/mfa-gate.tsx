"use client";

import { useEffect, useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { ALLOWED_EMAIL_DOMAIN, isAllowedEmail } from "@/lib/domain";
import { createClient } from "@/lib/supabase/browser";

type EnrolledFactor = {
  id: string;
  friendly_name?: string;
  factor_type?: string;
  status?: string;
};

type EnrollmentData = {
  id: string;
  totp?: {
    qr_code?: string;
    secret?: string;
    uri?: string;
  };
};

type GateState = "checking" | "enroll" | "challenge" | "ready";

export function MfaGate({ email }: { email: string }) {
  const router = useRouter();
  const [gateState, setGateState] = useState<GateState>("checking");
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<string>("Inspecting session state...");
  const [verifyCode, setVerifyCode] = useState("");
  const [enrollment, setEnrollment] = useState<EnrollmentData | null>(null);
  const [factor, setFactor] = useState<EnrolledFactor | null>(null);
  const [isPending, startTransition] = useTransition();

  useEffect(() => {
    let ignore = false;

    async function hydrate() {
      const supabase = createClient();
      setError(null);

      if (!isAllowedEmail(email)) {
        await supabase.auth.signOut();
        if (!ignore) {
          setError(`Only ${ALLOWED_EMAIL_DOMAIN} email addresses are allowed.`);
          setGateState("checking");
          router.replace("/");
        }
        return;
      }

      const [{ data: aalData, error: aalError }, { data: factorsData, error: factorsError }] =
        await Promise.all([
          supabase.auth.mfa.getAuthenticatorAssuranceLevel(),
          supabase.auth.mfa.listFactors()
        ]);

      if (aalError) {
        if (!ignore) {
          setError(aalError.message);
        }
        return;
      }

      if (factorsError) {
        if (!ignore) {
          setError(factorsError.message);
        }
        return;
      }

      const verifiedTotp = (factorsData?.totp ?? []).find((item) => item.status === "verified");

      if (aalData.currentLevel === "aal2") {
        if (!ignore) {
          setGateState("ready");
          setStatus("Second factor verified. Loading your web instance...");
          startTransition(() => {
            router.replace("/app");
            router.refresh();
          });
        }
        return;
      }

      if (verifiedTotp) {
        if (!ignore) {
          setFactor(verifiedTotp);
          setGateState("challenge");
          setStatus("Enter the code from your authenticator app.");
        }
        return;
      }

      if (!ignore) {
        setGateState("enroll");
        setStatus("No MFA factor is enrolled yet. Set up TOTP to continue.");
      }
    }

    hydrate();

    return () => {
      ignore = true;
    };
  }, [email, router, startTransition]);

  async function handleEnroll() {
    const supabase = createClient();
    setError(null);
    setStatus("Generating your authenticator setup...");

    const { data, error: enrollError } = await supabase.auth.mfa.enroll({
      factorType: "totp",
      friendlyName: "ThreatLocker Web App"
    });

    if (enrollError) {
      setError(enrollError.message);
      return;
    }

    setEnrollment(data as EnrollmentData);
    setFactor({ id: data.id, status: "unverified" });
    setGateState("enroll");
    setStatus("Scan the QR code, then enter the 6-digit code from your authenticator app.");
  }

  async function handleVerify(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!factor?.id) {
      setError("No MFA factor is available to verify.");
      return;
    }

    const supabase = createClient();
    setError(null);
    setStatus("Verifying second factor...");

    const { error: verifyError } = await supabase.auth.mfa.challengeAndVerify({
      factorId: factor.id,
      code: verifyCode.trim()
    });

    if (verifyError) {
      setError(verifyError.message);
      return;
    }

    setGateState("ready");
    setStatus("MFA complete. Opening your workspace...");
    startTransition(() => {
      router.replace("/app");
      router.refresh();
    });
  }

  return (
    <main className="page-shell">
      <div className="auth-grid">
        <section className="hero-panel">
          <span className="hero-kicker">Multi-Factor Verification</span>
          <h1>Only authenticated ThreatLocker users reach the app.</h1>
          <p>
            Your primary sign-in is complete. This step either enrolls your TOTP device or
            verifies your existing factor before the app becomes available.
          </p>

          <div className="hero-list">
            <div className="hero-item">Signed in as {email}</div>
            <div className="hero-item">Approved domain: {ALLOWED_EMAIL_DOMAIN}</div>
            <div className="hero-item">Required second factor: authenticator app TOTP</div>
          </div>
        </section>

        <section className="card stack">
          <div>
            <h2>Verify Access</h2>
            <p className="muted">{status}</p>
          </div>

          {error ? <div className="danger">{error}</div> : null}

          {gateState === "checking" ? <div className="status">Checking session...</div> : null}

          {gateState === "enroll" ? (
            <>
              {!enrollment ? (
                <div className="button-row">
                  <button className="button" onClick={handleEnroll} type="button">
                    Set Up Authenticator
                  </button>
                </div>
              ) : (
                <>
                  <div className="qr-wrap">
                    {enrollment.totp?.qr_code ? (
                      <div
                        dangerouslySetInnerHTML={{ __html: enrollment.totp.qr_code }}
                      />
                    ) : (
                      <div className="warning">QR code not returned. Use the secret below.</div>
                    )}
                  </div>
                  {enrollment.totp?.secret ? (
                    <div className="status">Manual setup secret: {enrollment.totp.secret}</div>
                  ) : null}
                  <form className="stack" onSubmit={handleVerify}>
                    <div className="field">
                      <label htmlFor="verify-code">Authenticator Code</label>
                      <input
                        id="verify-code"
                        inputMode="numeric"
                        maxLength={6}
                        pattern="[0-9]{6}"
                        placeholder="123456"
                        required
                        value={verifyCode}
                        onChange={(event) => setVerifyCode(event.target.value)}
                      />
                    </div>
                    <button className="button-secondary" disabled={isPending} type="submit">
                      Confirm MFA
                    </button>
                  </form>
                </>
              )}
            </>
          ) : null}

          {gateState === "challenge" ? (
            <form className="stack" onSubmit={handleVerify}>
              <div className="field">
                <label htmlFor="mfa-code">Authenticator Code</label>
                <input
                  id="mfa-code"
                  inputMode="numeric"
                  maxLength={6}
                  pattern="[0-9]{6}"
                  placeholder="123456"
                  required
                  value={verifyCode}
                  onChange={(event) => setVerifyCode(event.target.value)}
                />
              </div>
              <button className="button" disabled={isPending} type="submit">
                Verify and Continue
              </button>
            </form>
          ) : null}

          {gateState === "ready" ? <div className="status">Redirecting to the app...</div> : null}
        </section>
      </div>
    </main>
  );
}
