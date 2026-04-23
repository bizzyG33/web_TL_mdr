"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { ALLOWED_EMAIL_DOMAIN, isAllowedEmail } from "@/lib/domain";
import { createClient } from "@/lib/supabase/browser";

export function SignInPanel() {
  const router = useRouter();
  const [mode, setMode] = useState<"sign-in" | "create-account">("sign-in");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage(null);
    setError(null);

    if (!isAllowedEmail(email)) {
      setError(`Only ${ALLOWED_EMAIL_DOMAIN} email addresses are allowed.`);
      return;
    }

    const supabase = createClient();
    const normalizedEmail = email.trim().toLowerCase();

    if (mode === "create-account") {
      const { data, error: signUpError } = await supabase.auth.signUp({
        email: normalizedEmail,
        password
      });

      if (signUpError) {
        setError(signUpError.message);
        return;
      }

      if (data.session) {
        setMessage("Account created. Continuing to MFA enrollment.");
        startTransition(() => {
          router.push("/auth/check");
          router.refresh();
        });
        return;
      }

      setMessage(
        "Account created. If email confirmation is enabled in Supabase, confirm the email first, then sign in to complete MFA."
      );
      return;
    }

    const { error: signInError } = await supabase.auth.signInWithPassword({
      email: normalizedEmail,
      password
    });

    if (signInError) {
      setError(signInError.message);
      return;
    }

    setMessage("Primary authentication complete. Continuing to MFA.");
    startTransition(() => {
      router.push("/auth/check");
      router.refresh();
    });
  }

  return (
    <section className="card stack">
      <div>
        <h2>{mode === "sign-in" ? "Sign In" : "Create Account"}</h2>
        <p className="muted">
          This portal only accepts Supabase users with `@threatlocker.com` addresses. MFA is
          required before the app workspace opens.
        </p>
      </div>

      <div className="segmented-control" role="tablist" aria-label="Authentication mode">
        <button
          aria-selected={mode === "sign-in"}
          className={`segment ${mode === "sign-in" ? "is-active" : ""}`}
          type="button"
          onClick={() => {
            setMode("sign-in");
            setMessage(null);
            setError(null);
          }}
        >
          Sign In
        </button>
        <button
          aria-selected={mode === "create-account"}
          className={`segment ${mode === "create-account" ? "is-active" : ""}`}
          type="button"
          onClick={() => {
            setMode("create-account");
            setMessage(null);
            setError(null);
          }}
        >
          Create Account
        </button>
      </div>

      <form className="stack" onSubmit={handleSubmit}>
        <div className="field">
          <label htmlFor="email">Work Email</label>
          <input
            id="email"
            autoComplete="email"
            inputMode="email"
            placeholder={`name${ALLOWED_EMAIL_DOMAIN}`}
            required
            type="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
          />
        </div>

        <div className="field">
          <label htmlFor="password">Password</label>
          <input
            id="password"
            autoComplete={mode === "sign-in" ? "current-password" : "new-password"}
            required
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
        </div>

        {message ? <div className="status">{message}</div> : null}
        {error ? <div className="danger">{error}</div> : null}

        <div className="button-row">
          <button className="button" disabled={isPending} type="submit">
            {isPending
              ? "Working..."
              : mode === "sign-in"
                ? "Continue"
                : "Create Account"}
          </button>
        </div>
      </form>
    </section>
  );
}
