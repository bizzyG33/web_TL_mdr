import { redirect } from "next/navigation";
import { EmailAlertGeneratorApp } from "@/components/email-alert-generator-app";
import { SignOutButton } from "@/components/sign-out-button";
import { createClient } from "@/lib/supabase/server";
import { ensureCurrentUserInstance, hasRequiredApiKeys } from "@/lib/user-instance";
import { isAllowedEmail } from "@/lib/domain";

export default async function AppPage() {
  const supabase = await createClient();
  const {
    data: { user }
  } = await supabase.auth.getUser();
  const { data: assurance } = await supabase.auth.mfa.getAuthenticatorAssuranceLevel();

  if (!user?.email || !isAllowedEmail(user.email)) {
    redirect("/");
  }

  if (assurance?.currentLevel !== "aal2") {
    redirect("/auth/check");
  }

  const { instance } = await ensureCurrentUserInstance();
  if (!hasRequiredApiKeys(instance?.settings)) {
    redirect("/setup/api-keys");
  }

  return (
    <>
      <div className="app-toolbar">
        <SignOutButton />
      </div>
      <EmailAlertGeneratorApp userEmail={user.email} />
    </>
  );
}
