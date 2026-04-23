import { promises as fs } from "node:fs";
import path from "node:path";
import { redirect } from "next/navigation";
import { EmailAlertGeneratorApp } from "@/components/email-alert-generator-app";
import { SignOutButton } from "@/components/sign-out-button";
import { createClient } from "@/lib/supabase/server";
import { isAllowedEmail } from "@/lib/domain";

async function loadTemplates() {
  const templatesDir = path.join(process.cwd(), "templates");
  const entries = await fs.readdir(templatesDir, { withFileTypes: true });
  const templateFiles = entries.filter((entry) => entry.isFile() && entry.name.endsWith(".txt"));
  const templates = await Promise.all(
    templateFiles.map(async (entry) => {
      const content = await fs.readFile(path.join(templatesDir, entry.name), "utf8");
      return [entry.name, content] as const;
    })
  );

  return Object.fromEntries(templates);
}

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

  const templates = await loadTemplates();

  return (
    <>
      <div className="app-toolbar">
        <SignOutButton />
      </div>
      <EmailAlertGeneratorApp templates={templates} userEmail={user.email} />
    </>
  );
}
