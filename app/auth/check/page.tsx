import { redirect } from "next/navigation";
import { MfaGate } from "@/components/mfa-gate";
import { createClient } from "@/lib/supabase/server";

export default async function AuthCheckPage() {
  const supabase = await createClient();
  const {
    data: { user }
  } = await supabase.auth.getUser();

  if (!user) {
    redirect("/");
  }

  return <MfaGate email={user.email ?? ""} />;
}
