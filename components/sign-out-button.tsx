"use client";

import { useTransition } from "react";
import { useRouter } from "next/navigation";
import { createClient } from "@/lib/supabase/browser";

export function SignOutButton() {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();

  async function handleSignOut() {
    const supabase = createClient();
    await supabase.auth.signOut();
    startTransition(() => {
      router.replace("/");
      router.refresh();
    });
  }

  return (
    <button className="button-ghost" disabled={isPending} onClick={handleSignOut} type="button">
      {isPending ? "Signing out..." : "Sign Out"}
    </button>
  );
}
