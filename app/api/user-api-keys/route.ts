import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { ensureCurrentUserInstance } from "@/lib/user-instance";

type RequestBody = {
  virusTotal?: string;
  abuseIpDb?: string;
  proxyCheck?: string;
};

export async function POST(request: Request) {
  const supabase = await createClient();
  const {
    data: { user }
  } = await supabase.auth.getUser();

  if (!user?.id || !user.email) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = (await request.json()) as RequestBody;
  const virusTotal = body.virusTotal?.trim() ?? "";
  const abuseIpDb = body.abuseIpDb?.trim() ?? "";
  const proxyCheck = body.proxyCheck?.trim() ?? "";

  if (!virusTotal || !abuseIpDb || !proxyCheck) {
    return NextResponse.json(
      { error: "VirusTotal, AbuseIPDB, and proxycheck.io keys are all required." },
      { status: 400 }
    );
  }

  const { instance } = await ensureCurrentUserInstance();
  const nextSettings = {
    ...(instance?.settings ?? {}),
    apiKeys: {
      virusTotal,
      abuseIpDb,
      proxyCheck
    }
  };

  const { error } = await supabase.from("user_instances").upsert(
    {
      user_id: user.id,
      email: user.email.toLowerCase(),
      settings: nextSettings
    },
    {
      onConflict: "user_id"
    }
  );

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  return NextResponse.json({ ok: true });
}
