import { cache } from "react";
import { createClient } from "@/lib/supabase/server";

export type UserApiKeys = {
  virusTotal: string;
  abuseIpDb: string;
  proxyCheck: string;
};

type UserInstanceSettings = {
  apiKeys?: Partial<UserApiKeys>;
};

type UserInstanceRow = {
  user_id: string;
  email: string;
  settings: UserInstanceSettings | null;
};

export const ensureCurrentUserInstance = cache(async () => {
  const supabase = await createClient();
  const {
    data: { user }
  } = await supabase.auth.getUser();

  if (!user?.id || !user.email) {
    return { user: null, instance: null as UserInstanceRow | null };
  }

  const normalizedEmail = user.email.trim().toLowerCase();

  const { data: existing } = await supabase
    .from("user_instances")
    .select("user_id, email, settings")
    .eq("user_id", user.id)
    .maybeSingle<UserInstanceRow>();

  if (existing) {
    if (existing.email !== normalizedEmail) {
      await supabase
        .from("user_instances")
        .update({ email: normalizedEmail })
        .eq("user_id", user.id);
    }

    return {
      user,
      instance: {
        ...existing,
        email: normalizedEmail
      }
    };
  }

  const { data: inserted, error } = await supabase
    .from("user_instances")
    .insert({
      user_id: user.id,
      email: normalizedEmail,
      settings: {}
    })
    .select("user_id, email, settings")
    .single<UserInstanceRow>();

  if (error) {
    throw error;
  }

  return { user, instance: inserted };
});

export function getApiKeysFromSettings(
  settings: UserInstanceSettings | null | undefined
): UserApiKeys {
  const apiKeys = settings?.apiKeys ?? {};

  return {
    virusTotal: apiKeys.virusTotal?.trim() ?? "",
    abuseIpDb: apiKeys.abuseIpDb?.trim() ?? "",
    proxyCheck: apiKeys.proxyCheck?.trim() ?? ""
  };
}

export function hasRequiredApiKeys(settings: UserInstanceSettings | null | undefined): boolean {
  const apiKeys = getApiKeysFromSettings(settings);

  return Boolean(apiKeys.virusTotal && apiKeys.abuseIpDb && apiKeys.proxyCheck);
}
