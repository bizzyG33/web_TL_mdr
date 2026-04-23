import { redirect } from "next/navigation";
import { ApiKeysForm } from "@/components/api-keys-form";
import {
  ensureCurrentUserInstance,
  getApiKeysFromSettings,
  hasRequiredApiKeys
} from "@/lib/user-instance";

export default async function ApiKeysSetupPage() {
  const { user, instance } = await ensureCurrentUserInstance();

  if (!user?.email) {
    redirect("/");
  }

  if (hasRequiredApiKeys(instance?.settings)) {
    redirect("/app");
  }

  const apiKeys = getApiKeysFromSettings(instance?.settings);

  return (
    <ApiKeysForm
      configuredKeys={{
        virusTotal: Boolean(apiKeys.virusTotal),
        abuseIpDb: Boolean(apiKeys.abuseIpDb),
        proxyCheck: Boolean(apiKeys.proxyCheck)
      }}
      email={user.email}
    />
  );
}
