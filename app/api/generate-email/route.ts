import { NextResponse } from "next/server";
import {
  generateEmail,
  type AlertType,
  type AppTab,
  type ResponseAction,
  type SpecificDisablement
} from "@/lib/email-alert-generator";
import { buildEnrichmentOverrides, resolveActiveTemplateName } from "@/lib/ip-enrichment";
import { loadTemplates } from "@/lib/template-loader";
import {
  ensureCurrentUserInstance,
  getApiKeysFromSettings,
  hasRequiredApiKeys
} from "@/lib/user-instance";

type RequestBody = {
  tab: AppTab;
  alertType: AlertType;
  alertDisplayName: string;
  templateFileName: string;
  responseAction: ResponseAction;
  logText: string;
  organization: string;
  hostname: string;
  includeRunbookBlurb: boolean;
  includeExclusionAdded: boolean;
  includeEscalation: boolean;
  isSecureMode: boolean;
  isLearningMonitorMode: boolean;
  defenderAction: string;
  sentinelOneAction: string;
  specificDisablement: SpecificDisablement;
};

export async function POST(request: Request) {
  const { user, instance } = await ensureCurrentUserInstance();

  if (!user?.id || !user.email) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  if (!hasRequiredApiKeys(instance?.settings)) {
    return NextResponse.json(
      { error: "API keys are required before generating emails." },
      { status: 403 }
    );
  }

  const body = (await request.json()) as RequestBody;
  const templates = await loadTemplates();
  const activeTemplateName = resolveActiveTemplateName(
    body.alertType,
    body.templateFileName,
    body.specificDisablement
  );
  const template = templates[activeTemplateName];

  if (!template) {
    return NextResponse.json(
      { error: `Template not found: ${activeTemplateName}` },
      { status: 400 }
    );
  }

  const apiKeys = getApiKeysFromSettings(instance?.settings);
  const overrides = await buildEnrichmentOverrides(
    {
      alertType: body.alertType,
      templateFileName: body.templateFileName,
      specificDisablement: body.specificDisablement,
      logText: body.logText
    },
    template,
    apiKeys
  );

  const generation = generateEmail({
    ...body,
    templates,
    signerEmail: user.email,
    ...overrides
  });

  return NextResponse.json(generation);
}
