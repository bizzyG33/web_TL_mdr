export type AppTab = "cloud" | "endpoint";

export type ResponseAction =
  | "ClearingAlert"
  | "Escalating"
  | "Isolating"
  | "Lockdown"
  | "LockAccount"
  | "LockAccountAndRevokeSession";

export type AlertType =
  | "UserAtRisk"
  | "ImpossibleTravel"
  | "AnonymizedIp"
  | "PasswordSpray"
  | "UnfamiliarSignin"
  | "LoginToDisabledAccount"
  | "TemporaryAccessPass"
  | "CreationOfXAdminAccount"
  | "PrivilegedRole"
  | "ForwardingRule"
  | "DefenderDetection"
  | "DefenderExclusionCreated"
  | "SentinelOneDetection"
  | "PowershellPolicyBypass"
  | "BitlockerDisable"
  | "RegExport"
  | "Enumeration"
  | "Ransomware"
  | "NetStopThreatLocker"
  | "TlUninstallScriptExecution"
  | "DisableProtection"
  | "UserAddedToLocalAdmin"
  | "PublicRDPConnection"
  | "ClearedSecurityLogs"
  | "VulnerableDriver";

export type SpecificDisablement =
  | "Windows Defender"
  | "Windows Firewall"
  | "Recovery Environment"
  | "Net stop Threatlocker"
  | "Execution of TL uninstall script"
  | "Bitlocker Disable";

export type TemplateMap = Record<string, string>;

export type AlertOption = {
  alertType: AlertType;
  displayName: string;
  templateFileName: string;
  tab: AppTab;
};

export type GeneratorInput = {
  tab: AppTab;
  alertType: AlertType;
  alertDisplayName: string;
  templateFileName: string;
  templates: TemplateMap;
  signerEmail: string;
  ip1EnrichmentOverride?: Partial<IpEnrichmentResult>;
  ip2EnrichmentOverride?: Partial<IpEnrichmentResult>;
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

export type ParsedAlertLog = {
  rawFields: Record<string, string>;
  id: string;
  requestId: string;
  correlationId: string;
  riskEventType: string;
  riskState: string;
  riskLevel: string;
  riskDetail: string;
  source: string;
  detectionTimingType: string;
  activity: string;
  tokenIssuerType: string;
  activityDateTimeRaw: string;
  detectedDateTimeRaw: string;
  lastUpdatedDateTimeRaw: string;
  userId: string;
  userDisplayName: string;
  userPrincipalName: string;
  targetUserDisplayName: string;
  targetUserPrincipalName: string;
  privilegedRoleDisplayName: string;
  privilegedRoleObjectId: string;
  privilegedRoleTemplateId: string;
  privilegedRoleWellKnownObjectName: string;
  assetName: string;
  forwardingAddress: string;
  additionalInfo: string;
  additionalInfoRiskReasons: string;
  additionalInfoUserAgent: string;
  tapInitiatedByDisplayName: string;
  tapInitiatedByUserPrincipalName: string;
  tapStartDateTimeRaw: string;
  tapEndDateTimeRaw: string;
  ipAddress: string;
  firstLoginIp: string;
  secondLoginIp: string;
  firstLoginCreatedDateRaw: string;
  secondLoginCreatedDateRaw: string;
  firstLoginCity: string;
  firstLoginRegion: string;
  firstLoginCountry: string;
  secondLoginCity: string;
  secondLoginRegion: string;
  secondLoginCountry: string;
  locationCity: string;
  locationState: string;
  locationCountry: string;
  fallbackCity: string;
  fallbackRegion: string;
  fallbackCountry: string;
  epDomain: string;
  epUser: string;
  epDate: string;
  epProcessPath: string;
  epFullPath: string;
  epCmdLine: string;
  epSha256: string;
  epApplicationName: string;
  epProcessId: string;
  epTLockerHash: string;
  epParentProcessTLHash: string;
  epMessage: string;
  epDefenderType: string;
  epDefenderType1: string;
  epDefenderType2: string;
  epDefenderFile: string;
  epDefenderPath: string;
  epDefenderExclusionNewValue: string;
  epTrueContextId: string;
  epSentinelOnePath: string;
  epMessageSentinelOne: string;
  epSentinelOneType: string;
  epAdminAlertTitle: string;
  epAdminGroupName: string;
  epAddedMemberName: string;
  epAddedMemberDistinguishedName: string;
  epEventLogSourceId: string;
  epLogName: string;
  epSubjectAccountName: string;
  epSubjectAccountDomain: string;
  epMemberAccountName: string;
  epGroupName: string;
  epCreatedByProcess: string;
  epCertificate: string;
};

export type IpEnrichmentResult = {
  ipAddress: string;
  country: string;
  region: string;
  regionCode: string;
  city: string;
  isp: string;
  usedParsedLocationFallback: boolean;
  abuseSummary: string;
  abuseConfidenceScore: string;
  totalReports: string;
  virusTotalVerdict: string;
  virusTotalAttackHistory: string;
  maliciousCount: string;
  suspiciousCount: string;
  proxyCheckVpnStatus: string;
  locationDisplay: string;
};

export type GenerationOutput = {
  statusMessage: string;
  subject: string;
  body: string;
  bodyHtml: string;
  summaryBullets: string;
  clearReasoningStarter: string;
  validationSummary: string;
  templateFileName: string;
  parsedLog: ParsedAlertLog;
};

const HTML_SIGNATURE_TEMPLATE_NAME = "HtmlSignature.html";

const RUNBOOK_BLURB =
  "We recommend updating the runbook for this organization. Having an up-to-date runbook significantly enhances our response time and quality of communication for critical alerts.";
const EXCLUSION_BLURB = "An exclusion has been added for this detection.";
const ESCALATION_BLURB = "We're escalating this alert back for further review.";

const DEFAULT_DEFENDER_ACTION = "Quarantined/Blocked";
const DEFAULT_SENTINEL_ACTION = "Killed Binary";
export const DEFAULT_SPECIFIC_DISABLEMENT: SpecificDisablement = "Windows Defender";

export const cloudAlertOptions: AlertOption[] = [
  { alertType: "AnonymizedIp", displayName: "Anonymized IP", templateFileName: "AnonymizedIp.txt", tab: "cloud" },
  { alertType: "ForwardingRule", displayName: "Forwarding Rule", templateFileName: "ForwardingRule.txt", tab: "cloud" },
  { alertType: "ImpossibleTravel", displayName: "Impossible Travel", templateFileName: "ImpossibleTravel.txt", tab: "cloud" },
  { alertType: "LoginToDisabledAccount", displayName: "Login to Disabled Account", templateFileName: "LoginToDisabledAccount.txt", tab: "cloud" },
  { alertType: "PasswordSpray", displayName: "Password Spray", templateFileName: "PasswordSpray.txt", tab: "cloud" },
  { alertType: "PrivilegedRole", displayName: "Privileged Role", templateFileName: "PrivilegedRole.txt", tab: "cloud" },
  { alertType: "TemporaryAccessPass", displayName: "Temporary Access Pass", templateFileName: "TemporaryAccessPass.txt", tab: "cloud" },
  { alertType: "UnfamiliarSignin", displayName: "Unfamiliar Signin", templateFileName: "UnfamiliarSignin.txt", tab: "cloud" },
  { alertType: "UserAtRisk", displayName: "User at Risk", templateFileName: "UserAtRisk.txt", tab: "cloud" }
];

export const endpointAlertOptions: AlertOption[] = [
  { alertType: "ClearedSecurityLogs", displayName: "Cleared Security/Event Logs", templateFileName: "ClearedSecurityLogs.txt", tab: "endpoint" },
  { alertType: "CreationOfXAdminAccount", displayName: "Creation of X Admin Account", templateFileName: "CreationOfXAdminAccount.txt", tab: "endpoint" },
  { alertType: "DefenderDetection", displayName: "Defender Detection", templateFileName: "DefenderDetection.txt", tab: "endpoint" },
  { alertType: "DefenderExclusionCreated", displayName: "Defender Exclusion Created", templateFileName: "DefenderExclusionCreated.txt", tab: "endpoint" },
  { alertType: "DisableProtection", displayName: "Disable Protection", templateFileName: "WindowsDefender.txt", tab: "endpoint" },
  { alertType: "Enumeration", displayName: "Enumeration", templateFileName: "Enumeration.txt", tab: "endpoint" },
  { alertType: "PowershellPolicyBypass", displayName: "Powershell Policy Bypass", templateFileName: "PowershellPolicyBypass.txt", tab: "endpoint" },
  { alertType: "PublicRDPConnection", displayName: "Public RDP Connection", templateFileName: "PublicRDPConnection.txt", tab: "endpoint" },
  { alertType: "Ransomware", displayName: "Ransomware", templateFileName: "Ransomware.txt", tab: "endpoint" },
  { alertType: "RegExport", displayName: "Reg Export", templateFileName: "RegExport.txt", tab: "endpoint" },
  { alertType: "SentinelOneDetection", displayName: "Sentinel One Detection", templateFileName: "SentinelOneDetection.txt", tab: "endpoint" },
  { alertType: "UserAddedToLocalAdmin", displayName: "User added to Local Admin", templateFileName: "UserAddedToLocalAdmin.txt", tab: "endpoint" },
  { alertType: "VulnerableDriver", displayName: "Vulnerable Driver", templateFileName: "VulnerableDriver.txt", tab: "endpoint" }
];

export const responseActionOptions: Array<{ value: ResponseAction; label: string; endpointOnly?: boolean }> = [
  { value: "ClearingAlert", label: "Clearing Alert" },
  { value: "Escalating", label: "Escalating" },
  { value: "Isolating", label: "Isolating", endpointOnly: true },
  { value: "Lockdown", label: "Lockdown", endpointOnly: true },
  { value: "LockAccount", label: "Lock Account" },
  { value: "LockAccountAndRevokeSession", label: "Lock Account and Revoke Session" }
];

export const defenderActionOptions = ["Quarantined/Blocked", "No visible action/Unable to access"];
export const sentinelActionOptions = ["Killed Binary", "Quarantined"];
export const specificDisablementOptions: SpecificDisablement[] = [
  "Windows Defender",
  "Windows Firewall",
  "Recovery Environment",
  "Net stop Threatlocker",
  "Execution of TL uninstall script",
  "Bitlocker Disable"
];

export function getAlertOptions(tab: AppTab): AlertOption[] {
  return tab === "cloud" ? cloudAlertOptions : endpointAlertOptions;
}

export function getDefaultResponseAction(): ResponseAction {
  return "ClearingAlert";
}

export function getDefaultDefenderAction(): string {
  return DEFAULT_DEFENDER_ACTION;
}

export function getDefaultSentinelAction(): string {
  return DEFAULT_SENTINEL_ACTION;
}

export function resolveSpecificDisablementTemplate(disablement: SpecificDisablement): string {
  switch (disablement) {
    case "Bitlocker Disable":
      return "BitlockerDisable.txt";
    case "Execution of TL uninstall script":
      return "TlUninstallScriptExecution.txt";
    case "Net stop Threatlocker":
      return "NetStopThreatLocker.txt";
    case "Recovery Environment":
      return "RecoveryEnvironment.txt";
    case "Windows Firewall":
      return "WindowsFirewall.txt";
    default:
      return "WindowsDefender.txt";
  }
}

export function generateEmail(input: GeneratorInput): GenerationOutput {
  const parsedLog = parseAlertLog(input.logText);
  const templateFileName =
    input.alertType === "DisableProtection"
      ? resolveSpecificDisablementTemplate(input.specificDisablement)
      : input.templateFileName;
  const template = withSignatureToken(
    input.templates[templateFileName] ?? `Template not found: ${templateFileName}`
  );
  const ip1 = buildIpEnrichment(parsedLog, "ip1", input.alertType);
  const ip2 = buildIpEnrichment(parsedLog, "ip2", input.alertType);
  const finalIp1 = applyIpEnrichmentOverride(ip1, input.ip1EnrichmentOverride);
  const finalIp2 = applyIpEnrichmentOverride(ip2, input.ip2EnrichmentOverride);
  const signerName = buildSignatureNameFromEmail(input.signerEmail);
  const replacements = buildReplacementMap(input, parsedLog, finalIp1, finalIp2, signerName);
  const htmlReplacements = buildHtmlReplacementMap(input, replacements, signerName);
  const subject = buildGeneratedEmailSubject(
    input.tab,
    input.alertDisplayName,
    input.organization,
    input.hostname,
    parsedLog.assetName
  );
  const body = fillTemplate(template, replacements);
  const bodyHtml = composeHtml(template, htmlReplacements);
  const validationSummary = buildValidationSummary(parsedLog, input.alertType);
  const hasWarnings =
    validationSummary !== "No validation issues detected." &&
    validationSummary !== "No validation warnings.";
  const clearReasoningStarter = buildClearReasoningStarter(input.organization, input.alertDisplayName);

  return {
    statusMessage: hasWarnings
      ? `Generation complete with validation warnings. Action: ${toDisplayText(input.responseAction)}`
      : `Generation complete. Action: ${toDisplayText(input.responseAction)}`,
    subject,
    body,
    bodyHtml,
    summaryBullets: buildSummaryBullets(parsedLog, finalIp1, finalIp2, input),
    clearReasoningStarter,
    validationSummary,
    templateFileName,
    parsedLog
  };
}

function withSignatureToken(template: string): string {
  return template.includes("{{Signature}}") ? template : `${template.trimEnd()}\n\n{{Signature}}`;
}

function fillTemplate(template: string, replacements: Record<string, string>): string {
  return template.replace(/\{\{[^}]+\}\}/g, (token) => {
    const normalized = token.toLowerCase();
    if (normalized in replacements) {
      return replacements[normalized];
    }

    return "N/A";
  });
}

function buildReplacementMap(
  input: GeneratorInput,
  parsed: ParsedAlertLog,
  ip1: IpEnrichmentResult,
  ip2: IpEnrichmentResult,
  signerName: string
): Record<string, string> {
  const finalAssetName = firstNonEmpty(input.hostname, parsed.assetName);
  const maintenanceStatus = input.isSecureMode
    ? "This device is currently in Secure Mode."
    : input.isLearningMonitorMode
      ? "This device is not in Secure Mode, as such, any application being executed will be permitted."
      : "";

  const replacements: Record<string, string> = {
    "{{ip1}}": defangIfIpLike(ip1.ipAddress),
    "{{ip2}}": defangIfIpLike(ip2.ipAddress),
    "{{alerttype}}": input.alertType,
    "{{assetname}}": valueOrNA(finalAssetName),
    "{{organization}}": valueOrNA(input.organization),
    "{{id}}": valueOrNA(parsed.id),
    "{{requestid}}": valueOrNA(parsed.requestId),
    "{{correlationid}}": valueOrNA(parsed.correlationId),
    "{{riskeventtype}}": valueOrNA(parsed.riskEventType),
    "{{riskstate}}": valueOrNA(parsed.riskState),
    "{{risklevel}}": valueOrNA(parsed.riskLevel),
    "{{riskdetail}}": valueOrNA(parsed.riskDetail),
    "{{source}}": valueOrNA(parsed.source),
    "{{detectiontimingtype}}": valueOrNA(parsed.detectionTimingType),
    "{{activity}}": valueOrNA(parsed.activity),
    "{{tokenissuertype}}": valueOrNA(parsed.tokenIssuerType),
    "{{userid}}": valueOrNA(parsed.userId),
    "{{userdisplayname}}": valueOrNA(parsed.userDisplayName),
    "{{userprincipalname}}": valueOrNA(parsed.userPrincipalName),
    "{{forwardingaddress}}": valueOrNA(parsed.forwardingAddress),
    "{{targetuserdisplayname}}": valueOrNA(parsed.targetUserDisplayName),
    "{{targetuserprincipalname}}": valueOrNA(parsed.targetUserPrincipalName),
    "{{privilegedroledisplayname}}": valueOrNA(parsed.privilegedRoleDisplayName),
    "{{privilegedroleobjectid}}": valueOrNA(parsed.privilegedRoleObjectId),
    "{{privilegedroletemplateid}}": valueOrNA(parsed.privilegedRoleTemplateId),
    "{{privilegedrolewellknownobjectname}}": valueOrNA(parsed.privilegedRoleWellKnownObjectName),
    "{{activitytimeutc}}": formatUtcTimeOrNA(parsed.activityDateTimeRaw),
    "{{detectedtimeutc}}": formatUtcTimeOrNA(parsed.detectedDateTimeRaw),
    "{{lastupdatedtimeutc}}": formatUtcTimeOrNA(parsed.lastUpdatedDateTimeRaw),
    "{{firstlogincreateddate}}": valueOrNA(parsed.firstLoginCreatedDateRaw),
    "{{secondlogincreateddate}}": valueOrNA(parsed.secondLoginCreatedDateRaw),
    "{{firstlogintimeutc}}": formatUtcTimeOrNA(parsed.firstLoginCreatedDateRaw),
    "{{secondlogintimeutc}}": formatUtcTimeOrNA(parsed.secondLoginCreatedDateRaw),
    "{{additionalinfo}}": valueOrNA(parsed.additionalInfo),
    "{{additionalinforiskreasons}}": valueOrNA(parsed.additionalInfoRiskReasons),
    "{{additionalinfouseragent}}": valueOrNA(parsed.additionalInfoUserAgent),
    "{{tapinitiatedbydisplayname}}": valueOrNA(parsed.tapInitiatedByDisplayName),
    "{{tapinitiatedbyuserprincipalname}}": valueOrNA(parsed.tapInitiatedByUserPrincipalName),
    "{{tapduration}}": calculateTapDuration(parsed.tapStartDateTimeRaw, parsed.tapEndDateTimeRaw),
    "{{tapstarttimeutc}}": formatUtcTimeOrNA(parsed.tapStartDateTimeRaw),
    "{{tapendtimeutc}}": formatUtcTimeOrNA(parsed.tapEndDateTimeRaw),
    "{{ip1location}}": valueOrNA(ip1.locationDisplay),
    "{{ip1country}}": valueOrNA(ip1.country),
    "{{ip1region}}": valueOrNA(ip1.region),
    "{{ip1city}}": valueOrNA(ip1.city),
    "{{ip1isp}}": valueOrNA(ip1.isp),
    "{{ip1abusescore}}": valueOrNA(ip1.abuseConfidenceScore),
    "{{ip1abusereports}}": valueOrNA(ip1.totalReports),
    "{{ip1abusesummary}}": valueOrNA(ip1.abuseSummary),
    "{{ip1virustotalmalicious}}": valueOrNA(ip1.maliciousCount),
    "{{ip1virustotalsuspicious}}": valueOrNA(ip1.suspiciousCount),
    "{{ip1virustotalverdict}}": valueOrNA(ip1.virusTotalVerdict),
    "{{ip1virustotalattackhistory}}": valueOrNA(ip1.virusTotalAttackHistory),
    "{{vtattackhistory}}": valueOrNA(ip1.virusTotalAttackHistory),
    "{{ip1proxycheckvpnstatus}}": valueOrNA(ip1.proxyCheckVpnStatus),
    "{{proxycheckvpnstatus}}": valueOrNA(ip1.proxyCheckVpnStatus),
    "{{ip2location}}": valueOrNA(ip2.locationDisplay),
    "{{ip2country}}": valueOrNA(ip2.country),
    "{{ip2region}}": valueOrNA(ip2.region),
    "{{ip2city}}": valueOrNA(ip2.city),
    "{{ip2isp}}": valueOrNA(ip2.isp),
    "{{ip2abusescore}}": valueOrNA(ip2.abuseConfidenceScore),
    "{{ip2abusereports}}": valueOrNA(ip2.totalReports),
    "{{ip2abusesummary}}": valueOrNA(ip2.abuseSummary),
    "{{ip2virustotalmalicious}}": valueOrNA(ip2.maliciousCount),
    "{{ip2virustotalsuspicious}}": valueOrNA(ip2.suspiciousCount),
    "{{ip2virustotalverdict}}": valueOrNA(ip2.virusTotalVerdict),
    "{{ip2virustotalattackhistory}}": valueOrNA(ip2.virusTotalAttackHistory),
    "{{ip2proxycheckvpnstatus}}": valueOrNA(ip2.proxyCheckVpnStatus),
    "{{responseaction}}": toDisplayText(input.responseAction),
    "{{responsefooter}}": buildFooter(
      input.responseAction,
      input.includeExclusionAdded,
      input.includeEscalation
    ),
    "{{signature}}": buildPlainTextSignature(signerName),
    "{{signaturename}}": signerName,
    "{{runbookblurb}}": input.includeRunbookBlurb ? RUNBOOK_BLURB : "",
    "{{exclusionaddedblurb}}": input.includeExclusionAdded ? EXCLUSION_BLURB : "",
    "{{maintenancestatus}}": maintenanceStatus,
    "{{eporg}}": valueOrNA(input.organization),
    "{{epdomain}}": valueOrNA(parsed.epDomain),
    "{{epuser}}": valueOrNA(parsed.epUser || parsed.userDisplayName || parsed.userPrincipalName),
    "{{epdate}}": valueOrNA(parsed.epDate),
    "{{epdetectedtimeest}}": formatEndpointEstTimeOrNA(parsed.epDate),
    "{{epprocesspath}}": valueOrNA(parsed.epProcessPath),
    "{{epfullpath}}": valueOrNA(parsed.epFullPath),
    "{{epcmdline}}": valueOrNA(parsed.epCmdLine),
    "{{epsha256}}": valueOrNA(parsed.epSha256),
    "{{epapplicationname}}": valueOrNA(parsed.epApplicationName),
    "{{epprocessid}}": valueOrNA(parsed.epProcessId),
    "{{eptlockerhash}}": valueOrNA(parsed.epTLockerHash),
    "{{epparentprocesstlhash}}": valueOrNA(parsed.epParentProcessTLHash),
    "{{epmessage}}": valueOrNA(parsed.epMessage),
    "{{epdefendertype}}": valueOrNA(parsed.epDefenderType),
    "{{epdefendertype1}}": valueOrNA(parsed.epDefenderType1),
    "{{epdefendertype2}}": valueOrNA(parsed.epDefenderType2),
    "{{epdefenderaction}}": valueOrNA(input.defenderAction),
    "{{epdefenderfile}}": valueOrNA(parsed.epDefenderFile),
    "{{epdefenderpath}}": valueOrNA(parsed.epDefenderPath),
    "{{epdefenderexclusionnewvalue}}": valueOrNA(parsed.epDefenderExclusionNewValue),
    "{{epsentineloneaction}}": valueOrNA(input.sentinelOneAction),
    "{{eptruecontextid}}": valueOrNA(parsed.epTrueContextId),
    "{{epsentinelonetype}}": valueOrNA(parsed.epSentinelOneType),
    "{{epsentinelonepath}}": valueOrNA(parsed.epSentinelOnePath),
    "{{epmessagesentinelone}}": valueOrNA(parsed.epMessageSentinelOne),
    "{{epadminalerttitle}}": valueOrNA(parsed.epAdminAlertTitle),
    "{{epadmingroupname}}": valueOrNA(parsed.epAdminGroupName),
    "{{epaddedmembername}}": valueOrNA(parsed.epAddedMemberName),
    "{{epaddedmemberdn}}": valueOrNA(parsed.epAddedMemberDistinguishedName),
    "{{epeventlogsourceid}}": valueOrNA(parsed.epEventLogSourceId),
    "{{eplogname}}": valueOrNA(parsed.epLogName),
    "{{epsubjectaccountname}}": valueOrNA(parsed.epSubjectAccountName),
    "{{epsubjectaccountdomain}}": valueOrNA(parsed.epSubjectAccountDomain),
    "{{epgroupname}}": valueOrNA(parsed.epGroupName),
    "{{epcreatedbyprocess}}": valueOrNA(parsed.epCreatedByProcess),
    "{{epcertificate}}": valueOrNA(parsed.epCertificate)
  };

  return replacements;
}

function buildHtmlReplacementMap(
  input: GeneratorInput,
  baseReplacements: Record<string, string>,
  signerName: string
): Record<string, string> {
  const htmlSignatureTemplate = input.templates[HTML_SIGNATURE_TEMPLATE_NAME] ?? "";

  return {
    ...baseReplacements,
    "{{signature}}": htmlSignatureTemplate
      ? htmlSignatureTemplate.replaceAll("===NAME===", escapeHtml(signerName))
      : escapeHtmlWithBreaks(baseReplacements["{{signature}}"] ?? signerName)
  };
}

function applyIpEnrichmentOverride(
  base: IpEnrichmentResult,
  override?: Partial<IpEnrichmentResult>
): IpEnrichmentResult {
  if (!override) {
    return base;
  }

  const sanitizedOverride = Object.fromEntries(
    Object.entries(override).filter(([, value]) => value !== undefined)
  ) as Partial<IpEnrichmentResult>;

  const merged: IpEnrichmentResult = {
    ...base,
    ...sanitizedOverride
  };

  merged.locationDisplay = buildLocationDisplay(merged.city, merged.regionCode, merged.country);
  return merged;
}

function composeHtml(template: string, replacements: Record<string, string>): string {
  const lines = template.replace(/\r\n/g, "\n").split("\n");
  const html = lines
    .map((line) => {
      if (!line.trim()) {
        return '<div style="margin:0; line-height:1.5;"><br></div>';
      }

      return `<div style="margin:0; line-height:1.5; color:#000000; background:transparent;">${replaceLineTokensWithHtml(line, replacements)}</div>`;
    })
    .join("");

  return html;
}

function replaceLineTokensWithHtml(line: string, replacements: Record<string, string>): string {
  let position = 0;
  let output = "";

  while (position < line.length) {
    const tokenStart = line.indexOf("{{", position);

    if (tokenStart < 0) {
      output += escapeHtml(line.slice(position));
      break;
    }

    if (tokenStart > position) {
      output += escapeHtml(line.slice(position, tokenStart));
    }

    const tokenEnd = line.indexOf("}}", tokenStart);
    if (tokenEnd < 0) {
      output += escapeHtml(line.slice(tokenStart));
      break;
    }

    const token = line.slice(tokenStart, tokenEnd + 2);
    const normalized = token.toLowerCase();

    if (normalized in replacements) {
      if (normalized === "{{signature}}") {
        output += replacements[normalized] || "";
      } else {
        output += `<strong>${escapeHtmlWithBreaks(replacements[normalized] || "N/A")}</strong>`;
      }
    } else {
      output += escapeHtml(token);
    }

    position = tokenEnd + 2;
  }

  return output;
}

export function parseAlertLog(logText: string): ParsedAlertLog {
  const lines = logText.split(/\r?\n/);
  const rawFields: Record<string, string> = {};

  for (const rawLine of lines) {
    const trimmed = rawLine.trim();
    if (!trimmed) {
      continue;
    }

    const separatorIndex = trimmed.indexOf(":");
    if (separatorIndex <= 0) {
      continue;
    }

    const key = trimmed.slice(0, separatorIndex).trim();
    const value = trimmed.slice(separatorIndex + 1).trim();

    if (!(key.toLowerCase() in rawFields)) {
      rawFields[key.toLowerCase()] = value;
    }
  }

  const get = (...keys: string[]): string => {
    for (const key of keys) {
      const value = rawFields[key.toLowerCase()];
      if (value) {
        return value;
      }
    }

    return "";
  };

  const message = get("Message", "message");
  const certificate = get("Certificate", "certificate");

  const epDefenderType = extractNamedField(message, "Name");
  const [epDefenderType1, epDefenderType2] = splitOnFirst(epDefenderType, ":");
  const epDefenderFile = extractNamedField(message, "Path");
  const epMessageSentinelOne = extractNamedField(message, "Description") || message;
  const epUser =
    get("UserName", "userName", "Subject User Name", "SubjectUserName", "Account Name") ||
    extractNamedField(message, "Account Name") ||
    get("userDisplayName", "userPrincipalName");
  const ipAddress =
    get(
      "ClientIP",
      "clientIp",
      "clientIP",
      "ipAddress",
      "IPAddress",
      "ip",
      "IP Address",
      "SourceIPAddress",
      "sourceIpAddress",
      "sourceIPAddress",
      "remoteIpAddress",
      "remoteIP",
      "address",
      "ipaddr",
      "Source IP Address"
    ) || extractFirstIp(logText);

  return {
    rawFields,
    id: get("id"),
    requestId: get("requestId"),
    correlationId: get("correlationId"),
    riskEventType: get("riskEventType", "RiskType", "Operation"),
    riskState: get("riskState", "Resultstatus"),
    riskLevel: get("riskLevel"),
    riskDetail: get("riskDetail", "EventDescription", "LogonError"),
    source: get("source", "Workload", "EventLog Description"),
    detectionTimingType: get("detectionTimingType"),
    activity: get("activity", "Operation", "Action Type"),
    tokenIssuerType: get("tokenIssuerType"),
    activityDateTimeRaw: get("activityDateTime", "Date", "date", "IssuedAtTime"),
    detectedDateTimeRaw: get("detectedDateTime", "CreationTime", "Date", "date"),
    lastUpdatedDateTimeRaw: get("lastUpdatedDateTime"),
    userId: get("userId", "userid", "UserKey"),
    userDisplayName: get(
      "userDisplayName",
      "user display name",
      "displayName",
      "accountDisplayName",
      "username",
      "userName",
      "identity",
      "accountName",
      "UserName"
    ),
    userPrincipalName: get(
      "userPrincipalName",
      "user principal name",
      "upn",
      "accountUpn",
      "account",
      "user",
      "userPrincipal",
      "UserName",
      "UserId"
    ),
    targetUserDisplayName: get("TargetUserDisplayName", "targetUserDisplayName", "Target Display Name"),
    targetUserPrincipalName: get("TargetUserPrincipalName", "targetUserPrincipalName", "Target User Principal Name"),
    privilegedRoleDisplayName:
      get("PrivilegedRoleDisplayName", "Role.DisplayName", "role.displayname") ||
      extractNamedField(logText, "Role.DisplayName"),
    privilegedRoleObjectId:
      get("PrivilegedRoleObjectId", "Role.ObjectID", "role.objectid") ||
      extractNamedField(logText, "Role.ObjectID"),
    privilegedRoleTemplateId:
      get("PrivilegedRoleTemplateId", "Role.TemplateId", "TemplateId") ||
      extractNamedField(logText, "Role.TemplateId"),
    privilegedRoleWellKnownObjectName:
      get("PrivilegedRoleWellKnownObjectName", "Role.WellKnownObjectName", "RoleDefinitionOriginId") ||
      extractNamedField(logText, "Role.WellKnownObjectName"),
    assetName: get(
      "assetName",
      "asset name",
      "AssetName",
      "MachineName",
      "machineName",
      "hostName",
      "deviceName",
      "device",
      "Endpoint",
      "Host",
      "Computer"
    ),
    forwardingAddress:
      get("ForwardingSmtpAddress", "Forwarding Address") ||
      extractNamedField(logText, "ForwardingSmtpAddress"),
    additionalInfo: get("additionalInfo"),
    additionalInfoRiskReasons: get("AdditionalInfoRiskReasons"),
    additionalInfoUserAgent: get("AdditionalInfoUserAgent"),
    tapInitiatedByDisplayName:
      get("TapInitiatedByDisplayName", "InitiatedByDisplayName") ||
      extractNamedField(logText, "displayName"),
    tapInitiatedByUserPrincipalName:
      get("TapInitiatedByUserPrincipalName", "InitiatedByUserPrincipalName") ||
      extractNamedField(logText, "userPrincipalName"),
    tapStartDateTimeRaw:
      get("TapStartDateTime", "TemporaryAccessPass.TemporaryAccessPass.StartDateTime") ||
      extractNamedField(logText, "TemporaryAccessPass.TemporaryAccessPass.StartDateTime"),
    tapEndDateTimeRaw:
      get("TapEndDateTime", "TemporaryAccessPass.TemporaryAccessPass.EndTime") ||
      extractNamedField(logText, "TemporaryAccessPass.TemporaryAccessPass.EndTime"),
    ipAddress,
    firstLoginIp:
      get("FirstLoginIp", "First Login IP", "firstLoginIp", "FirstLogin.IP", "FirstLogin.IpAddress") ||
      extractNamedField(logText, "FirstLogin.IP") ||
      extractNamedField(logText, "First Login IP"),
    secondLoginIp:
      get("SecondLoginIp", "Second Login IP", "secondLoginIp", "SecondLogin.IP", "SecondLogin.IpAddress") ||
      extractNamedField(logText, "SecondLogin.IP") ||
      extractNamedField(logText, "Second Login IP"),
    firstLoginCreatedDateRaw:
      get(
        "FirstLoginCreatedDate",
        "First Login CreatedDate",
        "FirstLogin.CreatedDate",
        "FirstLogin.CreatedDateTime",
        "First Login Time",
        "FirstLogin.Timestamp"
      ) ||
      extractNamedField(logText, "FirstLogin.CreatedDate") ||
      extractNamedField(logText, "FirstLogin.CreatedDateTime") ||
      extractNamedField(logText, "First Login Time"),
    secondLoginCreatedDateRaw:
      get(
        "SecondLoginCreatedDate",
        "Second Login CreatedDate",
        "SecondLogin.CreatedDate",
        "SecondLogin.CreatedDateTime",
        "Second Login Time",
        "SecondLogin.Timestamp"
      ) ||
      extractNamedField(logText, "SecondLogin.CreatedDate") ||
      extractNamedField(logText, "SecondLogin.CreatedDateTime") ||
      extractNamedField(logText, "Second Login Time"),
    firstLoginCity:
      get("FirstLoginCity", "First Login City", "FirstLogin.City", "FirstLogin.Location.City") ||
      extractNamedField(logText, "FirstLogin.City"),
    firstLoginRegion:
      get("FirstLoginRegion", "First Login Region", "FirstLogin.Region", "FirstLogin.Location.State") ||
      extractNamedField(logText, "FirstLogin.Region"),
    firstLoginCountry:
      get("FirstLoginCountry", "First Login Country", "FirstLogin.Country", "FirstLogin.Location.Country") ||
      extractNamedField(logText, "FirstLogin.Country"),
    secondLoginCity:
      get("SecondLoginCity", "Second Login City", "SecondLogin.City", "SecondLogin.Location.City") ||
      extractNamedField(logText, "SecondLogin.City"),
    secondLoginRegion:
      get("SecondLoginRegion", "Second Login Region", "SecondLogin.Region", "SecondLogin.Location.State") ||
      extractNamedField(logText, "SecondLogin.Region"),
    secondLoginCountry:
      get("SecondLoginCountry", "Second Login Country", "SecondLogin.Country", "SecondLogin.Location.Country") ||
      extractNamedField(logText, "SecondLogin.Country"),
    locationCity: get("LocationCity", "city", "City"),
    locationState: get("LocationState", "state", "Region"),
    locationCountry: get("LocationCountry", "countryOrRegion", "Country", "country"),
    fallbackCity: get("City", "city"),
    fallbackRegion: get("Region", "region"),
    fallbackCountry: get("Country", "country"),
    epDomain:
      get("Domain", "SubjectDomainName", "Subject Account Domain", "domain") ||
      extractNamedField(message, "Domain Name"),
    epUser,
    epDate: get("Date", "date", "CreationTime"),
    epProcessPath: get("Process Path", "ProcessPath"),
    epFullPath: get("Full Path", "FullPath"),
    epCmdLine: get(
      "Cmd Line Parameters",
      "CmdLineParameters",
      "Process Path With CmdLine",
      "ProcessPathWithCmdLine",
      "Full Path With CmdLine"
    ),
    epSha256: get("SHA256", "sha256"),
    epApplicationName: get("Application Name", "ApplicationName", "Policy Name"),
    epProcessId: get("Process ID", "ProcessID"),
    epTLockerHash: get("TLHash", "tlhash"),
    epParentProcessTLHash: get("Parent Process TLHash", "ParentProcessTLHash"),
    epMessage: message,
    epDefenderType,
    epDefenderType1,
    epDefenderType2,
    epDefenderFile: stripSentinelPrefixes(epDefenderFile),
    epDefenderPath: get("Process Path", "ProcessPath") || stripSentinelPrefixes(epDefenderFile),
    epDefenderExclusionNewValue:
      get("New Value", "NewValue") || extractNamedField(message, "New Value"),
    epTrueContextId: get("TrueContextId", "True Context ID"),
    epSentinelOnePath: stripSentinelPrefixes(
      get("Path", "Full Path", "FullPath") || extractNamedField(message, "Path")
    ),
    epMessageSentinelOne,
    epSentinelOneType: get("Log Name", "LogName", "Threat Name", "ThreatName"),
    epAdminAlertTitle: get("Admin Alert Title", "AdminAlertTitle"),
    epAdminGroupName:
      get("Admin Group Name", "AdminGroupName") ||
      extractNamedField(message, "Group Name"),
    epAddedMemberName:
      get("Added Member Name", "AddedMemberName", "MemberName") ||
      extractNamedField(message, "Member Name"),
    epAddedMemberDistinguishedName:
      get("Added Member Distinguished Name", "AddedMemberDistinguishedName") ||
      extractNamedField(message, "Member"),
    epEventLogSourceId: get("EventLog Source ID", "EventLogSourceId", "Event ID"),
    epLogName: get("Log Name", "LogName"),
    epSubjectAccountName:
      get("Subject Account Name", "SubjectAccountName") ||
      extractNamedField(message, "Account Name"),
    epSubjectAccountDomain:
      get("Subject Account Domain", "SubjectAccountDomain") ||
      extractNamedField(message, "Domain Name"),
    epMemberAccountName: get("Member Account Name", "MemberAccountName") || extractNamedField(message, "Member Name"),
    epGroupName: get("Group Name", "GroupName") || extractNamedField(message, "Group Name"),
    epCreatedByProcess: get("Created By Process", "CreatedByProcess"),
    epCertificate: normalizeCertificate(certificate)
  };
}

function buildIpEnrichment(
  parsed: ParsedAlertLog,
  target: "ip1" | "ip2",
  alertType: AlertType
): IpEnrichmentResult {
  const isImpossibleTravel = alertType === "ImpossibleTravel";
  const ipAddress =
    target === "ip1"
      ? isImpossibleTravel
        ? parsed.firstLoginIp
        : parsed.ipAddress
      : parsed.secondLoginIp;

  const city =
    target === "ip1"
      ? isImpossibleTravel
        ? parsed.firstLoginCity
        : firstNonEmpty(parsed.locationCity, parsed.fallbackCity)
      : parsed.secondLoginCity;
  const region =
    target === "ip1"
      ? isImpossibleTravel
        ? parsed.firstLoginRegion
        : firstNonEmpty(parsed.locationState, parsed.fallbackRegion)
      : parsed.secondLoginRegion;
  const country =
    target === "ip1"
      ? isImpossibleTravel
        ? parsed.firstLoginCountry
        : firstNonEmpty(parsed.locationCountry, parsed.fallbackCountry)
      : parsed.secondLoginCountry;

  const base: Omit<IpEnrichmentResult, "locationDisplay"> = {
    ipAddress,
    country: country || "Unknown",
    region: region || "Unknown",
    regionCode: region || "Unknown",
    city: city || "Unknown",
    isp: "Unavailable in web-only mode",
    usedParsedLocationFallback: Boolean(city || region || country),
    abuseSummary: "Unavailable in web-only mode",
    abuseConfidenceScore: "N/A",
    totalReports: "N/A",
    virusTotalVerdict: "Unavailable in web-only mode",
    virusTotalAttackHistory: "Unavailable in web-only mode",
    maliciousCount: "N/A",
    suspiciousCount: "N/A",
    proxyCheckVpnStatus:
      alertType === "AnonymizedIp" || alertType === "PublicRDPConnection"
        ? "Unavailable in web-only mode"
        : "N/A"
  };

  return {
    ...base,
    locationDisplay: buildLocationDisplay(base.city, base.regionCode, base.country)
  };
}

function buildSummaryBullets(
  parsed: ParsedAlertLog,
  ip1: IpEnrichmentResult,
  ip2: IpEnrichmentResult,
  input: GeneratorInput
): string {
  const lines: string[] = [];

  if (input.organization.trim()) {
    lines.push(`- Organization: ${input.organization.trim()}`);
  }

  if (input.hostname.trim()) {
    lines.push(`- Hostname: ${input.hostname.trim()}`);
  }

  lines.push(`- User: ${safe(parsed.userDisplayName, parsed.userPrincipalName, "N/A")}`);
  lines.push(`- Alert Type: ${input.alertDisplayName}`);
  lines.push(`- Action Taken: ${toDisplayText(input.responseAction)}`);

  if (parsed.riskLevel.trim()) {
    lines.push(`- Risk Level: ${parsed.riskLevel.trim()}`);
  }

  if (parsed.activity.trim()) {
    lines.push(`- Activity: ${parsed.activity.trim()}`);
  }

  if (input.alertType === "ImpossibleTravel") {
    lines.push(`- First login IP: ${valueOrNA(parsed.firstLoginIp)}`);
    lines.push(`- First login time: ${valueOrNA(parsed.firstLoginCreatedDateRaw)}`);
    lines.push(`- Second login IP: ${valueOrNA(parsed.secondLoginIp)}`);
    lines.push(`- Second login time: ${valueOrNA(parsed.secondLoginCreatedDateRaw)}`);
  } else {
    lines.push(`- IP: ${valueOrNA(ip1.ipAddress)}`);
    lines.push(`- Detected time (EST): ${valueOrNA(parsed.detectedDateTimeRaw || parsed.epDate)}`);
  }

  if (ip1.locationDisplay !== "N/A") {
    lines.push(`- IP1 Location: ${ip1.locationDisplay}`);
  }

  if (ip1.isp !== "Unavailable in web-only mode" && ip1.isp !== "Unknown") {
    lines.push(`- IP1 ISP: ${ip1.isp}`);
  }

  if (ip2.ipAddress.trim()) {
    lines.push(`- IP2 Location: ${ip2.locationDisplay}`);
  }

  return lines.join("\n");
}

function buildValidationSummary(parsed: ParsedAlertLog, alertType: AlertType): string {
  const issues: string[] = [];

  if (!isEndpointAlert(alertType) && !parsed.riskEventType.trim()) {
    issues.push("- riskEventType / RiskType was not found.");
  }

  if (!parsed.activity.trim()) {
    issues.push("- activity / Operation was not found.");
  }

  if (!parsed.userDisplayName.trim() && !parsed.userPrincipalName.trim() && !parsed.epUser.trim()) {
    issues.push("- No user identifier was found.");
  }

  if (alertType === "ImpossibleTravel") {
    if (!parsed.firstLoginIp.trim()) {
      issues.push("- FirstLoginIp was not found.");
    }

    if (!parsed.secondLoginIp.trim()) {
      issues.push("- SecondLoginIp was not found.");
    }

    if (!parsed.firstLoginCreatedDateRaw.trim()) {
      issues.push("- First login CreatedDate was not found.");
    }

    if (!parsed.secondLoginCreatedDateRaw.trim()) {
      issues.push("- Second login CreatedDate was not found.");
    }
  } else if (!isEndpointAlert(alertType) && !parsed.ipAddress.trim()) {
    issues.push("- Client IP was not found.");
  }

  if (isEndpointAlert(alertType) && !parsed.epDate.trim()) {
    issues.push("- Endpoint Date field was not found.");
  }

  return issues.length === 0 ? "No validation issues detected." : issues.join("\n");
}

function buildGeneratedEmailSubject(
  tab: AppTab,
  detectionName: string,
  organization: string,
  hostname: string,
  parsedAssetName: string
): string {
  if (tab === "cloud") {
    return `Threatlocker MDR | ${detectionName} | ${valueOrNA(organization.trim())}`;
  }

  const subjectParts = ["Threatlocker MDR", detectionName];
  const trimmedOrg = organization.trim();
  const endpointName = hostname.trim() || parsedAssetName.trim();

  if (trimmedOrg) {
    subjectParts.push(trimmedOrg);
  }

  if (endpointName) {
    subjectParts.push(endpointName);
  }

  return subjectParts.join(" | ");
}

function buildClearReasoningStarter(organization: string, detectionName: string): string {
  const generatedAt = new Date();
  const organizationName = organization.trim() || "N/A";

  return `Email sent on ${formatDate(generatedAt)} at ${formatTime(generatedAt)} to ${organizationName} regarding ${getIndefiniteArticle(detectionName)} ${detectionName} alert.`;
}

function buildFooter(
  responseAction: ResponseAction,
  includeExclusionAdded: boolean,
  includeEscalation: boolean
): string {
  if (includeEscalation) {
    return includeExclusionAdded ? `${ESCALATION_BLURB} ${EXCLUSION_BLURB}` : ESCALATION_BLURB;
  }

  let footer = "";

  switch (responseAction) {
    case "ClearingAlert":
      footer =
        "At this time, we have determined there is no immediate threat to this asset; however, we recommend confirming this is expected behavior.";
      break;
    case "Escalating":
      footer =
        "At this time, the alert is being escalated for additional review and investigation. We will continue to monitor this asset for any additional indicators of compromise.";
      break;
    case "Isolating":
      footer =
        "At this time, the affected endpoint is being isolated as a precautionary containment measure while the activity is investigated further.";
      break;
    case "Lockdown":
      footer =
        "At this time, containment actions have been initiated and the impacted environment has been placed into lockdown to prevent additional unauthorized activity.";
      break;
    case "LockAccount":
      footer =
        "At this time, the account has been locked as a precautionary measure pending validation of the observed activity.";
      break;
    case "LockAccountAndRevokeSession":
      footer =
        "At this time, the account has been locked and active sessions have been revoked as a precautionary measure pending further investigation.";
      break;
  }

  return includeExclusionAdded ? `${footer} ${EXCLUSION_BLURB}` : footer;
}

function formatUtcTimeOrNA(rawValue: string): string {
  if (!safeTrim(rawValue)) {
    return "N/A";
  }

  const parsed = parseFlexibleDate(rawValue);
  if (Number.isNaN(parsed.getTime())) {
    return "N/A";
  }

  return new Intl.DateTimeFormat("en-US", {
    timeZone: "UTC",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false
  }).format(parsed) + " UTC";
}

function formatEndpointEstTimeOrNA(rawValue: string): string {
  if (!safeTrim(rawValue)) {
    return "N/A";
  }

  const parsed = parseFlexibleDate(rawValue);
  if (Number.isNaN(parsed.getTime())) {
    return rawValue;
  }

  return new Intl.DateTimeFormat("en-US", {
    timeZone: "America/New_York",
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true
  }).format(parsed);
}

function calculateTapDuration(startRaw: string, endRaw: string): string {
  const start = parseFlexibleDate(startRaw);
  const end = parseFlexibleDate(endRaw);

  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) {
    return "N/A";
  }

  const milliseconds = end.getTime() - start.getTime();
  if (milliseconds <= 0) {
    return "N/A";
  }

  const minutes = Math.floor(milliseconds / 60000);
  if (minutes >= 60) {
    return `${Math.floor(minutes / 60)} Hours`;
  }

  if (minutes >= 1) {
    return `${minutes} Minutes`;
  }

  return `${Math.floor(milliseconds / 1000)} Seconds`;
}

function buildLocationDisplay(city: string, regionCode: string, country: string): string {
  const cleanCity = cleanLocationPart(city);
  const cleanRegion = cleanLocationPart(regionCode);
  const cleanCountry = cleanLocationPart(country);
  const isUsa = ["united states", "usa", "us"].includes(cleanCountry.toLowerCase());

  if (isUsa) {
    if (cleanCity && cleanRegion) {
      return `${cleanCity}, ${cleanRegion}`;
    }

    if (cleanRegion) {
      return cleanRegion;
    }

    if (cleanCountry) {
      return cleanCountry;
    }
  } else {
    if (cleanCity && cleanCountry) {
      return `${cleanCity}, ${cleanCountry}`;
    }

    if (cleanCountry) {
      return cleanCountry;
    }
  }

  return "N/A";
}

function cleanLocationPart(value: string): string {
  const trimmed = safeTrim(value);
  if (!trimmed || trimmed === "Unknown" || trimmed === "Unavailable") {
    return "";
  }

  return trimmed;
}

function normalizeCertificate(value: string): string {
  if (!safeTrim(value)) {
    return "";
  }

  const match = value.match(/(?:CN|cn)=([^,]+)/);
  return match?.[1]?.trim() ?? safeTrim(value);
}

function buildSignatureNameFromEmail(email: string): string {
  const localPart = safeTrim(email).toLowerCase().split("@")[0] ?? "";
  const words = localPart
    .split(/[._-]+/)
    .map((word) => word.trim())
    .filter(Boolean);

  if (words.length === 0) {
    return "ThreatLocker MDR";
  }

  return words
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

function buildPlainTextSignature(signerName: string): string {
  return [
    signerName,
    "ThreatLocker MDR",
    "Managed Detection & Response",
    "soc@yourdomain.com",
    "www.threatlocker.com"
  ].join("\n");
}

function escapeHtmlWithBreaks(value: string): string {
  return value
    .split(/\r?\n/)
    .map((line) => escapeHtml(line))
    .join("<br>");
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function extractNamedField(text: string, fieldName: string): string {
  const escaped = escapeRegex(fieldName);
  const match = text.match(new RegExp(`${escaped}\\s*:\\s*(.+)`, "i"));
  return match?.[1]?.trim() ?? "";
}

function stripSentinelPrefixes(value: string): string {
  return (value ?? "").replace(/^(?:file|containerfile):_+/i, "").trim();
}

function extractFirstIp(text: string): string {
  const matches = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g);
  if (!matches) {
    return "";
  }

  return matches.find((match) => match !== "0.0.0.0" && match !== "127.0.0.1") ?? "";
}

function splitOnFirst(value: string, separator: string): [string, string] {
  if (!value.includes(separator)) {
    return [safeTrim(value), ""];
  }

  const index = value.indexOf(separator);
  return [safeTrim(value.slice(0, index)), safeTrim(value.slice(index + separator.length))];
}

function safe(...values: string[]): string {
  return values.find((value) => safeTrim(value)) ?? "";
}

function valueOrNA(value: string | null | undefined): string {
  const trimmed = safeTrim(value);
  return trimmed ? trimmed : "N/A";
}

function firstNonEmpty(...values: Array<string | null | undefined>): string {
  return values.find((value) => safeTrim(value)) ?? "";
}

function defangIfIpLike(value: string | null | undefined): string {
  const trimmed = safeTrim(value);
  if (!trimmed) {
    return "N/A";
  }

  return trimmed.includes(".") || trimmed.includes(":")
    ? trimmed.replaceAll(".", "[.]").replaceAll(":", "[:]")
    : trimmed;
}

function formatDate(date: Date): string {
  return new Intl.DateTimeFormat("en-US", {
    month: "long",
    day: "numeric",
    year: "numeric"
  }).format(date);
}

function formatTime(date: Date): string {
  return new Intl.DateTimeFormat("en-US", {
    hour: "numeric",
    minute: "2-digit",
    hour12: true
  }).format(date);
}

function getIndefiniteArticle(phrase: string): string {
  const lowered = safeTrim(phrase).toLowerCase();
  if (!lowered) {
    return "a";
  }

  if (["honest", "honor", "hour", "heir"].some((prefix) => lowered.startsWith(prefix))) {
    return "an";
  }

  if (["uni", "use", "user", "euro", "one", "once"].some((prefix) => lowered.startsWith(prefix))) {
    return "a";
  }

  return "aeiou".includes(lowered[0] ?? "") ? "an" : "a";
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function safeTrim(value: string | null | undefined): string {
  return typeof value === "string" ? value.trim() : "";
}

function parseFlexibleDate(rawValue: string): Date {
  const trimmed = safeTrim(rawValue);
  if (!trimmed) {
    return new Date(Number.NaN);
  }

  if (/^\d{10}$/.test(trimmed)) {
    return new Date(Number(trimmed) * 1000);
  }

  if (/^\d{13}$/.test(trimmed)) {
    return new Date(Number(trimmed));
  }

  const direct = new Date(trimmed);
  if (!Number.isNaN(direct.getTime())) {
    return direct;
  }

  const normalized = trimmed
    .replace(/\bUTC\b/i, "Z")
    .replace(/\s+/g, " ")
    .replace(/^(\d{1,2})\/(\d{1,2})\/(\d{4}),?\s+/, "$3-$1-$2 ");

  return new Date(normalized);
}

export function toDisplayText(action: ResponseAction): string {
  switch (action) {
    case "ClearingAlert":
      return "Clearing Alert";
    case "Escalating":
      return "Escalating";
    case "Isolating":
      return "Isolating";
    case "Lockdown":
      return "Lockdown";
    case "LockAccount":
      return "Lock Account";
    case "LockAccountAndRevokeSession":
      return "Lock Account and Revoke Session";
  }
}

export function isEndpointAlert(alertType: AlertType): boolean {
  return [
    "DefenderDetection",
    "DefenderExclusionCreated",
    "SentinelOneDetection",
    "PowershellPolicyBypass",
    "BitlockerDisable",
    "RegExport",
    "Enumeration",
    "Ransomware",
    "NetStopThreatLocker",
    "TlUninstallScriptExecution",
    "DisableProtection",
    "UserAddedToLocalAdmin",
    "PublicRDPConnection",
    "ClearedSecurityLogs",
    "VulnerableDriver",
    "CreationOfXAdminAccount"
  ].includes(alertType);
}
