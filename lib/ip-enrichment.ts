import {
  resolveSpecificDisablementTemplate,
  type AlertType,
  type GeneratorInput,
  type IpEnrichmentResult,
  type SpecificDisablement
} from "@/lib/email-alert-generator";
import type { UserApiKeys } from "@/lib/user-instance";

type TemplateNeeds = {
  abuseIpDb: boolean;
  virusTotal: boolean;
  proxyCheck: boolean;
};

type ProxyCheckResponse = Record<string, unknown> & {
  status?: string;
};

export function getTemplateNeeds(template: string): TemplateNeeds {
  const normalized = template.toLowerCase();

  return {
    abuseIpDb:
      normalized.includes("{{ip1abusescore}}") ||
      normalized.includes("{{ip1abusereports}}") ||
      normalized.includes("{{ip1abusesummary}}") ||
      normalized.includes("{{ip2abusescore}}") ||
      normalized.includes("{{ip2abusereports}}") ||
      normalized.includes("{{ip2abusesummary}}"),
    virusTotal:
      normalized.includes("{{ip1virustotalmalicious}}") ||
      normalized.includes("{{ip1virustotalsuspicious}}") ||
      normalized.includes("{{ip1virustotalverdict}}") ||
      normalized.includes("{{ip1virustotalattackhistory}}") ||
      normalized.includes("{{vtattackhistory}}") ||
      normalized.includes("{{ip2virustotalmalicious}}") ||
      normalized.includes("{{ip2virustotalsuspicious}}") ||
      normalized.includes("{{ip2virustotalverdict}}") ||
      normalized.includes("{{ip2virustotalattackhistory}}"),
    proxyCheck:
      normalized.includes("{{ip1location}}") ||
      normalized.includes("{{ip1country}}") ||
      normalized.includes("{{ip1region}}") ||
      normalized.includes("{{ip1city}}") ||
      normalized.includes("{{ip1isp}}") ||
      normalized.includes("{{ip1proxycheckvpnstatus}}") ||
      normalized.includes("{{proxycheckvpnstatus}}") ||
      normalized.includes("{{ip2location}}") ||
      normalized.includes("{{ip2country}}") ||
      normalized.includes("{{ip2region}}") ||
      normalized.includes("{{ip2city}}") ||
      normalized.includes("{{ip2isp}}") ||
      normalized.includes("{{ip2proxycheckvpnstatus}}")
  };
}

export function resolveActiveTemplateName(
  alertType: AlertType,
  templateFileName: string,
  specificDisablement: SpecificDisablement
): string {
  return alertType === "DisableProtection"
    ? resolveSpecificDisablementTemplate(specificDisablement)
    : templateFileName;
}

export async function buildEnrichmentOverrides(
  input: Pick<
    GeneratorInput,
    "alertType" | "templateFileName" | "specificDisablement" | "logText"
  >,
  template: string,
  apiKeys: UserApiKeys
): Promise<{
  ip1EnrichmentOverride?: Partial<IpEnrichmentResult>;
  ip2EnrichmentOverride?: Partial<IpEnrichmentResult>;
}> {
  const needs = getTemplateNeeds(template);
  if (!needs.abuseIpDb && !needs.virusTotal && !needs.proxyCheck) {
    return {};
  }

  const { parseAlertLog } = await import("@/lib/email-alert-generator");
  const parsedLog = parseAlertLog(input.logText);

  const ip1 =
    input.alertType === "ImpossibleTravel"
      ? safeTrim(parsedLog.firstLoginIp)
      : safeTrim(parsedLog.ipAddress);
  const ip2 = input.alertType === "ImpossibleTravel" ? safeTrim(parsedLog.secondLoginIp) : "";

  const [ip1EnrichmentOverride, ip2EnrichmentOverride] = await Promise.all([
    enrichIp(ip1, needs, apiKeys),
    enrichIp(ip2, needs, apiKeys)
  ]);

  return { ip1EnrichmentOverride, ip2EnrichmentOverride };
}

async function enrichIp(
  ipAddress: string,
  needs: TemplateNeeds,
  apiKeys: UserApiKeys
): Promise<Partial<IpEnrichmentResult> | undefined> {
  if (!ipAddress) {
    return undefined;
  }

  const result: Partial<IpEnrichmentResult> = {};

  const tasks: Promise<void>[] = [];

  if (needs.proxyCheck && apiKeys.proxyCheck) {
    tasks.push(
      fetchProxyCheck(ipAddress, apiKeys.proxyCheck).then((proxyData) => {
        if (!proxyData) {
          return;
        }

        result.country = proxyData.country || result.country;
        result.region = proxyData.region || result.region;
        result.regionCode = proxyData.regionCode || result.regionCode;
        result.city = proxyData.city || result.city;
        result.isp = proxyData.provider || result.isp;
        result.proxyCheckVpnStatus = proxyData.vpnStatus || result.proxyCheckVpnStatus;
        result.virusTotalAttackHistory = result.virusTotalAttackHistory || proxyData.attackHistory;
      })
    );
  }

  tasks.push(
    fetchIpInfo(ipAddress).then((ipInfoData) => {
      if (!ipInfoData) {
        return;
      }

      result.country = chooseBetterLocationValue(result.country, ipInfoData.country);
      result.region = chooseBetterLocationValue(result.region, ipInfoData.region);
      result.regionCode = chooseBetterLocationValue(result.regionCode, ipInfoData.region);
      result.city = chooseBetterLocationValue(result.city, ipInfoData.city);
      result.isp = chooseBetterProviderValue(result.isp, ipInfoData.org);
    })
  );

  if (needs.abuseIpDb && apiKeys.abuseIpDb) {
    tasks.push(
      fetchAbuseIpDb(ipAddress, apiKeys.abuseIpDb).then((abuseData) => {
        if (!abuseData) {
          return;
        }

        result.abuseConfidenceScore = abuseData.abuseConfidenceScore;
        result.totalReports = abuseData.totalReports;
        result.abuseSummary = abuseData.summary;
      })
    );
  }

  if (needs.virusTotal && apiKeys.virusTotal) {
    tasks.push(
      fetchVirusTotal(ipAddress, apiKeys.virusTotal).then((virusTotalData) => {
        if (!virusTotalData) {
          return;
        }

        result.maliciousCount = virusTotalData.maliciousCount;
        result.suspiciousCount = virusTotalData.suspiciousCount;
        result.virusTotalVerdict = virusTotalData.verdict;
        result.virusTotalAttackHistory = virusTotalData.attackHistory;
      })
    );
  }

  await Promise.all(tasks);
  return result;
}

async function fetchAbuseIpDb(ipAddress: string, apiKey: string) {
  const response = await fetch(
    `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ipAddress)}&maxAgeInDays=90`,
    {
      headers: {
        Key: apiKey,
        Accept: "application/json"
      },
      cache: "no-store"
    }
  );

  if (!response.ok) {
    return undefined;
  }

  const payload = (await response.json()) as {
    data?: {
      abuseConfidenceScore?: number;
      totalReports?: number;
    };
  };

  const score = payload.data?.abuseConfidenceScore;
  const reports = payload.data?.totalReports;

  return {
    abuseConfidenceScore: score?.toString() ?? "N/A",
    totalReports: reports?.toString() ?? "N/A",
    summary: `Abuse Confidence: ${score ?? "N/A"}, Reports: ${reports ?? "N/A"}`
  };
}

async function fetchVirusTotal(ipAddress: string, apiKey: string) {
  const response = await fetch(
    `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ipAddress)}`,
    {
      headers: {
        "x-apikey": apiKey
      },
      cache: "no-store"
    }
  );

  if (!response.ok) {
    return undefined;
  }

  const payload = (await response.json()) as {
    data?: {
      attributes?: {
        reputation?: number;
        last_analysis_stats?: {
          malicious?: number;
          suspicious?: number;
        };
      };
    };
  };

  const stats = payload.data?.attributes?.last_analysis_stats;
  const maliciousCount = stats?.malicious ?? 0;
  const suspiciousCount = stats?.suspicious ?? 0;
  const reputation = payload.data?.attributes?.reputation;

  return {
    maliciousCount: maliciousCount.toString(),
    suspiciousCount: suspiciousCount.toString(),
    verdict: `Malicious: ${maliciousCount}, Suspicious: ${suspiciousCount}`,
    attackHistory: reputation == null ? "Unavailable" : `Reputation: ${reputation}`
  };
}

async function fetchProxyCheck(ipAddress: string, apiKey: string) {
  const response = await fetch(
    `https://proxycheck.io/v2/${encodeURIComponent(ipAddress)}?key=${encodeURIComponent(apiKey)}&vpn=3&asn=1&risk=1`,
    {
      cache: "no-store"
    }
  );

  if (!response.ok) {
    return undefined;
  }

  const payload = (await response.json()) as ProxyCheckResponse;
  const ipData = payload[ipAddress] as Record<string, unknown> | undefined;

  if (!ipData) {
    return undefined;
  }

  const proxy = toString(ipData.proxy).toLowerCase() === "yes";
  const vpn = toString(ipData.vpn).toLowerCase() === "yes";
  const type = toString(ipData.type);
  const risk = toString(ipData.risk);
  const attackHistory = toString(ipData.attack_history);
  const provider = normalizeProviderName(
    toString(ipData.provider) || toString(ipData.isp) || toString(ipData.organisation)
  );

  return {
    country: toString(ipData.country),
    region: toString(ipData.region),
    regionCode: toString(ipData.regioncode) || toString(ipData.region),
    city: toString(ipData.city),
    provider,
    vpnStatus: proxy || vpn
      ? type
        ? `Proxy/VPN detected (${type})`
        : proxy && vpn
          ? "Proxy and VPN detected"
          : proxy
            ? "Proxy detected"
            : "VPN detected"
      : "No proxy/VPN detected",
    attackHistory: attackHistory
      ? `Proxycheck risk: ${risk || "N/A"}, Attack history: ${attackHistory}`
      : risk
        ? `Proxycheck risk: ${risk}`
        : "Unavailable"
  };
}

function toString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function safeTrim(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

async function fetchIpInfo(ipAddress: string) {
  const response = await fetch(`https://ipinfo.io/${encodeURIComponent(ipAddress)}/json`, {
    headers: {
      Accept: "application/json"
    },
    cache: "no-store"
  });

  if (!response.ok) {
    return undefined;
  }

  const payload = (await response.json()) as {
    city?: string;
    region?: string;
    country?: string;
    org?: string;
  };

  return {
    city: safeTrim(payload.city),
    region: safeTrim(payload.region),
    country: safeTrim(payload.country),
    org: normalizeProviderName(safeTrim(payload.org))
  };
}

function chooseBetterLocationValue(current: string | undefined, fallback: string | undefined): string | undefined {
  if (!fallback) {
    return current;
  }

  if (!current || isUnavailableValue(current)) {
    return fallback;
  }

  return current;
}

function chooseBetterProviderValue(current: string | undefined, fallback: string | undefined): string | undefined {
  if (!fallback) {
    return current;
  }

  if (!current || isUnavailableValue(current) || current === "Unavailable in web-only mode") {
    return fallback;
  }

  return current;
}

function normalizeProviderName(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) {
    return "";
  }

  return trimmed.replace(/^AS\d+\s+/i, "");
}

function isUnavailableValue(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  return !normalized || normalized === "unknown" || normalized === "unavailable" || normalized === "n/a";
}
