"use client";

import { useState } from "react";
import {
  DEFAULT_SPECIFIC_DISABLEMENT,
  type AlertOption,
  type AppTab,
  type GenerationOutput,
  type SpecificDisablement,
  cloudAlertOptions,
  defenderActionOptions,
  endpointAlertOptions,
  getDefaultDefenderAction,
  getDefaultResponseAction,
  getDefaultSentinelAction,
  responseActionOptions,
  sentinelActionOptions,
  specificDisablementOptions
} from "@/lib/email-alert-generator";

type Props = {
  userEmail: string;
};

type GenerationState = GenerationOutput | null;

export function EmailAlertGeneratorApp({ userEmail }: Props) {
  const [tab, setTab] = useState<AppTab>("cloud");
  const [selectedAlert, setSelectedAlert] = useState<AlertOption>(cloudAlertOptions[0]);
  const [responseAction, setResponseAction] = useState(getDefaultResponseAction());
  const [logText, setLogText] = useState("");
  const [organization, setOrganization] = useState("");
  const [hostname, setHostname] = useState("");
  const [includeRunbookBlurb, setIncludeRunbookBlurb] = useState(false);
  const [includeExclusionAdded, setIncludeExclusionAdded] = useState(false);
  const [includeEscalation, setIncludeEscalation] = useState(false);
  const [isSecureMode, setIsSecureMode] = useState(false);
  const [isLearningMonitorMode, setIsLearningMonitorMode] = useState(false);
  const [defenderAction, setDefenderAction] = useState(getDefaultDefenderAction());
  const [sentinelOneAction, setSentinelOneAction] = useState(getDefaultSentinelAction());
  const [specificDisablement, setSpecificDisablement] =
    useState<SpecificDisablement>(DEFAULT_SPECIFIC_DISABLEMENT);
  const [statusMessage, setStatusMessage] = useState("Ready.");
  const [generation, setGeneration] = useState<GenerationState>(null);

  const alertOptions = tab === "cloud" ? cloudAlertOptions : endpointAlertOptions;
  const visibleResponseActions = responseActionOptions.filter(
    (option) => tab === "endpoint" || !option.endpointOnly
  );
  const isDefenderDetection = selectedAlert.alertType === "DefenderDetection";
  const isSentinelOneDetection = selectedAlert.alertType === "SentinelOneDetection";
  const isDisableProtection = selectedAlert.alertType === "DisableProtection";

  function handleTabChange(nextTab: AppTab) {
    const nextAlerts = nextTab === "cloud" ? cloudAlertOptions : endpointAlertOptions;
    setTab(nextTab);
    setSelectedAlert(nextAlerts[0]);
    setResponseAction(getDefaultResponseAction());
    setStatusMessage("Workflow switched.");
    setGeneration(null);
  }

  async function handleGenerate() {
    if (!logText.trim()) {
      setStatusMessage("Paste the event log before generating.");
      return;
    }

    if (!organization.trim()) {
      setStatusMessage("Organization is required.");
      return;
    }

    setStatusMessage("Generating email...");

    const response = await fetch("/api/generate-email", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        tab,
        alertType: selectedAlert.alertType,
        alertDisplayName: selectedAlert.displayName,
        templateFileName: selectedAlert.templateFileName,
        responseAction,
        logText,
        organization,
        hostname,
        includeRunbookBlurb,
        includeExclusionAdded,
        includeEscalation,
        isSecureMode,
        isLearningMonitorMode,
        defenderAction,
        sentinelOneAction,
        specificDisablement
      })
    });

    const payload = (await response.json()) as GenerationOutput & { error?: string };
    if (!response.ok) {
      setStatusMessage(payload.error ?? "Unable to generate email.");
      return;
    }

    setGeneration(payload);
    setStatusMessage(payload.statusMessage);
    setLogText("");
    setHostname("");
  }

  function handleClear() {
    setLogText("");
    setHostname("");
    setGeneration(null);
    setStatusMessage("Cleared.");
  }

  async function copyText(value: string, successMessage: string) {
    if (!value.trim()) {
      return;
    }

    await navigator.clipboard.writeText(value);
    setStatusMessage(successMessage);
  }

  async function copyEmailHtml(html: string, text: string, successMessage: string) {
    if (!html.trim() || !text.trim()) {
      return;
    }

    if (typeof ClipboardItem !== "undefined" && navigator.clipboard.write) {
      const item = new ClipboardItem({
        "text/html": new Blob([html], { type: "text/html" }),
        "text/plain": new Blob([text], { type: "text/plain" })
      });

      await navigator.clipboard.write([item]);
      setStatusMessage(successMessage);
      return;
    }

    await navigator.clipboard.writeText(text);
    setStatusMessage(`${successMessage} Plain text fallback used.`);
  }

  return (
    <main className="generator-shell">
      <div className="generator-topbar">
        <div>
          <span className="hero-kicker">Authenticated Workspace</span>
          <h1 className="generator-title">Email Alert Generator</h1>
          <p className="generator-subtitle">
            Web remake of the desktop workflow using the original template set and Supabase-backed
            access controls.
          </p>
        </div>
        <div className="workspace-badge">
          <span>Signed in as</span>
          <strong>{userEmail}</strong>
        </div>
      </div>

      <div className="generator-layout">
        <section className="workspace-panel workspace-input">
          <div className="tab-row">
            <button
              className={`tab-chip ${tab === "cloud" ? "is-active" : ""}`}
              type="button"
              onClick={() => handleTabChange("cloud")}
            >
              Cloud
            </button>
            <button
              className={`tab-chip ${tab === "endpoint" ? "is-active" : ""}`}
              type="button"
              onClick={() => handleTabChange("endpoint")}
            >
              Endpoint
            </button>
          </div>

          <div className="form-stack">
            <div className="field">
              <label htmlFor="alert-type">Alert Type</label>
              <select
                id="alert-type"
                className="select-field"
                value={selectedAlert.templateFileName}
                onChange={(event) => {
                  const nextAlert = alertOptions.find(
                    (option) => option.templateFileName === event.target.value
                  );

                  if (nextAlert) {
                    setSelectedAlert(nextAlert);
                    setGeneration(null);
                  }
                }}
              >
                {alertOptions.map((option) => (
                  <option key={option.templateFileName} value={option.templateFileName}>
                    {option.displayName}
                  </option>
                ))}
              </select>
            </div>

            <div className="field">
              <label>Response Action</label>
              <div className="radio-grid">
                {visibleResponseActions.map((option) => (
                  <label className="choice-card" key={option.value}>
                    <input
                      checked={responseAction === option.value}
                      name="response-action"
                      type="radio"
                      onChange={() => setResponseAction(option.value)}
                    />
                    <span>{option.label}</span>
                  </label>
                ))}
              </div>
            </div>

            {isDefenderDetection ? (
              <div className="field">
                <label htmlFor="defender-action">Defender Action</label>
                <select
                  id="defender-action"
                  className="select-field"
                  value={defenderAction}
                  onChange={(event) => setDefenderAction(event.target.value)}
                >
                  {defenderActionOptions.map((option) => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ))}
                </select>
              </div>
            ) : null}

            {isSentinelOneDetection ? (
              <div className="field">
                <label htmlFor="sentinel-action">SentinelOne Action</label>
                <select
                  id="sentinel-action"
                  className="select-field"
                  value={sentinelOneAction}
                  onChange={(event) => setSentinelOneAction(event.target.value)}
                >
                  {sentinelActionOptions.map((option) => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ))}
                </select>
              </div>
            ) : null}

            {isDisableProtection ? (
              <div className="field">
                <label htmlFor="disablement">Specific Disablement</label>
                <select
                  id="disablement"
                  className="select-field"
                  value={specificDisablement}
                  onChange={(event) =>
                    setSpecificDisablement(event.target.value as SpecificDisablement)
                  }
                >
                  {specificDisablementOptions.map((option) => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ))}
                </select>
              </div>
            ) : null}

            <div className="toggle-row">
              <label className="toggle-card">
                <input
                  checked={isSecureMode}
                  type="checkbox"
                  onChange={(event) => setIsSecureMode(event.target.checked)}
                />
                <span>Secure Mode</span>
              </label>
              <label className="toggle-card">
                <input
                  checked={isLearningMonitorMode}
                  type="checkbox"
                  onChange={(event) => setIsLearningMonitorMode(event.target.checked)}
                />
                <span>Learning/Monitor Mode</span>
              </label>
            </div>

            <div className={tab === "cloud" ? "field" : "double-field"}>
              <div className="field">
                <label htmlFor="organization">Organization</label>
                <input
                  id="organization"
                  placeholder="Organization Name"
                  value={organization}
                  onChange={(event) => setOrganization(event.target.value)}
                />
              </div>
              {tab === "endpoint" ? (
                <div className="field">
                  <label htmlFor="hostname">Hostname</label>
                  <input
                    id="hostname"
                    placeholder="Hostname"
                    value={hostname}
                    onChange={(event) => setHostname(event.target.value)}
                  />
                </div>
              ) : null}
            </div>

            <div className="toggle-row">
              <label className="toggle-card">
                <input
                  checked={includeRunbookBlurb}
                  type="checkbox"
                  onChange={(event) => setIncludeRunbookBlurb(event.target.checked)}
                />
                <span>Include Runbook Update Blurb</span>
              </label>
              <label className="toggle-card">
                <input
                  checked={includeExclusionAdded}
                  type="checkbox"
                  onChange={(event) => setIncludeExclusionAdded(event.target.checked)}
                />
                <span>Exclusion Added</span>
              </label>
              <label className="toggle-card">
                <input
                  checked={includeEscalation}
                  type="checkbox"
                  onChange={(event) => setIncludeEscalation(event.target.checked)}
                />
                <span>Include Escalation Note</span>
              </label>
            </div>

            <div className="field">
              <label htmlFor="log-text">Paste Event Log</label>
              <textarea
                id="log-text"
                className="text-area"
                placeholder="Paste Event Log Content Here..."
                value={logText}
                onChange={(event) => setLogText(event.target.value)}
              />
            </div>

            <div className="button-row">
              <button className="button" type="button" onClick={handleGenerate}>
                Generate
              </button>
              <button className="button-ghost" type="button" onClick={handleClear}>
                Clear
              </button>
            </div>

            <div className="status">{statusMessage}</div>
          </div>
        </section>

        <section className="workspace-panel workspace-output">
          <div className="output-card subject-card">
            <div className="panel-heading">
              <div>
                <h2>Email Subject</h2>
              </div>
              <button
                className="button-ghost"
                type="button"
                onClick={() =>
                  copyText(generation?.subject ?? "", "Generated subject copied to clipboard.")
                }
              >
                Copy
              </button>
            </div>
            <div className="readout">{generation?.subject ?? "No subject generated yet."}</div>
          </div>

          <div className="output-card email-card">
            <div className="panel-heading">
              <div>
                <h2>Generated HTML Email</h2>
              </div>
              <button
                className="button-ghost"
                type="button"
                onClick={() =>
                  copyEmailHtml(
                    generation?.bodyHtml ?? "",
                    generation?.body ?? "",
                    "Generated HTML email copied to clipboard."
                  )
                }
              >
                Copy HTML
              </button>
            </div>
            <div
              className="email-preview"
              dangerouslySetInnerHTML={{
                __html:
                  generation?.bodyHtml ??
                  '<div style="margin:0; line-height:1.5; color:#000000;"><strong>No preview available.</strong></div>'
              }}
            />
          </div>

          <div className="output-card reasoning-card">
            <div className="panel-heading">
              <div>
                <h2>Clear Reasoning Starter</h2>
              </div>
              <button
                className="button-ghost"
                type="button"
                onClick={() =>
                  copyText(
                    generation?.clearReasoningStarter ?? "",
                    "Clear reasoning starter copied to clipboard."
                  )
                }
              >
                Copy
              </button>
            </div>
            <div className="readout">
              {generation?.clearReasoningStarter ?? "No clear reasoning starter generated yet."}
            </div>
          </div>
        </section>
      </div>
    </main>
  );
}
