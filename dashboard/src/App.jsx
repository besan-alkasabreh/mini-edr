import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import {
  clearAuthSession,
  createLiveSocket,
  createResponseAction,
  decodeCommand,
  exportPdfReport,
  exportTelemetryCsv,
  getAgents,
  getAuthToken,
  getAuthUser,
  getIncidentTimeline,
  getLiveEvents,
  getResponseActions,
  getStats,
  getTelemetry,
  loginDashboard,
  updateIncidentStatus,
} from "./api";
import "./index.css";

function safeArray(arr) {
  return Array.isArray(arr) ? arr : [];
}

function deduplicateById(arr, key = "id") {
  const map = new Map();

  safeArray(arr).forEach((item, index) => {
    if (!item) return;

    const resolvedKey =
      item[key] ??
      `${item.timestamp || "no-time"}-${item.event_title || "no-title"}-${index}`;

    map.set(resolvedKey, item);
  });

  return Array.from(map.values());
}

function formatValue(value) {
  if (value === null || value === undefined || value === "") return "-";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

const DISPLAY_TIME_ZONE = "Asia/Amman";

function hasExplicitTimezone(value) {
  return /(?:Z|[+-]\d{2}:?\d{2})$/i.test(String(value).trim());
}

function normalizeDateInput(value) {
  if (!value) return null;
  if (value instanceof Date) return value;

  if (typeof value === "number") {
    return new Date(value);
  }

  const raw = String(value).trim();
  if (!raw) return null;


  const isoLike = raw.includes("T") ? raw : raw.replace(" ", "T");
  const normalized = hasExplicitTimezone(isoLike) ? isoLike : `${isoLike}Z`;
  return new Date(normalized);
}

function parseDateValue(value) {
  const date = normalizeDateInput(value);
  return date && !Number.isNaN(date.getTime()) ? date : null;
}

function formatDateTime(value) {
  const date = parseDateValue(value);
  if (!date) return "-";

  return new Intl.DateTimeFormat("en-GB", {
    timeZone: DISPLAY_TIME_ZONE,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date);
}

function fastSortByNewest(items, key) {
  return [...safeArray(items)].sort(
    (a, b) =>
      (parseDateValue(b?.[key])?.getTime() ?? 0) -
      (parseDateValue(a?.[key])?.getTime() ?? 0)
  );
}

function getRuleScore(item) {
  return Number(item?.rule_score ?? 0);
}

function getAiScore(item) {
  return Number(item?.ai_score ?? 0);
}

function getRiskNumber(item) {
  const rawRisk = item?.risk_score ?? item?.final_risk_score;
  if (typeof rawRisk === "string") {
    const parsed = Number.parseFloat(rawRisk);
    return Number.isFinite(parsed) ? parsed : 0;
  }

  const risk = Number(rawRisk);
  if (Number.isFinite(risk)) return risk;

  const ruleScore = getRuleScore(item);
  const aiScore = getAiScore(item);

  if (ruleScore > 0 && aiScore > 0) {
    return Math.min(Math.round((ruleScore + aiScore) / 2), 100);
  }

  return Number.isFinite(ruleScore) ? ruleScore : 0;
}

function severityFromRiskScore(score) {
  const value = Number(score);
  const riskScore = Number.isFinite(value) ? value : 0;
  if (riskScore <= 30) return "low";
  if (riskScore <= 60) return "medium";
  if (riskScore <= 80) return "high";
  return "critical";
}

function getRiskClass(score) {
  return severityFromRiskScore(score);
}

function getSeverity(item) {
  if (!item) return "low";
  return severityFromRiskScore(getRiskNumber(item));
}

function getSeverityClass(severity) {
  switch (String(severity || "").toLowerCase()) {
    case "critical":
      return "critical"; // 
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    default:
      return "low";
  }
}

function getSeverityLabel(severity) {
  const normalized = String(severity || "").toLowerCase();
  if (!normalized) return "Low";
  return normalized.charAt(0).toUpperCase() + normalized.slice(1);
}

function getAiSeverityFromScore(item) {
  return getSeverityLabel(severityFromRiskScore(getAiScore(item)));
}

function getRiskReasons(item) {
  if (!item?.risk_reasons) return [];
  if (Array.isArray(item.risk_reasons)) return item.risk_reasons;

  try {
    const parsed = JSON.parse(item.risk_reasons);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function parseMaybeJsonArray(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value;

  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);
      return Array.isArray(parsed) ? parsed : value ? [value] : [];
    } catch {
      return value ? [value] : [];
    }
  }

  return [];
}

function getDecodedCommand(item) {
  return item?.decoded_command || "";
}

function getDecodeMethod(item) {
  return item?.decode_method || "";
}

function getDecodeLayers(item) {
  return parseMaybeJsonArray(item?.decode_layers);
}

function getDecodedSuspiciousKeywords(item) {
  return parseMaybeJsonArray(item?.decoded_suspicious_keywords);
}

function getDecodedMitreTechnique(item) {
  return item?.decoded_mitre_technique || "-";
}

function getDecodedMitreTactic(item) {
  return item?.decoded_mitre_tactic || "-";
}

function getAttackIntent(item) {
  return parseMaybeJsonArray(item?.attack_intent);
}

function getAttackSummary(item) {
  return item?.attack_summary || "";
}

function getAiAttackExplanation(item) {
  const explanation = item?.ai_attack_explanation || "";
  if (!explanation) return "";

  return String(explanation).replace(
    /AI predicted severity:\s*(Low|Medium|High|Critical)/i,
    `AI predicted severity: ${getAiSeverityFromScore(item)}`
  );
}

function getAttackConfidence(item) {
  return item?.attack_confidence || "";
}

function extractAiFieldFromText(text, label) {
  const value = String(text || "");
  if (!value) return "";

  const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const regex = new RegExp(`${escaped}\\s*:?\\s*([^.;\\n]+)`, "i");
  const match = value.match(regex);
  return match?.[1]?.trim() || "";
}

function getAiConfidenceLevel(item) {
  return (
    item?.ai_confidence_level ||
    item?.confidence_level ||
    item?.ai_model_details?.confidence_level ||
    getAttackConfidence(item) ||
    extractAiFieldFromText(getAiAttackExplanation(item), "with") ||
    "Informational"
  );
}

function getAiAttackCategory(item) {
  return (
    item?.ai_attack_category ||
    item?.attack_category ||
    item?.ai_model_details?.attack_category ||
    extractAiFieldFromText(getAiAttackExplanation(item), "Predicted attack category") ||
    extractAiFieldFromText(getAttackSummary(item), "Attack category") ||
    "Benign / Informational"
  );
}

function getAiSeverityFromText(text) {
  const value = String(text || "");
  const match =
    value.match(/AI predicted severity:\s*(Low|Medium|High|Critical)/i) ||
    value.match(/classified this event as\s*(Low|Medium|High|Critical)\s*severity/i);

  return match ? getSeverityLabel(match[1]) : null;
}

function getAiSeverity(item) {
  return getAiSeverityFromScore(item);
}

function getAiModelDetails(item) {
  if (!item?.ai_model_details) return {};
  if (typeof item.ai_model_details === "object") return item.ai_model_details;

  try {
    const parsed = JSON.parse(item.ai_model_details);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function getAiModelStatusText(item) {
  const details = getAiModelDetails(item);

  if (details.severity_model_loaded === true) {
    return "Threat + Severity Models";
  }

  if (details.severity_model_loaded === false) {
    return "Threat Model Only";
  }

  if (item?.ai_score || item?.ai_attack_explanation || item?.attack_summary) {
    return "Hybrid AI";
  }

  return "Rule / Informational";
}

function getAttackChain(item) {
  return parseMaybeJsonArray(item?.attack_chain);
}

function getCorrelatedAlerts(item) {
  return parseMaybeJsonArray(item?.correlated_alerts);
}

function getRecommendedAction(item) {
  return item?.recommended_action || "";
}

function hasAdvancedAiIntelligence(item) {
  return Boolean(
    getAttackConfidence(item) ||
    getAiConfidenceLevel(item) ||
    getAiAttackCategory(item) ||
    getAiModelStatusText(item) ||
    getAttackChain(item).length ||
    getCorrelatedAlerts(item).length ||
    getRecommendedAction(item)
  );
}

function hasAttackIntelligence(item) {
  return Boolean(
    getDecodedMitreTechnique(item) !== "-" ||
    getDecodedMitreTactic(item) !== "-" ||
    getAttackIntent(item).length ||
    getAttackSummary(item) ||
    getAiAttackExplanation(item) ||
    hasAdvancedAiIntelligence(item)
  );
}


function hasDecodedAnalysis(item) {
  return Boolean(
    getDecodedCommand(item) ||
    getDecodeMethod(item) ||
    getDecodeLayers(item).length ||
    getDecodedSuspiciousKeywords(item).length ||
    hasAttackIntelligence(item)
  );
}

function getTopReason(item) {
  return item?.top_reason || "No specific reason";
}

function getAlertType(item) {
  return item?.alert_type || "General Suspicious Activity";
}

function getIncidentAlertLabel(item) {
  const alert = String(getAlertType(item) || "").trim();
  const reason = String(getTopReason(item) || "").toLowerCase();
  const category = String(getEventCategory(item) || "").toLowerCase();

  if (alert && !["informational", "general suspicious activity", "general detection"].includes(alert.toLowerCase())) {
    return alert;
  }

  if (reason.includes("memory")) return "High Memory Usage";
  if (reason.includes("cpu")) return "High CPU Usage";
  if (reason.includes("process count")) return "High Process Count";
  if (reason.includes("temp") || reason.includes("appdata")) return "Temp/AppData Execution";
  if (reason.includes("powershell")) return "PowerShell Activity";
  if (reason.includes("encoded") || reason.includes("decode")) return "Encoded Command";
  if (reason.includes("connection") || reason.includes("port")) return "Network Activity";

  if (category === "system_resource") return "System Resource Alert";
  if (category === "process_execution") return "Process Execution Alert";
  if (category === "network_connection") return "Network Connection Alert";
  if (category === "credential_access") return "Credential Access Alert";

  return alert || "General Detection";
}

function hasRealDecodedCommand(item) {
  return Boolean(
    getDecodedCommand(item) ||
    getDecodeMethod(item) ||
    getDecodeLayers(item).length ||
    getDecodedSuspiciousKeywords(item).length
  );
}


function getDisplayEventCategory(item) {
  const rawCategory = String(getEventCategory(item) || "").toLowerCase();
  const reason = String(getTopReason(item) || "").toLowerCase();
  const alert = String(getIncidentAlertLabel(item) || "").toLowerCase();

  if (rawCategory && !["general_detection", "general detection", "general"].includes(rawCategory)) {
    return prettifyCategory(rawCategory);
  }

  if (
    reason.includes("memory") ||
    reason.includes("cpu") ||
    reason.includes("process count") ||
    alert.includes("memory") ||
    alert.includes("cpu")
  ) {
    return "System Resource";
  }

  if (
    reason.includes("powershell") ||
    reason.includes("encoded") ||
    reason.includes("decode") ||
    reason.includes("temp") ||
    reason.includes("appdata") ||
    alert.includes("execution")
  ) {
    return "Execution";
  }

  if (
    reason.includes("connection") ||
    reason.includes("port") ||
    alert.includes("network")
  ) {
    return "Network Activity";
  }

  if (
    reason.includes("credential") ||
    reason.includes("lsass") ||
    reason.includes("mimikatz")
  ) {
    return "Credential Access";
  }

  return "General Detection";
}

function getCompactReason(item) {
  const reason = String(getTopReason(item) || "").trim();
  if (!reason || reason === "No specific reason") return "No specific reason";

  const memoryMatch = reason.match(/memory\s+usage\s*\(([^)]+)\)/i);
  if (memoryMatch) return `Memory usage ${memoryMatch[1]}`;

  const cpuMatch = reason.match(/cpu\s+usage\s*\(([^)]+)\)/i);
  if (cpuMatch) return `CPU usage ${cpuMatch[1]}`;

  const processMatch = reason.match(/process\s+count\s*\(([^)]+)\)/i);
  if (processMatch) return `Process count ${processMatch[1]}`;

  if (reason.toLowerCase().includes("temp") || reason.toLowerCase().includes("appdata")) {
    return "Execution from Temp/AppData path";
  }

  if (reason.toLowerCase().includes("powershell")) {
    return "PowerShell activity detected";
  }

  if (reason.toLowerCase().includes("encoded") || reason.toLowerCase().includes("decode")) {
    return "Encoded command indicator";
  }

  if (reason.toLowerCase().includes("connection") || reason.toLowerCase().includes("port")) {
    return "Network activity requires review";
  }

  return shorten(reason, 48);
}

function getMitreTechnique(item) {
  return item?.mitre_technique || "-";
}

function getMitreTactic(item) {
  return item?.mitre_tactic || "-";
}

function getDetectionSource(item) {
  return item?.detection_source || "Unknown";
}

function getEventCategory(item) {
  return item?.event_category || "general_detection";
}

function getIncidentStatus(item) {
  return item?.incident_status || "New";
}

function getIncidentStatusClass(status) {
  switch (status) {
    case "New":
      return "status-new";
    case "Investigating":
      return "status-investigating";
    case "Resolved":
      return "status-resolved";
    case "False Positive":
      return "status-false-positive";
    default:
      return "status-new";
  }
}

function getHostStatusClass(status) {
  switch (status) {
    case "Critical":
      return "critical";
    case "Warning":
      return "warning";
    case "Healthy":
      return "healthy";
    default:
      return "unknown";
  }
}

function getLiveSeverityClass(severity) {
  switch (String(severity || "").toLowerCase()) {
    case "critical":
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    default:
      return "medium";
  }
}

function prettifyCategory(value) {
  const text = String(value || "").replaceAll("_", " ").trim();
  if (!text) return "-";
  return text
    .split(" ")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function shorten(value, max = 60) {
  const text = formatValue(value);
  if (text.length <= max) return text;
  return `${text.slice(0, max)}...`;
}

function chartTooltipStyle() {
  return {
    contentStyle: {
      backgroundColor: "#0f1b2d",
      border: "1px solid #223454",
      borderRadius: "12px",
      color: "#eaf2ff",
    },
  };
}


const SUSPICIOUS_NETWORK_PORTS = new Set([1337, 4444, 5555, 8080, 8081, 8443, 9001, 9999]);

function extractConnectionIp(value) {
  if (!value) return "";
  const text = String(value).trim();
  if (!text || text === "-") return "";

  if (text.startsWith("[") && text.includes("]")) {
    return text.slice(1, text.indexOf("]"));
  }

  const parts = text.split(":");
  if (parts.length === 2 && /^\d+$/.test(parts[1])) {
    return parts[0];
  }

  return text;
}

function isLoopbackIp(value) {
  const ip = extractConnectionIp(value).toLowerCase();
  return (
    ip === "localhost" ||
    ip === "::1" ||
    ip.startsWith("127.")
  );
}

function isPrivateOrLocalIp(value) {
  const ip = extractConnectionIp(value).toLowerCase();

  if (!ip) return true;
  if (isLoopbackIp(ip)) return true;
  if (ip.startsWith("10.")) return true;
  if (ip.startsWith("192.168.")) return true;
  if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(ip)) return true;
  if (ip.startsWith("169.254.")) return true;
  if (ip.startsWith("fe80:")) return true;

  return false;
}

function getConnectionPort(conn) {
  const directPort = conn?.remote_port ?? conn?.destination_port;
  if (directPort !== null && directPort !== undefined && directPort !== "") {
    const numberPort = Number(directPort);
    return Number.isNaN(numberPort) ? directPort : numberPort;
  }

  const remote = String(conn?.remote_address || "");
  const parts = remote.split(":");
  const last = parts[parts.length - 1];
  const parsed = Number(last);
  return Number.isNaN(parsed) ? "" : parsed;
}

function classifyNetworkConnection(conn) {
  const remote = conn?.remote_address || conn?.destination_ip || "";
  const status = String(conn?.status || "").toUpperCase();
  const port = getConnectionPort(conn);
  const numericPort = Number(port);
  const hasRemote = Boolean(remote && remote !== "-");
  const external = hasRemote && !isPrivateOrLocalIp(remote);
  const suspiciousPort = !Number.isNaN(numericPort) && SUSPICIOUS_NETWORK_PORTS.has(numericPort);

  if (external && suspiciousPort) {
    return {
      level: "high",
      label: "Suspicious External",
      reason: `External connection using suspicious port ${numericPort}`,
    };
  }

  if (external && status === "ESTABLISHED") {
    return {
      level: "medium",
      label: "External Active",
      reason: "Active connection to an external remote address",
    };
  }

  if (suspiciousPort) {
    return {
      level: "medium",
      label: "Suspicious Port",
      reason: `Connection references suspicious port ${numericPort}`,
    };
  }

  if (status === "LISTEN") {
    return {
      level: "low",
      label: "Listening Service",
      reason: "Local service is waiting for incoming connections",
    };
  }

  if (status === "ESTABLISHED") {
    return {
      level: "low",
      label: "Active Local",
      reason: "Active internal/local connection",
    };
  }

  if (status === "TIME_WAIT") {
    return {
      level: "low",
      label: "Recently Closed",
      reason: "Connection closed recently and is waiting for cleanup",
    };
  }

  return {
    level: "low",
    label: "Normal",
    reason: "No suspicious network indicator detected",
  };
}

function getConnectionSortWeight(conn) {
  const classification = classifyNetworkConnection(conn);
  if (classification.level === "high") return 3;
  if (classification.level === "medium") return 2;
  if (String(conn?.status || "").toUpperCase() === "ESTABLISHED") return 1;
  return 0;
}


const SUSPICIOUS_PROCESS_KEYWORDS = [
  "powershell.exe",
  "pwsh.exe",
  "cmd.exe",
  "wscript.exe",
  "cscript.exe",
  "rundll32.exe",
  "regsvr32.exe",
  "mshta.exe",
  "wmic.exe",
  "psexec.exe",
  "certutil.exe",
  "mimikatz.exe",
];

function classifyRiskReason(reason) {
  const text = String(reason || "").toLowerCase();

  if (
    text.includes("critical command shell") ||
    text.includes("shadow copy") ||
    text.includes("event log clearing") ||
    text.includes("registry hive dump") ||
    text.includes("credential dump") ||
    text.includes("credential theft") ||
    text.includes("lsass")
  ) {
    return {
      weight: 50,
      severity: "Critical",
      badgeClass: "critical",
      mitre: "Impact / Credential Access / Defense Evasion",
      why: "This command can remove recovery evidence, tamper with logs, or access credentials.",
    };
  }

  if (
    text.includes("high-risk command shell") ||
    text.includes("certutil download") ||
    text.includes("bitsadmin transfer") ||
    text.includes("scheduled task creation") ||
    text.includes("service creation") ||
    text.includes("local administrator group") ||
    text.includes("local user creation") ||
    text.includes("command-line download")
  ) {
    return {
      weight: 40,
      severity: "High",
      badgeClass: "high",
      mitre: "Execution / Persistence / Tool Transfer",
      why: "This command can download tools, create persistence, or modify privileged access.",
    };
  }

  if (text.includes("base64") || text.includes("encoded") || text.includes("decode")) {
    return {
      weight: 40,
      severity: "High",
      badgeClass: "high",
      mitre: "Defense Evasion / Obfuscated Files or Information",
      why: "Encoded or decoded command content can hide the real attack command.",
    };
  }

  if (text.includes("cmd.exe") || text.includes("powershell") || text.includes("command shell")) {
    return {
      weight: 30,
      severity: "Medium",
      badgeClass: "medium",
      mitre: "Execution / Command and Scripting Interpreter",
      why: "Command interpreters are commonly abused to execute malicious instructions.",
    };
  }

  if (text.includes("memory") || text.includes("cpu")) {
    return {
      weight: 15,
      severity: "Medium",
      badgeClass: "medium",
      mitre: "Impact / Resource Hijacking",
      why: "Abnormal resource usage can indicate malicious or unstable process activity.",
    };
  }

  if (text.includes("external") || text.includes("connection") || text.includes("port")) {
    return {
      weight: 25,
      severity: "Medium",
      badgeClass: "medium",
      mitre: "Command and Control / Application Layer Protocol",
      why: "Suspicious network activity can indicate communication with an external controller.",
    };
  }

  if (text.includes("temp") || text.includes("appdata")) {
    return {
      weight: 25,
      severity: "Medium",
      badgeClass: "medium",
      mitre: "Defense Evasion / Masquerading",
      why: "Execution from user-writable paths is often used to hide malicious payloads.",
    };
  }

  return {
    weight: 10,
    severity: "Low",
    badgeClass: "low",
    mitre: "General Detection",
    why: "This signal contributed to the final risk score.",
  };
}

function buildEnrichedRiskReasons(reasons) {
  return safeArray(reasons).map((reason, index) => ({
    id: `${index}-${String(reason).slice(0, 24)}`,
    reason: String(reason),
    ...classifyRiskReason(reason),
  }));
}

function getPrimaryRiskReason(reasons) {
  const enriched = buildEnrichedRiskReasons(reasons);
  return [...enriched].sort((a, b) => b.weight - a.weight)[0] || null;
}

function isSuspiciousProcess(proc, event = {}) {
  const procName = String(proc?.name || "").toLowerCase();
  const eventProcess = String(event?.process_name || "").toLowerCase();
  const pid = String(proc?.pid ?? "");
  const eventPid = String(event?.pid ?? "");

  if (eventProcess && procName === eventProcess) return true;
  if (eventPid && pid === eventPid) return true;
  return SUSPICIOUS_PROCESS_KEYWORDS.some((keyword) => procName.includes(keyword));
}

function getProcessAnalysis(proc, event = {}) {
  const cpu = Number(proc?.cpu_percent ?? 0);
  const memory = Number(proc?.memory_percent ?? 0);

  if (isSuspiciousProcess(proc, event)) {
    return {
      label: "Suspicious",
      className: "high",
      reason: "Process matches the event or a suspicious interpreter/tool name",
    };
  }

  if (cpu >= 50 || memory >= 50) {
    return {
      label: "Resource Spike",
      className: "medium",
      reason: "High CPU or memory usage observed",
    };
  }

  return {
    label: "Normal",
    className: "low",
    reason: "No suspicious process indicator detected",
  };
}

function buildLiveEventMessage(item) {
  const title = item?.event_title || "Live Event";
  const host = item?.hostname || "-";
  const reason = item?.reason || "Suspicious activity detected";
  const eventType = item?.event_type || "";
  const severity = String(item?.severity || "medium").toLowerCase();

  const icon =
    severity === "high" || severity === "critical"
      ? ""
      : severity === "medium"
        ? ""
        : "";

  if (eventType === "system") {
    return `${icon} ${title} on ${host} | ${reason}`;
  }

  if (eventType === "connection") {
    const processName = item?.process_name || "related process";
    const ip = item?.destination_ip || "-";
    const port = item?.destination_port || "-";
    return `${icon} ${title} -> ${processName} -> ${ip}:${port} on ${host} | ${reason}`;
  }

  const processName = item?.process_name || "process";
  const parent = item?.parent_process || "no parent";
  return `${icon} ${title} -> ${processName} (${parent}) on ${host} | ${reason}`;
}

function Sidebar({ activeView, setActiveView }) {
  const monitoringItems = ["Overview", "Agents", "Telemetry"];
  const operationsItems = ["Incidents", "Response Actions"];

  const renderItem = (item) => (
    <button
      key={item}
      className={`sidebar-item ${activeView === item ? "active" : ""}`}
      onClick={() => setActiveView(item)}
      type="button"
    >
      <span className="sidebar-item-text">{item}</span>
    </button>
  );

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div className="sidebar-title">Mini EDR</div>
        <div className="sidebar-subtitle">Security Console</div>
      </div>

      <div className="sidebar-section-label">Monitoring</div>
      <nav className="sidebar-nav">{monitoringItems.map(renderItem)}</nav>

      <div className="sidebar-section-label sidebar-section-gap">
        Operations
      </div>
      <nav className="sidebar-nav">{operationsItems.map(renderItem)}</nav>
    </aside>
  );
}

function SummaryCard({ title, value, subtitle }) {
  return (
    <div className="card">
      <h3>{title}</h3>
      <div className="metric">{value}</div>
      {subtitle ? <div className="card-subtitle">{subtitle}</div> : null}
    </div>
  );
}

function readDashboardSession() {
  const token = getAuthToken();
  if (!token) return null;

  return {
    token,
    username: getAuthUser() || "Analyst",
  };
}

function LoginScreen({ onLogin }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      setLoading(true);
      setError("");
      const data = await loginDashboard(username, password);

      onLogin({
        token: data.access_token,
        username: data.username || username,
      });
    } catch (err) {
      setError(err?.message || "Login failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="auth-shell">
      <section className="auth-panel">
        <div className="auth-brand">
          <div className="sidebar-title">Mini EDR</div>
          <div className="sidebar-subtitle">Security Console</div>
        </div>

        <form className="auth-form" onSubmit={handleSubmit}>
          <label>
            <span>Username</span>
            <input
              className="input"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              required
            />
          </label>

          <label>
            <span>Password</span>
            <input
              className="input"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
            />
          </label>

          {error ? <div className="error auth-error">{error}</div> : null}

          <button className="button auth-submit" type="submit" disabled={loading}>
            {loading ? "Signing in..." : "Sign in"}
          </button>
        </form>
      </section>
    </main>
  );
}

function ReportsMenu({ onExportCsv, onExportPdf }) {
  const [open, setOpen] = useState(false);
  const menuRef = useRef(null);

  useEffect(() => {
    function handleClickOutside(e) {
      if (menuRef.current && !menuRef.current.contains(e.target)) {
        setOpen(false);
      }
    }

    document.addEventListener("mousedown", handleClickOutside);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
    };
  }, []);

  return (
    <div className="reports-menu" ref={menuRef}>
      <button
        className={`button button-secondary ${open ? "active" : ""}`}
        onClick={() => setOpen((v) => !v)}
        type="button"
      >
        Reports ▾
      </button>

      {open && (
        <div className="reports-dropdown">
          <button
            className="reports-dropdown-item"
            onClick={() => {
              setOpen(false);
              onExportCsv();
            }}
            type="button"
          >
            Export CSV
          </button>

          <button
            className="reports-dropdown-item"
            onClick={() => {
              setOpen(false);
              onExportPdf();
            }}
            type="button"
          >
            Export PDF
          </button>
        </div>
      )}
    </div>
  );
}

export default function App() {
  const [session, setSession] = useState(() => readDashboardSession());

  const handleLogout = useCallback(() => {
    clearAuthSession();
    setSession(null);
  }, []);

  if (!session?.token) {
    return <LoginScreen onLogin={setSession} />;
  }

  return <DashboardApp session={session} onLogout={handleLogout} />;
}

function IncidentStatusSelect({ item, onStatusChange }) {
  const [loading, setLoading] = useState(false);

  const handleChange = async (e) => {
    const newStatus = e.target.value;
    try {
      setLoading(true);
      await onStatusChange(item.id, newStatus);
    } finally {
      setLoading(false);
    }
  };

  return (
    <select
      className={`input compact-select ${getIncidentStatusClass(
        getIncidentStatus(item)
      )}`}
      value={getIncidentStatus(item)}
      onChange={handleChange}
      disabled={loading}
    >
      <option value="New">New</option>
      <option value="Investigating">Investigating</option>
      <option value="Resolved">Resolved</option>
      <option value="False Positive">False Positive</option>
    </select>
  );
}

const RESPONSE_ACTION_LABELS = {
  collect_diagnostics: "Collect Diagnostics",
  mark_host_for_isolation_review: "Mark Host for Isolation Review",
  blocklisted_ip_review: "Blocklisted IP Review",
  kill_process_request: "Kill Process Request",
};

function getResponseActionLabel(actionType) {
  return RESPONSE_ACTION_LABELS[actionType] || actionType || "-";
}

function getResponseStatusClass(status) {
  const value = String(status || "").toLowerCase();
  if (value === "executed") return "status-badge resolved";
  if (value === "failed") return "status-badge high";
  if (value === "in_progress") return "status-badge investigating";
  return "status-badge new";
}


function normalizeTimelineType(item = {}) {
  const raw = String(item.event_type || item.type || item.action_type || "").toLowerCase();
  const message = String(item.message || item.title || "").toLowerCase();

  if (raw.includes("created") || message.includes("created")) return "CREATED";
  if (raw.includes("detect") || message.includes("detect") || message.includes("trigger")) return "DETECTION";
  if (raw.includes("status") || message.includes("status") || message.includes("investigating") || message.includes("resolved")) return "STATUS";
  if (raw.includes("response") || raw.includes("action") || message.includes("response") || message.includes("diagnostic")) return "ACTION";
  if (raw.includes("close") || message.includes("closed")) return "RESOLVED";

  return "EVENT";
}

function getTimelineMeta(item = {}, fallbackSeverity = "low") {
  const type = normalizeTimelineType(item);
  const severity = String(fallbackSeverity || "low").toLowerCase();

  const map = {
    CREATED: {
      icon: "🟢",
      label: "Incident Created",
      badgeClass: "low",
      description: "Incident was created based on telemetry analysis.",
    },
    DETECTION: {
      icon: "",
      label: "Detection Triggered",
      badgeClass: severity === "high" || severity === "critical" ? "high" : "medium",
      description: "Detection logic identified suspicious behavior for this event.",
    },
    STATUS: {
      icon: "",
      label: "Status Changed",
      badgeClass: "medium",
      description: "Incident lifecycle status was updated by the analyst.",
    },
    ACTION: {
      icon: "",
      label: "Response Action",
      badgeClass: "medium",
      description: "A safe response workflow was requested for this incident.",
    },
    RESOLVED: {
      icon: "",
      label: "Incident Resolved",
      badgeClass: "low",
      description: "Incident was closed after analyst review.",
    },
    EVENT: {
      icon: "•",
      label: "Timeline Event",
      badgeClass: "low",
      description: "Additional activity was recorded for this incident.",
    },
  };

  return map[type] || map.EVENT;
}

function cleanTimelineMessage(message, fallbackTitle) {
  const raw = String(message || "").trim();
  if (!raw) return fallbackTitle;

  const normalized = raw.toLowerCase();
  if (normalized === "created" || normalized === "incident created: informational") {
    return fallbackTitle;
  }

  return raw
    .replace(/^incident created:\s*/i, "")
    .replace(/^created$/i, fallbackTitle)
    .trim() || fallbackTitle;
}

function getTimelineDescription(item = {}, meta, event = {}) {
  const explicit = item.description || item.details || item.reason || item.result_message || item.note;
  if (explicit) return String(explicit);

  const type = normalizeTimelineType(item);

  if (type === "DETECTION") {
    return getTopReason(event) || meta.description;
  }

  if (type === "CREATED") {
    const severity = getSeverityLabel(getSeverity(event));
    return `Incident was created with ${severity} severity after telemetry analysis.`;
  }

  if (type === "STATUS") {
    const fromStatus = item.old_status || item.from_status;
    const toStatus = item.new_status || item.to_status || item.status;
    if (fromStatus && toStatus) return `${fromStatus} → ${toStatus}`;
    if (toStatus) return `New status: ${toStatus}`;
  }

  if (type === "ACTION") {
    const action = getResponseActionLabel(item.action_type || item.action);
    const target = item.target_value ? `Target: ${item.target_value}` : "Target: Review required";
    return `${action}. ${target}`;
  }

  return meta.description;
}

function buildProfessionalTimeline(rawTimeline = [], event = {}) {
  const timelineItems = safeArray(rawTimeline)
    .filter(Boolean)
    .map((item, index) => {
      const meta = getTimelineMeta(item, getSeverity(event));
      const title = cleanTimelineMessage(item.title || item.message, meta.label);
      const description = getTimelineDescription(item, meta, event);

      return {
        id: item.id || `${normalizeTimelineType(item)}-${item.created_at || item.timestamp || index}`,
        type: normalizeTimelineType(item),
        icon: meta.icon,
        title,
        description,
        badgeClass: meta.badgeClass,
        time: item.created_at || item.timestamp || item.requested_at || event.timestamp,
        severity: getSeverity(event),
        rawType: item.event_type || item.type || "timeline",
      };
    });

  const hasCreated = timelineItems.some((item) => item.type === "CREATED");
  if (!hasCreated && event?.id) {
    const meta = getTimelineMeta({ event_type: "created" }, getSeverity(event));
    timelineItems.unshift({
      id: `auto-created-${event.id}`,
      type: "CREATED",
      icon: meta.icon,
      title: meta.label,
      description: getTimelineDescription({ event_type: "created" }, meta, event),
      badgeClass: meta.badgeClass,
      time: event.timestamp,
      severity: getSeverity(event),
      rawType: "created",
    });
  }

  const hasDetection = timelineItems.some((item) => item.type === "DETECTION");
  if (!hasDetection && event?.id && getRiskNumber(event) > 30) {
    const meta = getTimelineMeta({ event_type: "detection" }, getSeverity(event));
    timelineItems.splice(Math.min(1, timelineItems.length), 0, {
      id: `auto-detection-${event.id}`,
      type: "DETECTION",
      icon: meta.icon,
      title: getAlertType(event) || meta.label,
      description: getTopReason(event) || meta.description,
      badgeClass: meta.badgeClass,
      time: event.timestamp,
      severity: getSeverity(event),
      rawType: "detection",
    });
  }

  return timelineItems.sort(
    (a, b) =>
      (parseDateValue(a.time)?.getTime() ?? 0) -
      (parseDateValue(b.time)?.getTime() ?? 0)
  );
}

function getTargetOptionsForAction(actionType, event = {}) {
  const options = [];

  const addOption = (label, value) => {
    if (value === null || value === undefined || value === "") return;
    const normalized = String(value).trim();
    if (!normalized || normalized === "-") return;

    const exists = options.some((item) => item.value === normalized);
    if (!exists) {
      options.push({ label, value: normalized });
    }
  };

  if (actionType === "collect_diagnostics") {
    addOption("Hostname", event.hostname);
    addOption("Agent ID", event.agent_id);
    return options;
  }

  if (actionType === "mark_host_for_isolation_review") {
    addOption("Hostname", event.hostname);
    addOption("Agent ID", event.agent_id);
    addOption("Local IP", event.ip_address);
    return options;
  }

  if (actionType === "blocklisted_ip_review") {
    addOption("Destination IP", event.destination_ip);
    addOption("Public IP", event.public_ip);
    addOption("Local IP", event.ip_address);
    return options;
  }

  if (actionType === "kill_process_request") {
    addOption("Process Name", event.process_name);
    addOption("Process ID", event.pid);
    return options;
  }

  addOption("Hostname", event.hostname);
  addOption("Agent ID", event.agent_id);
  addOption("Process Name", event.process_name);
  addOption("Process ID", event.pid);
  addOption("Destination IP", event.destination_ip);
  addOption("Destination Port", event.destination_port);
  addOption("Public IP", event.public_ip);
  addOption("Local IP", event.ip_address);

  return options;
}

function getDefaultTargetForAction(actionType, event = {}) {
  const options = getTargetOptionsForAction(actionType, event);
  return options[0]?.value || "";
}

function ResponseActionForm({ event, onCreateAction }) {
  const [actionType, setActionType] = useState("collect_diagnostics");
  const [customAction, setCustomAction] = useState("");
  const [targetMode, setTargetMode] = useState("auto");
  const [targetValue, setTargetValue] = useState("");
  const [customTarget, setCustomTarget] = useState("");
  const [note, setNote] = useState("");
  const [loading, setLoading] = useState(false);
  const [successMessage, setSuccessMessage] = useState("");

  const targetOptions = useMemo(
    () => getTargetOptionsForAction(actionType, event),
    [actionType, event]
  );

  const finalActionType =
    actionType === "custom" ? customAction.trim() : actionType;

  const finalTargetValue =
    targetMode === "custom" ? customTarget.trim() : targetValue;

  useEffect(() => {
    const defaultTarget = getDefaultTargetForAction(actionType, event);

    if (defaultTarget) {
      setTargetMode("auto");
      setTargetValue(String(defaultTarget));
      return;
    }

    if (targetOptions.length) {
      setTargetMode("auto");
      setTargetValue(targetOptions[0].value);
      return;
    }

    setTargetMode("custom");
    setTargetValue("");
  }, [actionType, event, targetOptions]);

  const submit = async () => {
    if (!finalActionType) {
      alert("Please select an action or write a custom action.");
      return;
    }

    try {
      setLoading(true);
      setSuccessMessage("");

      await onCreateAction({
        telemetry_id: event.id,
        agent_id: event.agent_id,
        hostname: event.hostname,
        action_type: finalActionType,
        target_value: finalTargetValue || null,
        note: note || null,
      });

      setTargetValue(getDefaultTargetForAction("collect_diagnostics", event));
      setCustomTarget("");
      setNote("");
      setCustomAction("");
      setActionType("collect_diagnostics");
      setSuccessMessage("Response action created successfully.");
    } catch (err) {
      console.error("Create response action error:", err);
      alert("Failed to create response action.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="panel section-gap">
      <div className="panel-title">Create Response Action</div>
      <div className="panel-subtitle soft-bottom">
        Choose a response action and select a target, or write custom values manually.
      </div>

      <div className="toolbar">
        <select
          className="input"
          value={actionType}
          onChange={(e) => setActionType(e.target.value)}
        >
          <option value="collect_diagnostics">Collect Diagnostics</option>
          <option value="mark_host_for_isolation_review">
            Mark Host for Isolation Review
          </option>
          <option value="blocklisted_ip_review">Blocklisted IP Review</option>
          <option value="kill_process_request">Kill Process Request</option>
          <option value="custom">Custom Action...</option>
        </select>

        {actionType === "custom" && (
          <input
            className="input"
            placeholder="Write custom action type"
            value={customAction}
            onChange={(e) => setCustomAction(e.target.value)}
          />
        )}

        <select
          className="input"
          value={targetMode === "custom" ? "custom" : targetValue}
          onChange={(e) => {
            if (e.target.value === "custom") {
              setTargetMode("custom");
              return;
            }

            setTargetMode("auto");
            setTargetValue(e.target.value);
          }}
        >
          {targetOptions.length ? (
            targetOptions.map((option) => (
              <option key={`${option.label}-${option.value}`} value={option.value}>
                {option.label}: {option.value}
              </option>
            ))
          ) : (
            <option value="">No detected targets</option>
          )}

          <option value="custom">Custom Target...</option>
        </select>

        {targetMode === "custom" && (
          <input
            className="input"
            placeholder="Write target value"
            value={customTarget}
            onChange={(e) => setCustomTarget(e.target.value)}
          />
        )}

        <input
          className="input"
          placeholder="Operator note"
          value={note}
          onChange={(e) => setNote(e.target.value)}
        />

        <button
          className="button"
          onClick={submit}
          disabled={loading}
          type="button"
        >
          {loading ? "Creating..." : "Create Response"}
        </button>
      </div>

      <div className="panel-subtitle" style={{ marginTop: "10px" }}>
        Target for this action: {finalTargetValue || "No target selected"} · Safe Lab Mode:
        actions are logged and reviewed without destructive execution.
      </div>

      {successMessage ? (
        <div className="badge low" style={{ marginTop: "10px" }}>
          {successMessage}
        </div>
      ) : null}
    </div>
  );
}

function EventDetailsModal({ event, onClose, onStatusChange, onCreateAction }) {
  const [decodedResult, setDecodedResult] = useState(null);
  const [decodeLoading, setDecodeLoading] = useState(false);
  const [decodeError, setDecodeError] = useState("");
  const [timeline, setTimeline] = useState([]);
  const [activeEvidenceTab, setActiveEvidenceTab] = useState("risk");

  useEffect(() => {
    if (!event?.id) return;

    getIncidentTimeline(event.id)
      .then((data) => {
        setTimeline(Array.isArray(data) ? data : []);
      })
      .catch((err) => {
        console.error("Timeline error:", err);
        setTimeline([]);
      });
  }, [event?.id]);

  if (!event) return null;

  const reasons = getRiskReasons(event);
  const enrichedReasons = buildEnrichedRiskReasons(reasons);
  const primaryReason = getPrimaryRiskReason(reasons);

  const topProcesses = Array.isArray(event.top_cpu_processes)
    ? event.top_cpu_processes.slice(0, 6)
    : [];
  const suspiciousProcesses = topProcesses.filter((proc) =>
    isSuspiciousProcess(proc, event)
  );

  const allConnections = Array.isArray(event.network_connections)
    ? event.network_connections
    : [];

  const topConnections = [...allConnections]
    .sort((a, b) => getConnectionSortWeight(b) - getConnectionSortWeight(a))
    .slice(0, 8);

  const networkSummary = {
    total: allConnections.length,
    established: allConnections.filter(
      (conn) => String(conn?.status || "").toUpperCase() === "ESTABLISHED"
    ).length,
    external: allConnections.filter(
      (conn) => conn?.remote_address && !isPrivateOrLocalIp(conn.remote_address)
    ).length,
    suspicious: allConnections.filter((conn) =>
      ["high", "medium"].includes(classifyNetworkConnection(conn).level)
    ).length,
  };

  const backendDecodedCommand = getDecodedCommand(event);
  const backendDecodeMethod = getDecodeMethod(event);
  const backendDecodeLayers = getDecodeLayers(event);
  const backendDecodedKeywords = getDecodedSuspiciousKeywords(event);

  const aiAttackExplanation = getAiAttackExplanation(event);
  const attackSummary = getAttackSummary(event);
  const aiAttackCategory = getAiAttackCategory(event);
  const aiSeverity = getAiSeverity(event);
  const aiModelStatus = getAiModelStatusText(event);
  const hasActiveAiAnalysis = getAiScore(event) > 0;
  const showSupportingEvidence = false;
  const attackChain = getAttackChain(event);
  const correlatedAlerts = getCorrelatedAlerts(event);
  const recommendedAction = getRecommendedAction(event);
  const backendHasDecodedAnalysis = hasDecodedAnalysis(event);
  const professionalTimeline = buildProfessionalTimeline(timeline, event);

  const canDecode =
    typeof event.command_line === "string" &&
    event.command_line.trim() !== "" &&
    /(?:^|\s)(?:-enc|-e|\/enc|\/e)(?::|\s)/i.test(event.command_line);

  const handleDecodeCommand = async () => {
    try {
      setDecodeLoading(true);
      setDecodeError("");
      const result = await decodeCommand(event.command_line || "");
      setDecodedResult(result);
    } catch (err) {
      setDecodedResult(null);
      setDecodeError(err?.message || "Failed to decode command.");
    } finally {
      setDecodeLoading(false);
    }
  };

  const evidenceTabs = [
    {
      key: "risk",
      label: "Risk",
      badge: primaryReason ? `+${primaryReason.weight}` : "0",
    },
    {
      key: "processes",
      label: "Processes",
      badge: `${suspiciousProcesses.length}`,
    },
    {
      key: "network",
      label: "Network",
      badge: `${networkSummary.suspicious}`,
    },
    {
      key: "timeline",
      label: "Timeline",
      badge: `${professionalTimeline.length}`,
    },
  ];

  if (attackChain.length || correlatedAlerts.length) {
    evidenceTabs.push({
      key: "correlation",
      label: "AI Correlation",
      badge: `${attackChain.length + correlatedAlerts.length}`,
    });
  }

  const renderEvidenceTab = () => {
    if (activeEvidenceTab === "risk") {
      return enrichedReasons.length ? (
        <div className="risk-reasons-table-wrap">
          <table className="risk-reasons-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Reason</th>
                <th>Weight</th>
                <th>MITRE Context</th>
                <th>Analyst Note</th>
              </tr>
            </thead>
            <tbody>
              {enrichedReasons.map((reason, index) => (
                <tr key={reason.id}>
                  <td>{index + 1}</td>
                  <td className="pre-wrap-cell">{reason.reason}</td>
                  <td>
                    <span className={`badge ${reason.badgeClass}`}>
                      +{reason.weight}
                    </span>
                  </td>
                  <td>{reason.mitre}</td>
                  <td className="pre-wrap-cell">{reason.why}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="empty">No detailed risk reasons available.</div>
      );
    }

    if (activeEvidenceTab === "processes") {
      if (!topProcesses.length) {
        return <div className="empty">No process details available.</div>;
      }

      return (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Risk</th>
                <th>Name</th>
                <th>PID</th>
                <th>CPU</th>
                <th>Memory</th>
                <th>Analysis</th>
              </tr>
            </thead>
            <tbody>
              {topProcesses.map((proc, index) => {
                const processAnalysis = getProcessAnalysis(proc, event);
                return (
                  <tr
                    key={`${proc.pid || index}-${proc.name || "proc"}`}
                    className={processAnalysis.className === "high" ? "row-high" : ""}
                  >
                    <td>
                      <span className={`badge ${processAnalysis.className}`}>
                        {processAnalysis.label}
                      </span>
                    </td>
                    <td>{proc.name || "-"}</td>
                    <td>{proc.pid ?? "-"}</td>
                    <td>{proc.cpu_percent ?? 0}</td>
                    <td>{proc.memory_percent ?? 0}</td>
                    <td className="pre-wrap-cell">{processAnalysis.reason}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      );
    }

    if (activeEvidenceTab === "network") {
      return (
        <>
          <div className="toolbar soft-bottom">
            <span className="badge low">Total: {networkSummary.total}</span>
            <span className="badge low">Established: {networkSummary.established}</span>
            <span className={networkSummary.external ? "badge medium" : "badge low"}>
              External: {networkSummary.external}
            </span>
            <span className={networkSummary.suspicious ? "badge medium" : "badge low"}>
              Review: {networkSummary.suspicious}
            </span>
          </div>

          {!topConnections.length ? (
            <div className="empty">No connection details available.</div>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Risk</th>
                    <th>Local</th>
                    <th>Remote</th>
                    <th>Port</th>
                    <th>Status</th>
                    <th>PID</th>
                    <th>Analysis</th>
                  </tr>
                </thead>
                <tbody>
                  {topConnections.map((conn, index) => {
                    const classification = classifyNetworkConnection(conn);
                    const rowClass =
                      classification.level === "high"
                        ? "row-high"
                        : classification.level === "medium"
                          ? "row-medium"
                          : "";

                    return (
                      <tr
                        key={`${conn.pid || index}-${conn.remote_address || "conn"}-${conn.local_address || "local"}`}
                        className={rowClass}
                      >
                        <td>
                          <span className={`badge ${classification.level}`}>
                            {classification.label}
                          </span>
                        </td>
                        <td>{conn.local_address || "-"}</td>
                        <td>{conn.remote_address || "-"}</td>
                        <td>{getConnectionPort(conn) || "-"}</td>
                        <td>
                          <span
                            className={`status-badge ${
                              String(conn.status || "").toUpperCase() === "ESTABLISHED"
                                ? "healthy"
                                : String(conn.status || "").toUpperCase() === "LISTEN"
                                  ? "warning"
                                  : "unknown"
                            }`}
                          >
                            {conn.status || "-"}
                          </span>
                        </td>
                        <td>{conn.pid ?? "-"}</td>
                        <td className="pre-wrap-cell">{classification.reason}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </>
      );
    }

    if (activeEvidenceTab === "timeline") {
      return professionalTimeline.length ? (
        <div className="event-list incident-timeline-list">
          {professionalTimeline.map((item, index) => (
            <div
              className={`event-item timeline-${item.type.toLowerCase()}`}
              key={item.id || index}
              style={{
                borderLeft: `4px solid ${
                  item.badgeClass === "high"
                    ? "#ff5d73"
                    : item.badgeClass === "medium"
                      ? "#ffb648"
                      : "#22c55e"
                }`,
              }}
            >
              <div className="event-main">
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "10px",
                    flexWrap: "wrap",
                    marginBottom: "8px",
                  }}
                >
                  <span className={`badge ${item.badgeClass}`}>{item.icon}</span>
                  <strong style={{ color: "#eaf2ff", fontSize: "15px" }}>
                    {item.title}
                  </strong>
                  <span className="badge low">{prettifyCategory(item.type)}</span>
                  <span className="event-time">{formatDateTime(item.time)}</span>
                </div>
                <div className="event-reason pre-wrap-cell">{item.description}</div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="empty">No timeline events available.</div>
      );
    }

    if (activeEvidenceTab === "correlation") {
      return (
        <>
          {attackChain.length ? (
            <div className="detail-item" style={{ marginBottom: "12px" }}>
              <div className="detail-key">Attack Chain Reconstruction</div>
              <div className="detail-value">
                <div className="event-list">
                  {attackChain.map((stage, index) => (
                    <div className="event-item" key={`${index}-${stage}`}>
                      <div className="event-main">
                        <strong>Stage {index + 1}</strong>
                        <div className="event-reason pre-wrap-cell">{stage}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : null}

          {correlatedAlerts.length ? (
            <div className="risk-reasons-table-wrap">
              <table className="risk-reasons-table">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Alert</th>
                    <th>MITRE</th>
                    <th>Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {correlatedAlerts.map((alert, index) => (
                    <tr key={`${index}-${alert.alert_type || "alert"}`}>
                      <td>{index + 1}</td>
                      <td>{alert.alert_type || "-"}</td>
                      <td>{`${alert.tactic || "-"} / ${alert.technique || "-"}`}</td>
                      <td className="pre-wrap-cell">
                        {alert.explanation || alert.reason || "-"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}

          {!attackChain.length && !correlatedAlerts.length ? (
            <div className="empty">No advanced AI correlation found for this event.</div>
          ) : null}
        </>
      );
    }

    return null;
  };

  return (
    <div
      className="modal-overlay"
      onClick={(e) => {
        if (e.target === e.currentTarget) {
          onClose();
        }
      }}
    >
      <div className={`modal-card modal-wide severity-${getSeverityClass(getSeverity(event))}`}>
        <div className="modal-header" style={{ alignItems: "flex-start" }}>
          <div>
            <div className="panel-title">Telemetry Event Details</div>
            <div className="panel-subtitle">
              SOC-style incident view with AI verdict, technical evidence, and response workflow
            </div>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap", justifyContent: "flex-end" }}>
            <span className={`badge ${getSeverityClass(getSeverity(event))}`}>
              {getSeverityLabel(getSeverity(event))}
            </span>
            <span className={`badge ${getRiskClass(getRiskNumber(event))}`}>
              Risk {getRiskNumber(event)} / 100
            </span>
            <button className="small-button" onClick={onClose} type="button">
              Close
            </button>
          </div>
        </div>

        <div className="soc-top-grid align-start">
          <div className="panel soc-summary-panel">
            <div className="panel-header soft-bottom">
              <div>
                <div className="panel-title">Detection Summary</div>
                <div className="panel-subtitle">What happened, why it was recorded, and current incident status</div>
              </div>
            </div>

            <div className="details-grid soc-summary-grid">
              <div className="detail-item">
                <div className="detail-key">Event ID</div>
                <div className="detail-value">{event.id}</div>
              </div>

              <div className="detail-item">
                <div className="detail-key">Timestamp</div>
                <div className="detail-value">{formatDateTime(event.timestamp)}</div>
              </div>

              <div className="detail-item">
                <div className="detail-key">Alert Type</div>
                <div className="detail-value">{getAlertType(event)}</div>
              </div>

              <div className="detail-item">
                <div className="detail-key">Incident Status</div>
                <div className="detail-value">
                  <IncidentStatusSelect item={event} onStatusChange={onStatusChange} />
                </div>
              </div>

              <div className="detail-item soc-wide-card">
                <div className="detail-key">Primary Reason</div>
                <div className="detail-value pre-wrap-cell compact-evidence-text">
                  <span className="highlight-reason">{primaryReason?.reason || getTopReason(event)}</span>
                </div>
              </div>

              <div className="detail-item">
                <div className="detail-key">Severity</div>
                <div className="detail-value">
                  <span className={`badge ${getSeverityClass(getSeverity(event))}`}>
                    {getSeverityLabel(getSeverity(event))}
                  </span>
                </div>
              </div>

              <div className="detail-item">
                <div className="detail-key">Risk Score</div>
                <div className="detail-value">
                  <span className={`badge ${getRiskClass(getRiskNumber(event))}`}>
                    {getRiskNumber(event)} / 100
                  </span>
                  <div className="risk-bar compact-risk-bar">
                    <div className="risk-fill" style={{ width: `${getRiskNumber(event)}%` }} />
                  </div>
                </div>
              </div>

              <div className="detail-item">
                <div className="detail-key">Detection Source</div>
                <div className="detail-value">{getDetectionSource(event)}</div>
              </div>

              <div className="detail-item">
                <div className="detail-key">Event Category</div>
                <div className="detail-value">{prettifyCategory(getEventCategory(event))}</div>
              </div>
            </div>
          </div>

          <div className="panel soc-technical-panel">
            <div className="panel-header soft-bottom">
              <div>
                <div className="panel-title">Technical Evidence</div>
                <div className="panel-subtitle">Endpoint, process, MITRE, destination, and system context</div>
              </div>
            </div>

            <div className="details-grid soc-tech-grid">
              <div className="detail-item">
                <div className="detail-key">Hostname</div>
                <div className="detail-value">{event.hostname || "-"}</div>
              </div>

              <div className="detail-item">
                <div className="detail-key">Local IP</div>
                <div className="detail-value">{event.ip_address || "-"}</div>
              </div>

              <div className="detail-item">
                <div className="detail-key">Process</div>
                <div className="detail-value">{event.process_name || "-"}</div>
              </div>

              <div className="detail-item">
                <div className="detail-key">Parent Process</div>
                <div className="detail-value">{event.parent_process || "-"}</div>
              </div>

              <div className="detail-item">
                <div className="detail-key">MITRE</div>
                <div className="detail-value">{getMitreTechnique(event)} / {getMitreTactic(event)}</div>
              </div>

              <div className="detail-item">
                <div className="detail-key">Destination</div>
                <div className="detail-value">
                  {event.destination_ip || "-"}{event.destination_port ? `:${event.destination_port}` : ""}
                </div>
              </div>

              <div className="detail-item soc-wide-card">
                <div className="detail-key">System Metrics</div>
                <div className="detail-value">
                  CPU {event.cpu_percent ?? 0}% · Memory {event.memory_percent ?? 0}% · Processes {event.process_count ?? 0}
                </div>
              </div>
            </div>
          </div>
        </div>

        {hasActiveAiAnalysis ? (
        <div className="panel section-gap soc-ai-verdict-panel">
          <div className="panel-header soft-bottom">
            <div>
              <div className="panel-title">AI Verdict</div>
              <div className="panel-subtitle">AI predicted severity, predicted category, and model contribution</div>
            </div>
            <span className={`badge ${getSeverityClass(aiSeverity)}`}>
              {getSeverityLabel(aiSeverity)} AI Predicted
            </span>
          </div>

          <div className="details-grid soc-ai-verdict-grid">
            <div className="detail-item">
              <div className="detail-key">AI Predicted Severity</div>
              <div className="detail-value">
                <span className={`badge ${getSeverityClass(aiSeverity)}`}>
                  {getSeverityLabel(aiSeverity)}
                </span>
              </div>
            </div>

            <div className="detail-item soc-category-card">
              <div className="detail-key">Attack Category</div>
              <div className="detail-value">{aiAttackCategory}</div>
            </div>

            <div className="detail-item">
              <div className="detail-key">Risk Score</div>
              <div className="detail-value">
                <span className={`badge ${getRiskClass(getRiskNumber(event))}`}>
                  {getRiskNumber(event)} / 100
                </span>
                <div className="risk-bar compact-risk-bar">
                  <div className="risk-fill" style={{ width: `${getRiskNumber(event)}%` }} />
                </div>
              </div>
            </div>

            <div className="detail-item">
              <div className="detail-key">Score Breakdown</div>
              <div className="detail-value score-badges">
                <span className={`badge ${getRuleScore(event) > 0 ? "medium" : "low"}`}>Rule +{getRuleScore(event)}</span>
                <span className={`badge ${getAiScore(event) > 0 ? "medium" : "low"}`}>AI +{getAiScore(event)}</span>
              </div>
            </div>

            <div className="detail-item soc-model-card">
              <div className="detail-key">Model Status</div>
              <div className="detail-value">{aiModelStatus}</div>
            </div>
          </div>
        </div>
        ) : null}

        {hasActiveAiAnalysis ? (
        <div className="panel section-gap">
          <div className="panel-header soft-bottom">
            <div>
              <div className="panel-title">AI Analysis</div>
              <div className="panel-subtitle">Narrative summary and recommended analyst action</div>
            </div>
          </div>

          <div className="details-grid">
            <div className="detail-item" style={{ gridColumn: "1 / -1" }}>
              <div className="detail-key">Attack Summary</div>
              <div className="detail-value pre-wrap-cell">
                {attackSummary || "No attack summary available."}
              </div>
            </div>

            <div className="detail-item" style={{ gridColumn: "1 / -1" }}>
              <div className="detail-key">Recommended Analyst Action</div>
              <div className="detail-value pre-wrap-cell">
                {recommendedAction || "No immediate response required. Continue monitoring."}
              </div>
            </div>

            {aiAttackExplanation ? (
              <div className="detail-item" style={{ gridColumn: "1 / -1" }}>
                <div className="detail-key">AI Explanation</div>
                <div className="detail-value pre-wrap-cell ai-attack-explanation-box">
                  {aiAttackExplanation}
                </div>
              </div>
            ) : null}
          </div>
        </div>
        ) : null}

        <div className="panel section-gap">
          <div className="panel-header soft-bottom">
            <div>
              <div className="panel-title">Command & File Evidence</div>
              <div className="panel-subtitle">Command line, decoded content, execution path, and file evidence</div>
            </div>
          </div>

          <div className="details-grid">
            <div className="detail-item" style={{ gridColumn: "1 / -1" }}>
              <div
                className="detail-key"
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: "12px",
                  flexWrap: "wrap",
                }}
              >
                <span>Command Line</span>
                {canDecode && (
                  <button
                    className="small-button"
                    onClick={handleDecodeCommand}
                    disabled={decodeLoading}
                    type="button"
                  >
                    {decodeLoading ? "Decoding..." : "Decode Base64"}
                  </button>
                )}
              </div>
              <div className="detail-value pre-wrap-cell">{event.command_line || "-"}</div>
            </div>

            {backendHasDecodedAnalysis ? (
              <>
                <div className="detail-item">
                  <div className="detail-key">Decode Method</div>
                  <div className="detail-value">{backendDecodeMethod || "-"}</div>
                </div>

                <div className="detail-item">
                  <div className="detail-key">Decoded Keywords</div>
                  <div className="detail-value">
                    {backendDecodedKeywords.length ? backendDecodedKeywords.join(", ") : "-"}
                  </div>
                </div>

                <div className="detail-item" style={{ gridColumn: "1 / -1" }}>
                  <div className="detail-key">Decoded Command</div>
                  <div className="detail-value pre-wrap-cell">{backendDecodedCommand || "-"}</div>
                </div>

                {backendDecodeLayers.length ? (
                  <div className="detail-item" style={{ gridColumn: "1 / -1" }}>
                    <div className="detail-key">Decode Layers</div>
                    <div className="detail-value pre-wrap-cell">
                      {backendDecodeLayers.join(" → ")}
                    </div>
                  </div>
                ) : null}
              </>
            ) : null}

            {decodeError ? (
              <div className="detail-item" style={{ gridColumn: "1 / -1" }}>
                <div className="detail-key">Decode Error</div>
                <div className="detail-value pre-wrap-cell">{decodeError}</div>
              </div>
            ) : null}

            {decodedResult ? (
              <>
                <div className="detail-item">
                  <div className="detail-key">Manual Decode Status</div>
                  <div className="detail-value">
                    <span className={`badge ${decodedResult.success ? "low" : "medium"}`}>
                      {decodedResult.success ? "Decoded" : "Not Decoded"}
                    </span>
                  </div>
                </div>

                <div className="detail-item" style={{ gridColumn: "1 / -1" }}>
                  <div className="detail-key">Manual Decode Result</div>
                  <div className="detail-value pre-wrap-cell">
                    {decodedResult.decoded_text || decodedResult.message || "-"}
                  </div>
                </div>
              </>
            ) : null}

            <div className="detail-item" style={{ gridColumn: "1 / -1" }}>
              <div className="detail-key">File Path</div>
              <div className="detail-value pre-wrap-cell">{event.file_path || "-"}</div>
            </div>
          </div>
        </div>

        {showSupportingEvidence ? (
        <div className="panel section-gap">
          <div className="panel-header soft-bottom">
            <div>
              <div className="panel-title">Supporting Evidence</div>
              <div className="panel-subtitle">Detailed evidence is grouped into tabs to reduce visual clutter</div>
            </div>
          </div>

          <div className="toolbar soft-bottom">
            {evidenceTabs.map((tab) => (
              <button
                key={tab.key}
                className={`small-button ${activeEvidenceTab === tab.key ? "active" : ""}`}
                onClick={() => setActiveEvidenceTab(tab.key)}
                type="button"
              >
                {tab.label} · {tab.badge}
              </button>
            ))}
          </div>

          {renderEvidenceTab()}
        </div>
        ) : null}

        <div className="panel section-gap">
          <div className="panel-title">Response Actions</div>
          <ResponseActionForm event={event} onCreateAction={onCreateAction} />
        </div>
      </div>
    </div>
  );
}
function AgentDetailsModal({ agent, telemetry, responseActions, onClose }) {
  if (!agent) return null;

  const hostTelemetry = telemetry
    .filter((item) => item.hostname === agent.hostname)
    .sort(
      (a, b) =>
        (parseDateValue(b.timestamp)?.getTime() ?? 0) -
        (parseDateValue(a.timestamp)?.getTime() ?? 0)
    )
    .slice(0, 8);

  const hostActions = responseActions
    .filter((item) => item.hostname === agent.hostname)
    .sort(
      (a, b) =>
        (parseDateValue(b.requested_at)?.getTime() ?? 0) -
        (parseDateValue(a.requested_at)?.getTime() ?? 0)
    )
    .slice(0, 8);

  return (
    <div
      className="modal-overlay"
      onClick={(e) => {
        if (e.target === e.currentTarget) {
          onClose();
        }
      }}
    >
      <div className="modal-card modal-wide">
        <div className="modal-header">
          <div>
            <div className="panel-title">Agent Details</div>
            <div className="panel-subtitle">
              Endpoint identity, geo context, risk summary, and recent activity
            </div>
          </div>

          <button className="small-button" onClick={onClose} type="button">
            Close
          </button>
        </div>

        <div className="details-grid">
          <div className="detail-item">
            <div className="detail-key">Agent ID</div>
            <div className="detail-value">{agent.agent_id || "-"}</div>
          </div>
          <div className="detail-item">
            <div className="detail-key">Hostname</div>
            <div className="detail-value">{agent.hostname || "-"}</div>
          </div>
          <div className="detail-item">
            <div className="detail-key">Local IP</div>
            <div className="detail-value">{agent.ip_address || "-"}</div>
          </div>
          <div className="detail-item">
            <div className="detail-key">Public IP</div>
            <div className="detail-value">{agent.public_ip || "-"}</div>
          </div>
          <div className="detail-item">
            <div className="detail-key">Country</div>
            <div className="detail-value">{agent.country || "-"}</div>
          </div>
          <div className="detail-item">
            <div className="detail-key">City</div>
            <div className="detail-value">{agent.city || "-"}</div>
          </div>
          <div className="detail-item">
            <div className="detail-key">ISP</div>
            <div className="detail-value">{agent.isp || "-"}</div>
          </div>
          <div className="detail-item">
            <div className="detail-key">OS</div>
            <div className="detail-value">{agent.os || "-"}</div>
          </div>
          <div className="detail-item">
            <div className="detail-key">Created At</div>
            <div className="detail-value">{formatDateTime(agent.created_at)}</div>
          </div>
          <div className="detail-item">
            <div className="detail-key">Last Seen</div>
            <div className="detail-value">{formatDateTime(agent.last_seen)}</div>
          </div>
          <div className="detail-item">
            <div className="detail-key">Host Status</div>
            <div className="detail-value">
              <span className={`status-badge ${getHostStatusClass(agent.host_status)}`}>
                {agent.host_status || "Unknown"}
              </span>
            </div>
          </div>
          <div className="detail-item">
            <div className="detail-key">Latest Risk</div>
            <div className="detail-value">{agent.latest_risk ?? 0}</div>
          </div>
          <div className="detail-item">
            <div className="detail-key">Average Risk</div>
            <div className="detail-value">{agent.average_risk ?? 0}</div>
          </div>
          <div className="detail-item">
            <div className="detail-key">High Events Count</div>
            <div className="detail-value">{agent.high_events_count ?? 0}</div>
          </div>
        </div>

        <div className="two-column-grid section-gap align-start">
          <div className="panel">
            <div className="panel-title">Recent Telemetry</div>
            <div className="panel-subtitle soft-bottom">
              Latest events for this endpoint
            </div>

            {!hostTelemetry.length ? (
              <div className="empty">No telemetry found for this agent.</div>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>time</th>
                      <th>severity</th>
                      <th>alert</th>
                      <th>decoded</th>
                      <th>reason</th>
                    </tr>
                  </thead>
                  <tbody>
                    {hostTelemetry.map((item) => (
                      <tr key={item.id}>
                        <td>{formatDateTime(item.timestamp)}</td>
                        <td>
                          <span className={`badge ${getSeverityClass(getSeverity(item))}`}>
                            {getSeverityLabel(getSeverity(item))}
                          </span>
                        </td>
                        <td>{getAlertType(item)}</td>
                        <td>{hasDecodedAnalysis(item) ? "Yes" : "-"}</td>
                        <td>{shorten(getTopReason(item), 50)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="panel">
            <div className="panel-title">Recent Response Actions</div>
            <div className="panel-subtitle soft-bottom">
              Latest response workflow activity
            </div>

            {!hostActions.length ? (
              <div className="empty">No response actions found for this agent.</div>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>action</th>
                      <th>target</th>
                      <th>status</th>
                      <th>requested</th>
                    </tr>
                  </thead>
                  <tbody>
                    {hostActions.map((item) => (
                      <tr key={item.id}>
                        <td>{item.action_type || "-"}</td>
                        <td>{item.target_value || "-"}</td>
                        <td>{item.status || "-"}</td>
                        <td>{formatDateTime(item.requested_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}


function EventFilters({
  severityFilter,
  setSeverityFilter,
  statusFilter,
  setStatusFilter,
  hostFilter,
  setHostFilter,
  hosts,
}) {
  return (
    <div className="toolbar soft-bottom">
      <select
        className="input compact-select"
        value={severityFilter}
        onChange={(e) => setSeverityFilter(e.target.value)}
      >
        <option value="All">All Severity</option>
        <option value="Critical">Critical</option>
        <option value="High">High</option>
        <option value="Medium">Medium</option>
        <option value="Low">Low</option>
      </select>

      <select
        className="input compact-select"
        value={statusFilter}
        onChange={(e) => setStatusFilter(e.target.value)}
      >
        <option value="All">All Status</option>
        <option value="New">New</option>
        <option value="Investigating">Investigating</option>
        <option value="Resolved">Resolved</option>
        <option value="False Positive">False Positive</option>
      </select>

      <select
        className="input compact-select"
        value={hostFilter}
        onChange={(e) => setHostFilter(e.target.value)}
      >
        <option value="All">All Hosts</option>
        {hosts.map((host) => (
          <option key={host} value={host}>
            {host}
          </option>
        ))}
      </select>

      {(severityFilter !== "All" ||
        statusFilter !== "All" ||
        hostFilter !== "All") && (
        <button
          className="small-button"
          onClick={() => {
            setSeverityFilter("All");
            setStatusFilter("All");
            setHostFilter("All");
          }}
          type="button"
        >
          Clear Filters
        </button>
      )}
    </div>
  );
}

function TelemetryTable({ data, onStatusChange, onOpenEvent }) {
  const [severityFilter, setSeverityFilter] = useState("All");
  const [statusFilter, setStatusFilter] = useState("All");
  const [hostFilter, setHostFilter] = useState("All");

  const hosts = useMemo(
    () =>
      [...new Set(safeArray(data).map((item) => item.hostname).filter(Boolean))]
        .sort((a, b) => String(a).localeCompare(String(b))),
    [data]
  );

  const filteredRows = useMemo(() => {
    return safeArray(data).filter((item) => {
      const severity = getSeverityLabel(getSeverity(item));
      const status = getIncidentStatus(item);
      const host = item?.hostname || "";

      return (
        (severityFilter === "All" || severity === severityFilter) &&
        (statusFilter === "All" || status === statusFilter) &&
        (hostFilter === "All" || host === hostFilter)
      );
    });
  }, [data, severityFilter, statusFilter, hostFilter]);

  if (!data.length) {
    return (
      <div className="panel">
        <div className="panel-title">Telemetry Events</div>
        <div className="panel-subtitle soft-bottom">
          Cleaned event stream with the most useful investigation fields
        </div>
        <div className="empty-state compact-empty">
          <div className="empty-state-icon">i</div>
          <div className="empty-state-title">No telemetry events</div>
          <div className="empty-state-text">
            Events will appear here once the agent starts sending telemetry.
          </div>
        </div>
      </div>
    );
  }

  const rows = [...filteredRows]
    .sort(
      (a, b) =>
        (parseDateValue(b.timestamp)?.getTime() ?? 0) -
        (parseDateValue(a.timestamp)?.getTime() ?? 0)
    )
    .slice(0, 120);

  return (
    <div className="panel">
      <div className="panel-header">
        <div>
          <div className="panel-title">Telemetry Events</div>
          <div className="panel-subtitle">
            Latest endpoint detections and investigation-ready context
          </div>
        </div>

        <div className="badge medium">
          {rows.length} of {data.length} events
        </div>
      </div>

      <EventFilters
        severityFilter={severityFilter}
        setSeverityFilter={setSeverityFilter}
        statusFilter={statusFilter}
        setStatusFilter={setStatusFilter}
        hostFilter={hostFilter}
        setHostFilter={setHostFilter}
        hosts={hosts}
      />

      {!rows.length ? (
        <div className="empty">No telemetry matches the selected filters.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Host</th>
                <th>Alert</th>
                <th>Category</th>
                <th>Severity</th>
                <th>Source</th>
                <th>Decoded</th>
                <th>Status</th>
                <th>Reason</th>
                <th></th>
              </tr>
            </thead>

            <tbody>
              {rows.map((row) => {
                const severity = getSeverity(row);

                return (
                  <tr key={row.id} className={`row-${getSeverityClass(severity)}`}>
                    <td>{formatDateTime(row.timestamp)}</td>
                    <td>
                      <strong>{row.hostname || "-"}</strong>
                    </td>
                    <td className="pre-wrap-cell">{getIncidentAlertLabel(row)}</td>
                    <td>{getDisplayEventCategory(row)}</td>
                    <td>
                      <span className={`badge ${getSeverityClass(severity)}`}>
                        {getSeverityLabel(severity)}
                      </span>
                    </td>
                    <td>
                      <span className="badge low">{getDetectionSource(row)}</span>
                    </td>
                    <td>
                      <span className={`badge ${hasRealDecodedCommand(row) ? "medium" : "low"}`}>
                        {hasRealDecodedCommand(row) ? "Yes" : "No"}
                      </span>
                    </td>
                    <td style={{ minWidth: 160 }}>
                      <IncidentStatusSelect
                        item={row}
                        onStatusChange={onStatusChange}
                      />
                    </td>
                    <td className="pre-wrap-cell">
                      {getCompactReason(row)}
                    </td>
                    <td>
                      <button
                        className="small-button"
                        onClick={() => onOpenEvent(row)}
                        type="button"
                      >
                        View
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function AgentsTable({ data, onOpenAgent }) {
  if (!data.length) {
    return (
      <div className="panel">
        <div className="panel-title">Agents</div>
        <div className="empty">No agents found.</div>
      </div>
    );
  }

  return (
    <div className="panel">
      <div className="panel-title">Agents</div>
      <div className="panel-subtitle soft-bottom">
        Geo-enriched endpoint inventory with host risk summary
      </div>

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>hostname</th>
              <th>local ip</th>
              <th>public ip</th>
              <th>country</th>
              <th>os</th>
              <th>host status</th>
              <th>online_status</th> 
              <th>last seen</th>
              <th>latest risk</th>
              <th>details</th>
            </tr>
          </thead>
          <tbody>
            {data.map((row) => (
              <tr key={row.agent_id}>
                <td>{row.hostname}</td>
                <td>{row.ip_address}</td>
                <td>{row.public_ip}</td>
                <td>{row.country || "-"}</td>
                <td>{row.os}</td>
                <td>
                  <span className={`status-badge ${getHostStatusClass(row.host_status)}`}>
                    {row.host_status}
                  </span>
                </td>
                <td>
                 <span className={`status-badge ${
                    row.online_status === "Online" ? "healthy" : "unknown"
                    }`}>
                    {row.online_status || "Offline"}
                 </span>
               </td>
                <td>{formatDateTime(row.last_seen)}</td>
                <td>{row.latest_risk ?? 0}</td>
                <td>
                  <button
                    className="small-button"
                    onClick={() => onOpenAgent(row)}
                    type="button"
                  >
                    View Details
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ResponseActionsTable({ data }) {
  if (!data.length) {
    return (
      <div className="panel">
        <div className="panel-title">Response Actions</div>
        <div className="empty">No response actions found.</div>
      </div>
    );
  }

  return (
    <div className="panel">
      <div className="panel-title">Response Actions</div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>id</th>
              <th>telemetry</th>
              <th>hostname</th>
              <th>action</th>
              <th>target</th>
              <th>status</th>
              <th>requested</th>
              <th>executed</th>
              <th>result</th>
            </tr>
          </thead>
          <tbody>
            {data.map((row) => (
              <tr key={row.id}>
                <td>{row.id}</td>
                <td>{row.telemetry_id}</td>
                <td>{row.hostname}</td>
                <td>{getResponseActionLabel(row.action_type)}</td>
                <td>{row.target_value ?? "-"}</td>
                <td><span className={getResponseStatusClass(row.status)}>{row.status}</span></td>
                <td>{formatDateTime(row.requested_at)}</td>
                <td>{formatDateTime(row.executed_at)}</td>
                <td>{row.result_message ?? "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function CriticalAlertsPanel({ telemetry, onOpenEvent, onStatusChange }) {
  const criticalAlerts = telemetry
    .filter((item) => getRiskNumber(item) > 80)
    .sort((a, b) => getRiskNumber(b) - getRiskNumber(a))
    .slice(0, 6);

  return (
    <div className="panel">
      <div className="panel-title">Critical Alerts</div>
      <div className="panel-subtitle soft-bottom">
        Highest severity alerts that need immediate attention
      </div>

      {!criticalAlerts.length ? (
        <div className="empty-state">
          <div className="empty-state-icon">✓</div>
          <div className="empty-state-title">No critical alerts</div>
          <div className="empty-state-text">
            No critical detections require immediate attention right now.
          </div>
        </div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>host</th>
                <th>severity</th>
                <th>alert</th>
                <th>mitre</th>
                <th>status</th>
                <th>details</th>
              </tr>
            </thead>
            <tbody>
              {criticalAlerts.map((item) => (
                <tr key={item.id} className="row-high">
                  <td>{item.hostname || "-"}</td>
                  <td>
                    <span className={`badge ${getSeverityClass(getSeverity(item))}`}>
                      {getSeverityLabel(getSeverity(item))}
                    </span>
                  </td>
                  <td>{getAlertType(item)}</td>
                  <td>{getMitreTactic(item)}</td>
                  <td style={{ minWidth: 170 }}>
                    <IncidentStatusSelect item={item} onStatusChange={onStatusChange} />
                  </td>
                  <td>
                    <button className="small-button" onClick={() => onOpenEvent(item)} type="button">
                      View
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function LiveActivityFeed({ liveEvents, responseActions }) {
  const liveEventFeed = safeArray(liveEvents).map((item, index) => {
    const sourceLabel =
      item.detection_source ||
      item.source ||
      (String(item.event_title || "").toLowerCase().includes("ai") ? "AI" : "Rule-Based");

    return {
      id: `live-${item.timestamp || index}-${item.event_title || "event"}-${item.process_name || "proc"}-${index}`,
      time: item.timestamp || null,
      type: "Live",
      source: sourceLabel,
      severity:
        item.risk_score !== undefined && item.risk_score !== null
          ? severityFromRiskScore(getRiskNumber(item))
          : item.severity || "medium",
      title: item.event_title || "Security Event",
      host: item.hostname || "-",
      message: item.reason || buildLiveEventMessage(item),
      mitre:
        item.mitre_tactic ||
        item.mitre_technique ||
        item.decoded_mitre_tactic ||
        item.decoded_mitre_technique ||
        "",
    };
  });

  const actionFeed = safeArray(responseActions).map((item) => ({
    id: `action-${item.id}`,
    time: item.requested_at || null,
    type: "Response",
    source: "Workflow",
    severity:
      item.status === "failed"
        ? "high"
        : item.status === "executed"
          ? "low"
          : "medium",
    title: getResponseActionLabel(item.action_type),
    host: item.hostname || "-",
    message: `${item.hostname || "-"} | ${getResponseActionLabel(item.action_type)} | ${item.status || "-"}`,
    mitre: "",
  }));

  const merged = [...liveEventFeed, ...actionFeed]
    .sort(
      (a, b) =>
        (parseDateValue(b.time)?.getTime() ?? 0) -
        (parseDateValue(a.time)?.getTime() ?? 0)
    )
    .slice(0, 10);

  return (
    <div className="panel overview-feed-panel">
      <div className="panel-header soft-bottom">
        <div>
          <div className="panel-title">Live Activity Feed</div>
          <div className="panel-subtitle">
            Real-time detections, AI signals, and response workflow
          </div>
        </div>
        <span className="badge low">{merged.length} latest</span>
      </div>

      {!merged.length ? (
        <div className="empty-state compact-empty">
          <div className="empty-state-icon">✓</div>
          <div className="empty-state-title">No live activity yet</div>
          <div className="empty-state-text">
            New agent detections and response actions will appear here.
          </div>
        </div>
      ) : (
        <div className="event-list overview-feed-list">
          {merged.map((item) => (
            <div className={`event-item row-${getLiveSeverityClass(item.severity)}`} key={item.id}>
              <div className="event-main">
                <div className="overview-feed-header">
                  <span className={`badge ${getLiveSeverityClass(item.severity)}`}>
                    {item.type}
                  </span>
                  <span className="badge low">{item.source}</span>
                  {item.mitre ? <span className="badge medium">MITRE</span> : null}
                  <strong className="overview-feed-title">{item.title}</strong>
                  <span className="overview-feed-host">{item.host}</span>
                  <span className="event-time">{formatDateTime(item.time)}</span>
                </div>

                <div className="event-reason">{item.message}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function TopRiskyHostsPanel({ agents, onOpenAgent }) {
  const topHosts = [...safeArray(agents)]
    .sort((a, b) => Number(b.latest_risk ?? 0) - Number(a.latest_risk ?? 0))
    .slice(0, 5);

  return (
    <div className="panel">
      <div className="panel-title">Top Risky Hosts</div>
      <div className="panel-subtitle soft-bottom">
        Endpoints with the highest current host risk
      </div>

      {!topHosts.length ? (
        <div className="empty">No hosts available.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>host</th>
                <th>country</th>
                <th>status</th>
                <th>latest risk</th>
                <th>avg risk</th>
                <th>details</th>
              </tr>
            </thead>
            <tbody>
              {topHosts.map((host) => (
                <tr key={host.agent_id}>
                  <td>{host.hostname}</td>
                  <td>{host.country || "-"}</td>
                  <td>
                    <span className={`status-badge ${getHostStatusClass(host.host_status)}`}>
                      {host.host_status || "Unknown"}
                    </span>
                  </td>
                  <td>{host.latest_risk ?? 0}</td>
                  <td>{host.average_risk ?? 0}</td>
                  <td>
                    <button className="small-button" onClick={() => onOpenAgent(host)} type="button">
                      View
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function RiskDistributionChart({ telemetry }) {
  const critical = telemetry.filter((item) => getRiskNumber(item) > 80).length;
  const high = telemetry.filter(
    (item) => getRiskNumber(item) > 60 && getRiskNumber(item) <= 80
  ).length;
  const medium = telemetry.filter(
    (item) => getRiskNumber(item) > 30 && getRiskNumber(item) <= 60
  ).length;
  const low = telemetry.filter((item) => getRiskNumber(item) <= 30).length;

  const data = [
    { name: "Critical", value: critical, color: "#ff5d73" },
    { name: "High", value: high, color: "#ff5d73" },
    { name: "Medium", value: medium, color: "#ffb648" },
    { name: "Low", value: low, color: "#22c55e" },
  ];

  return (
    <div className="panel">
      <div className="panel-title">Risk Distribution</div>
      <div className="panel-subtitle soft-bottom">
        High, medium, and low telemetry distribution
      </div>

      <div className="chart-box">
        <ResponsiveContainer width="100%" height={260}>
          <PieChart>
            <Pie data={data} dataKey="value" nameKey="name" outerRadius={88} innerRadius={46} label>
              {data.map((entry, index) => (
                <Cell key={index} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip {...chartTooltipStyle()} />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

function HostHealthChart({ agents }) {
  const critical = agents.filter((item) => item.host_status === "Critical").length;
  const warning = agents.filter((item) => item.host_status === "Warning").length;
  const healthy = agents.filter((item) => item.host_status === "Healthy").length;

  const data = [
    { name: "Critical", value: critical, color: "#ff5d73" },
    { name: "Warning", value: warning, color: "#ffb648" },
    { name: "Healthy", value: healthy, color: "#22c55e" },
  ];

  return (
    <div className="panel">
      <div className="panel-title">Host Health</div>
      <div className="panel-subtitle soft-bottom">
        Current health status for monitored endpoints
      </div>

      <div className="chart-box">
        <ResponsiveContainer width="100%" height={260}>
          <PieChart>
            <Pie data={data} dataKey="value" nameKey="name" outerRadius={88} innerRadius={46} label>
              {data.map((entry, index) => (
                <Cell key={index} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip {...chartTooltipStyle()} />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

function MitreTacticsChart({ telemetry }) {
  const grouped = telemetry.reduce((acc, item) => {
    const key = getMitreTactic(item) || "Unknown";
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});

  const palette = ["#4f8cff", "#22c55e", "#ffb648", "#ff5d73", "#8b5cf6", "#06b6d4"];

  const data = Object.entries(grouped)
    .map(([name, value], index) => ({
      name,
      value,
      color: palette[index % palette.length],
    }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 6);

  return (
    <div className="panel">
      <div className="panel-title">MITRE Tactics</div>
      <div className="panel-subtitle soft-bottom">
        Most common ATT&CK tactics seen in telemetry
      </div>

      <div className="chart-box">
        <ResponsiveContainer width="100%" height={260}>
          <PieChart>
            <Pie data={data} dataKey="value" nameKey="name" outerRadius={88} innerRadius={46} label>
              {data.map((entry, index) => (
                <Cell key={index} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip {...chartTooltipStyle()} />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

function IncidentOverview({ telemetry, onOpenEvent, onStatusChange }) {
  const incidents = telemetry.filter((item) => {
    if (!item?.id) return false;

    const severity = String(getSeverity(item) || "").toLowerCase();
    const status = getIncidentStatus(item);
    const riskScore = getRiskNumber(item);

    return (
      riskScore > 30 ||
      severity === "medium" ||
      severity === "high" ||
      severity === "critical" ||
      status === "Investigating" ||
      status === "Resolved" ||
      status === "False Positive"
    );
  });

  const latestSecurityEvents = telemetry
    .filter((item) => item?.id)
    .sort(
      (a, b) =>
        (parseDateValue(b.timestamp)?.getTime() ?? 0) -
        (parseDateValue(a.timestamp)?.getTime() ?? 0)
    )
    .slice(0, 6);

  const counts = {
    New: incidents.filter((i) => getIncidentStatus(i) === "New").length,
    Investigating: incidents.filter((i) => getIncidentStatus(i) === "Investigating").length,
    Resolved: incidents.filter((i) => getIncidentStatus(i) === "Resolved").length,
    "False Positive": incidents.filter((i) => getIncidentStatus(i) === "False Positive").length,
  };

  const latestIncidents = [...incidents]
    .sort(
      (a, b) =>
        (parseDateValue(b.timestamp)?.getTime() ?? 0) -
        (parseDateValue(a.timestamp)?.getTime() ?? 0)
    )
    .slice(0, 8);

  const rowsToShow = latestIncidents.length ? latestIncidents : latestSecurityEvents;

  return (
    <div className="panel incident-overview-panel">
      <div className="panel-header">
        <div>
          <div className="panel-title">Incident Overview</div>
          <div className="panel-subtitle">
            Medium+ incidents are prioritized. Low telemetry remains available in Telemetry.
          </div>
        </div>

        <div className={incidents.length ? "badge medium" : "badge low"}>
          {incidents.length} prioritized incidents
        </div>
      </div>

      <div className="incident-kpis">
        <div className="incident-kpi status-new">
          <div className="incident-kpi-label">New</div>
          <div className="incident-kpi-value">{counts.New}</div>
        </div>

        <div className="incident-kpi status-investigating">
          <div className="incident-kpi-label">Investigating</div>
          <div className="incident-kpi-value">{counts.Investigating}</div>
        </div>

        <div className="incident-kpi status-resolved">
          <div className="incident-kpi-label">Resolved</div>
          <div className="incident-kpi-value">{counts.Resolved}</div>
        </div>

        <div className="incident-kpi status-false-positive">
          <div className="incident-kpi-label">False Positive</div>
          <div className="incident-kpi-value">{counts["False Positive"]}</div>
        </div>
      </div>

      {!rowsToShow.length ? (
        <div className="empty-state compact-empty">
          <div className="empty-state-icon">✓</div>
          <div className="empty-state-title">No incidents detected</div>
          <div className="empty-state-text">
            System is clean. No telemetry incidents found.
          </div>
        </div>
      ) : (
        <>
          {!latestIncidents.length ? (
            <div className="overview-info-banner">
              No medium or high incidents right now. Showing latest low-risk telemetry for situational awareness.
            </div>
          ) : null}

          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Host</th>
                  <th>Alert</th>
                  <th>Risk</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th></th>
                </tr>
              </thead>

              <tbody>
                {rowsToShow.map((item) => {
                  const severity = getSeverity(item);

                  return (
                    <tr key={item.id} className={`row-${getSeverityClass(severity)}`}>
                      <td>{formatDateTime(item.timestamp)}</td>

                      <td>
                        <strong>{item.hostname || "-"}</strong>
                      </td>

                      <td>{getAlertType(item)}</td>

                      <td>
                        <span className={`badge ${getRiskClass(getRiskNumber(item))}`}>
                          {getRiskNumber(item)}
                        </span>
                      </td>

                      <td>
                        <span className={`badge ${getSeverityClass(severity)}`}>
                          {getSeverityLabel(severity)}
                        </span>
                      </td>

                      <td style={{ minWidth: 160 }}>
                        <IncidentStatusSelect
                          item={item}
                          onStatusChange={onStatusChange}
                        />
                      </td>

                      <td>
                        <button
                          className="small-button"
                          onClick={() => onOpenEvent(item)}
                          type="button"
                        >
                          View
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}

function IncidentsPage({ telemetry, onOpenEvent, onStatusChange }) {
  const [severityFilter, setSeverityFilter] = useState("All");
  const [statusFilter, setStatusFilter] = useState("All");
  const [hostFilter, setHostFilter] = useState("All");

  const allIncidents = useMemo(
    () =>
      telemetry
        .filter((item) => {
          if (!item?.id) return false;

          const severity = String(getSeverity(item) || "").toLowerCase();
          const riskScore = getRiskNumber(item);

          return (
            severity === "medium" ||
            severity === "high" ||
            severity === "critical" ||
            riskScore > 30
          );
        })
        .sort(
          (a, b) =>
            (parseDateValue(b.timestamp)?.getTime() ?? 0) -
            (parseDateValue(a.timestamp)?.getTime() ?? 0)
        ),
    [telemetry]
  );

  const hosts = useMemo(
    () =>
      [...new Set(allIncidents.map((item) => item.hostname).filter(Boolean))]
        .sort((a, b) => String(a).localeCompare(String(b))),
    [allIncidents]
  );

  const incidents = allIncidents.filter((item) => {
    const severity = getSeverityLabel(getSeverity(item));
    const status = getIncidentStatus(item);
    const host = item?.hostname || "";

    return (
      (severityFilter === "All" || severity === severityFilter) &&
      (statusFilter === "All" || status === statusFilter) &&
      (hostFilter === "All" || host === hostFilter)
    );
  });

  const stats = {
    total: incidents.length,
    newCount: incidents.filter((item) => getIncidentStatus(item) === "New").length,
    investigating: incidents.filter(
      (item) => getIncidentStatus(item) === "Investigating"
    ).length,
    resolved: incidents.filter((item) => getIncidentStatus(item) === "Resolved").length,
    falsePositive: incidents.filter(
      (item) => getIncidentStatus(item) === "False Positive"
    ).length,
  };

  return (
    <>
      <div className="grid incident-kpi-grid">
        <SummaryCard title="Total Incidents" value={stats.total} subtitle="Medium severity and above" />
        <SummaryCard title="New" value={stats.newCount} subtitle="Awaiting review" />
        <SummaryCard title="Investigating" value={stats.investigating} subtitle="Active investigation" />
        <SummaryCard title="Resolved" value={stats.resolved} subtitle="Closed incidents" />
        <SummaryCard title="False Positive" value={stats.falsePositive} subtitle="Dismissed alerts" />
      </div>

      <div className="panel incident-overview-panel">
        <div className="panel-title">Incident Management</div>
        <div className="panel-subtitle soft-bottom">
          Review, classify, and investigate incident lifecycle. Showing Medium / High / Critical only.
        </div>

        <EventFilters
          severityFilter={severityFilter}
          setSeverityFilter={setSeverityFilter}
          statusFilter={statusFilter}
          setStatusFilter={setStatusFilter}
          hostFilter={hostFilter}
          setHostFilter={setHostFilter}
          hosts={hosts}
        />

        {!incidents.length ? (
          <div className="empty-state compact-empty">
            <div className="empty-state-icon">i</div>
            <div className="empty-state-title">No matching incidents</div>
            <div className="empty-state-text">
              No incidents match the selected severity, status, and host filters.
            </div>
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>time</th>
                  <th>host</th>
                  <th>alert</th>
                  <th>category</th>
                  <th>severity</th>
                  <th>source</th>
                  <th>decoded</th>
                  <th>mitre tactic</th>
                  <th>status</th>
                  <th>reason</th>
                  <th>details</th>
                </tr>
              </thead>
              <tbody>
                {incidents.map((item) => (
                  <tr key={item.id}>
                    <td>{formatDateTime(item.timestamp)}</td>
                    <td>{item.hostname || "-"}</td>
                    <td>{getIncidentAlertLabel(item)}</td>
                    <td>{getDisplayEventCategory(item)}</td>
                    <td>
                      <span className={`badge ${getSeverityClass(getSeverity(item))}`}>
                        {getSeverityLabel(getSeverity(item))}
                      </span>
                    </td>
                    <td>{getDetectionSource(item)}</td>
                    <td>
                      <span className={`badge ${hasRealDecodedCommand(item) ? "medium" : "low"}`}>
                        {hasRealDecodedCommand(item) ? "Yes" : "No"}
                      </span>
                    </td>
                    <td>{getMitreTactic(item)}</td>
                    <td style={{ minWidth: 170 }}>
                      <IncidentStatusSelect item={item} onStatusChange={onStatusChange} />
                    </td>
                    <td>{getCompactReason(item)}</td>
                    <td>
                      <button className="small-button" onClick={() => onOpenEvent(item)} type="button">
                        View
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}


function ResponseSummaryPanel({ stats, highestRisk, responseActions }) {
  const totalActions =
    Number(stats.pending_actions ?? 0) +
    Number(stats.executed_actions ?? 0) +
    Number(stats.failed_actions ?? 0);

  const executed = Number(stats.executed_actions ?? 0);
  const failed = Number(stats.failed_actions ?? 0);
  const successRate = totalActions ? Math.round((executed / totalActions) * 100) : 0;

  const latestAction = safeArray(responseActions)
    .sort(
      (a, b) =>
        (parseDateValue(b.requested_at)?.getTime() ?? 0) -
        (parseDateValue(a.requested_at)?.getTime() ?? 0)
    )[0];

  return (
    <div className="panel response-summary-panel">
      <div className="panel-header soft-bottom">
        <div>
          <div className="panel-title">Response Summary</div>
          <div className="panel-subtitle">
            Current response workflow health and action readiness
          </div>
        </div>
        <span className={failed ? "badge high" : "badge low"}>
          {failed ? "Needs review" : "Healthy"}
        </span>
      </div>

      <div className="summary-stack response-summary-stack">
        <SummaryCard
          title="Total Actions"
          value={totalActions}
          subtitle="All response workflows"
        />
        <SummaryCard
          title="Pending"
          value={stats.pending_actions ?? 0}
          subtitle="Awaiting agent pickup"
        />
        <SummaryCard
          title="Success Rate"
          value={`${successRate}%`}
          subtitle={totalActions ? "Executed / total" : "No actions yet"}
        />
        <SummaryCard
          title="Highest Risk"
          value={highestRisk}
          subtitle="Maximum score"
        />
      </div>

      <div className="overview-response-footer">
        <span className="badge low">Executed: {executed}</span>
        <span className={failed ? "badge high" : "badge low"}>Failed: {failed}</span>
        <span className="overview-muted">
          Latest: {latestAction ? `${getResponseActionLabel(latestAction.action_type)} · ${formatDateTime(latestAction.requested_at)}` : "No response actions yet"}
        </span>
      </div>
    </div>
  );
}

function DashboardApp({ session, onLogout }) {
  const [stats, setStats] = useState({});
  const [agents, setAgents] = useState([]);
  const [telemetry, setTelemetry] = useState([]);
  const [liveEvents, setLiveEvents] = useState([]);
  const [responseActions, setResponseActions] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [activeView, setActiveView] = useState("Overview");
  const [openedEvent, setOpenedEvent] = useState(null);
  const [openedAgent, setOpenedAgent] = useState(null);
  const socketRef = useRef(null);
  const reconnectTimerRef = useRef(null);
  const isMountedRef = useRef(true);

  const loadLiveEvents = useCallback(async () => {
    try {
      const data = await getLiveEvents(100);
      if (!isMountedRef.current) return;

      setLiveEvents(
        fastSortByNewest(
          deduplicateById(safeArray(data), "timestamp"),
          "timestamp"
        ).slice(0, 100)
      );
    } catch {
      //
    }
  }, []);

  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      setError("");
      const [statsData, agentsData, telemetryData, responseActionsData] =
        await Promise.all([
          getStats(),
          getAgents(),
          getTelemetry(),
          getResponseActions(),
        ]);

      if (!isMountedRef.current) return;

      setStats(statsData || {});
      setAgents(safeArray(agentsData));
      setTelemetry(
        fastSortByNewest(
          deduplicateById(safeArray(telemetryData), "id"),
          "timestamp"
        ).slice(0, 300)
      );
      setResponseActions(
        fastSortByNewest(
          deduplicateById(safeArray(responseActionsData), "id"),
          "requested_at"
        )
      );

      await loadLiveEvents();
    } catch (err) {
      if (!isMountedRef.current) return;

      if (err?.status === 401) {
        onLogout();
        return;
      }

      setError(
        err?.response?.data?.detail ||
        err?.message ||
        "Backend connection failed"
      );
    } finally {
      if (isMountedRef.current) {
        setLoading(false);
      }
    }
  }, [loadLiveEvents, onLogout]);

  useEffect(() => {
    isMountedRef.current = true;
    loadData();
    const interval = setInterval(() => {
      loadData();
    }, 5000);

    let socket;

    const refreshAgents = async () => {
      try {
        const data = await getAgents();
        if (isMountedRef.current) {
          setAgents(safeArray(data));
        }
      } catch {
        //
      }
    };

    const connect = () => {
      socket = createLiveSocket();
      if (!socket) return;

      socketRef.current = socket;

      socket.onopen = () => {
        if (!isMountedRef.current) return;

        setError("");

        try {
          socket.send("ping");
        } catch {
          //
        }

        socket._pingTimer = setInterval(() => {
          try {
            socket.send("ping");
          } catch {
            clearInterval(socket._pingTimer);
          }
        }, 20000);
      };

      socket.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);

          if (payload.type === "live_event_created") {
            setLiveEvents((prev) =>
              fastSortByNewest(
                deduplicateById([payload.data, ...prev], "timestamp"),
                "timestamp"
              ).slice(0, 100)
            );

            refreshAgents();
          }

          if (payload.type === "telemetry_created") {
            setTelemetry((prev) =>
              fastSortByNewest(
                deduplicateById([payload.data, ...prev], "id"),
                "timestamp"
              ).slice(0, 300)
            );

            refreshAgents();
          }

          if (payload.type === "telemetry_updated") {
            setTelemetry((prev) =>
              fastSortByNewest(
                prev.map((x) => (x.id === payload.data.id ? payload.data : x)),
                "timestamp"
              )
            );

            setOpenedEvent((prev) =>
              prev && prev.id === payload.data.id ? payload.data : prev
            );

            refreshAgents();
          }

          if (payload.type === "response_action_created") {
            setResponseActions((prev) =>
              fastSortByNewest(
                deduplicateById([payload.data, ...prev], "id"),
                "requested_at"
              )
            );
          }

          if (payload.type === "response_action_updated") {
            setResponseActions((prev) =>
              fastSortByNewest(
                prev.map((x) => (x.id === payload.data.id ? payload.data : x)),
                "requested_at"
              )
            );
          }

          if (payload.type === "stats_updated") {
            setStats(payload.data || {});
          }
        } catch {
          //
        }
      };

      socket.onclose = () => {
        if (!isMountedRef.current) return;
        reconnectTimerRef.current = setTimeout(connect, 3000);
      };

      socket.onerror = () => {
        try {
          socket.close();
        } catch {
          //
        }
      };
    };

    connect();

    return () => {
      isMountedRef.current = false;

      try {
        if (socketRef.current?._pingTimer) {
          clearInterval(socketRef.current._pingTimer);
        }
        if (socketRef.current) {
          socketRef.current.close();
        }
      } catch {
        //
      }

      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
      }
      clearInterval(interval); // 🔥 هون أضيفيها
    };
  }, [loadData]);

  const handleStatusChange = async (id, newStatus) => {
    try {
      await updateIncidentStatus(id, newStatus);
    } catch (err) {
      setError(
        err?.response?.data?.detail ||
        err?.message ||
        "Failed to update incident status."
      );
    }
  };

  const handleCreateResponseAction = async (payload) => {
    try {
      await createResponseAction(payload);
    } catch (err) {
      setError(
        err?.response?.data?.detail ||
        err?.message ||
        "Failed to create response action."
      );
    }
  };

  const handleExportCsv = async () => {
    try {
      await exportTelemetryCsv();
    } catch (err) {
      setError(
        err?.response?.data?.detail ||
        err?.message ||
        "Failed to export CSV report."
      );
    }
  };

  const handleExportPdf = async () => {
    try {
      await exportPdfReport();
    } catch (err) {
      setError(
        err?.response?.data?.detail ||
        err?.message ||
        "Failed to export PDF report."
      );
    }
  };

  const highestRisk = useMemo(() => {
    if (!telemetry.length) return 0;
    return telemetry.reduce(
      (max, item) => Math.max(max, getRiskNumber(item)),
      0
    );
  }, [telemetry]);

  const dashboardContent = (
    <>
      <div className="grid overview-kpi-grid">
        <SummaryCard
          title="Connected Hosts"
          value={stats.connected_hosts ?? 0}
          subtitle="Registered endpoints"
        />
        <SummaryCard
          title="Total Events"
          value={stats.total_events ?? telemetry.length ?? 0}
          subtitle="Stored telemetry records"
        />
        <SummaryCard
          title="Critical Alerts"
          value={stats.critical_alerts ?? 0}
          subtitle="Risk score 81-100"
        />
        <SummaryCard
          title="Medium Alerts"
          value={telemetry.filter((item) => getRiskNumber(item) > 30 && getRiskNumber(item) <= 60).length}
          subtitle="Risk score 31-60"
        />
        <SummaryCard
          title="Low Alerts"
          value={stats.low_alerts ?? 0}
          subtitle="Risk score 0-30"
        />
        <SummaryCard
          title="Open Incidents"
          value={stats.investigating_incidents ?? 0}
          subtitle="Under investigation"
        />
        <SummaryCard
          title="Live Events"
          value={stats.live_events_count ?? liveEvents.length ?? 0}
          subtitle="Recent real-time detections"
        />
        <SummaryCard
          title="Backend Status"
          value="Online"
          subtitle={`Last update: ${formatDateTime(stats.server_time)}`}
        />
      </div>

      <div className="charts-grid overview-charts-grid">
        <RiskDistributionChart telemetry={telemetry} />
        <HostHealthChart agents={agents} />
        <MitreTacticsChart telemetry={telemetry} />
      </div>

      <IncidentOverview
        telemetry={telemetry}
        onOpenEvent={setOpenedEvent}
        onStatusChange={handleStatusChange}
      />

      <div className="dashboard-row-balanced overview-row">
        <div className="panel-span-large">
          <TopRiskyHostsPanel agents={agents} onOpenAgent={setOpenedAgent} />
        </div>
        <div className="panel-span-small">
          <CriticalAlertsPanel
            telemetry={telemetry}
            onOpenEvent={setOpenedEvent}
            onStatusChange={handleStatusChange}
          />
        </div>
      </div>

      <div className="dashboard-row-balanced overview-row">
        <div className="panel-span-large">
          <LiveActivityFeed
            liveEvents={liveEvents}
            responseActions={responseActions}
          />
        </div>
        <div className="panel-span-small">
          <ResponseSummaryPanel
            stats={stats}
            highestRisk={highestRisk}
            responseActions={responseActions}
          />
        </div>
      </div>
    </>
  );

  return (
    <div className="layout">
      <Sidebar activeView={activeView} setActiveView={setActiveView} />

      <main className="main">
        <div className="topbar">
          <div>
            <h1>
              {activeView === "Overview"
                ? "Security Overview"
                : activeView === "Incidents"
                  ? "Incident Management"
                  : activeView}
            </h1>
            <p>
              {activeView === "Incidents"
                ? "Track incident status, review suspicious events, and manage investigation workflow."
                : "Real-time endpoint monitoring, telemetry analysis, MITRE mapping, and controlled incident response workflow."}
            </p>
          </div>

          <div className="topbar-actions">
            <span className="user-chip">{session?.username || "Analyst"}</span>
            <button className="button button-secondary" onClick={onLogout} type="button">
              Sign out
            </button>
            <ReportsMenu
              onExportCsv={handleExportCsv}
              onExportPdf={handleExportPdf}
            />
          </div>
        </div>

        {typeof error === "string" ? error : error?.message}
        {loading && (
          <div className="panel">
            <div className="panel-subtitle">Loading latest data...</div>
          </div>
        )}

        {activeView === "Overview" && dashboardContent}

        {activeView === "Incidents" && (
          <IncidentsPage
            telemetry={telemetry}
            onOpenEvent={setOpenedEvent}
            onStatusChange={handleStatusChange}
          />
        )}

        {activeView === "Agents" && (
          <AgentsTable data={agents} onOpenAgent={setOpenedAgent} />
        )}

        {activeView === "Telemetry" && (
          <TelemetryTable
            data={telemetry}
            onStatusChange={handleStatusChange}
            onOpenEvent={setOpenedEvent}
          />
        )}

        {activeView === "Response Actions" && (
          <ResponseActionsTable data={responseActions} />
        )}
      </main>

      {openedEvent && (
        <EventDetailsModal
          event={openedEvent}
          onClose={() => setOpenedEvent(null)}
          onStatusChange={handleStatusChange}
          onCreateAction={handleCreateResponseAction}
        />
      )}

      {openedAgent && (
        <AgentDetailsModal
          agent={openedAgent}
          telemetry={telemetry}
          responseActions={responseActions}
          onClose={() => setOpenedAgent(null)}
        />
      )}
    </div>
  );
}
