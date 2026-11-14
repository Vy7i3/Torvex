//! Self-contained HTML dashboard.
//!
//! One file, no external assets, no build step: the report JSON is embedded and
//! a small vanilla-JavaScript app renders it. Filtering, sorting, search and
//! expand/collapse all happen in the browser, so the report works from a USB
//! stick, an email attachment or `torvex serve`.
//!
//! The same template backs the web dashboard; `render_web` enables the scan form
//! and injects the per-process request token.

use crate::engine::ScanReport;

/// Renders a static report file.
pub fn render_report(report: &ScanReport) -> String {
    render(Some(report), false, "", None)
}

/// Renders the web dashboard, optionally with a report already loaded.
pub fn render_web(report: Option<&ScanReport>, token: &str, default_path: Option<&str>) -> String {
    render(report, true, token, default_path)
}

fn render(
    report: Option<&ScanReport>,
    web: bool,
    token: &str,
    default_path: Option<&str>,
) -> String {
    let data = match report {
        Some(report) => serde_json::to_string(report).unwrap_or_else(|_| "null".to_owned()),
        None => "null".to_owned(),
    };
    let data = safe_json_for_script(&data);
    let version = report
        .map(|report| report.version.clone())
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_owned());

    TEMPLATE
        .replace("__TORVEX_DATA__", &data)
        .replace("__TORVEX_WEB__", if web { "true" } else { "false" })
        .replace("__TORVEX_TOKEN__", token)
        .replace("__TORVEX_DEFAULT_PATH__", default_path.unwrap_or("."))
        .replace("__TORVEX_VERSION__", &version)
}

/// Escapes a JSON document for embedding inside a `<script>` element.
fn safe_json_for_script(json: &str) -> String {
    json.replace("</", "<\\/")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

const TEMPLATE: &str = r####"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>Torvex report</title>
<style>
  :root {
    --bg: #0a0e14;
    --panel: #111823;
    --panel-2: #16202c;
    --line: #22303f;
    --text: #e6edf6;
    --muted: #8fa3b8;
    --accent: #4cc9f0;
    --critical: #ff4d6d;
    --high: #ff8c42;
    --medium: #ffd166;
    --low: #4cc9f0;
    --info: #7f93a8;
    --ok: #4ade80;
    --radius: 12px;
    --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; }
  body {
    background: radial-gradient(1200px 600px at 10% -10%, #12202e 0%, var(--bg) 55%) no-repeat, var(--bg);
    color: var(--text);
    font: 15px/1.5 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    min-height: 100vh;
  }
  a { color: var(--accent); }
  .wrap { max-width: 1180px; margin: 0 auto; padding: 28px 22px 80px; }
  header.top { display: flex; align-items: baseline; gap: 14px; flex-wrap: wrap; margin-bottom: 6px; }
  .brand { font-size: 26px; font-weight: 750; letter-spacing: .14em; }
  .brand span { color: var(--accent); }
  .tag { font-size: 12px; color: var(--muted); border: 1px solid var(--line); padding: 3px 9px; border-radius: 999px; }
  .meta { color: var(--muted); font-size: 13px; }
  .meta strong { color: var(--text); font-weight: 600; }
  .toolbar { display: flex; gap: 8px; flex-wrap: wrap; margin: 18px 0 4px; }
  button, .btn {
    background: var(--panel-2); color: var(--text); border: 1px solid var(--line);
    padding: 8px 14px; border-radius: 9px; font: inherit; font-size: 13px; cursor: pointer;
  }
  button:hover, .btn:hover { border-color: var(--accent); color: var(--accent); }
  button.primary { background: var(--accent); color: #06131b; border-color: var(--accent); font-weight: 650; }
  button.primary:hover { filter: brightness(1.1); color: #06131b; }
  input[type=text] {
    background: var(--panel); color: var(--text); border: 1px solid var(--line);
    padding: 9px 12px; border-radius: 9px; font: inherit; font-size: 13px; min-width: 240px;
  }
  input[type=text]:focus { outline: 2px solid rgba(76,201,240,.35); border-color: var(--accent); }
  .grid { display: grid; gap: 14px; }
  .hero { grid-template-columns: 240px 1fr; align-items: stretch; margin-top: 18px; }
  @media (max-width: 820px) { .hero { grid-template-columns: 1fr; } }
  .card { background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius); padding: 18px; }
  .card h2 { font-size: 12px; letter-spacing: .12em; text-transform: uppercase; color: var(--muted); margin: 0 0 12px; font-weight: 650; }
  .ringcard { display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 6px; }
  .ring { position: relative; width: 168px; height: 168px; }
  .ring svg { transform: rotate(-90deg); width: 100%; height: 100%; }
  .ring circle { fill: none; stroke-width: 11; }
  .ring .bg { stroke: #1b2836; }
  .ring .fg { stroke-linecap: round; transition: stroke-dashoffset .8s ease; filter: drop-shadow(0 0 8px rgba(76,201,240,.35)); }
  .ring .value { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; }
  .ring .value b { font-size: 38px; line-height: 1; font-weight: 700; }
  .ring .value small { color: var(--muted); font-size: 11px; letter-spacing: .1em; text-transform: uppercase; }
  .kpis { display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: 12px; }
  @media (max-width: 720px) { .kpis { grid-template-columns: repeat(2, minmax(0,1fr)); } }
  .kpi { background: var(--panel-2); border: 1px solid var(--line); border-radius: 10px; padding: 12px 14px; }
  .kpi b { display: block; font-size: 24px; font-weight: 700; }
  .kpi small { color: var(--muted); font-size: 11px; letter-spacing: .08em; text-transform: uppercase; }
  .bar { height: 8px; border-radius: 999px; background: #1b2836; overflow: hidden; display: flex; margin-top: 10px; }
  .bar i { display: block; height: 100%; }
  .legend { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 10px; color: var(--muted); font-size: 12px; }
  .legend span { display: inline-flex; align-items: center; gap: 6px; }
  .dot { width: 9px; height: 9px; border-radius: 50%; display: inline-block; }
  .filters { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin: 22px 0 10px; }
  .chip {
    border: 1px solid var(--line); background: transparent; color: var(--muted);
    padding: 5px 11px; border-radius: 999px; font-size: 12px; cursor: pointer;
  }
  .chip[aria-pressed=true] { color: var(--text); border-color: var(--accent); background: rgba(76,201,240,.08); }
  .chip .count { opacity: .65; margin-left: 5px; font-variant-numeric: tabular-nums; }
  .spacer { flex: 1; }
  details.finding {
    background: var(--panel); border: 1px solid var(--line); border-left: 3px solid var(--line);
    border-radius: 10px; margin-bottom: 9px; overflow: hidden;
  }
  details.finding[open] { background: var(--panel-2); }
  details.finding > summary {
    list-style: none; cursor: pointer; padding: 13px 15px; display: grid;
    grid-template-columns: 92px 1fr auto; gap: 12px; align-items: center;
  }
  details.finding > summary::-webkit-details-marker { display: none; }
  .sev {
    font-size: 11px; font-weight: 700; letter-spacing: .07em; text-transform: uppercase;
    padding: 4px 8px; border-radius: 6px; text-align: center; border: 1px solid currentColor;
  }
  .sev.critical { color: var(--critical); background: rgba(255,77,109,.10); }
  .sev.high { color: var(--high); background: rgba(255,140,66,.10); }
  .sev.medium { color: var(--medium); background: rgba(255,209,102,.10); }
  .sev.low { color: var(--low); background: rgba(76,201,240,.10); }
  .sev.info { color: var(--info); background: rgba(127,147,168,.10); }
  .ftitle { font-weight: 600; }
  .fsub { color: var(--muted); font-size: 12.5px; margin-top: 2px; word-break: break-all; font-family: var(--mono); }
  .fid { color: var(--muted); font-size: 11.5px; font-family: var(--mono); white-space: nowrap; }
  .body { padding: 0 16px 16px 16px; border-top: 1px solid var(--line); margin-top: 2px; padding-top: 14px; }
  .body p { margin: 0 0 12px; color: #c6d4e4; }
  .kv { display: grid; grid-template-columns: 130px 1fr; gap: 6px 14px; font-size: 13px; }
  .kv dt { color: var(--muted); }
  .kv dd { margin: 0; }
  .pills { display: flex; flex-wrap: wrap; gap: 6px; }
  .pill { font-size: 11px; font-family: var(--mono); border: 1px solid var(--line); color: var(--muted); padding: 2px 7px; border-radius: 5px; }
  .fix { border-left: 2px solid var(--ok); padding: 2px 0 2px 12px; color: #cfe9d8; margin-top: 12px; font-size: 13.5px; }
  .fix b { color: var(--ok); }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; color: var(--muted); font-weight: 600; font-size: 11px; letter-spacing: .08em; text-transform: uppercase; padding: 8px 10px; border-bottom: 1px solid var(--line); }
  td { padding: 9px 10px; border-bottom: 1px solid #1a2532; vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  code, .mono { font-family: var(--mono); font-size: 12.5px; }
  .truncate { max-width: 430px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .catgrid { display: grid; grid-template-columns: repeat(auto-fill, minmax(215px, 1fr)); gap: 10px; }
  .cat { background: var(--panel-2); border: 1px solid var(--line); border-radius: 9px; padding: 11px 12px; }
  .cat .row { display: flex; justify-content: space-between; font-size: 13px; }
  .cat .score { font-variant-numeric: tabular-nums; font-weight: 650; }
  .cat .mini { height: 5px; background: #1b2836; border-radius: 999px; margin-top: 8px; overflow: hidden; }
  .cat .mini i { display: block; height: 100%; background: var(--accent); }
  .empty { border: 1px dashed var(--line); border-radius: 10px; padding: 26px; text-align: center; color: var(--muted); }
  .notice { border: 1px solid #3a2b12; background: #1d1608; color: #ffd79a; padding: 10px 13px; border-radius: 9px; font-size: 13px; margin-bottom: 14px; }
  .danger { border-color: #3d1a23; background: #1d0e13; color: #ffc2cf; }
  footer { margin-top: 34px; color: var(--muted); font-size: 12px; line-height: 1.7; border-top: 1px solid var(--line); padding-top: 16px; }
  .hidden { display: none !important; }
  @media print {
    body { background: #fff; color: #111; }
    .toolbar, .filters, button { display: none !important; }
    .card, details.finding, .cat { border-color: #ccc; background: #fff; }
    .meta, .fsub, .fid, .kpi small { color: #444; }
    .sev { border-color: #666; }
  }
</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <div class="brand">TORVE<span>X</span></div>
    <div class="tag">v__TORVEX_VERSION__</div>
    <div class="tag">local-first</div>
    <div class="tag">not an antivirus</div>
  </header>
  <div class="meta" id="meta">Loading report…</div>

  <div class="toolbar" id="toolbar">
    <button class="btn" onclick="window.print()">Print / PDF</button>
    <button class="btn" onclick="downloadJson()">Download JSON</button>
    <button class="btn" onclick="toggleAll(true)">Expand all</button>
    <button class="btn" onclick="toggleAll(false)">Collapse all</button>
  </div>

  <div class="toolbar hidden" id="scanform">
    <input type="text" id="scanpath" placeholder="File or directory to scan" value="__TORVEX_DEFAULT_PATH__">
    <label class="chip"><input type="checkbox" id="eng-yara" checked> YARA</label>
    <label class="chip"><input type="checkbox" id="eng-native" checked> Native</label>
    <label class="chip"><input type="checkbox" id="eng-audit"> Host audit</label>
    <button class="primary" id="scanbtn" onclick="runScan()">Scan</button>
    <span class="meta" id="scanstatus"></span>
  </div>

  <div id="app"></div>

  <footer>
    <strong>How to read this report.</strong> Risk is <code>min(100, Σ severity points)</code> with
    critical 35, high 18, medium 7, low 2 and info 0; demo fixtures score 0. The host hardening
    index is earned points over available points for applicable controls, so it is relative to
    this host and policy — never a percentage of “security”. ATT&amp;CK and compliance mappings
    are indicative, not a certification. A finding is evidence to review; a clean result only
    means that no loaded rule matched. Torvex is not an antivirus and does not quarantine,
    delete or repair anything.
  </footer>
</div>

<script>
const REPORT = __TORVEX_DATA__;
const WEB = __TORVEX_WEB__;
const TOKEN = "__TORVEX_TOKEN__";
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const SOURCES = ["yara", "native", "audit", "correlation"];
const COLORS = {
  critical: "#ff4d6d", high: "#ff8c42", medium: "#ffd166",
  low: "#4cc9f0", info: "#7f93a8"
};

const state = {
  severity: new Set(SEVERITIES),
  source: new Set(SOURCES),
  query: "",
  sort: "severity"
};

const el = (id) => document.getElementById(id);
const esc = (value) => String(value == null ? "" : value)
  .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
  .replace(/"/g, "&quot;").replace(/'/g, "&#39;");

function fmtBytes(bytes) {
  if (!bytes) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let value = bytes, unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; }
  return (value >= 10 ? value.toFixed(0) : value.toFixed(1)) + " " + units[unit];
}
function fmtDuration(ms) {
  if (ms == null) return "—";
  if (ms < 1000) return ms + " ms";
  if (ms < 60000) return (ms / 1000).toFixed(2) + " s";
  return Math.floor(ms / 60000) + " min " + Math.round((ms % 60000) / 1000) + " s";
}
function sevClass(value) { return SEVERITIES.includes(value) ? value : "info"; }
function riskColor(risk) {
  if (risk >= 71) return COLORS.critical;
  if (risk >= 46) return COLORS.high;
  if (risk >= 21) return COLORS.medium;
  return "#4ade80";
}

function render() {
  if (!REPORT) {
    el("meta").textContent = WEB
      ? "No scan loaded. Pick a path above to start."
      : "This report contains no data.";
    el("app").innerHTML = '<div class="empty">No scan data.</div>';
    return;
  }

  const s = REPORT.summary || {};
  const risk = s.risk_score || 0;
  const findings = REPORT.findings || [];
  const audit = REPORT.audit || null;

  el("meta").innerHTML =
    "Scanned <strong>" + esc(REPORT.root) + "</strong> · " +
    esc(s.scanned || 0) + " files · " + fmtBytes(s.bytes_scanned || 0) + " · " +
    fmtDuration(REPORT.duration_ms) + " · " +
    esc((REPORT.generated_at || "").replace("T", " ").replace("Z", " UTC")) +
    (s.errors ? ' · <span style="color:var(--high)">' + esc(s.errors) + " incomplete</span>" : "");

  const engines = [];
  if (REPORT.engines && REPORT.engines.yara) {
    const rules = REPORT.rules || {};
    engines.push("YARA " + (rules.rule_count || 0) + " rules" +
      (rules.demo_rule_count ? " (" + rules.demo_rule_count + " demo)" : ""));
  }
  if (REPORT.engines && REPORT.engines.native) engines.push("Native " + REPORT.engines.native_rules + " rules");
  if (REPORT.engines && REPORT.engines.audit) engines.push("Host audit");
  if (REPORT.correlated) engines.push(REPORT.correlated + " correlated");

  const bySeverity = s.by_severity || {};
  const total = SEVERITIES.reduce((sum, key) => sum + (bySeverity[key] || 0), 0) || 1;
  const segments = SEVERITIES.map((key) =>
    '<i style="width:' + (((bySeverity[key] || 0) / total) * 100) + '%;background:' + COLORS[key] + '" title="' +
    esc(key) + ": " + (bySeverity[key] || 0) + '"></i>').join("");

  const dash = 2 * Math.PI * 52;
  const ring = '<div class="ringcard card">' +
    '<div class="ring"><svg viewBox="0 0 120 120">' +
    '<circle class="bg" cx="60" cy="60" r="52"></circle>' +
    '<circle class="fg" cx="60" cy="60" r="52" stroke="' + riskColor(risk) + '" ' +
    'stroke-dasharray="' + dash.toFixed(1) + '" stroke-dashoffset="' +
    (dash - dash * Math.min(100, risk) / 100).toFixed(1) + '"></circle></svg>' +
    '<div class="value"><b>' + risk + '</b><small>risk / 100</small></div></div>' +
    '<div class="meta">' + esc(findings.length) + " findings</div></div>";

  const auditKpi = audit
    ? '<div class="kpi"><b style="color:' + (audit.score.index >= 70 ? "var(--ok)" : "var(--medium)") + '">' +
      audit.score.index + '<span style="font-size:13px;color:var(--muted)">/100</span></b><small>hardening · grade ' +
      esc(audit.score.grade) + '</small></div>'
    : '<div class="kpi"><b style="color:var(--muted)">—</b><small>hardening (audit off)</small></div>';

  const kpis = '<div class="card"><h2>Severity distribution</h2>' +
    '<div class="kpis">' +
    '<div class="kpi"><b>' + esc(s.scanned || 0) + '</b><small>files scanned</small></div>' +
    '<div class="kpi"><b>' + esc(findings.length) + '</b><small>findings</small></div>' +
    '<div class="kpi"><b>' + esc(REPORT.correlated || 0) + '</b><small>correlated</small></div>' +
    auditKpi + '</div>' +
    '<div class="bar">' + segments + '</div>' +
    '<div class="legend">' + SEVERITIES.map((key) =>
      '<span><i class="dot" style="background:' + COLORS[key] + '"></i>' + key + " " +
      (bySeverity[key] || 0) + "</span>").join("") + '</div>' +
    (s.suspicious ? '<div class="meta" style="margin-top:10px">' + esc(s.suspicious) + " of " + esc(s.scanned) +
      " files matched at least one content rule.</div>" : "") +
    '</div>';

  el("app").innerHTML =
    (REPORT.rules && REPORT.rules.demo_rule_count > 0
      ? '<div class="notice">' + esc(REPORT.rules.demo_rule_count) + " of " + esc(REPORT.rules.rule_count) +
        " loaded YARA rules are demo fixtures. Matches from them are test data, not detection content.</div>"
      : "") +
    (REPORT.audit_error ? '<div class="notice danger">Host audit did not run: ' + esc(REPORT.audit_error) + "</div>" : "") +
    '<div class="grid hero">' + ring + kpis + '</div>' +
    '<div class="meta" style="margin-top:12px">' + engines.map(esc).join(" · ") + '</div>' +
    '<div class="filters" id="filters"></div>' +
    '<div id="findings"></div>' +
    (audit ? renderAudit(audit) : "") +
    renderFiles() +
    renderFailures();

  renderFilters();
  renderFindings();
}

function countFor(kind, value) {
  const findings = REPORT.findings || [];
  if (kind === "severity") return findings.filter((f) => f.severity === value).length;
  if (kind === "source") return findings.filter((f) => f.source === value).length;
  return 0;
}

function renderFilters() {
  const findings = REPORT.findings || [];
  const chip = (kind, value, active, count) =>
    '<button class="chip" aria-pressed="' + active + '" data-kind="' + kind + '" data-value="' + value + '">' +
    esc(value) + '<span class="count">' + count + "</span></button>";

  const severityChips = SEVERITIES.map((value) =>
    chip("severity", value, state.severity.has(value), countFor("severity", value))).join("");
  const sourceChips = SOURCES.filter((value) => countFor("source", value) > 0)
    .map((value) => chip("source", value, state.source.has(value), countFor("source", value))).join("");

  el("filters").innerHTML =
    '<input type="text" id="search" placeholder="Search id, title, path, tag…" value="' + esc(state.query) + '">' +
    severityChips + sourceChips +
    '<span class="spacer"></span>' +
    '<select id="sort" class="btn">' +
    ["severity", "id", "target", "source"].map((value) =>
      '<option value="' + value + '"' + (state.sort === value ? " selected" : "") + ">sort: " + value + "</option>").join("") +
    "</select>" +
    '<span class="meta" id="shown">' + findings.length + " shown</span>";

  el("search").addEventListener("input", (event) => {
    state.query = event.target.value.toLowerCase();
    renderFindings();
  });
  el("sort").addEventListener("change", (event) => {
    state.sort = event.target.value;
    renderFindings();
  });
  el("filters").querySelectorAll(".chip").forEach((button) => {
    button.addEventListener("click", () => {
      const kind = button.dataset.kind;
      const value = button.dataset.value;
      const set = kind === "severity" ? state.severity : state.source;
      if (set.has(value)) set.delete(value); else set.add(value);
      renderFilters();
      renderFindings();
    });
  });
}

function visibleFindings() {
  const findings = (REPORT.findings || []).filter((finding) => {
    if (!state.severity.has(finding.severity)) return false;
    if (!state.source.has(finding.source)) return false;
    if (state.query) {
      const haystack = [finding.id, finding.title, finding.target, finding.description,
        (finding.tags || []).join(" "), (finding.mitre || []).join(" "),
        (finding.compliance || []).join(" ")].join(" ").toLowerCase();
      if (!haystack.includes(state.query)) return false;
    }
    return true;
  });
  const order = { severity: 0, id: 0, target: 0, source: 0 };
  findings.sort((a, b) => {
    if (state.sort === "id") return String(a.id).localeCompare(String(b.id));
    if (state.sort === "target") return String(a.target).localeCompare(String(b.target));
    if (state.sort === "source") return String(a.source).localeCompare(String(b.source));
    const rank = SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity);
    return rank !== 0 ? rank : String(a.id).localeCompare(String(b.id));
  });
  return findings;
}

function renderFindings() {
  const findings = visibleFindings();
  const shown = el("shown");
  if (shown) shown.textContent = findings.length + " shown";

  if (!findings.length) {
    const message = (REPORT.findings || []).length
      ? "No findings match the current filters."
      : "No findings. A clean result only means no loaded rule matched.";
    el("findings").innerHTML = '<div class="empty">' + esc(message) + "</div>";
    return;
  }

  el("findings").innerHTML = findings.map((finding, index) => {
    const evidence = (finding.evidence || []).map((entry) =>
      '<span class="pill">' + esc(entry.kind) + ": " + esc(entry.value) + "</span>").join(" ");
    const mitre = (finding.mitre || []).map((id) =>
      '<span class="pill">ATT&amp;CK ' + esc(id) + "</span>").join(" ");
    const compliance = (finding.compliance || []).map((id) =>
      '<span class="pill">' + esc(id) + "</span>").join(" ");
    const tags = (finding.tags || []).map((tag) =>
      '<span class="pill">#' + esc(tag) + "</span>").join(" ");

    return '<details class="finding" style="border-left-color:' + COLORS[sevClass(finding.severity)] + '">' +
      '<summary><span class="sev ' + sevClass(finding.severity) + '">' + esc(finding.severity) + "</span>" +
      '<span><div class="ftitle">' + esc(finding.title) +
      (finding.demo ? ' <span class="pill">demo</span>' : "") + "</div>" +
      '<div class="fsub">' + esc(finding.target || "—") + "</div></span>" +
      '<span class="fid">' + esc(finding.id) + " · " + esc(finding.source) + "</span></summary>" +
      '<div class="body">' +
      (finding.description ? "<p>" + esc(finding.description) + "</p>" : "") +
      '<dl class="kv">' +
      (evidence ? "<dt>Evidence</dt><dd>" + evidence + "</dd>" : "") +
      (mitre ? "<dt>ATT&amp;CK</dt><dd>" + mitre + "</dd>" : "") +
      (compliance ? "<dt>Compliance</dt><dd>" + compliance + "</dd>" : "") +
      (tags ? "<dt>Tags</dt><dd>" + tags + "</dd>" : "") +
      "<dt>Level</dt><dd>" + esc(finding.level) + " / 15</dd>" +
      (finding.related && finding.related.length
        ? "<dt>Correlated from</dt><dd>" + finding.related.map((entry) => '<span class="pill">' + esc(entry) + "</span>").join(" ") + "</dd>"
        : "") +
      "</dl>" +
      (finding.remediation ? '<div class="fix"><b>Fix</b> — ' + esc(finding.remediation) + "</div>" : "") +
      "</div></details>";
  }).join("");
}

function renderAudit(audit) {
  const categories = (audit.categories || []).map((category) => {
    const score = category.score == null ? 0 : category.score;
    return '<div class="cat"><div class="row"><strong>' + esc(category.id) + "</strong>" +
      '<span class="score">' + (category.score == null ? "n/a" : score) + "</span></div>" +
      '<div class="meta">' + esc(category.title) + " · " + esc(category.passed) + " ok, " +
      esc(category.failed) + " open</div>" +
      '<div class="mini"><i style="width:' + score + "%;background:" +
      (score >= 80 ? "var(--ok)" : score >= 60 ? "var(--medium)" : "var(--critical)") + '"></i></div></div>';
  }).join("");

  const failures = (audit.results || []).filter((control) => control.status === "failed")
    .sort((a, b) => (b.level || 0) - (a.level || 0));
  const rows = failures.map((control) =>
    "<tr><td><span class=\"sev " + sevClass(control.severity) + "\">" + esc(control.severity) + "</span></td>" +
    "<td><strong>" + esc(control.title) + "</strong><div class=\"fsub\">" + esc(control.evidence) + "</div></td>" +
    '<td class="mono">' + esc(control.id) + "</td>" +
    "<td>" + esc(control.remediation) + "</td></tr>").join("");

  return '<h2 style="margin:26px 0 12px;font-size:15px">Host hardening — ' +
    esc(audit.score.index) + "/100 (grade " + esc(audit.score.grade) + ") · policy " + esc(audit.policy) +
    " · " + esc(audit.root) + (audit.live ? " (live)" : " (snapshot)") + "</h2>" +
    '<div class="catgrid">' + categories + "</div>" +
    (rows ? '<div class="card" style="margin-top:14px"><h2>Open host warnings (' + failures.length + ')</h2>' +
      "<table><thead><tr><th>Severity</th><th>Control</th><th>ID</th><th>Remediation</th></tr></thead><tbody>" +
      rows + "</tbody></table></div>" : "");
}

function renderFiles() {
  const files = (REPORT.results || []).filter((file) => file.verdict === "suspicious");
  if (!files.length) return "";
  files.sort((a, b) => {
    const rank = (file) => SEVERITIES.length - SEVERITIES.indexOf(
      (file.matches && file.matches[0] && file.matches[0].severity) || "info");
    return rank(b) - rank(a);
  });
  const rows = files.map((file) => {
    const top = (file.matches && file.matches[0]) || {};
    const analysis = file.analysis || {};
    const rules = (file.matches || []).map((match) =>
      '<span class="pill">' + esc(match.id || match.rule) + " · " + esc(match.source || match.engine) + "</span>").join(" ");
    return "<tr><td><span class=\"sev " + sevClass(top.severity) + "\">" + esc(top.severity) + "</span></td>" +
      '<td class="mono truncate" title="' + esc(file.path) + '">' + esc(file.path) + "</td>" +
      "<td>" + fmtBytes(file.size) + "</td>" +
      "<td>" + esc(analysis.kind || file.file_type || "?") + "</td>" +
      '<td class="mono">' + (analysis.entropy != null ? Number(analysis.entropy).toFixed(2) : "—") + "</td>" +
      '<td class="mono">' + esc((file.sha256 || "").slice(0, 16)) + "…</td></tr>" +
      (rules ? '<tr><td></td><td colspan="5">' + rules + "</td></tr>" : "");
  }).join("");
  return '<div class="card" style="margin-top:14px"><h2>Files with findings (' + files.length + ')</h2>' +
    "<table><thead><tr><th>Top</th><th>Path</th><th>Size</th><th>Kind</th><th>Entropy</th><th>SHA-256</th></tr></thead><tbody>" +
    rows + "</tbody></table></div>";
}

function renderFailures() {
  const failures = REPORT.failures || [];
  if (!failures.length) return "";
  return '<div class="card" style="margin-top:14px"><h2>Incomplete — ' + failures.length + " entries not checked</h2>" +
    '<div class="meta" style="margin-bottom:10px">These entries were not fully scanned, so this report is not a clean result.</div>' +
    "<table><thead><tr><th>Stage</th><th>Path</th><th>Error</th></tr></thead><tbody>" +
    failures.map((failure) =>
      '<tr><td class="mono">' + esc(failure.kind) + '</td><td class="mono truncate">' + esc(failure.path) +
      "</td><td>" + esc(failure.error) + "</td></tr>").join("") +
    "</tbody></table></div>";
}

function toggleAll(open) {
  document.querySelectorAll("details.finding").forEach((node) => { node.open = open; });
}

function downloadJson() {
  if (!REPORT) return;
  const blob = new Blob([JSON.stringify(REPORT, null, 2)], { type: "application/json" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = "torvex-report.json";
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

async function runScan() {
  if (!WEB) return;
  const path = el("scanpath").value.trim();
  const status = el("scanstatus");
  const button = el("scanbtn");
  if (!path) { status.textContent = "Enter a path."; return; }

  button.disabled = true;
  status.textContent = "Scanning…";
  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Torvex-Token": TOKEN },
      body: JSON.stringify({
        path: path,
        yara: el("eng-yara").checked,
        native: el("eng-native").checked,
        audit: el("eng-audit").checked
      })
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || ("HTTP " + response.status));
    status.textContent = "Done: " + payload.summary.findings + " findings.";
    window.__report = payload;
    location.reload();
  } catch (error) {
    status.textContent = "Failed: " + error.message;
  } finally {
    button.disabled = false;
  }
}

if (WEB) {
  el("scanform").classList.remove("hidden");
  const path = new URLSearchParams(location.search).get("path");
  if (path) el("scanpath").value = path;
}
render();
</script>
</body>
</html>
"####;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{RuleSetInfo, ScanReport};
    use crate::findings::{Finding, Severity, Source};

    fn sample() -> ScanReport {
        let mut report = ScanReport::new("/tmp/sample".to_owned(), RuleSetInfo::default());
        report.findings.push(
            Finding::new(
                "TVX-NAT-008",
                "Interactive reverse shell",
                Severity::Critical,
                Source::Native,
                "/tmp/sample/run.sh",
            )
            .with_description("bash -i >& redirects an interactive shell")
            .with_remediation("Isolate the host."),
        );
        report.refresh_summary();
        report
    }

    #[test]
    fn report_embeds_data_and_no_external_assets() {
        let html = render_report(&sample());
        assert!(html.contains("TVX-NAT-008"));
        assert!(html.contains("/tmp/sample/run.sh"));
        assert!(html.starts_with("<!doctype html>"));
        assert!(!html.contains("http://"));
        assert!(!html.contains("https://cdn"));
        assert!(!html.contains("__TORVEX_DATA__"));
    }

    #[test]
    fn script_injection_is_neutralised() {
        let mut report = sample();
        report.findings.push(Finding::new(
            "</script><script>alert(1)</script>",
            "x",
            Severity::High,
            Source::Yara,
            "t",
        ));
        let html = render_report(&report);
        assert!(!html.contains("</script><script>alert(1)"));
        assert!(html.contains("<\\/script>"));
    }

    #[test]
    fn web_mode_injects_token_and_form() {
        let html = render_web(Some(&sample()), "abc123", Some("/tmp"));
        assert!(html.contains("const WEB = true;"));
        assert!(html.contains("abc123"));
        assert!(html.contains("runScan"));
    }

    #[test]
    fn static_mode_has_no_scan_form() {
        let html = render_report(&sample());
        assert!(html.contains("const WEB = false;"));
        assert!(html.contains("const TOKEN = \"\";"));
    }

    #[test]
    fn empty_report_renders() {
        let report = ScanReport::new(".".to_owned(), RuleSetInfo::default());
        let html = render_report(&report);
        assert!(html.contains("const REPORT = {"));
    }
}
