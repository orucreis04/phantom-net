const els = {
  total: document.querySelector("#total-events"),
  unique: document.querySelector("#unique-sources"),
  highRisk: document.querySelector("#high-risk"),
  redirected: document.querySelector("#redirected"),
  topIps: document.querySelector("#top-ips"),
  topTags: document.querySelector("#top-tags"),
  events: document.querySelector("#events"),
  refresh: document.querySelector("#refresh"),
  refreshMode: document.querySelector("#refresh-mode"),
  autoRefresh: document.querySelector("#auto-refresh"),
  clearFilters: document.querySelector("#clear-filters"),
  lastUpdated: document.querySelector("#last-updated"),
  sourceFilter: document.querySelector("#source-filter"),
  decisionFilter: document.querySelector("#decision-filter"),
  riskFilter: document.querySelector("#risk-filter"),
  reportPeriod: document.querySelector("#report-period"),
  reportBuckets: document.querySelector("#report-buckets"),
  reportIps: document.querySelector("#report-ips"),
  reportTypes: document.querySelector("#report-types"),
  exportJson: document.querySelector("#export-json"),
  exportCsv: document.querySelector("#export-csv"),
  refreshAi: document.querySelector("#refresh-ai"),
  saveAiReport: document.querySelector("#save-ai-report"),
  aiSeverity: document.querySelector("#ai-severity"),
  aiHeadline: document.querySelector("#ai-headline"),
  aiSummary: document.querySelector("#ai-summary"),
  aiFindings: document.querySelector("#ai-findings"),
  aiActions: document.querySelector("#ai-actions"),
  aiDecoy: document.querySelector("#ai-decoy"),
  aiReports: document.querySelector("#ai-reports"),
  detailEmpty: document.querySelector("#detail-empty"),
  detailContent: document.querySelector("#detail-content"),
  detailIp: document.querySelector("#detail-ip"),
  detailEvents: document.querySelector("#detail-events"),
  detailRisk: document.querySelector("#detail-risk"),
  detailRedirected: document.querySelector("#detail-redirected"),
  detailHighRisk: document.querySelector("#detail-high-risk"),
  detailFirst: document.querySelector("#detail-first"),
  detailLast: document.querySelector("#detail-last"),
  detailServices: document.querySelector("#detail-services"),
  detailTags: document.querySelector("#detail-tags"),
  detailMitre: document.querySelector("#detail-mitre"),
  detailTimeline: document.querySelector("#detail-timeline"),
  clearDetail: document.querySelector("#clear-detail"),
  createIncident: document.querySelector("#create-incident"),
  incidents: document.querySelector("#incidents"),
  adminAudit: document.querySelector("#admin-audit"),
  siemState: document.querySelector("#siem-state"),
  siemFormats: document.querySelector("#siem-formats"),
  siemTargets: document.querySelector("#siem-targets"),
};

let selectedSource = "";
let dashboardTimer = null;
let reportsTimer = null;
let aiTimer = null;
let incidentsTimer = null;

function cell(value) {
  const td = document.createElement("td");
  td.textContent = value === 0 ? "0" : value || "-";
  return td;
}

function riskPill(score) {
  const span = document.createElement("span");
  span.className = `pill ${score >= 70 ? "risk" : "ok"}`;
  span.textContent = score;
  return span;
}

function decisionPill(decision) {
  const span = document.createElement("span");
  span.className = `pill decision ${decision === "redirect_to_decoy" ? "risk" : "ok"}`;
  span.textContent = decision === "redirect_to_decoy" ? "Decoy" : "Observe";
  return span;
}

function tagList(tags) {
  if (!tags) return "-";
  return tags.split(",").filter(Boolean).join(", ");
}

function mitreList(techniques) {
  if (!Array.isArray(techniques) || !techniques.length) return "-";
  return techniques.map((technique) => `${technique.id} ${technique.name}`).join(", ");
}

function formatTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function renderRows(target, rows, columns) {
  target.replaceChildren();
  if (!rows.length) {
    const tr = document.createElement("tr");
    const td = cell("No data yet");
    td.colSpan = columns.length;
    tr.append(td);
    target.append(tr);
    return;
  }
  for (const row of rows) {
    const tr = document.createElement("tr");
    for (const column of columns) {
      const td = document.createElement("td");
      const value = row[column];
      if (column === "risk_score" || column === "max_risk") td.append(riskPill(Number(value || 0)));
      else td.textContent = value || "-";
      tr.append(td);
    }
    target.append(tr);
  }
}

function renderReportRows(target, rows, render) {
  target.replaceChildren();
  if (!rows.length) {
    const tr = document.createElement("tr");
    const td = cell("No report data");
    td.colSpan = 6;
    tr.append(td);
    target.append(tr);
    return;
  }
  for (const row of rows) target.append(render(row));
}

function renderTopSources(rows) {
  els.topIps.replaceChildren();
  if (!rows.length) {
    const tr = document.createElement("tr");
    const td = cell("No data yet");
    td.colSpan = 3;
    tr.append(td);
    els.topIps.append(tr);
    return;
  }

  for (const row of rows) {
    const tr = document.createElement("tr");
    if (row.source_ip === selectedSource) tr.classList.add("selected-row");
    const ip = document.createElement("button");
    ip.className = "link-button";
    ip.textContent = row.source_ip;
    ip.addEventListener("click", () => selectSource(row.source_ip));
    const ipCell = document.createElement("td");
    ipCell.append(ip);
    tr.append(ipCell, cell(row.count));
    const riskCell = document.createElement("td");
    riskCell.append(riskPill(Number(row.max_risk || 0)));
    tr.append(riskCell);
    els.topIps.append(tr);
  }
}

function updateExportLinks() {
  const params = new URLSearchParams(eventQuery());
  params.set("format", "json");
  els.exportJson.href = `/api/reports/export?${params.toString()}`;
  params.set("format", "csv");
  els.exportCsv.href = `/api/reports/export?${params.toString()}`;
}

async function loadReports() {
  const response = await fetch(`/api/reports/summary?period=${encodeURIComponent(els.reportPeriod.value)}&limit=14`);
  const report = await response.json();

  renderReportRows(els.reportBuckets, report.buckets, (row) => {
    const tr = document.createElement("tr");
    const riskCell = document.createElement("td");
    riskCell.append(riskPill(Number(row.max_risk || 0)));
    tr.append(
      cell(row.bucket),
      cell(row.total_events),
      cell(row.unique_sources),
      cell(row.high_risk_events),
      cell(row.redirected_events),
      riskCell
    );
    return tr;
  });

  renderReportRows(els.reportIps, report.risky_ips, (row) => {
    const tr = document.createElement("tr");
    const ipButton = document.createElement("button");
    ipButton.className = "link-button";
    ipButton.textContent = row.source_ip;
    ipButton.addEventListener("click", () => selectSource(row.source_ip));
    const ipCell = document.createElement("td");
    ipCell.append(ipButton);
    const riskCell = document.createElement("td");
    riskCell.append(riskPill(Number(row.max_risk || 0)));
    tr.append(ipCell, cell(row.total_events), cell(row.high_risk_events), riskCell);
    return tr;
  });

  renderReportRows(els.reportTypes, report.attack_types, (row) => {
    const tr = document.createElement("tr");
    tr.append(cell(row.type), cell(row.count));
    return tr;
  });
}

function renderList(target, items) {
  target.replaceChildren();
  if (!items.length) {
    const item = document.createElement("li");
    item.textContent = "-";
    target.append(item);
    return;
  }
  for (const value of items) {
    const item = document.createElement("li");
    item.textContent = value;
    target.append(item);
  }
}

async function loadAiAnalysis() {
  const [summaryRes, decoyRes, reportsRes] = await Promise.all([
    fetch("/api/ai/summary?limit=150"),
    fetch("/api/ai/decoy-data?limit=150"),
    fetch("/api/ai/reports?limit=5"),
  ]);
  const summary = await summaryRes.json();
  const decoy = await decoyRes.json();
  const reports = await reportsRes.json();

  els.aiSeverity.textContent = summary.severity;
  els.aiSeverity.className = `severity ${summary.severity}`;
  els.aiHeadline.textContent = summary.headline;
  els.aiSummary.textContent = summary.summary;
  renderList(els.aiFindings, summary.key_findings);
  renderList(els.aiActions, summary.recommended_actions);
  els.aiDecoy.textContent = JSON.stringify(decoy, null, 2);
  renderList(
    els.aiReports,
    reports.reports.map((report) => `${formatTime(report.timestamp)} - ${report.severity}: ${report.headline}`)
  );
}

function renderEvents(rows) {
  els.events.replaceChildren();
  if (!rows.length) {
    const tr = document.createElement("tr");
    const td = cell("No matching activity");
    td.colSpan = 9;
    tr.append(td);
    els.events.append(tr);
    return;
  }

  for (const row of rows) {
    const tr = document.createElement("tr");
    if (row.source_ip === selectedSource) tr.classList.add("selected-row");
    const sourceButton = document.createElement("button");
    sourceButton.className = "link-button";
    sourceButton.textContent = row.source_ip;
    sourceButton.addEventListener("click", () => selectSource(row.source_ip));

    const sourceCell = document.createElement("td");
    sourceCell.append(sourceButton);
    const riskCell = document.createElement("td");
    riskCell.append(riskPill(Number(row.risk_score || 0)));
    const decisionCell = document.createElement("td");
    decisionCell.append(decisionPill(row.decision));

    tr.append(
      cell(formatTime(row.timestamp)),
      sourceCell,
      cell(row.service),
      cell(row.event_type),
      cell(row.path || row.payload),
      riskCell,
      decisionCell,
      cell(tagList(row.tags)),
      cell(mitreList(row.mitre_techniques))
    );
    els.events.append(tr);
  }
}

function renderChips(target, rows, nameKey) {
  target.replaceChildren();
  if (!rows.length) {
    const empty = document.createElement("span");
    empty.className = "muted";
    empty.textContent = "-";
    target.append(empty);
    return;
  }
  for (const row of rows) {
    const chip = document.createElement("span");
    chip.className = "chip";
    chip.textContent = `${row[nameKey]} ${row.count}`;
    target.append(chip);
  }
}

function renderDetail(detail) {
  if (!detail.summary) {
    clearDetail();
    return;
  }

  const summary = detail.summary;
  els.detailEmpty.classList.add("hidden");
  els.detailContent.classList.remove("hidden");
  els.detailIp.textContent = summary.source_ip;
  els.detailEvents.textContent = summary.total_events;
  els.detailRisk.textContent = summary.max_risk;
  els.detailRedirected.textContent = summary.redirected_events;
  els.detailHighRisk.textContent = summary.high_risk_events;
  els.detailFirst.textContent = formatTime(summary.first_seen);
  els.detailLast.textContent = formatTime(summary.last_seen);

  renderChips(els.detailServices, detail.services, "service");
  renderChips(els.detailTags, detail.tags, "tag");
  renderChips(els.detailMitre, mitreRowsFromEvents(detail.events), "label");
  els.detailTimeline.replaceChildren();

  for (const event of detail.events.slice(0, 12)) {
    const item = document.createElement("li");
    const title = document.createElement("strong");
    title.textContent = `${event.service} / ${event.event_type}`;
    const meta = document.createElement("span");
    meta.textContent = `${formatTime(event.timestamp)} - ${event.path || event.payload || "-"}`;
    const reason = document.createElement("em");
    reason.textContent = tagList(event.tags);
    item.append(title, meta, reason);
    els.detailTimeline.append(item);
  }
}

function mitreRowsFromEvents(events) {
  const seen = new Map();
  for (const event of events) {
    for (const technique of event.mitre_techniques || []) {
      const key = technique.id;
      const existing = seen.get(key) || { label: `${technique.id} ${technique.name}`, count: 0 };
      existing.count += 1;
      seen.set(key, existing);
    }
  }
  return [...seen.values()].sort((a, b) => b.count - a.count);
}

function renderIncidents(rows) {
  els.incidents.replaceChildren();
  if (!rows.length) {
    const tr = document.createElement("tr");
    const td = cell("No incidents");
    td.colSpan = 7;
    tr.append(td);
    els.incidents.append(tr);
    return;
  }
  for (const row of rows) {
    const tr = document.createElement("tr");
    const action = document.createElement("button");
    action.className = "link-button";
    action.textContent = row.status === "open" ? "Resolve" : "Reopen";
    action.addEventListener("click", () => updateIncident(row.id, row.status === "open" ? "resolved" : "open"));
    const actionCell = document.createElement("td");
    actionCell.append(action);
    tr.append(
      cell(row.id),
      cell(row.source_ip),
      cell(row.severity),
      cell(row.status),
      cell(mitreList(row.mitre_techniques)),
      cell(row.title),
      actionCell
    );
    els.incidents.append(tr);
  }
}

function renderSiemStatus(status) {
  els.siemState.textContent = status.enabled ? "Enabled" : "Disabled";
  els.siemState.className = `status-dot ${status.enabled ? "on" : "off"}`;
  els.siemFormats.textContent = (status.formats || []).join(" / ") || "-";
  els.siemTargets.replaceChildren();
  for (const [format, target] of Object.entries(status.targets || {})) {
    if (!(status.formats || []).includes(format)) continue;
    const row = document.createElement("div");
    const key = document.createElement("dt");
    const value = document.createElement("dd");
    key.textContent = format.toUpperCase();
    value.textContent = target;
    row.append(key, value);
    els.siemTargets.append(row);
  }
}

async function loadIncidents() {
  const response = await fetch("/api/incidents?limit=50");
  const payload = await response.json();
  renderIncidents(payload.incidents);
}

async function createIncident() {
  if (!selectedSource) return;
  const body = new URLSearchParams({
    source_ip: selectedSource,
    severity: "high",
    title: `Suspicious activity from ${selectedSource}`,
  });
  await fetch("/api/incidents/create", { method: "POST", body });
  await loadIncidents();
  await loadDashboard();
}

async function updateIncident(id, status) {
  const body = new URLSearchParams({ id, status });
  await fetch("/api/incidents/update", { method: "POST", body });
  await loadIncidents();
  await loadDashboard();
}

function clearDetail() {
  selectedSource = "";
  els.detailContent.classList.add("hidden");
  els.detailEmpty.classList.remove("hidden");
}

async function selectSource(sourceIp) {
  selectedSource = sourceIp;
  els.sourceFilter.value = sourceIp;
  const response = await fetch(`/api/sources/${encodeURIComponent(sourceIp)}`);
  renderDetail(await response.json());
  await loadDashboard();
}

function eventQuery() {
  const params = new URLSearchParams();
  params.set("limit", "150");
  if (els.sourceFilter.value.trim()) params.set("source_ip", els.sourceFilter.value.trim());
  if (els.decisionFilter.value) params.set("decision", els.decisionFilter.value);
  if (els.riskFilter.value) params.set("min_risk", els.riskFilter.value);
  return params.toString();
}

async function loadDashboard() {
  document.body.classList.add("is-loading");
  try {
    const [statsRes, eventsRes, auditRes, incidentsRes, siemRes] = await Promise.all([
      fetch("/api/stats"),
      fetch(`/api/events?${eventQuery()}`),
      fetch("/api/admin/audit?limit=20"),
      fetch("/api/incidents?limit=50"),
      fetch("/api/siem/status"),
    ]);
    const stats = await statsRes.json();
    const eventPayload = await eventsRes.json();
    const auditPayload = await auditRes.json();
    const incidentsPayload = await incidentsRes.json();
    const siemPayload = await siemRes.json();

    els.total.textContent = stats.total_events;
    els.unique.textContent = stats.unique_sources;
    els.highRisk.textContent = stats.high_risk_events;
    els.redirected.textContent = stats.redirected_sessions;
    els.lastUpdated.textContent = new Date().toLocaleTimeString();

    renderTopSources(stats.top_ips);
    renderRows(els.topTags, stats.top_tags, ["tags", "count"]);
    renderEvents(eventPayload.events);
    renderIncidents(incidentsPayload.incidents);
    renderSiemStatus(siemPayload);
    renderRows(els.adminAudit, auditPayload.audit, ["timestamp", "source_ip", "action", "status", "detail"]);
    updateExportLinks();

    if (selectedSource) {
      const response = await fetch(`/api/sources/${encodeURIComponent(selectedSource)}`);
      renderDetail(await response.json());
    }
  } finally {
    document.body.classList.remove("is-loading");
  }
}

els.refresh.addEventListener("click", loadDashboard);
els.autoRefresh.addEventListener("change", syncAutoRefresh);
els.clearFilters.addEventListener("click", () => {
  clearDetail();
  els.sourceFilter.value = "";
  els.decisionFilter.value = "";
  els.riskFilter.value = "";
  loadDashboard();
});
els.reportPeriod.addEventListener("change", loadReports);
els.refreshAi.addEventListener("click", loadAiAnalysis);
els.createIncident.addEventListener("click", createIncident);
els.saveAiReport.addEventListener("click", async () => {
  await fetch("/api/ai/report?limit=150");
  await loadAiAnalysis();
});
els.clearDetail.addEventListener("click", () => {
  clearDetail();
  els.sourceFilter.value = "";
  loadDashboard();
});
for (const control of [els.sourceFilter, els.decisionFilter, els.riskFilter]) {
  control.addEventListener("input", loadDashboard);
  control.addEventListener("change", loadDashboard);
}
loadDashboard();
loadReports();
loadAiAnalysis();
loadIncidents();
syncAutoRefresh();

function syncAutoRefresh() {
  for (const timer of [dashboardTimer, reportsTimer, aiTimer, incidentsTimer]) {
    if (timer) clearInterval(timer);
  }
  dashboardTimer = reportsTimer = aiTimer = incidentsTimer = null;
  els.refreshMode.textContent = els.autoRefresh.checked ? "Live" : "Manual";
  if (!els.autoRefresh.checked) return;
  dashboardTimer = setInterval(loadDashboard, 5000);
  reportsTimer = setInterval(loadReports, 15000);
  aiTimer = setInterval(loadAiAnalysis, 20000);
  incidentsTimer = setInterval(loadIncidents, 20000);
}
