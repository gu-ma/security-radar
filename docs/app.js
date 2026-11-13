"use strict";
const elements = {
  list: document.getElementById("list"),
  query: document.getElementById("query"),
  priority: document.getElementById("priority"),
  severity: document.getElementById("severity"),
  exploited: document.getElementById("exploited"),
  more: document.getElementById("more"),
};
let advisories = [];
let visibleLimit = 20;
function urgency(a) {
  const severity = {critical: 45, high: 25, medium: 5, low: 0, unknown: 0};
  return typeof a.attention_score === "number" ? a.attention_score :
    (a.exploited ? 80 : 0) + (severity[a.severity] || 0) +
      ((a.matched_topics || []).length ? 30 : 0);
}
function chronological(a, b) { return String(b.modified || b.published || "").localeCompare(String(a.modified || a.published || "")); }
function prioritize(a, b) { return urgency(b) - urgency(a) || chronological(a, b); }
function spotlight() {
  const important = advisories.filter(a => (a.matched_topics || []).length &&
    (a.exploited || ["critical", "high"].includes(a.severity)))
    .sort(prioritize);
  const container = document.getElementById("spotlight");
  container.replaceChildren();
  important.slice(0, 6).forEach(a => container.appendChild(card(a, true)));
  if (!important.length) container.appendChild(text("div", "No high-priority watchlist matches in the available data. Check source health before interpreting this as an all-clear.", "empty"));
  document.getElementById("focus-summary").textContent =
    important.length + " potential high-priority watchlist matches · showing up to 6 · source data may be incomplete.";
}

function text(tag, value, className) {
  const el = document.createElement(tag);
  el.textContent = String(value ?? "");
  if (className) el.className = className;
  return el;
}
function sourceLink(source) {
  try {
    const url = new URL(source.url);
    if (url.protocol !== "https:") return null;
    const link = text("a", (source.name || "Source") + " ↗");
    link.href = url.href;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    return link;
  } catch (_) { return null; }
}
function displayDate(value) {
  if (!value) return "Unknown date";
  const date = new Date(value);
  return isNaN(date.getTime()) ? String(value).slice(0, 10) : date.toLocaleDateString(undefined, {year:"numeric",month:"short",day:"numeric"});
}
function card(a, featured = false) {
  const article = document.createElement("article");
  article.className = "advisory";
  const head = text("div", "", "advisory-header");
  head.appendChild(text("span", a.id, "id"));
  head.appendChild(text("span", a.priority || "information", "tag " + (a.priority || "information")));
  head.appendChild(text("span", a.severity || "unknown", "tag " + (a.severity || "unknown")));
  if (a.exploited) head.appendChild(text("span", "CISA KEV", "tag exploited"));
  article.appendChild(head);
  article.appendChild(text("h3", a.title || a.id));
  if (a.summary) article.appendChild(text("p",
    a.summary.length > (featured ? 340 : 230) ?
      a.summary.slice(0, featured ? 340 : 230).trimEnd() + "…" : a.summary));
  const meta = text("div", "", "metadata");
  meta.appendChild(text("span", "Updated " + displayDate(a.modified || a.published)));
  const matches = a.matched_topics || [];
  if (matches.length) meta.appendChild(text("span", "Topics: " + matches.join(", ")));
  (a.sources || []).slice(0, 3).forEach(s => { const l = sourceLink(s); if (l) meta.appendChild(l); });
  article.appendChild(meta);
  if (featured) {
    const reasons = [];
    if (a.exploited) reasons.push("Listed in CISA KEV");
    if (a.severity === "critical") reasons.push("Critical severity" + (a.cvss ? " · CVSS " + a.cvss : ""));
    else if (a.severity === "high") reasons.push("High severity");
    if (matches.length) reasons.push("Watchlist: " + matches.join(", "));
    article.appendChild(text("p", "Why highlighted: " + reasons.join(" · ") + ". Local exposure not assessed.", "spotlight-reason"));
  }
  return article;
}
function render() {
  const q = elements.query.value.trim().toLowerCase();
  const p = elements.priority.value;
  const s = elements.severity.value;
  const e = elements.exploited.value;
  const matched = advisories.filter(a => {
    if (p && a.priority !== p) return false;
    if (s && a.severity !== s) return false;
    if (e && a.exploited !== (e === "yes")) return false;
    if (q && ![a.id, a.title, a.summary, ...(a.affected || []), ...(a.matched_topics || []), ...(a.aliases || [])].join(" ").toLowerCase().includes(q)) return false;
    return true;
  });
  matched.sort(prioritize);
  elements.list.replaceChildren();
  if (!matched.length) elements.list.appendChild(text("div", "No advisories match these filters. Try broadening your search.", "empty"));
  else matched.slice(0, visibleLimit).forEach(a => elements.list.appendChild(card(a)));
  document.getElementById("result-count").textContent = matched.length.toLocaleString() + " matching advisories";
  elements.more.hidden = visibleLimit >= matched.length;
}
function stat(id, value) { document.getElementById(id).textContent = value.toLocaleString(); }
async function load() {
  try {
    const responses = await Promise.all(["./data/advisories.json", "./data/status.json"].map(path => fetch(path, {cache: "no-store"})));
    if (responses.some(r => !r.ok)) throw new Error("Published data is not available yet");
    const [rows, status] = await Promise.all(responses.map(r => r.json()));
    if (!Array.isArray(rows)) throw new Error("Unexpected advisory schema");
    advisories = rows;
    stat("count-total", advisories.length);
    stat("count-exploited", advisories.filter(a => a.exploited).length);
    stat("count-matched", advisories.filter(a => (a.matched_topics || []).length).length);
    stat("count-critical", advisories.filter(a => a.severity === "critical").length);
    const sync = document.getElementById("sync-status");
    if (!status.last_run) sync.textContent = "Not yet populated — run the monitor workflow to collect advisories.";
    else sync.textContent = "Updated " + displayDate(status.last_run) +
      (status.partial ? " · Some sources failed: " + (status.source_errors || []).join(", ") : " · Sources collected successfully");
    spotlight();
    render();
  } catch (error) {
    document.getElementById("sync-status").textContent = "Data unavailable — inspect GitHub Actions.";
    elements.list.replaceChildren(text("div", error.message, "empty"));
  }
}
[elements.query, elements.priority, elements.severity, elements.exploited].forEach(el => el.addEventListener("input", () => { visibleLimit = 40; render(); }));
elements.more.addEventListener("click", () => { visibleLimit += 40; render(); });
load();
