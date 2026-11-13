/* Deterministic archive sorting; also usable in Node offline tests. */
(function (root) {
  "use strict";
  const severityRank = {critical: 4, high: 3, medium: 2, low: 1, unknown: 0};
  const modes = Object.freeze([
    "attention", "cvss-desc", "cvss-asc", "severity-desc",
    "published-desc", "published-asc", "updated-desc", "updated-asc"
  ]);

  function cvss(record) {
    const value = record.cvss;
    return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 10
      ? value : null;
  }
  function when(record, field) {
    const value = record[field];
    if (!value || typeof value !== "string") return null;
    const timestamp = Date.parse(value);
    return Number.isFinite(timestamp) ? timestamp : null;
  }
  function attention(record) {
    if (typeof record.attention_score === "number" && Number.isFinite(record.attention_score)) {
      return record.attention_score;
    }
    return (record.exploited ? 80 : 0) +
      ({critical:45, high:25, medium:5, low:0, unknown:0}[record.severity] || 0) +
      ((record.matched_topics || []).length ? 30 : 0);
  }
  function numeric(a, b, direction) {
    // Missing scores/dates come last in BOTH directions, never masquerade as 0.
    if (a === null && b === null) return 0;
    if (a === null) return 1;
    if (b === null) return -1;
    return direction * (a - b);
  }
  function tie(a, b) {
    return (attention(b) - attention(a)) ||
      numeric(when(a, "modified"), when(b, "modified"), -1) ||
      String(a.id || "").localeCompare(String(b.id || ""));
  }
  function comparator(mode) {
    switch (mode) {
      case "cvss-desc": return (a,b) => numeric(cvss(a), cvss(b), -1) || tie(a,b);
      case "cvss-asc": return (a,b) => numeric(cvss(a), cvss(b), 1) || tie(a,b);
      case "severity-desc": return (a,b) => {
        const x = severityRank[a.severity] || 0, y = severityRank[b.severity] || 0;
        return (y-x) || tie(a,b);
      };
      case "published-desc": return (a,b) => numeric(when(a,"published"), when(b,"published"), -1) || tie(a,b);
      case "published-asc": return (a,b) => numeric(when(a,"published"), when(b,"published"), 1) || tie(a,b);
      case "updated-desc": return (a,b) => numeric(when(a,"modified"), when(b,"modified"), -1) || tie(a,b);
      case "updated-asc": return (a,b) => numeric(when(a,"modified"), when(b,"modified"), 1) || tie(a,b);
      default: return tie;
    }
  }
  function sortAdvisories(records, mode = "attention") {
    const key = modes.includes(mode) ? mode : "attention";
    return [...records].sort(comparator(key));
  }
  const api = { sortAdvisories, modes };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  if (root) root.SecurityRadarSort = api;
})(typeof window !== "undefined" ? window : (typeof globalThis !== "undefined" ? globalThis : {}));
