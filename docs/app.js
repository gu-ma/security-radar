"use strict";
// Static site: public advisory fields are always inserted using textContent.
const labels = {
  "applications": "Applications", "dependencies": "Libraries & dependencies",
  "containers": "Containers & registries", "infrastructure": "Servers & infrastructure",
  "cloud-identity": "Cloud & identity", "ai-ml": "AI & ML tooling",
  "unclassified": "Unclassified"
};
const els = {
  list: document.getElementById("list"), spotlight: document.getElementById("spotlight"),
  query: document.getElementById("query"), category: document.getElementById("category"),
  topic: document.getElementById("topic"), priority: document.getElementById("priority"),
  severity: document.getElementById("severity"), exploited: document.getElementById("exploited"),
  more: document.getElementById("more"), archive: document.getElementById("archive"),
  tabs: document.getElementById("category-tabs")
};
let advisories = [], visibleLimit = 20, focusedCategory = "";
const severityPoints = {critical:45, high:25, medium:5, low:0, unknown:0};
function el(tag, value, cls) {
  const node = document.createElement(tag);
  node.textContent = String(value ?? "");
  if (cls) node.className = cls;
  return node;
}
function safeLink(source, caption) {
  try {
    const url = new URL(source.url);
    if (url.protocol !== "https:") return null;
    const link = el("a", caption || source.name || "Official advisory");
    link.href = url.href;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    return link;
  } catch { return null; }
}
function dateLabel(raw) {
  if (!raw) return "Unknown date";
  const d = new Date(raw);
  return Number.isNaN(d.getTime()) ? String(raw).slice(0,10)
    : d.toLocaleDateString(undefined,{year:"numeric",month:"short",day:"numeric"});
}
function urgency(a) {
  return typeof a.attention_score === "number" ? a.attention_score
    : (a.exploited ? 80 : 0) + (severityPoints[a.severity] || 0)
      + ((a.matched_topics || []).length ? 30 : 0);
}
function compare(a,b) {
  return urgency(b)-urgency(a) ||
    String(b.modified||b.published||"").localeCompare(String(a.modified||a.published||""));
}
function categoriesOf(a) { return a.categories || ["unclassified"]; }
function topicsOf(a) { return a.security_topics || []; }
function lineClamp(v, n) {
  const str = String(v || "");
  return str.length>n ? str.slice(0,n-1).trimEnd()+"…" : str;
}
function card(a, featured=false) {
  const article=el("article","","advisory"+(featured?" featured":""));
  const head=el("div","","advisory-header");
  head.append(el("span",a.id||"Unknown ID","id"));
  head.append(el("span",a.priority||"information","tag "+(a.priority||"information")));
  if (a.exploited) head.append(el("span","CISA KEV-listed","tag exploited"));
  article.append(head);
  const titleRow=el("div","","advisory-title-row");
  titleRow.append(el("h3",a.title||a.id||"Unnamed advisory"));
  const cvssBox=el("div","","cvss-box "+(a.severity||"unknown"));
  const score=(typeof a.cvss==="number")?a.cvss.toFixed(1):"N/A";
  cvssBox.append(el("strong",score,"cvss-number"));
  cvssBox.append(el("span",String(a.severity||"unknown").toUpperCase(),"cvss-severity"));
  cvssBox.append(el("small",a.cvss_version?"CVSS "+a.cvss_version:"CVSS · version not provided","cvss-label"));
  titleRow.append(cvssBox);
  article.append(titleRow);
  const tags=el("div","","tag-cloud");
  categoriesOf(a).forEach(c=>tags.append(el("span",labels[c]||c,"category-tag")));
  topicsOf(a).forEach(t=>tags.append(el("span",t,"topic-tag")));
  article.append(tags);
  if(featured){
    article.append(el("h4","Why it matters","card-subtitle"));
    article.append(el("p",lineClamp(a.why_it_matters||a.summary||
      "No description provided by the source.",340),"description"));
    article.append(el("h4","Suggested next step","card-subtitle"));
    article.append(el("p",a.suggested_next_step||
      "Check affected versions against the original advisory.","description"));
  } else {
    article.append(el("p",lineClamp(a.why_it_matters||a.summary||
      "Description not provided by source.",220),"description"));
  }
  const meta=el("div","","metadata");
  meta.append(el("span","Updated "+dateLabel(a.modified||a.published)));
  if((a.matched_topics||[]).length)
    meta.append(el("span","Watchlist: "+a.matched_topics.join(", ")));
  const src=a.sources||[];
  for(const s of src.slice(0,3)){
    const link=safeLink(s,"Original advisory: "+(s.name||"Source")+" ↗");
    if(link) meta.append(link);
  }
  article.append(meta);
  if(featured) article.append(el("p",
    "Why highlighted: "+[
      a.exploited?"CISA KEV listing":null,
      (a.severity==="critical"||a.severity==="high")?(a.severity+" severity"):null,
      (a.matched_topics||[]).length?"watchlist match":null
    ].filter(Boolean).join(" · ")+". Institutional exposure is not assessed.",
    "spotlight-reason"));
  return article;
}
function spotlight() {
  const matches=advisories.filter(a=>
    (a.matched_topics||[]).length &&
    (a.exploited || ["critical","high"].includes(a.severity)) &&
    (!focusedCategory || categoriesOf(a).includes(focusedCategory))
  ).sort(compare);
  els.spotlight.replaceChildren();
  matches.slice(0,6).forEach(a=>els.spotlight.append(card(a,true)));
  if(!matches.length) els.spotlight.append(el("div",
    "No qualifying watchlist matches in the current data for this category. This is not an all-clear.",
    "empty"));
  document.getElementById("focus-summary").textContent=
    matches.length+" potential high-priority matches · showing up to 6 · local exposure not assessed.";
}
function renderArchive() {
  const q=els.query.value.trim().toLowerCase();
  const rows=advisories.filter(a=>
    (!els.category.value||categoriesOf(a).includes(els.category.value)) &&
    (!els.topic.value||topicsOf(a).includes(els.topic.value)) &&
    (!els.priority.value||a.priority===els.priority.value) &&
    (!els.severity.value||a.severity===els.severity.value) &&
    (!els.exploited.value||a.exploited===(els.exploited.value==="yes")) &&
    (!q||[a.id,a.title,a.summary,...(a.affected||[]),
      ...(a.matched_topics||[]),...(a.aliases||[]),
      ...categoriesOf(a),...topicsOf(a)].join(" ").toLowerCase().includes(q))
  ).sort(compare);
  els.list.replaceChildren();
  if(!rows.length) els.list.append(el("div","No advisories match these filters.","empty"));
  else rows.slice(0,visibleLimit).forEach(a=>els.list.append(card(a)));
  document.getElementById("result-count").textContent=
    rows.length.toLocaleString()+" matching advisories";
  els.more.hidden=visibleLimit>=rows.length;
}
function syncQueryUrl() {
  const url=new URL(window.location.href);
  const value=els.query.value.trim();
  if(value)url.searchParams.set("q",value);else url.searchParams.delete("q");
  const cat=els.category.value;
  if(cat)url.searchParams.set("category",cat);else url.searchParams.delete("category");
  const topic=els.topic.value;
  if(topic)url.searchParams.set("topic",topic);else url.searchParams.delete("topic");
  window.history.replaceState(null,"",url);
}
function setFocusedCategory(value) {
  focusedCategory=value;
  els.tabs.querySelectorAll("button[data-category]").forEach(button=>{
    const selected=button.dataset.category===value;
    button.classList.toggle("active",selected);
    button.setAttribute("aria-pressed",String(selected));
  });
  spotlight();
}
async function load() {
  try {
    const responses=await Promise.all(["./data/advisories.json","./data/status.json"].map(
      url=>fetch(url,{cache:"no-store"})));
    if(responses.some(r=>!r.ok))throw Error("Published data is not available.");
    const [rows,status]=await Promise.all(responses.map(r=>r.json()));
    if(!Array.isArray(rows))throw Error("Unexpected advisory schema");
    advisories=rows;
    const stat=(id,value)=>{document.getElementById(id).textContent=value.toLocaleString()};
    stat("count-total",rows.length);
    stat("count-exploited",rows.filter(a=>a.exploited).length);
    stat("count-matched",rows.filter(a=>(a.matched_topics||[]).length).length);
    stat("count-critical",rows.filter(a=>a.severity==="critical").length);
    document.getElementById("sync-status").textContent=!status.last_run
      ?"Collection has not run yet."
      :"Updated "+dateLabel(status.last_run)+(status.partial
      ?" · Partial data: "+(status.source_errors||[]).join(", ")
      :" · All enabled sources succeeded");
    const params=new URLSearchParams(window.location.search);
    if(params.has("q"))els.query.value=params.get("q");
    if(params.has("category")&&[...els.category.options].some(o=>o.value===params.get("category")))
      els.category.value=params.get("category");
    if(params.has("topic")&&[...els.topic.options].some(o=>o.value===params.get("topic")))
      els.topic.value=params.get("topic");
    if(params.has("q")||params.has("category")||params.has("topic"))
      els.archive.open=true;
    setFocusedCategory("");
    renderArchive();
  } catch(err) {
    document.getElementById("sync-status").textContent="Data unavailable; inspect GitHub Actions.";
    els.list.replaceChildren(el("div",String(err.message||err),"empty"));
    els.spotlight.replaceChildren(el("div","Could not load advisory data.","empty"));
  }
}
els.tabs.addEventListener("click",e=>{
  const button=e.target.closest("button[data-category]");
  if(button&&els.tabs.contains(button))setFocusedCategory(button.dataset.category);
});
[els.query,els.category,els.topic,els.priority,els.severity,els.exploited].forEach(input=>
  input.addEventListener("input",()=>{visibleLimit=20;renderArchive();syncQueryUrl()})
);
els.more.addEventListener("click",()=>{visibleLimit+=20;renderArchive()});
load();
