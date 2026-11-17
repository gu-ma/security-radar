"use strict";
const SOURCE_NAMES={cisa_kev:"CISA KEV",github_advisories:"GitHub Advisories",nist_nvd:"NIST NVD",redhat_quay:"Red Hat Quay"};
const RUN_ACTIONS="https://github.com/gu-ma/security-radar/actions/workflows/monitor.yml";
const $=(id)=>document.getElementById(id);
function elem(type,text,cls){const e=document.createElement(type);if(text!==undefined)e.textContent=String(text);if(cls)e.className=cls;return e;}
function date(raw){if(!raw)return "Not recorded";const dt=new Date(raw);return Number.isNaN(dt.getTime())?"Not recorded":dt.toISOString().replace("T"," ").replace(".000Z"," UTC").replace("Z"," UTC");}
function dateValid(raw){return typeof raw==="string"&&Number.isFinite(Date.parse(raw));}
function link(label,url){try{const parsed=new URL(url);if(parsed.protocol!=="https:"||parsed.hostname!=="github.com"||!parsed.pathname.startsWith("/gu-ma/security-radar/actions/runs/"))return null;const a=elem("a",label);a.href=parsed.href;a.target="_blank";a.rel="noopener noreferrer";return a;}catch{return null;}}
function badge(value){const states=["healthy","degraded","failed","stale"];const state=states.includes(value)?value:"stale";return elem("span",state.toUpperCase(),"status-badge "+state);}
function overall(status){
 const seconds=(Date.now()-Date.parse(status.last_run||""))/1000;
 const stale=!dateValid(status.last_run)||seconds>36*3600;
 const state=stale?"stale":status.failed?"failed":status.partial?"degraded":"healthy";
 const wrap=elem("div",undefined,"status-overview-text");
 wrap.append(badge(state),elem("span","Last collection: "+date(status.last_run),"status-muted"));
 const box=$("health-overview");box.replaceChildren(wrap);
 const action=link("View execution log ↗",status.run_url);
 if(action)box.append(action);
 else {const a=elem("a","GitHub Actions ↗");a.href=RUN_ACTIONS;a.target="_blank";a.rel="noopener noreferrer";box.append(a);}
}
function sources(status){
 const root=$("health-sources");root.replaceChildren();
 const entries=Object.entries(status.sources||{});
 if(!entries.length){root.append(elem("div","No source metadata has been published.","status-empty"));return;}
 for(const [name,row] of entries){
  const box=elem("article",undefined,"health-source"),head=elem("div",undefined,"health-card-top");
  const state=row.state==="ok"?"healthy":"failed";
  head.append(elem("strong",SOURCE_NAMES[name]||name,"health-card-title"),badge(state));
  box.append(head);
  const details=elem("div",undefined,"health-details");
  details.append(elem("p","Last success: "+date(row.last_success)));
  details.append(elem("p","Last attempt: "+date(row.last_attempt)));
  details.append(elem("p","Last complete batch: "+(Number.isInteger(row.count)?row.count:"Not recorded")+" records"));
  if(row.state!=="ok"){
   details.append(elem("p","Failure type: "+(row.error_type||"Not classified")));
   details.append(elem("p","Consecutive failures: "+(Number.isInteger(row.consecutive_failures)?row.consecutive_failures:"Unknown")));
   if(row.first_failure)details.append(elem("p","First failure: "+date(row.first_failure)));
  }
  box.append(details);
  if(row.error)box.append(elem("p",row.error,"health-error"));
  root.append(box);
 }
}
function historyRows(history){
 const root=$("health-history");root.replaceChildren();
 if(!Array.isArray(history)||!history.length){root.append(elem("div","No recorded collection runs yet. History starts with the next collection.","status-empty"));return;}
 for(const run of history.slice(0,40)){
  const box=elem("article",undefined,"health-run"),top=elem("div",undefined,"health-run-top");
  const left=elem("div",undefined,"status-overview-text");
  left.append(badge(run.result),elem("span",date(run.finished_at),"status-muted"));
  top.append(left);
  const a=link("Execution log ↗",run.run_url);if(a)top.append(a);
  box.append(top);
  const detail=elem("div",undefined,"health-run-info");
  detail.append(elem("span","Stored: "+(Number.isInteger(run.stored_records)?run.stored_records:"?"),"status-muted"));
  detail.append(elem("span","New relevant: "+(Number.isInteger(run.new_relevant_alerts)?run.new_relevant_alerts:"?"),"status-muted"));
  if(typeof run.duration_seconds==="number")detail.append(elem("span","Duration: "+run.duration_seconds+" s","status-muted"));
  const issues=run.source_errors||[];
  if(issues.length)detail.append(elem("span","Source errors: "+issues.map(n=>SOURCE_NAMES[n]||n).join(", "),"status-muted"));
  box.append(detail);root.append(box);
 }
}
async function load(){
 try{
  const [statusRes,historyRes]=await Promise.all([fetch("./data/status.json",{cache:"no-store"}),fetch("./data/history.json",{cache:"no-store"})]);
  if(!statusRes.ok)throw Error("Status data unavailable");
  const status=await statusRes.json();
  const history=historyRes.ok?await historyRes.json():[];
  overall(status);sources(status);historyRows(history);
 }catch(err){
  $("health-overview").replaceChildren(elem("div","Health data unavailable. Check GitHub Actions.","status-empty"));
  $("health-sources").replaceChildren();
  $("health-history").replaceChildren();
 }
}
load();
