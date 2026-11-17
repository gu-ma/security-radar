/* UTC publication vs. update filters. Source-advisory dates, not observation dates. */
(function(root){
  "use strict";
  const DAY=86400000;
  const modes=Object.freeze(["", "published-7", "published-30", "updated-7", "updated-30"]);
  function timestamp(raw){
    if(typeof raw!=="string" || !raw.trim()) return null;
    const n=Date.parse(raw);
    return Number.isFinite(n)?n:null;
  }
  function within(raw,days,now){
    const stamp=timestamp(raw);
    return stamp!==null && stamp>=now-days*DAY && stamp<=now;
  }
  function isOlderUpdate(row, minimumDays=30){
    const published=timestamp(row.published),modified=timestamp(row.modified);
    return published!==null && modified!==null && modified-published>=minimumDays*DAY;
  }
  function matchesActivity(row,mode,now=Date.now()){
    if(!mode)return true;
    if(!modes.includes(mode))return false;
    const days=mode.endsWith("-7")?7:30;
    if(mode.startsWith("published-"))return within(row.published,days,now);
    return within(row.modified,days,now) && !within(row.published,days,now);
  }
  const api={modes,matchesActivity,isOlderUpdate};
  if(typeof module!=="undefined"&&module.exports)module.exports=api;
  if(root)root.SecurityRadarDates=api;
})(typeof window!=="undefined"?window:typeof globalThis!=="undefined"?globalThis:{});
