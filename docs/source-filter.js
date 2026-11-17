/* Match the normalized source names, not affected vendors.
   Advisories may be collected from more than one upstream source. */
(function(root){
  "use strict";
  const SOURCES = Object.freeze({
    cisa_kev: "CISA KEV",
    github_advisories: "GitHub Advisory Database",
    nist_nvd: "NIST NVD",
    redhat_quay: "Red Hat Security Data API"
  });
  function matchesSource(advisory, sourceId) {
    if(!sourceId) return true;
    const expected=SOURCES[sourceId];
    if(!expected || !advisory || !Array.isArray(advisory.sources)) return false;
    return advisory.sources.some(source=>source &&
      typeof source.name==="string" && source.name===expected);
  }
  const api={matchesSource,SOURCES};
  if(typeof module!=="undefined" && module.exports)module.exports=api;
  if(root)root.SecurityRadarSources=api;
})(typeof window!=="undefined"?window:typeof globalThis!=="undefined"?globalThis:{});
