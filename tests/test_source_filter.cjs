"use strict";
const test=require("node:test");
const assert=require("node:assert/strict");
const {matchesSource,SOURCES}=require("../docs/source-filter.js");

test("origin matches by source, including merged multi-source records",()=>{
 const record={id:"CVE-2026-0001",sources:[
   {name:"NIST NVD",url:"https://nvd.nist.gov/vuln/detail/CVE-2026-0001"},
   {name:"GitHub Advisory Database",url:"https://github.com/advisories/GHSA-abcd-efgh-ijkl"}]};
 assert.equal(matchesSource(record,"nist_nvd"),true);
 assert.equal(matchesSource(record,"github_advisories"),true);
 assert.equal(matchesSource(record,"redhat_quay"),false);
 assert.equal(matchesSource(record,""),true);
});
test("source is distinct from vendor, affected products and CVE text",()=>{
 const record={title:"Red Hat Quay",affected:["Quay"],sources:[{name:"NIST NVD"}]};
 assert.equal(matchesSource(record,"redhat_quay"),false);
 assert.equal(matchesSource(record,"nist_nvd"),true);
});
test("unknown identifiers and bad source arrays are safe",()=>{
 assert.equal(matchesSource({sources:[]},"unknown"),false);
 assert.equal(matchesSource({sources:null},"nist_nvd"),false);
 assert.equal(Object.keys(SOURCES).length,4);
});
