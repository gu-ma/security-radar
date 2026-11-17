"use strict";
const test=require("node:test");
const assert=require("node:assert/strict");
const {matchesActivity,isOlderUpdate,modes}=require("../docs/date-views.js");
const now=Date.parse("2026-11-17T09:00:00Z");
const old={id:"CVE-2024-34359",published:"2024-05-13T14:10:18Z",modified:"2026-11-16T15:19:28Z"};
const newAdvisory={id:"CVE-2026-11111",published:"2026-11-16T15:00:00Z",modified:"2026-11-17T07:00:00Z"};

test("old advisories updated yesterday are not newly published",()=>{
 assert.equal(matchesActivity(old,"published-7",now),false);
 assert.equal(matchesActivity(old,"published-30",now),false);
 assert.equal(matchesActivity(old,"updated-7",now),true);
 assert.equal(matchesActivity(old,"updated-30",now),true);
 assert.equal(isOlderUpdate(old),true);
});
test("newly published advisories are not mistaken for old updates",()=>{
 assert.equal(matchesActivity(newAdvisory,"published-7",now),true);
 assert.equal(matchesActivity(newAdvisory,"updated-7",now),false);
 assert.equal(isOlderUpdate(newAdvisory),false);
});
test("missing or malformed publication dates do not enter new feed",()=>{
 const invalid={published:"bad-date",modified:"2026-11-16T15:00:00Z"};
 assert.equal(matchesActivity(invalid,"published-7",now),false);
 assert.equal(matchesActivity(invalid,"updated-7",now),true);
});
test("time bounds are strict and future dates are ignored",()=>{
 const future={published:"2026-11-18T00:00:00Z",modified:"2026-11-18T01:00:00Z"};
 assert.equal(matchesActivity(future,"published-7",now),false);
 assert.equal(matchesActivity(future,"updated-7",now),false);
});
test("modes are stable for deep links and unknown ones are rejected",()=>{
 assert.deepEqual(modes,["","published-7","published-30","updated-7","updated-30"]);
 assert.equal(matchesActivity(old,"",now),true);
 assert.equal(matchesActivity(old,"typo",now),false);
});
