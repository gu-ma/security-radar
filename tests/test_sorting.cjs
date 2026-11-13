"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { sortAdvisories, modes } = require("../docs/sorting.js");

const records = [
  { id:"A", cvss:9.8, severity:"critical", published:"2026-11-11T09:00:00Z", modified:"2026-11-11T10:00:00Z", attention_score:120 },
  { id:"B", cvss:5.4, severity:"medium", published:"2026-11-13T09:00:00Z", modified:"2026-11-13T10:00:00Z", attention_score:20 },
  { id:"C", cvss:null, severity:"unknown", published:"", modified:"", attention_score:40 },
  { id:"D", cvss:8.0, severity:"high", published:"2026-11-12T09:00:00Z", modified:"2026-11-12T10:00:00Z", attention_score:70 }
];
const ids = (mode, rows=records) => sortAdvisories(rows, mode).map(r=>r.id);

test("high attention by default and no input mutation", () => {
  const initial = [...records];
  assert.deepEqual(ids("attention"), ["A","D","C","B"]);
  assert.deepEqual(records, initial);
});
test("CVSS highest and lowest keep unscored last", () => {
  assert.deepEqual(ids("cvss-desc"), ["A","D","B","C"]);
  assert.deepEqual(ids("cvss-asc"), ["B","D","A","C"]);
});
test("severity order uses labels, not alphabet", () =>
  assert.deepEqual(ids("severity-desc"), ["A","D","B","C"]));
test("published and updated date sorting", () => {
  assert.deepEqual(ids("published-desc"), ["B","D","A","C"]);
  assert.deepEqual(ids("published-asc"), ["A","D","B","C"]);
  assert.deepEqual(ids("updated-desc"), ["B","D","A","C"]);
  assert.deepEqual(ids("updated-asc"), ["A","D","B","C"]);
});
test("unknown sort uses attention rather than crash", () =>
  assert.deepEqual(ids("made-up"), ids("attention")));
test("sort is stable with deterministic tie-break", () => {
  const rows = [{id:"C",attention_score:1},{id:"A",attention_score:1},{id:"B",attention_score:1}];
  assert.deepEqual(ids("attention", rows), ["A","B","C"]);
});
test("all published modes are unique", () => {
  assert.equal(new Set(modes).size, modes.length);
});
