#!/usr/bin/env bash
# Exact-collection aggregate for the Core required job.
# Rejects empty, array, wrong-name, extra, missing, and non-success needs.
set -euo pipefail
node --input-type=module - <<'JS_RESULTS'
const EXPECTED = Object.freeze(['quality']);
const raw = process.env.NEEDS_JSON;
if (raw === undefined || raw === '') {
  throw new Error('NEEDS_JSON is required');
}
let jobs;
try {
  jobs = JSON.parse(raw);
} catch (err) {
  throw new Error(`NEEDS_JSON must be valid JSON: ${err.message}`);
}
if (jobs === null || typeof jobs !== 'object' || Array.isArray(jobs)) {
  throw new Error('NEEDS_JSON must be a single plain object');
}
const keys = Object.keys(jobs).sort();
const expected = [...EXPECTED].sort();
if (
  keys.length !== expected.length ||
  !expected.every((name, index) => keys[index] === name)
) {
  throw new Error(
    `required lanes must be exactly [${EXPECTED.join(', ')}]; got [${keys.join(', ') || '(none)'}]`,
  );
}
const failed = EXPECTED.filter((name) => {
  const job = jobs[name];
  return (
    job === null ||
    typeof job !== 'object' ||
    Array.isArray(job) ||
    job.result !== 'success'
  );
});
if (failed.length) {
  throw new Error('required lanes did not pass: ' + failed.join(', '));
}
console.log('all required lanes passed');
JS_RESULTS
