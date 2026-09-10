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
// JSON.parse discards earlier duplicate keys. Walk the already-valid token
// stream so a later success cannot overwrite an earlier failure, including
// escaped spellings of the same key and duplicate nested result fields.
const scopes = [];
for (const token of raw.match(/"(?:\\[\s\S]|[^"\\])*"|[{}\[\],:]/g) ?? []) {
  if (token === '{' || token === '[') {
    scopes.push({ object: token === '{', key: token === '{', seen: new Set() });
  } else if (token === '}' || token === ']') {
    scopes.pop();
  } else {
    const scope = scopes.at(-1);
    if (token === ',' && scope?.object) scope.key = true;
    if (token.startsWith('"') && scope?.object && scope.key) {
      const key = JSON.parse(token);
      if (scope.seen.has(key)) throw new Error(`duplicate JSON key: ${key}`);
      scope.seen.add(key);
      scope.key = false;
    }
  }
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
