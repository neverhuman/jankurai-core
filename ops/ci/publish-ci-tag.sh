#!/usr/bin/env bash
# Publish a new immutable tag only after the required default-branch check passes.
set -euo pipefail
[[ "${GITHUB_EVENT_NAME:-}" == push && "${GITHUB_REF:-}" == refs/heads/main ]]
[[ "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ ]]
node --input-type=module - <<'JS_TAG'
import { spawnSync } from 'node:child_process';
const repo = process.env.GITHUB_REPOSITORY, sha = process.env.GITHUB_SHA, ref = 'tags/ci-' + sha;
const existing = spawnSync('gh', ['api', `repos/${repo}/git/ref/${ref}`], { encoding: 'utf8' });
if (existing.status === 0) {
  const object = JSON.parse(existing.stdout).object;
  if (object.type !== 'commit' || object.sha !== sha) throw new Error('immutable CI tag mismatch');
} else {
  if (!existing.stderr.includes('HTTP 404')) throw new Error(existing.stderr);
  const result = spawnSync('gh', ['api', '--method', 'POST', `repos/${repo}/git/refs`, '--input', '-'], {
    input: JSON.stringify({ ref: 'refs/' + ref, sha }), encoding: 'utf8' });
  if (result.status !== 0) throw new Error(result.stderr);
}
console.log('Published immutable ci-' + sha);
JS_TAG
