import assert from 'node:assert/strict';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const workflow = fs.readFileSync(path.join(root, '.github/workflows/ci.yml'), 'utf8');
const lanes = ['quality'];

function aggregate(value) {
  const result = spawnSync('bash', [path.join(root, 'ops/ci/aggregate.sh')], {
    encoding: 'utf8',
    env: { ...process.env, NEEDS_JSON: value },
  });
  assert.ifError(result.error);
  return result.status === 0;
}

const success = { result: 'success', outputs: {} };
const successfulJobs = Object.fromEntries(lanes.map((lane) => [lane, success]));

test('successful quality lane passes', () => {
  assert.equal(aggregate(JSON.stringify(successfulJobs)), true);
});

for (const [name, value] of [
  ['empty object', '{}'],
  ['empty array', '[]'],
  ['null', 'null'],
  ['string', '"success"'],
  ['boolean', 'true'],
  ['number', '0'],
  ['missing input', ''],
  ['malformed JSON', '{'],
  ['multiple JSON values', '{}\n{}'],
  ['renamed job', JSON.stringify({ audit: success })],
  ['wrong name complete-quality-gates', JSON.stringify({ 'complete-quality-gates': success })],
  ['extra job', JSON.stringify({ ...successfulJobs, extra: success })],
  ['successful array', JSON.stringify([success])],
  ['duplicate job', '{"quality":{"result":"failure"},"quality":{"result":"success"}}'],
  ['duplicate result', '{"quality":{"result":"failure","result":"success"}}'],
  ['escaped duplicate job', '{"quality":{"result":"failure"},"qu\\u0061lity":{"result":"success"}}'],
  ['escaped duplicate result', '{"quality":{"result":"failure","r\\u0065sult":"success"}}'],
]) {
  test(`required aggregate rejects ${name}`, () => assert.equal(aggregate(value), false));
}

test('quoted punctuation and independent nested keys are valid payload data', () => {
  assert.equal(aggregate(JSON.stringify({quality: {result: 'success', outputs: {
    quoted: '\"result\":\"failure\",{[}', records: '[{"same":1},{"same":2}]',
    nested: [{same: 1}, {same: 2}],
  }}})), true);
});

for (const lane of lanes) {
  test(`required aggregate rejects missing ${lane}`, () => {
    assert.equal(aggregate('{}'), false);
  });
  for (const value of [
    null,
    [],
    'success',
    {},
    { result: true },
    { result: 0 },
    ...['failure', 'cancelled', 'skipped', 'pending', 'neutral', 'timed_out'].map(
      (result) => ({ result }),
    ),
  ]) {
    test(`required aggregate rejects ${lane} outcome ${JSON.stringify(value)}`, () => {
      const jobs = { ...successfulJobs, [lane]: value };
      assert.equal(aggregate(JSON.stringify(jobs)), false);
    });
  }
}

function assertWorkflowLanes(source) {
  // Keep this deliberately narrow: a workflow layout change requires review.
  const jobs = [...source.matchAll(/^  ([\w-]+):$/gm)].map((match) => match[1]);
  assert.deepEqual(jobs, ['push', 'pull_request', 'quality', 'required', 'publish-ci-tag']);
  assert.match(source, /^    name: complete-quality-gates$/m);
  assert.match(source, /^    needs: quality$/m);
  assert.match(source, /^    if: always\(\)$/m);
  assert.match(source, /^      - run: node --test scripts\/ci-aggregate\.test\.mjs$/m);
  assert.match(source, /^      - run: bash ops\/ci\/aggregate\.sh$/m);
}

test('workflow retains the quality lane and always-run aggregate', () => {
  assertWorkflowLanes(workflow);
});

test('workflow mutations removing quality or always() are rejected', () => {
  for (const changed of [
    workflow.replace('needs: quality', 'needs: []'),
    workflow.replace('needs: quality', 'needs: audit'),
    workflow.replace(/\n  quality:\n[\s\S]*?(?=\n  required:)/, '\n'),
    workflow.replace(/^    if: always\(\)\n/m, ''),
    workflow.replace('name: complete-quality-gates', 'name: quality'),
    workflow.replace('node --test scripts/ci-aggregate.test.mjs', 'true'),
    workflow.replace('bash ops/ci/aggregate.sh', 'bash ops/ci/required.sh'),
  ]) {
    assert.notEqual(changed, workflow);
    assert.throws(() => assertWorkflowLanes(changed));
  }
});
