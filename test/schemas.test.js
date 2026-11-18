import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';

const root = new URL('../', import.meta.url);

test('actor.json has required fields and version 0.0', () => {
  const actor = JSON.parse(fs.readFileSync(new URL('.actor/actor.json', root), 'utf8'));
  assert.equal(actor.actorSpecification, 1);
  assert.equal(actor.version, '0.0');
  assert.equal(actor.name, 'mcp-tool-contract');
  assert.ok(actor.inputSchema);
  assert.ok(actor.outputSchema);
  assert.ok(actor.storages?.dataset);
});

test('all JSON schemas are valid JSON', () => {
  for (const path of ['.actor/input_schema.json', '.actor/output_schema.json', '.actor/dataset_schema.json', 'package.json']) {
    JSON.parse(fs.readFileSync(new URL(path, root), 'utf8'));
  }
});

test('runtime entrypoint exists', () => {
  assert.ok(fs.existsSync(new URL('src/main.js', root)));
});
