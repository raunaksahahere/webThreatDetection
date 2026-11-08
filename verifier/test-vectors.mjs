// Checks this verifier's wtd.commitment.v1 implementation against docs/commitment-vectors.json,
// which the Python backend generated. Run: node verifier/test-vectors.mjs   (or: npm test)
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { InputError, commitmentOf, jcs, parseJson, reportIdOf, validateEnvelope } from './commitment.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const vectorsFile = resolve(here, '..', 'docs', 'commitment-vectors.json');
const doc = parseJson(readFileSync(vectorsFile, 'utf8'));
const fixture = (name) => parseJson(readFileSync(resolve(here, 'fixtures', name), 'utf8'));

doc.vectors.forEach((v, i) => {
  test(`vectors[${i}]: JCS bytes match jcs_utf8 byte-for-byte`, () => {
    assert.ok(Buffer.from(jcs(v.envelope), 'utf8').equals(Buffer.from(v.jcs_utf8, 'utf8')));
  });
  test(`vectors[${i}]: commitment reproduces`, () => {
    assert.equal(commitmentOf(v.envelope), v.commitment);
  });
  test(`vectors[${i}]: reportId reproduces report_id_bytes32`, () => {
    assert.equal(validateEnvelope(v.envelope), doc.report_id);
    assert.equal(reportIdOf(v.envelope.threat_report.report_id), doc.report_id_bytes32);
  });
});

test('different salt gives a different commitment', () => {
  assert.notEqual(doc.vectors[0].commitment, doc.vectors[1].commitment);
});

test('tampered vector: commitment reproduces and differs from vectors[0]', () => {
  assert.equal(commitmentOf(doc.tampered.envelope), doc.tampered.commitment);
  assert.notEqual(commitmentOf(doc.tampered.envelope), doc.vectors[0].commitment);
});

test('fixtures in verifier/fixtures are the vector envelopes', () => {
  assert.equal(commitmentOf(fixture('vector0.envelope.json')), doc.vectors[0].commitment);
  assert.equal(commitmentOf(fixture('vector1.envelope.json')), doc.vectors[1].commitment);
  assert.equal(commitmentOf(fixture('tampered.envelope.json')), doc.tampered.commitment);
});

test('input checks: wrong schema, bad salt, floats are rejected', () => {
  const env = structuredClone(doc.vectors[0].envelope);
  assert.throws(() => validateEnvelope({ ...env, schema: 'wtd.commitment.v2' }), InputError);
  assert.throws(() => validateEnvelope({ ...env, salt: 'ABC' }), InputError);
  assert.throws(() => parseJson('{"a": 1.5}'), InputError);
  assert.throws(() => parseJson('{"a": 1.0}'), InputError);
  assert.throws(() => parseJson('{"a": 9007199254740993}'), InputError);
  assert.deepEqual(parseJson('{"a": -42}'), { a: -42 });
});
