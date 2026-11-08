// wtd.commitment.v1 primitives (docs/INTERFACES.md §3), shared by verify.mjs and test-vectors.mjs.
//   commitment = SHA-256(RFC 8785 JCS(envelope))                  -> 0x + 64 lowercase hex
//   reportId   = SHA-256(UTF-8("wtd.report-id.v1:" + report_id))  -> 0x + 64 lowercase hex
import { createHash } from 'node:crypto';
import canonicalize from 'canonicalize';

export const ENVELOPE_SCHEMA = 'wtd.commitment.v1';
export const REPORT_ID_PREFIX = 'wtd.report-id.v1:';
export const CLASSIFICATIONS = ['Inconclusive', 'Low Risk', 'Suspicious', 'High Risk', 'Confirmed Malicious'];
export const STATUSES = ['Pending', 'Validated', 'Disputed', 'Retracted'];

/** Thrown for malformed input (verifier exit code 3). */
export class InputError extends Error {}

const sha256 = (text) => '0x' + createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');

/** RFC 8785 canonical JSON text of a parsed JSON value. */
export const jcs = (value) => canonicalize(value);

/** Commitment of a parsed envelope. */
export const commitmentOf = (envelope) => sha256(jcs(envelope));

/** bytes32 on-chain id for a threat_report.report_id string. */
export const reportIdOf = (reportId) => sha256(REPORT_ID_PREFIX + reportId);

/**
 * JSON.parse that rejects non-integer or unsafe-integer numbers. The spec forbids floats, and
 * numbers outside +-2^53 would canonicalize differently across JSON implementations.
 */
export function parseJson(text) {
  try {
    return JSON.parse(text, (key, value, context) => {
      if (typeof value === 'number') {
        const source = context?.source ?? String(value);
        if (!Number.isSafeInteger(value) || /[.eE]/.test(source)) {
          throw new InputError(`number ${source} at key "${key}" is not a safe integer (floats are not allowed)`);
        }
      }
      return value;
    });
  } catch (err) {
    if (err instanceof InputError) throw err;
    throw new InputError(`invalid JSON: ${err.message}`);
  }
}

/** Structural checks on an envelope; throws InputError. Returns the threat_report.report_id. */
export function validateEnvelope(env) {
  if (env === null || typeof env !== 'object' || Array.isArray(env)) throw new InputError('envelope is not a JSON object');
  if (env.schema !== ENVELOPE_SCHEMA) {
    throw new InputError(`envelope.schema is ${JSON.stringify(env.schema)}, expected "${ENVELOPE_SCHEMA}"`);
  }
  if (typeof env.salt !== 'string' || !/^[0-9a-f]{64}$/.test(env.salt)) {
    throw new InputError('envelope.salt must be 64 lowercase hex characters');
  }
  const report = env.threat_report;
  if (report === null || typeof report !== 'object' || Array.isArray(report)) {
    throw new InputError('envelope.threat_report is not a JSON object');
  }
  if (typeof report.report_id !== 'string' || report.report_id.length === 0) {
    throw new InputError('envelope.threat_report.report_id must be a non-empty string');
  }
  return report.report_id;
}
