#!/usr/bin/env node
// Independent verifier for wtd.commitment.v1 envelopes (docs/INTERFACES.md §5).
// It recomputes the commitment and reportId locally and reads the registry's storage through
// view calls over JSON-RPC. It never talks to the WTD backend and does not rely on event logs.
//
//   node verifier/verify.mjs --envelope <file.json> [--rpc http://127.0.0.1:8545]
//                            [--contract 0x... | --deployment deployments/local.json]
//
// Exit codes: 0 matches the latest revision, 2 matches an older (superseded) revision,
//             1 no match / tampered, 3 chain or input error.
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { createPublicClient, getAddress, http, isAddress, parseAbi } from 'viem';
import {
  CLASSIFICATIONS, STATUSES, InputError, commitmentOf, parseJson, reportIdOf, validateEnvelope,
} from './commitment.mjs';

const EXIT = { MATCH_LATEST: 0, NO_MATCH: 1, SUPERSEDED: 2, ERROR: 3 };
const DEFAULT_RPC = 'http://127.0.0.1:8545';
const DEFAULT_DEPLOYMENT = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'deployments', 'local.json');

// Minimal ABI, written from INTERFACES.md §4 (enums are uint8 on the wire).
const abi = parseAbi([
  'struct Revision { bytes32 commitment; uint8 classification; uint64 timestamp; address author; }',
  'struct StatusChange { uint8 status; uint64 timestamp; address by; bytes32 noteHash; }',
  'function revisionCount(bytes32 reportId) view returns (uint256)',
  'function getRevision(bytes32 reportId, uint256 index) view returns (Revision)',
  'function statusCount(bytes32 reportId) view returns (uint256)',
  'function getStatusChange(bytes32 reportId, uint256 index) view returns (StatusChange)',
  'function currentStatus(bytes32 reportId) view returns (uint8)',
]);

const iso = (seconds) => new Date(Number(seconds) * 1000).toISOString().replace('.000Z', 'Z');
const classLabel = (code) => `${code} ${CLASSIFICATIONS[code] ?? '(unknown code)'}`;
const statusLabel = (code) => STATUSES[code] ?? `(unknown status ${code})`;
const line = (label, value) => console.log(`${label.padEnd(22)}: ${value}`);

function fail(message, code = EXIT.ERROR) {
  console.error(`ERROR: ${message}`);
  process.exit(code);
}

function readArgs() {
  try {
    const { values } = parseArgs({
      options: {
        envelope: { type: 'string' }, rpc: { type: 'string' }, contract: { type: 'string' },
        deployment: { type: 'string' }, help: { type: 'boolean', short: 'h' },
      },
    });
    if (values.help) {
      console.log('usage: node verifier/verify.mjs --envelope <file.json> [--rpc URL] [--contract 0x..|--deployment file.json]');
      process.exit(EXIT.MATCH_LATEST);
    }
    if (!values.envelope) throw new InputError('--envelope <file.json> is required');
    if (values.contract && values.deployment) throw new InputError('use either --contract or --deployment, not both');
    return values;
  } catch (err) {
    return fail(err.message);
  }
}

function loadTarget(args) {
  if (args.contract) {
    if (!isAddress(args.contract, { strict: false })) fail(`--contract ${args.contract} is not an address`);
    return { address: getAddress(args.contract), chainId: undefined, source: '--contract' };
  }
  const file = resolve(args.deployment ?? DEFAULT_DEPLOYMENT);
  let deployment;
  try {
    deployment = parseJson(readFileSync(file, 'utf8'));
  } catch (err) {
    fail(`cannot read deployment file ${file}: ${err.message}`);
  }
  if (!isAddress(String(deployment?.address), { strict: false })) fail(`deployment file ${file} has no valid "address"`);
  // A public deployment file may name a public RPC endpoint; --rpc still overrides it.
  const rpc = typeof deployment.rpc === 'string' && /^https?:\/\//.test(deployment.rpc) ? deployment.rpc : undefined;
  return { address: getAddress(deployment.address), chainId: deployment.chainId, rpc, source: file };
}

async function main() {
  const args = readArgs();

  // 1. Recompute everything from the envelope alone.
  let envelope;
  try {
    envelope = parseJson(readFileSync(args.envelope, 'utf8'));
  } catch (err) {
    fail(`cannot read envelope ${args.envelope}: ${err.message}`);
  }
  let reportIdText;
  try {
    reportIdText = validateEnvelope(envelope);
  } catch (err) {
    fail(err.message);
  }
  const commitment = commitmentOf(envelope);
  const reportId = reportIdOf(reportIdText);
  const claimed = envelope.threat_report.classification;

  console.log('WTD independent verifier (wtd.commitment.v1; on-chain storage reads only)');
  line('envelope', args.envelope);
  line('report_id', reportIdText);
  line('reportId (bytes32)', reportId);
  line('commitment (local)', commitment);

  // 2. Read the registry directly from the chain, pinned to one block for a consistent view.
  const target = loadTarget(args);
  const rpc = args.rpc ?? target.rpc ?? DEFAULT_RPC;
  const client = createPublicClient({ transport: http(rpc, { timeout: 10_000, retryCount: 0 }) });
  let chainId, blockNumber, revisions, statuses, current;
  try {
    chainId = await client.getChainId();
    if (target.chainId !== undefined && Number(target.chainId) !== chainId) {
      fail(`deployment file is for chain ${target.chainId} but ${rpc} is chain ${chainId}`);
    }
    blockNumber = await client.getBlockNumber();
    const code = await client.getCode({ address: target.address, blockNumber });
    if (!code || code === '0x') fail(`no contract code at ${target.address} on chain ${chainId} (chain reset? redeploy)`);
    const read = (functionName, extra = []) =>
      client.readContract({ address: target.address, abi, functionName, args: [reportId, ...extra], blockNumber });
    const revisionCount = await read('revisionCount');
    revisions = [];
    for (let i = 0n; i < revisionCount; i++) revisions.push(await read('getRevision', [i]));
    statuses = [];
    if (revisionCount > 0n) {
      const statusCount = await read('statusCount');
      for (let i = 0n; i < statusCount; i++) statuses.push(await read('getStatusChange', [i]));
      current = await read('currentStatus');
    }
  } catch (err) {
    fail(`chain read failed (${rpc}): ${err.shortMessage ?? err.message}`);
  }

  line('rpc', rpc);
  line('chain id', chainId);
  line('contract', `${target.address} (from ${target.source})`);
  line('read at block', blockNumber);

  if (revisions.length === 0) {
    line('revisions on chain', 0);
    console.log(`RESULT: NO MATCH - report ${reportId} is not registered on this contract (exit 1)`);
    process.exit(EXIT.NO_MATCH);
  }

  const latest = revisions.length - 1;
  const matched = revisions.findIndex((r) => r.commitment.toLowerCase() === commitment);
  line('revisions on chain', `${revisions.length} (latest = #${latest})`);
  revisions.forEach((r, i) => {
    const mark = i === matched ? '  <= matches envelope' : '';
    console.log(`  #${i}  ${r.commitment}  class ${classLabel(r.classification)}  ${iso(r.timestamp)}  by ${r.author}${mark}`);
  });

  line('latest revision', `#${latest}`);
  if (matched >= 0) {
    const r = revisions[matched];
    line('matched revision', `#${matched}${matched === latest ? ' (latest)' : ` (superseded by #${latest})`}`);
    line('  author', r.author);
    line('  timestamp', `${iso(r.timestamp)} (block timestamp, unix ${r.timestamp})`);
    const consistent = CLASSIFICATIONS[r.classification] === claimed;
    line('  classification', `${classLabel(r.classification)} on chain; envelope says ${JSON.stringify(claimed)}` +
      (consistent ? ' (consistent)' : ' (WARNING: inconsistent)'));
  } else {
    line('matched revision', 'none');
  }

  line('status history', `${statuses.length} entr${statuses.length === 1 ? 'y' : 'ies'}`);
  statuses.forEach((s, i) => {
    console.log(`  #${i}  ${statusLabel(s.status).padEnd(9)}  ${iso(s.timestamp)}  by ${s.by}  note ${s.noteHash}`);
  });
  line('current status', `${statusLabel(current)} (applies to latest revision #${latest}; a revision resets it to Pending)`);

  if (matched === latest) {
    console.log(`RESULT: MATCH - envelope matches the latest revision #${latest} (exit 0)`);
    process.exit(EXIT.MATCH_LATEST);
  }
  if (matched >= 0) {
    console.log(`RESULT: SUPERSEDED - envelope matches revision #${matched}, but #${latest} is the latest (exit 2)`);
    process.exit(EXIT.SUPERSEDED);
  }
  console.log('RESULT: NO MATCH - envelope does not match any on-chain revision of this report; it was altered or never anchored (exit 1)');
  process.exit(EXIT.NO_MATCH);
}

main().catch((err) => fail(`unexpected error: ${err.stack ?? err}`));
