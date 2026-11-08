# Web3 layer: tamper-evident threat reports

Spec: `docs/INTERFACES.md` §3 (commitment), §4 (contract), §5 (verifier). This file covers how to
run it, the design, and the output observed on 2026-11-08.

## Run it

Needs Foundry 1.9.0 (`forge`, `anvil`, `cast` in `~/.foundry/bin`), Node 24, `jq`, `curl`.

```bash
export PATH="$HOME/.foundry/bin:$PATH"

# contract tests
(cd contracts && forge test -vv)

# verifier deps + test vectors (must pass)
(cd verifier && npm ci && node test-vectors.mjs)

# local chain (anvil, chain id 31337, state in chain-state/anvil.json) and deployment
scripts/chain.sh start        # idempotent; also: run (foreground) | stop | status | reset
scripts/deploy.sh             # writes deployments/local.json; skips if that address still has code

# verify an envelope (e.g. the file from GET /api/analyses/{id}/threat-report/download)
node verifier/verify.mjs --envelope verifier/fixtures/vector1.envelope.json
# exit 0 latest revision | 2 superseded revision | 1 no match / tampered | 3 chain or input error

# full end-to-end demo (needs a chain without the test-vector report: scripts/chain.sh reset
# deletes ALL local chain state first). Leaves the chain stopped.
verifier/e2e-demo.sh

scripts/chain.sh stop
```

Accounts are anvil's defaults from the public test mnemonic (`test test ... junk`): #0
`0xf39F…2266` owner/deployer, #1 `0x7099…79C8` reporter (backend signer), #2 `0x3C44…93BC`
reviewer. Those keys are public. `deploy.sh` refuses any chain id other than 31337.

## Design

**Off chain:** the threat report and its envelope
`{"schema":"wtd.commitment.v1","salt":<32 random bytes hex>,"threat_report":{...}}`. Indicators,
URLs, message text and findings stay here.

**On chain (`contracts/src/ThreatReportRegistry.sol`):**
- `reportId = sha256("wtd.report-id.v1:" + report_id)`
- per revision: `commitment = sha256(JCS(envelope))`, a classification code 0–4, the block timestamp
  and the author
- per report: an append-only status log (`Pending/Validated/Disputed/Retracted`, reviewer,
  timestamp, `noteHash`)

**Why the salt:** the report itself is not public, but someone who guesses its contents (for
example "is URL X in a High Risk report?") could hash candidates and compare them with the public
commitment. The 32-byte random salt makes that infeasible. Only someone holding the envelope can
check it.

**Roles and rules:**
- The `owner` (two-step transfer) grants or revokes `reporter` and `reviewer`.
- Reporters `register` new ids. Only the original author, while still a reporter, can `revise`,
  and only with `expectedRevision == revisionCount`.
- Every commitment is non-zero and globally unique, and classification is at most 4.
- Reviewers `setStatus` only on reports they did not author.
- A revise resets a non-Pending status by appending a `Pending` entry (by the author, `noteHash` 0).
- Nothing is ever overwritten or deleted. Every revert is a custom error.

**Verifier (`verifier/verify.mjs`):** it recomputes both hashes locally (`canonicalize` +
`node:crypto`). It then reads `revisionCount/getRevision/statusCount/getStatusChange/currentStatus`
from storage, pinned to one block. It uses an embedded `parseAbi` ABI and never calls the backend
or reads event logs.

**What this does and does not prove:** a match is tamper evidence under the contract's rules:
- the envelope is byte-identical (after JCS) to what a registered reporter anchored at that
  revision and time;
- older revisions stay visible, and the verifier tells you if the file is superseded.

It is **not proof that the report is true**. It also does not prove who wrote the report beyond
the reporter key. On this local dev chain the guarantee is weak: anvil's dev RPCs (`anvil_setStorageAt`,
`anvil_setCode`, `evm_revert`, `anvil_reset`) or a deleted `chain-state/anvil.json` can rewrite or
erase history. A public chain or a chain run by an independent party would be needed for
third-party trust.

## Observed results (2026-11-08, real output)

`forge test -vv` (Foundry 1.9.0, solc 0.8.38, forge-std 1.17.0):
```
Suite result: ok. 22 passed; 0 failed; 0 skipped; finished in 7.81ms (11.39ms CPU time)
Ran 1 test suite in 10.01ms (7.81ms CPU time): 22 tests passed, 0 failed, 0 skipped (22 total tests)
```
The suite covers:
- the happy path (register → revise → setStatus);
- the role reverts: non-reporter or revoked reporter, another reporter revising, non-reviewer
  setStatus, reviewer self-review;
- revision and input reverts: out-of-order or stale `expectedRevision`, duplicate id, reused /
  zero commitment, classification 5 and 255 (plus a fuzz test);
- revise resetting the status to Pending;
- append-only history;
- two-step ownership, including cancel;
- all events.

`node verifier/test-vectors.mjs`: `tests 10, pass 10, fail 0`. Both vectors' JCS bytes, commitments
and `report_id_bytes32` reproduce, and the tampered vector differs from `vectors[0]`.

`verifier/e2e-demo.sh` on a fresh chain (`scripts/chain.sh reset` first). These are excerpts
copied verbatim from the run log:
```
started: anvil pid 40769 | rpc http://127.0.0.1:8545 | chain id 31337 | block 0
deployed ThreatReportRegistry; wrote /home/raunak/Desktop/WebThreatDetection/deployments/local.json
{
  "chainId": 31337,
  "address": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
  "deployTx": "0x917d177ccea01abe2281701c673fac3f4be5bdf252783e161ab60bb58ba6597a",
  "deployBlock": 1,
  "owner": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
  "reporter": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  "reviewer": "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
  "deployedAt": "2026-11-08T08:42:29Z"
}

=== register vectors[0] (reportId 0xefacb7938499ae4b0a14eb00d995022aae753863306a67b24c60d3d131ba59df, commitment 0x354eb41ec43a25cef41b6a5c0cbad3caaeccce534a0a72c5639965df6eab2e7d, classification 3) from account #1
tx 0xeceace898fe2015923124b3abdf8393f06e59a65b8a12b7842b4c609b2b62451  block 3  status 0x1
$ node verifier/verify.mjs --envelope verifier/fixtures/vector0.envelope.json
RESULT: MATCH - envelope matches the latest revision #0 (exit 0)
exit code: 0 (expected 0)
$ node verifier/verify.mjs --envelope verifier/fixtures/tampered.envelope.json
RESULT: NO MATCH - envelope does not match any on-chain revision of this report; it was altered or never anchored (exit 1)
exit code: 1 (expected 1)

=== revise to vectors[1] (expectedRevision 1, commitment 0xbd344a60dacde8bfa66a10e333cfa829c12230b352fa45940eccf6f9bb6dfe78) from account #1
tx 0xff26dffc2fbfa55a88368a2eb1ef1500f8a088c1c381109b0c46c4d0c8797755  block 4  status 0x1
$ node verifier/verify.mjs --envelope verifier/fixtures/vector0.envelope.json
RESULT: SUPERSEDED - envelope matches revision #0, but #1 is the latest (exit 2)
exit code: 2 (expected 2)
$ node verifier/verify.mjs --envelope verifier/fixtures/vector1.envelope.json
RESULT: MATCH - envelope matches the latest revision #1 (exit 0)
exit code: 0 (expected 0)

=== setStatus(Validated, noteHash 0xa662c23968021c0a4c648e7f46da5c5641d33f9bd2ebd0c2d2eb47f9cee3200f) from account #2 (reviewer)
tx 0xebbf51b52ef08f5653791e4aab3e2a3082e4be0fa8300257320743060cee5da5  block 5  status 0x1

=== restart anvil (state file chain-state/anvil.json)
before restart: block 5, contract logs 6
stopped (pid 40769); state: /home/raunak/Desktop/WebThreatDetection/chain-state/anvil.json (127927 bytes)
started: anvil pid 41159 | rpc http://127.0.0.1:8545 | chain id 31337 | block 5
after restart:  block 5, contract logs 6
deploy tx receipt after restart: true
already deployed: 0x5FbDB2315678afecb367f032d93F642f64180aa3 has code on chain 31337; skipping (FORCE=1 to redeploy)
```
This is the full verifier output after the restart, for `vector0`:
```
WTD independent verifier (wtd.commitment.v1; on-chain storage reads only)
envelope              : verifier/fixtures/vector0.envelope.json
report_id             : 6f1c2a3e-1111-4c4c-9a9a-0123456789ab
reportId (bytes32)    : 0xefacb7938499ae4b0a14eb00d995022aae753863306a67b24c60d3d131ba59df
commitment (local)    : 0x354eb41ec43a25cef41b6a5c0cbad3caaeccce534a0a72c5639965df6eab2e7d
rpc                   : http://127.0.0.1:8545
chain id              : 31337
contract              : 0x5FbDB2315678afecb367f032d93F642f64180aa3 (from /home/raunak/Desktop/WebThreatDetection/deployments/local.json)
read at block         : 5
revisions on chain    : 2 (latest = #1)
  #0  0x354eb41ec43a25cef41b6a5c0cbad3caaeccce534a0a72c5639965df6eab2e7d  class 3 High Risk  2026-11-08T08:42:31Z  by 0x70997970C51812dc3A010C7d01b50e0d17dc79C8  <= matches envelope
  #1  0xbd344a60dacde8bfa66a10e333cfa829c12230b352fa45940eccf6f9bb6dfe78  class 3 High Risk  2026-11-08T08:42:32Z  by 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
latest revision       : #1
matched revision      : #0 (superseded by #1)
  author              : 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
  timestamp           : 2026-11-08T08:42:31Z (block timestamp, unix 1794127351)
  classification      : 3 High Risk on chain; envelope says "High Risk" (consistent)
status history        : 1 entry
  #0  Validated  2026-11-08T08:42:33Z  by 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC  note 0xa662c23968021c0a4c648e7f46da5c5641d33f9bd2ebd0c2d2eb47f9cee3200f
current status        : Validated (applies to latest revision #1; a revision resets it to Pending)
RESULT: SUPERSEDED - envelope matches revision #0, but #1 is the latest (exit 2)
```
After the restart, `vector1` gave exit 0 (Validated), `vector0` exit 2 and `tampered` exit 1. The run
ended `E2E: all expectations met` with the chain stopped.

With the chain stopped, the verifier exits 3 (`ERROR: chain read failed (http://127.0.0.1:8545):
HTTP request failed.`). A `wtd.commitment.v2` schema, a missing file and a missing `--envelope`
also exit 3.

**Restart persistence:** storage, block number (5), transaction receipts and contract event logs
(6 before, 6 after) all survived the stop/start with anvil 1.9.0 `--state`. The verifier relies
only on storage view calls in any case.

**Current local state:** `chain-state/anvil.json` (gitignored) holds this demo deployment with the
test-vector report at revision 1, status Validated, and `deployments/local.json` points at it.
`scripts/chain.sh reset` wipes it, and the next `scripts/deploy.sh` redeploys.

## Notes

- `contracts/lib/forge-std` (1.17.0) was installed with `forge install --no-git` so no submodule is
  added to the parent repository; it is plain vendored source. `out/`, `cache/` and `broadcast/`
  are gitignored.
- `forge fmt --check` would reformat the one-line struct and enum declarations. They are kept
  compact on purpose, to mirror INTERFACES §4.
