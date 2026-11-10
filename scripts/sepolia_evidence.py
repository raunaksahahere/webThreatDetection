#!/usr/bin/env python3
"""Run the registry demonstration against a PUBLIC chain and record what actually happened.

    backend/.venv/bin/python scripts/sepolia_evidence.py            # Ethereum Sepolia (chain id 11155111), writes docs/evidence/
    scripts/testnet.sh deploy must have been run first (it writes deployments/sepolia.json).

What it does, checking each step on the chain rather than trusting its own bookkeeping:
  1. confirms the chain id is 11155111, the deployment has bytecode, the deploy receipt succeeded, and the owner/reporter/reviewer roles;
  2. registers a clearly synthetic demonstration report (the cross-language commitment test vector, submitter "demo"),
     verifies it with the independent verifier over a public RPC (expect exit 0), and verifies a tampered envelope (expect exit 1);
  3. revises the report, checks the old envelope is "superseded" (exit 2) and the new one is current (exit 0);
  4. records an independent review (Validated, with the hash of a note kept off-chain) from the separate reviewer key and verifies again.
It then writes docs/evidence/sepolia-demo.json (machine-readable), docs/evidence/sepolia-demo.txt (the verifier's own output) and
docs/SEPOLIA_EVIDENCE.md. Nothing is written if a step fails. Private keys are read from .env.sepolia, used in this process only (never on a command line),
and never printed or written; only public addresses, hashes and block numbers are recorded.

REHEARSAL: `--rehearsal-chain-id N --rpc URL --deployment FILE --out DIR` runs the same flow on a disposable local chain with keys from
the environment, writing only to DIR. Output from a rehearsal is labelled as such and is never the committed evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CAST = str(Path.home() / ".foundry/bin/cast")
FORGE = str(Path.home() / ".foundry/bin/forge")
SEPOLIA = 11155111
PUBLIC_RPC = "https://ethereum-sepolia-rpc.publicnode.com"
EXPLORER = "https://sepolia.etherscan.io"
VECTORS = ROOT / "docs" / "commitment-vectors.json"
MIN_BALANCE_WEI = 5 * 10**15  # 0.005 ETH covers the register + revise transactions comfortably


ABI = [  # the three state-changing functions this demonstration uses (see contracts/src/ThreatReportRegistry.sol)
    {"type": "function", "name": "register", "stateMutability": "nonpayable", "outputs": [],
     "inputs": [{"name": "reportId", "type": "bytes32"}, {"name": "commitment", "type": "bytes32"}, {"name": "classification", "type": "uint8"}]},
    {"type": "function", "name": "revise", "stateMutability": "nonpayable", "outputs": [],
     "inputs": [{"name": "reportId", "type": "bytes32"}, {"name": "expectedRevision", "type": "uint256"}, {"name": "commitment", "type": "bytes32"},
                {"name": "classification", "type": "uint8"}]},
    {"type": "function", "name": "setStatus", "stateMutability": "nonpayable", "outputs": [],
     "inputs": [{"name": "reportId", "type": "bytes32"}, {"name": "status", "type": "uint8"}, {"name": "noteHash", "type": "bytes32"}]},
]


class Stop(Exception):
    pass


def run(args: list[str], env: dict | None = None, check: bool = True) -> subprocess.CompletedProcess:
    p = subprocess.run(args, capture_output=True, text=True, env={**os.environ, **(env or {})}, cwd=ROOT)
    if check and p.returncode != 0:
        raise Stop(f"{' '.join(a for a in args[:3])} failed: {(p.stderr or p.stdout).strip()[:300]}")
    return p


def cast(*a: str, rpc: str, env: dict | None = None) -> str:
    return run([CAST, *a, "--rpc-url", rpc], env=env).stdout.strip()


def load_keys() -> tuple[str, str]:
    reporter, reviewer = os.environ.get("WTD_REPORTER_KEY", ""), os.environ.get("WTD_REVIEWER_KEY", "")
    f = ROOT / ".env.sepolia"
    if (not reporter or not reviewer) and f.exists():
        for line in f.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                if k.strip() == "WTD_REPORTER_KEY" and not reporter:
                    reporter = v.strip()
                if k.strip() == "WTD_REVIEWER_KEY" and not reviewer:
                    reviewer = v.strip()
    if not reporter or not reviewer:
        raise Stop("WTD_REPORTER_KEY / WTD_REVIEWER_KEY not found (run scripts/testnet.sh keys)")
    return reporter, reviewer


def address_of(key: str) -> str:
    """Public address of a key, computed in-process so the key never appears in a command line."""
    try:
        from eth_account import Account  # in backend/.venv (web3)
    except ImportError:
        raise Stop("run this script with backend/.venv/bin/python (needs eth_account)")
    return Account.from_key(key).address


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--deployment", default=str(ROOT / "deployments" / "sepolia.json"))
    ap.add_argument("--rpc", default=os.environ.get("WTD_PUBLIC_RPC", PUBLIC_RPC), help="public RPC used for ALL reads and by the verifier")
    ap.add_argument("--rehearsal-chain-id", type=int, default=0)
    ap.add_argument("--out", default="")
    args = ap.parse_args()
    rehearsal = bool(args.rehearsal_chain_id)
    chain_expected = args.rehearsal_chain_id or SEPOLIA
    if rehearsal and not args.out:
        print("STOPPED: rehearsal needs --out so it can never overwrite the committed evidence", file=sys.stderr)
        return 3
    out_dir = Path(args.out) if args.out else ROOT / "docs" / "evidence"
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        dep = json.loads(Path(args.deployment).read_text())
    except OSError:
        print(f"no deployment record at {args.deployment}.\nRun `scripts/testnet.sh deploy` (needs a funded Sepolia reporter key) first.", file=sys.stderr)
        return 3
    rpc = args.rpc
    reporter_key, reviewer_key = load_keys()
    reporter, reviewer = address_of(reporter_key), address_of(reviewer_key)
    steps: list[dict] = []
    transcript: list[str] = []

    def log(msg: str) -> None:
        print(msg, flush=True)

    try:
        chain_id = int(cast("chain-id", rpc=rpc))
        if chain_id != chain_expected or int(dep["chainId"]) != chain_expected:
            raise Stop(f"chain id is {chain_id} (deployment record says {dep['chainId']}), expected {chain_expected}; refusing to sign anything")
        if not rehearsal and chain_id == 1:
            raise Stop("mainnet; refusing")
        addr = dep["address"]
        code = cast("code", addr, rpc=rpc)
        if code in ("0x", ""):
            raise Stop(f"no bytecode at {addr} on chain {chain_id}")
        code_hash = run([CAST, "keccak", code]).stdout.strip()
        rec = json.loads(run([CAST, "receipt", dep["deployTx"], "--json", "--rpc-url", rpc]).stdout)
        if int(rec["status"], 16) != 1:
            raise Stop("deploy transaction did not succeed")
        created = (rec.get("contractAddress") or "").lower()
        if created != addr.lower():
            raise Stop(f"deploy receipt created {created or 'nothing'}, not {addr}")
        roles = {"owner": cast("call", addr, "owner()(address)", rpc=rpc),
                 "reporter_has_role": cast("call", addr, "isReporter(address)(bool)", reporter, rpc=rpc),
                 "reviewer_has_role": cast("call", addr, "isReviewer(address)(bool)", reviewer, rpc=rpc)}
        if roles["reporter_has_role"] != "true" or roles["reviewer_has_role"] != "true":
            raise Stop(f"roles are not configured on-chain: {roles}")
        # Runtime bytecode vs a fresh local build of the same source.
        build = run([FORGE, "inspect", "ThreatReportRegistry", "deployedBytecode", "--root", str(ROOT / "contracts")]).stdout.strip()
        local_hash = run([CAST, "keccak", build]).stdout.strip()
        bytecode = {"onchain_keccak256": code_hash, "local_build_keccak256": local_hash, "matches_local_build": code_hash == local_hash,
                    "solc": (re.search(r'solc(?:_version)?\s*=\s*"([^"]+)"', (ROOT / "contracts" / "foundry.toml").read_text()) or [None, "see contracts/foundry.toml"])[1]}
        bal = int(cast("balance", reporter, rpc=rpc))
        if bal < MIN_BALANCE_WEI:
            raise Stop(f"reporter {reporter} has {bal / 1e18:.6f} ETH on chain {chain_id}; fund it (about 0.02 test ETH) and rerun")
        log(f"chain {chain_id}, contract {addr}, roles ok, reporter balance {bal / 1e18:.4f} ETH")

        v = json.loads(VECTORS.read_text())
        rid, c0, c1 = v["report_id_bytes32"], v["vectors"][0]["commitment"], v["vectors"][1]["commitment"]
        if int(cast("call", addr, "revisionCount(bytes32)(uint256)", rid, rpc=rpc).split()[0]) != 0:
            raise Stop("the demonstration report is already registered on this contract; deploy a fresh one to repeat the demonstration")

        from web3 import Web3

        w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 30}))
        contract = w3.eth.contract(address=Web3.to_checksum_address(addr), abi=ABI)
        b32 = lambda h: bytes.fromhex(h[2:] if h.startswith("0x") else h)

        def send(key: str, label: str, fn_name: str, *a) -> dict:
            """Sign in this process (the key never reaches a command line), send, wait for the receipt, require success."""
            from eth_account import Account

            acct = Account.from_key(key)
            fn = getattr(contract.functions, fn_name)(*a)
            tx = fn.build_transaction({"from": acct.address, "nonce": w3.eth.get_transaction_count(acct.address, "pending"), "chainId": chain_id})
            tx["gas"] = int(w3.eth.estimate_gas(tx) * 1.3)
            h = w3.eth.send_raw_transaction(acct.sign_transaction(tx).raw_transaction)
            rcpt = w3.eth.wait_for_transaction_receipt(h, timeout=240)
            r = {"step": label, "tx": "0x" + h.hex().removeprefix("0x"), "block": int(rcpt["blockNumber"]), "status": int(rcpt["status"]),
                 "explorer": f"{EXPLORER}/tx/0x{h.hex().removeprefix('0x')}" if chain_id == SEPOLIA else None}
            if r["status"] != 1:
                raise Stop(f"{label} reverted")
            steps.append(r)
            log(f"{label}: tx {r['tx']} block {r['block']}")
            return r

        verifier_results: list[dict] = []

        def verify(label: str, envelope: str, expected: int) -> None:
            cmd = ["node", "verifier/verify.mjs", "--envelope", envelope, "--rpc", rpc, "--contract", addr]
            for attempt in range(1, 7):  # a public RPC can serve a read from a node that is a block behind
                p = run(cmd, check=False)
                if p.returncode == expected:
                    break
                time.sleep(4)
            text = (p.stdout + p.stderr).strip()
            transcript.append(f"$ node verifier/verify.mjs --envelope {envelope} --rpc <public RPC> --contract {addr}\n{text}\nexit code: {p.returncode} (expected {expected})\n")
            verifier_results.append({"label": label, "envelope": envelope, "expected_exit": expected, "observed_exit": p.returncode, "attempts": attempt})
            log(f"verify {label}: exit {p.returncode} (expected {expected})")
            if p.returncode != expected:
                raise Stop(f"verifier outcome for '{label}' was {p.returncode}, expected {expected}")

        send(reporter_key, "register vectors[0] (synthetic demonstration report)", "register", b32(rid), b32(c0), 3)
        verify("registered envelope matches", "verifier/fixtures/vector0.envelope.json", 0)
        verify("altered envelope is rejected", "verifier/fixtures/tampered.envelope.json", 1)
        send(reporter_key, "revise to vectors[1]", "revise", b32(rid), 1, b32(c1), 3)
        verify("old envelope is reported as superseded", "verifier/fixtures/vector0.envelope.json", 2)
        verify("revised envelope is current", "verifier/fixtures/vector1.envelope.json", 0)
        note = "demonstration review: indicators confirmed (synthetic)"
        note_hash = "0x" + hashlib.sha256(note.encode()).hexdigest()
        send(reviewer_key, "independent review: Validated (note hash only on-chain)", "setStatus", b32(rid), 1, b32(note_hash))
        verify("after review: current revision, status Validated", "verifier/fixtures/vector1.envelope.json", 0)
        raw_logs = run([CAST, "logs", "--from-block", str(dep["deployBlock"]), "--address", addr, "--json", "--rpc-url", rpc]).stdout
        needles = ("sbi-kyc-update", "hxxps", "refund", "quotes")  # plain text or hex of any report text
        hexed = [w.encode().hex() for w in needles]
        onchain_text_leak = [w for w in needles if w in raw_logs.lower()] + [h for h in hexed if h in raw_logs.lower()]
        for s_ in steps:  # the calldata of each transaction: only hashes and codes
            tx = run([CAST, "tx", s_["tx"], "input", "--rpc-url", rpc]).stdout.strip().lower()
            onchain_text_leak += [s_["step"] for h in hexed if h in tx]
        if onchain_text_leak:
            raise Stop(f"report text found on-chain: {onchain_text_leak}")

        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        label = "REHEARSAL on a disposable local chain (not public evidence)" if rehearsal else "Ethereum Sepolia (public testnet)"
        evidence = {
            "kind": label, "recorded_at": now, "chain_id": chain_id, "network": "sepolia" if chain_id == SEPOLIA else f"chain-{chain_id}",
            "contract": addr, "explorer_address": f"{EXPLORER}/address/{addr}" if chain_id == SEPOLIA else None,
            "deploy_tx": dep["deployTx"], "deploy_block": dep["deployBlock"], "deployed_at": dep.get("deployedAt"),
            "owner": roles["owner"], "reporter": reporter, "reviewer": reviewer, "roles_checked_on_chain": roles,
            "runtime_bytecode": bytecode, "public_rpc_used": rpc if rpc == PUBLIC_RPC else "a public RPC (not recorded)",
            "demonstration_report": {"description": "SYNTHETIC test vector; submitter 'demo'; defanged example indicators; not real threat intelligence",
                                     "report_id_bytes32": rid, "commitment_revision_0": c0, "commitment_revision_1": c1,
                                     "review_note_sha256": note_hash, "review_note_text": note},
            "transactions": steps, "verifier": verifier_results, "report_text_found_on_chain": False,
        }
        (out_dir / "sepolia-demo.json").write_text(json.dumps(evidence, indent=1) + "\n")
        (out_dir / "sepolia-demo.txt").write_text(f"{label}; recorded {now}\n\n" + "\n".join(transcript))
        (out_dir / ("SEPOLIA_EVIDENCE.md" if not rehearsal else "REHEARSAL_EVIDENCE.md")).write_text(render(evidence, rehearsal))
        log(f"wrote evidence to {out_dir}")
        return 0
    except Stop as e:
        print(f"STOPPED: {e}", file=sys.stderr)
        return 3


def render(e: dict, rehearsal: bool) -> str:
    x = lambda h, kind: f"[`{h[:10]}…{h[-6:]}`]({EXPLORER}/{kind}/{h})" if e["chain_id"] == SEPOLIA else f"`{h}`"
    L = [f"# {'REHEARSAL - ' if rehearsal else ''}Public registry evidence ({e['kind']})", "",
         f"Recorded {e['recorded_at']} by `scripts/sepolia_evidence.py`. Every value below was read back from the chain during that run.", ""]
    if rehearsal:
        L += ["**This is a rehearsal on a disposable local chain. It is not public evidence.**", ""]
    L += ["| | |", "|---|---|", f"| Network | {e['network']} (chain id {e['chain_id']}) |", f"| Contract `ThreatReportRegistry` | {x(e['contract'], 'address')} |",
          f"| Deployment transaction | {x(e['deploy_tx'], 'tx')}, block {e['deploy_block']} |", f"| Owner / reporter / reviewer | `{e['owner']}` / `{e['reporter']}` / `{e['reviewer']}` |",
          f"| Runtime bytecode keccak-256 | `{e['runtime_bytecode']['onchain_keccak256']}` ({'identical to' if e['runtime_bytecode']['matches_local_build'] else 'DIFFERENT from'} a fresh local build of `contracts/src/ThreatReportRegistry.sol`, solc {e['runtime_bytecode']['solc']}) |", ""]
    d = e["demonstration_report"]
    L += ["## The demonstration report", "", f"{d['description']}. reportId `{d['report_id_bytes32']}`.", "",
          "## Transactions", "", "| Step | Transaction | Block | Status |", "|---|---|---|---|"]
    for s in e["transactions"]:
        L.append(f"| {s['step']} | {x(s['tx'], 'tx')} | {s['block']} | {'success' if s['status'] == 1 else 'FAILED'} |")
    L += ["", "## Independent verification (Node + viem, public RPC, no WTD backend)", "", "| Check | Expected exit | Observed exit |", "|---|---|---|"]
    for v in e["verifier"]:
        L.append(f"| {v['label']} | {v['expected_exit']} | {v['observed_exit']} |")
    L += ["", "Exit codes: 0 matches the latest revision, 1 altered or not registered, 2 matches an older (superseded) revision, 3 error. The verifier's full output is in "
          "[`evidence/sepolia-demo.txt`](evidence/sepolia-demo.txt); the raw record is [`evidence/sepolia-demo.json`](evidence/sepolia-demo.json).", "",
          "## Reproduce", "", "```bash", "cd verifier && npm ci && cd ..",
          f"node verifier/verify.mjs --envelope verifier/fixtures/vector1.envelope.json --rpc {PUBLIC_RPC} --contract {e['contract']}   # exit 0 = current revision",
          f"node verifier/verify.mjs --envelope verifier/fixtures/tampered.envelope.json --rpc {PUBLIC_RPC} --contract {e['contract']}  # exit 1 = altered",
          f"node verifier/verify.mjs --envelope verifier/fixtures/vector0.envelope.json --rpc {PUBLIC_RPC} --contract {e['contract']}   # exit 2 = superseded revision", "```", "",
          "## What this does and does not show", "",
          "- Only a salted commitment hash, a classification code and a note hash are on-chain; the report text, URLs and indicators are not (checked: no report text appears in the contract's logs or any transaction's calldata).",
          "- A match proves the envelope is unchanged since it was registered and shows its revision and review history. It does not prove the report's conclusions are true.",
          "- Reporter and reviewer are two keys held by the project operator, so this demonstrates integrity and ordering, not independent third-party review.",
          "- The demonstration report is a synthetic test vector, not threat intelligence about a real site.", ""]
    return "\n".join(L)


if __name__ == "__main__":
    raise SystemExit(main())
