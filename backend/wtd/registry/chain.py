"""Registry client (web3.py). Writes commitments; reads revisions and status directly from storage.

Local development uses anvil's publicly known test key for account #1 (reporter) ONLY when the
connected chain id is 31337. Any other chain requires WTD_REPORTER_KEY and refuses the test keys.
"""
from __future__ import annotations

import json
from functools import lru_cache

from web3 import Web3

from ..config import ROOT, SETTINGS
from ..models import iso

ANVIL_REPORTER_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"  # anvil test account #1 (public)
ANVIL_REVIEWER_KEY = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"  # anvil test account #2 (public)
STATUS = ["Pending", "Validated", "Disputed", "Retracted"]


class ChainUnavailable(RuntimeError):
    pass


def _deployment() -> dict:
    if not SETTINGS.deployment_file.exists():
        raise ChainUnavailable("no deployment file; run scripts/chain.sh start && scripts/deploy.sh")
    return json.loads(SETTINGS.deployment_file.read_text())


@lru_cache(maxsize=1)
def _abi() -> list:
    p = ROOT / "contracts" / "out" / "ThreatReportRegistry.sol" / "ThreatReportRegistry.json"
    if not p.exists():
        raise ChainUnavailable("contract ABI not built; run scripts/deploy.sh (it runs forge build)")
    return json.loads(p.read_text())["abi"]


def _w3() -> Web3:
    w3 = Web3(Web3.HTTPProvider(SETTINGS.rpc_url, request_kwargs={"timeout": 6}))
    try:
        w3.eth.chain_id
    except Exception as e:
        raise ChainUnavailable(f"RPC {SETTINGS.rpc_url} not reachable ({type(e).__name__})") from e
    return w3


def _contract(w3: Web3):
    dep = _deployment()
    if w3.eth.chain_id != dep["chainId"]:
        raise ChainUnavailable(f"connected chain id {w3.eth.chain_id} does not match deployment {dep['chainId']}")
    addr = Web3.to_checksum_address(dep["address"])
    if not w3.eth.get_code(addr):
        raise ChainUnavailable("no contract code at the deployed address (chain was reset?); run scripts/deploy.sh")
    return w3.eth.contract(address=addr, abi=_abi()), dep


def _signer_key(w3: Web3, role: str = "reporter") -> str:
    if role == "reporter" and SETTINGS.reporter_key:
        return SETTINGS.reporter_key
    if w3.eth.chain_id != 31337:
        raise ChainUnavailable("WTD_REPORTER_KEY must be set for non-local chains")
    return ANVIL_REPORTER_KEY if role == "reporter" else ANVIL_REVIEWER_KEY


def status() -> dict:
    try:
        w3 = _w3()
        c, dep = _contract(w3)
        return {"connected": True, "chain_id": w3.eth.chain_id, "contract": c.address, "block": w3.eth.block_number}
    except ChainUnavailable as e:
        return {"connected": False, "chain_id": None, "contract": None, "error": str(e)}


def _send(w3: Web3, fn, key: str) -> dict:
    acct = w3.eth.account.from_key(key)
    tx = fn.build_transaction({"from": acct.address, "nonce": w3.eth.get_transaction_count(acct.address), "chainId": w3.eth.chain_id})
    signed = acct.sign_transaction(tx)
    h = w3.eth.send_raw_transaction(signed.raw_transaction)
    rcpt = w3.eth.wait_for_transaction_receipt(h, timeout=30)
    if rcpt.status != 1:
        raise RuntimeError("transaction reverted")
    return {"tx_hash": "0x" + bytes(rcpt.transactionHash).hex().removeprefix("0x"), "block_number": rcpt.blockNumber, "from": acct.address}


def register(report_id_b32: str, commitment: str, cls_code: int) -> dict:
    w3 = _w3()
    c, dep = _contract(w3)
    res = _send(w3, c.functions.register(bytes.fromhex(report_id_b32[2:]), bytes.fromhex(commitment[2:]), cls_code), _signer_key(w3))
    return {**res, "chain_id": w3.eth.chain_id, "contract": c.address, "revision": 0, "registered_at": iso()}


def revise(report_id_b32: str, expected_revision: int, commitment: str, cls_code: int) -> dict:
    w3 = _w3()
    c, dep = _contract(w3)
    res = _send(w3, c.functions.revise(bytes.fromhex(report_id_b32[2:]), expected_revision, bytes.fromhex(commitment[2:]), cls_code), _signer_key(w3))
    return {**res, "chain_id": w3.eth.chain_id, "contract": c.address, "revision": expected_revision, "registered_at": iso()}


def read(report_id_b32: str) -> dict:
    w3 = _w3()
    c, dep = _contract(w3)
    rid = bytes.fromhex(report_id_b32[2:])
    n = c.functions.revisionCount(rid).call()
    revisions = []
    for i in range(n):
        rv = c.functions.getRevision(rid, i).call()
        revisions.append({"index": i, "commitment": "0x" + bytes(rv[0]).hex(), "classification": rv[1], "timestamp": rv[2], "author": rv[3]})
    history = []
    if n:
        for i in range(c.functions.statusCount(rid).call()):
            s = c.functions.getStatusChange(rid, i).call()
            history.append({"index": i, "status": STATUS[s[0]], "timestamp": s[1], "by": s[2], "note_hash": "0x" + bytes(s[3]).hex()})
    return {"chain_id": w3.eth.chain_id, "contract": c.address, "revisions": revisions, "status_history": history}
