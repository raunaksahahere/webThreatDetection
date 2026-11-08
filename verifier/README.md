# wtd-verifier

Independent verifier for `wtd.commitment.v1` threat-report envelopes anchored in
`ThreatReportRegistry` (spec: `docs/INTERFACES.md` §3–§5). It recomputes the commitment and
reportId locally and reads the contract's storage over JSON-RPC with view calls. It never
contacts the WTD backend and does not depend on event logs.

```bash
cd verifier && npm ci          # viem 2.57.8, canonicalize 2.1.0 (exact pins, see package-lock.json)
node test-vectors.mjs          # must pass: reproduces docs/commitment-vectors.json byte-for-byte
node verify.mjs --envelope <envelope.json> [--rpc http://127.0.0.1:8545] \
                [--contract 0x... | --deployment ../deployments/local.json]
```

Exit codes: `0` matches the latest revision · `2` matches an older (superseded) revision ·
`1` no match / tampered / not registered · `3` chain or input error.

Without `--contract`/`--deployment` it reads `deployments/local.json` from the repository root
and checks that the RPC's chain id matches the one recorded there.

- `commitment.mjs`: JCS (RFC 8785 via `canonicalize`) + SHA-256 (`node:crypto`) and input checks.
  Numbers that are not safe integers are rejected (the spec forbids floats).
- `fixtures/`: the three envelopes from `docs/commitment-vectors.json`, as standalone files.
- `e2e-demo.sh`: end-to-end run on the local anvil chain (see `docs/WEB3.md`).

## Licence

MIT License. Copyright (c) 2026 WebThreatDetection contributors.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions: The above copyright notice and this
permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Dependencies: `viem` (MIT), `canonicalize` (Apache-2.0).
