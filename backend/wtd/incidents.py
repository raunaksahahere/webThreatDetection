"""Incident clustering over stored indicators (deterministic), with an honest cluster type.

A cluster is a connected component of reports that share an indicator (same keyed hash). Its type says what the
link actually means, so repeat checks of one site are never presented as a campaign:
- "campaign": at least two *different* targets share a campaign-specific identifier (certificate key, UPI ID,
  wallet, phone number or e-mail address).
- "shared_infrastructure": different targets share only an IP address or registrable domain (common on shared
  hosting and CDNs; weak evidence on its own).
- "repeat_checks": every report in the cluster is the same target analysed more than once.
"""
from __future__ import annotations

import hashlib

from . import pipeline

CAMPAIGN_TYPES = ("cert_spki", "upi", "crypto_wallet", "phone", "email")


def clusters() -> list[dict]:
    edges = pipeline.STORE.indicator_edges()
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    pair_shared: dict[tuple[str, str], set[tuple[str, str]]] = {}
    for a, b, t, d in edges:
        parent[find(a)] = find(b)
        pair_shared.setdefault((a, b), set()).add((t, d))

    groups: dict[str, dict] = {}
    for (a, b), s in pair_shared.items():
        g = groups.setdefault(find(a), {"ids": set(), "pairs": []})
        g["ids"] |= {a, b}
        g["pairs"].append((a, b, s))

    out = []
    for g in groups.values():
        reps = [r for r in (pipeline.STORE.get(i) for i in g["ids"]) if r]
        if len(reps) < 2:
            continue
        by_id = {r.id: r for r in reps}
        targets = {r.input_sha256 for r in reps}
        # Campaign evidence only counts between reports about different targets.
        cross = [(a, b, s) for a, b, s in g["pairs"] if a in by_id and b in by_id and by_id[a].input_sha256 != by_id[b].input_sha256]
        cross_types = {t for _, _, s in cross for t, _ in s}
        if len(targets) == 1:
            kind = "repeat_checks"
        elif cross_types & set(CAMPAIGN_TYPES):
            kind = "campaign"
        else:
            kind = "shared_infrastructure"
        ids_sorted = sorted(by_id)
        dates = sorted(r.created_at for r in reps)
        shared = sorted({f"{t}: {d}" for _, _, s in g["pairs"] for t, d in s})
        links = [{"a": a, "b": b, "shared": sorted(f"{t}: {d}" for t, d in s),
                  "different_targets": by_id[a].input_sha256 != by_id[b].input_sha256}
                 for a, b, s in g["pairs"] if a in by_id and b in by_id][:40]
        out.append({
            "cluster_id": hashlib.sha256("|".join(ids_sorted).encode()).hexdigest()[:12],
            "kind": kind,
            "report_ids": ids_sorted,
            "distinct_targets": len(targets),
            "shared": shared[:20],
            "links": links,
            "classifications": sorted({(r.assessment.classification if r.assessment else r.status) for r in reps}),
            "reports": [{"id": r.id, "kind": r.kind, "target": r.input_display[:160], "created_at": r.created_at,
                         "classification": r.assessment.classification if r.assessment else None,
                         "rule": r.assessment.rule_id if r.assessment else None} for r in sorted(reps, key=lambda r: r.created_at)],
            "first_seen": dates[0], "last_seen": dates[-1],
        })
    order = {"campaign": 0, "shared_infrastructure": 1, "repeat_checks": 2}
    out.sort(key=lambda c: c["last_seen"], reverse=True)
    return sorted(out, key=lambda c: order[c["kind"]])  # stable: newest first within each type


def get(cluster_id: str) -> dict | None:
    return next((c for c in clusters() if c["cluster_id"] == cluster_id), None)
