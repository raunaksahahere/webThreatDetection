"""TLS certificate and trust analysis on the chain captured from the pinned connection.

Separates (a) configuration problems (expired, hostname mismatch, incomplete chain, weak key)
from (b) trust incidents (a certificate or key in the chain is on a browser distrust list).
Never claims to detect a CA's internal key-generation weakness from a URL.
Matching against distrust data is by certificate SHA-256 / SPKI SHA-256 / issuer+serial only,
never by CA name.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path

import certifi
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509 import DNSName, IPAddress
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

from ..models import Finding, Module, Provenance, Severity, Strength, iso

DATA = Path(__file__).resolve().parent.parent / "data" / "distrust"
PROJECT_DATA = Path(__file__).resolve().parents[3] / "data"
SOURCE = "wtd.tls_checks v1 (captured chain + cryptography verifier)"
MAX_VALIDITY_AFTER = (datetime(2026, 3, 15, tzinfo=timezone.utc), 200)  # CA/B Forum SC-081 phase 1


# ---------------------------------------------------------------- distrust index
@dataclass
class DistrustEntry:
    source: str
    detail: str
    provenance: Provenance
    reference: str


@dataclass
class DistrustIndex:
    by_cert_sha256: dict[str, DistrustEntry] = field(default_factory=dict)
    by_spki_sha256: dict[str, DistrustEntry] = field(default_factory=dict)
    by_issuer_serial: dict[tuple[bytes, int], DistrustEntry] = field(default_factory=dict)
    by_subject_spki: dict[tuple[bytes, str], DistrustEntry] = field(default_factory=dict)
    sources: list[dict] = field(default_factory=list)


def _parse_chromium_inc(text: str) -> list[tuple[str, str]]:
    """Return [(cert_sha256_from_comment, spki_sha256_hex)] from cert_verify_proc_blocklist.inc."""
    out = []
    for m in re.finditer(r"//\s*([0-9a-f]{64})\.pem\s*\{([^}]*)\}", text):
        hexbytes = re.findall(r"0x([0-9a-fA-F]{2})", m.group(2))
        if len(hexbytes) == 32:
            out.append((m.group(1), "".join(hexbytes).lower()))
    return out


@lru_cache(maxsize=1)
def default_distrust_index() -> DistrustIndex:
    idx = DistrustIndex()
    inc = DATA / "chromium_cert_verify_proc_blocklist.inc"
    if inc.exists():
        pairs = _parse_chromium_inc(inc.read_text())
        for cert_sha, spki in pairs:
            e = DistrustEntry("Chromium SPKI blocklist (net/cert/cert_verify_proc_blocklist.inc, snapshot 2026-11-08)",
                              f"key of {cert_sha[:16]}… is blocked in Chromium-based browsers", Provenance.dataset,
                              "https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/blocklist/README.md")
            idx.by_spki_sha256[spki] = e
            idx.by_cert_sha256.setdefault(cert_sha, e)
        idx.sources.append({"name": "Chromium SPKI blocklist", "entries": len(pairs), "snapshot": "2026-11-08"})
    curated = DATA / "curated_incidents.json"
    if curated.exists():
        doc = json.loads(curated.read_text())
        for inc_ in doc["incidents"]:
            for c in inc_["certificates"]:
                idx.by_cert_sha256[c["sha256"].lower()] = DistrustEntry(
                    inc_["source"], f"{c['name']}: {inc_['summary']}", Provenance.dataset, inc_["reference"])
        idx.sources.append({"name": "Curated incident list", "entries": sum(len(i["certificates"]) for i in doc["incidents"]), "snapshot": doc["checked"]})
    onecrl = PROJECT_DATA / "onecrl.json"
    if onecrl.exists():
        try:
            recs = json.loads(onecrl.read_text())["data"]
            n = 0
            for r in recs:
                if not r.get("enabled", True):
                    continue
                bug = (r.get("details") or {}).get("bug") or "Mozilla OneCRL"
                e = DistrustEntry("Mozilla OneCRL (snapshot)", "revoked/distrusted CA certificate", Provenance.dataset, str(bug))
                if r.get("issuerName") and r.get("serialNumber"):
                    serial = int.from_bytes(base64.b64decode(r["serialNumber"]), "big")
                    idx.by_issuer_serial[(base64.b64decode(r["issuerName"]), serial)] = e
                    n += 1
                elif r.get("subject") and r.get("pubKeyHash"):
                    idx.by_subject_spki[(base64.b64decode(r["subject"]), base64.b64decode(r["pubKeyHash"]).hex())] = e
                    n += 1
            idx.sources.append({"name": "Mozilla OneCRL", "entries": n, "snapshot": "data/onecrl.json"})
        except (ValueError, KeyError):
            pass
    synthetic = DATA / "synthetic_demo.json"
    if synthetic.exists():
        for s in json.loads(synthetic.read_text())["entries"]:
            idx.by_spki_sha256[s["spki_sha256"].lower()] = DistrustEntry(
                "SYNTHETIC demo distrust list (not real intelligence)", s["detail"], Provenance.synthetic, "fixtures/tls/README.md")
        idx.sources.append({"name": "Synthetic demo list", "entries": len(json.loads(synthetic.read_text())["entries"]), "snapshot": "synthetic"})
    return idx


@lru_cache(maxsize=1)
def default_store() -> Store:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return Store(x509.load_pem_x509_certificates(Path(certifi.where()).read_bytes()))


# ---------------------------------------------------------------- helpers
def spki_sha256(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def _key_desc(cert: x509.Certificate) -> tuple[str, int | None, str | None]:
    k = cert.public_key()
    if isinstance(k, rsa.RSAPublicKey):
        return "RSA", k.key_size, None
    if isinstance(k, ec.EllipticCurvePublicKey):
        return "EC", k.key_size, k.curve.name
    if isinstance(k, ed25519.Ed25519PublicKey):
        return "Ed25519", 256, None
    if isinstance(k, ed448.Ed448PublicKey):
        return "Ed448", 456, None
    if isinstance(k, dsa.DSAPublicKey):
        return "DSA", k.key_size, None
    return type(k).__name__, None, None


def _ext(cert, cls):
    try:
        return cert.extensions.get_extension_for_class(cls).value
    except x509.ExtensionNotFound:
        return None


def _sans(cert) -> tuple[list[str], list[str]]:
    san = _ext(cert, x509.SubjectAlternativeName)
    if not san:
        return [], []
    return san.get_values_for_type(DNSName), [str(i) for i in san.get_values_for_type(IPAddress)]


def hostname_matches(host: str, dns_names: list[str], ips: list[str]) -> bool:
    h = host.lower().rstrip(".")
    if h in ips:
        return True
    for n in dns_names:
        n = n.lower().rstrip(".")
        if n == h:
            return True
        if n.startswith("*.") and "." in h:
            rest = h.split(".", 1)[1]
            if rest == n[2:] and h.split(".", 1)[0] != "":
                return True
    return False


def _cert_summary(c: x509.Certificate) -> dict:
    kt, ks, curve = _key_desc(c)
    return {
        "subject": c.subject.rfc4514_string()[:300],
        "issuer": c.issuer.rfc4514_string()[:300],
        "serial_hex": format(c.serial_number, "x"),
        "not_before": iso(c.not_valid_before_utc),
        "not_after": iso(c.not_valid_after_utc),
        "sha256": c.fingerprint(hashes.SHA256()).hex(),
        "spki_sha256": spki_sha256(c),
        "key": f"{kt}-{ks}" + (f" ({curve})" if curve else ""),
        "signature_hash": c.signature_hash_algorithm.name if c.signature_hash_algorithm else "none",
        "self_issued": c.subject == c.issuer,
    }


def _f(code, title, observed, sev, strength, impact, rec, lim, ev, prov=Provenance.live, source=SOURCE) -> Finding:
    return Finding(id=code, code=code, module=Module.tls, title=title, observed=observed, evidence=ev, source=source,
                   provenance=prov, observed_at=iso(), severity=sev, strength=strength, impact=impact,
                   recommendation=rec, limitation=lim)


# ---------------------------------------------------------------- main analysis
def analyse_chain(
    host: str,
    is_ip: bool,
    chain_der: list[bytes],
    tls_version: str | None = None,
    cipher: str | None = None,
    *,
    now: datetime | None = None,
    store: Store | None = None,
    distrust: DistrustIndex | None = None,
    provenance: Provenance = Provenance.live,
) -> tuple[list[Finding], dict]:
    now = now or datetime.now(timezone.utc)
    store = store or default_store()
    distrust = distrust or default_distrust_index()
    findings: list[Finding] = []
    certs = [x509.load_der_x509_certificate(d) for d in chain_der]
    if not certs:
        return [], {"error": "no certificates captured"}
    leaf, inters = certs[0], certs[1:]
    dns_names, ip_names = _sans(leaf)
    summary: dict = {
        "tls_version": tls_version,
        "cipher": cipher,
        "chain": [_cert_summary(c) for c in certs],
        "leaf_dns_names": dns_names[:50],
        "leaf_dns_name_count": len(dns_names),
        "trust_store": f"certifi {certifi.__version__} (Mozilla roots)",
        "distrust_sources": [s["name"] for s in distrust.sources],
    }

    def F(*a, **kw):
        kw.setdefault("prov", provenance)
        findings.append(_f(*a, **kw))

    # Full verification (path + time + hostname), using the leaf's server identity.
    subject = IPAddress(__import__("ipaddress").ip_address(host)) if is_ip else DNSName(host)
    full_ok, full_err = True, None
    try:
        PolicyBuilder().store(store).time(now).build_server_verifier(subject).verify(leaf, inters)
    except VerificationError as e:
        full_ok, full_err = False, str(e).split(" (encountered")[0][:300]
    except ValueError as e:
        full_ok, full_err = False, f"verifier could not process the chain: {str(e)[:200]}"
    summary["verification"] = "valid" if full_ok else "failed"
    summary["verification_error"] = full_err

    # Diagnostics, each isolated.
    expired = [c for c in certs if c.not_valid_after_utc < now]
    not_yet = [c for c in certs if c.not_valid_before_utc > now]
    name_ok = hostname_matches(host, dns_names, ip_names)
    # Trust-only run: midpoint of leaf validity, leaf's own first SAN, isolates path/trust problems.
    trust_ok, trust_err = None, None
    if dns_names or ip_names:
        mid = leaf.not_valid_before_utc + (leaf.not_valid_after_utc - leaf.not_valid_before_utc) / 2
        ident = DNSName(dns_names[0].replace("*.", "wildcard-probe.")) if dns_names else IPAddress(__import__("ipaddress").ip_address(ip_names[0]))
        try:
            PolicyBuilder().store(store).time(mid).build_server_verifier(ident).verify(leaf, inters)
            trust_ok = True
        except (VerificationError, ValueError) as e:
            trust_ok, trust_err = False, str(e).split(" (encountered")[0][:300]
    summary["chain_trusted"] = trust_ok
    top = certs[-1]
    self_signed_leaf = len(certs) == 1 and leaf.subject == leaf.issuer

    if expired:
        c = expired[0]
        days = (now - c.not_valid_after_utc).days
        F("tls.expired", "Certificate has expired" if c is leaf else "A certificate in the chain has expired",
          f"'{c.subject.rfc4514_string()[:120]}' expired on {iso(c.not_valid_after_utc)} ({days} days ago).",
          Severity.medium, Strength.moderate,
          "Browsers show a security warning; an expired certificate means the site is unmaintained or misconfigured.",
          "Do not bypass browser certificate warnings, especially on login or payment pages.",
          "An expired certificate is a configuration problem; by itself it is not evidence of phishing.",
          {"subject": c.subject.rfc4514_string()[:200], "not_after": iso(c.not_valid_after_utc), "days_expired": days})
    if not_yet:
        c = not_yet[0]
        F("tls.not_yet_valid", "Certificate is not yet valid", f"Valid from {iso(c.not_valid_before_utc)}.",
          Severity.medium, Strength.moderate, "Browsers reject it.", "Do not bypass warnings.",
          "Can be caused by clock skew on our side or theirs.", {"not_before": iso(c.not_valid_before_utc)})
    if not name_ok:
        F("tls.hostname_mismatch", "Certificate does not match the website's name",
          f"The certificate covers {', '.join(dns_names[:4]) or 'no DNS names'}{'…' if len(dns_names) > 4 else ''} but the site is '{host}'.",
          Severity.high, Strength.moderate,
          "The certificate does not prove this site's identity; browsers show a warning.",
          "Do not enter any information. Navigate to the organisation's known address instead.",
          "Common on misconfigured shared hosting; not proof of phishing by itself.",
          {"host": host, "dns_names": dns_names[:20]})
    if self_signed_leaf:
        F("tls.self_signed", "Certificate is self-signed", "The server presented a single certificate that signed itself.",
          Severity.high, Strength.moderate, "No certificate authority vouches for this site's identity.",
          "Do not enter credentials or payment details.", "Normal for test and internal systems, not for public services.",
          {"subject": leaf.subject.rfc4514_string()[:200]})
    elif trust_ok is False:
        issuer_known = any(top.issuer == s.subject for s in [])  # placeholder for readability
        reason = "the chain does not lead to a root in the trust store" if top.subject != top.issuer else "the chain ends in a root that is not in the trust store"
        F("tls.untrusted_chain", "Certificate chain is not trusted", f"Path validation failed: {reason}. Verifier: {trust_err}",
          Severity.high, Strength.moderate,
          "Browsers will not trust this site's certificate; the identity claim is unverified.",
          "Do not bypass the warning.",
          "Can also be caused by a missing intermediate certificate (server misconfiguration). Trust store: Mozilla roots via certifi.",
          {"verifier_error": trust_err, "top_subject": top.subject.rfc4514_string()[:200], "top_issuer": top.issuer.rfc4514_string()[:200]})
    elif not full_ok and not expired and not not_yet and name_ok:
        F("tls.policy_failure", "Certificate failed standard web-PKI validation", f"Verifier: {full_err}", Severity.medium, Strength.weak,
          "The certificate does not meet browser policy requirements.", "Treat the site's identity as unverified.",
          "Our verifier is stricter than some browsers in edge cases.", {"verifier_error": full_err})

    # Key and signature strength.
    for i, c in enumerate(certs):
        kt, ks, curve = _key_desc(c)
        who = "leaf" if i == 0 else f"chain[{i}]"
        if kt == "RSA" and ks and ks < 2048:
            F("tls.weak_key" if i == 0 else f"tls.weak_key", f"Weak RSA key ({ks} bits) in {who}",
              f"{c.subject.rfc4514_string()[:120]} uses RSA-{ks}.", Severity.high, Strength.moderate,
              "Keys under 2048 bits are below the CA/B Forum minimum and can be factored with enough resources.",
              "The site operator should replace the certificate.", "Weak keys indicate poor configuration, not phishing.", {"key": f"RSA-{ks}", "cert": who})
            break
        if kt == "EC" and curve not in ("secp256r1", "secp384r1", "secp521r1"):
            F("tls.unusual_curve", f"Unusual elliptic curve in {who}", f"Curve {curve}.", Severity.medium, Strength.weak,
              "Only P-256, P-384 and P-521 are allowed for publicly trusted certificates.", "Treat as misconfigured.", "", {"curve": curve})
            break
    for i, c in enumerate(certs[:-1] if len(certs) > 1 else certs):
        h = c.signature_hash_algorithm.name if c.signature_hash_algorithm else None
        if h in ("sha1", "md5"):
            F("tls.weak_signature", f"Certificate signed with {h.upper()}", f"{'Leaf' if i == 0 else f'chain[{i}]'} is signed with {h.upper()}.",
              Severity.high, Strength.moderate, f"{h.upper()} signatures can be forged; browsers reject them.", "The operator must reissue the certificate.",
              "", {"algorithm": h})
            break

    # Lifetime policy (CA/B Forum SC-081).
    lifetime = (leaf.not_valid_after_utc - leaf.not_valid_before_utc).days
    summary["leaf_lifetime_days"] = lifetime
    public_chain = bool(trust_ok) or any(
        (distrust.by_cert_sha256.get(c.fingerprint(hashes.SHA256()).hex()) or distrust.by_spki_sha256.get(spki_sha256(c))) for c in certs[1:]
    )
    if public_chain and leaf.not_valid_before_utc >= MAX_VALIDITY_AFTER[0] and lifetime > MAX_VALIDITY_AFTER[1] + 1:
        F("tls.excess_lifetime", "Certificate lifetime exceeds the current public maximum",
          f"Issued {iso(leaf.not_valid_before_utc)} for {lifetime} days; certificates issued after 2026-03-15 may be valid for at most 200 days.",
          Severity.medium, Strength.moderate,
          "A publicly trusted CA should not issue such a certificate; it may come from a private, misbehaving, or compromised issuer.",
          "Treat the certificate's issuer as suspect.", "Private CAs are not bound by this rule.", {"lifetime_days": lifetime})

    # Certificate Transparency (embedded SCTs).
    scts = _ext(leaf, x509.PrecertificateSignedCertificateTimestamps)
    summary["embedded_scts"] = len(scts) if scts else 0
    if scts:
        earliest = min(s.timestamp.replace(tzinfo=timezone.utc) for s in scts)
        summary["earliest_sct"] = iso(earliest)
    elif trust_ok:
        F("tls.no_sct", "Certificate has no embedded Certificate Transparency proofs",
          "No SCTs embedded in the certificate (they may still be delivered via TLS extension or OCSP).", Severity.low, Strength.weak,
          "Chrome requires CT for publicly trusted certificates; missing embedded SCTs is unusual.",
          "No action needed by itself.", "SCTs can be delivered by other means we do not inspect.", {})

    # Distrust lists (fingerprint / SPKI / issuer+serial / subject+SPKI).
    hits = []
    for i, c in enumerate(certs):
        fp, sp = c.fingerprint(hashes.SHA256()).hex(), spki_sha256(c)
        e = (distrust.by_cert_sha256.get(fp) or distrust.by_spki_sha256.get(sp)
             or distrust.by_issuer_serial.get((c.issuer.public_bytes(), c.serial_number))
             or distrust.by_subject_spki.get((c.subject.public_bytes(), sp)))
        if e:
            hits.append((i, c, e, fp, sp))
    summary["distrust_hits"] = len(hits)
    for i, c, e, fp, sp in hits[:3]:
        F("tls.distrusted_ca", "Certificate chain includes a CA distrusted by browsers" if i > 0 else "Certificate is on a browser distrust list",
          f"{'Chain certificate' if i else 'Leaf'} '{c.subject.rfc4514_string()[:120]}' matches {e.source}: {e.detail}.",
          Severity.critical, Strength.strong,
          "A distrusted CA's keys can no longer be relied on; certificates chaining to it may have been forged to impersonate any site.",
          "Do not trust this connection. Report it, and do not enter any information.",
          "This identifies a certificate listed by a trust authority; it does not by itself show how the CA failed, and the list snapshot may be outdated.",
          {"position": i, "cert_sha256": fp, "spki_sha256": sp, "source": e.source, "reference": e.reference},
          prov=e.provenance if e.provenance == Provenance.synthetic else provenance if provenance == Provenance.synthetic else Provenance.dataset,
          source=e.source)

    # Revocation sources available (actual check performed by the inspector if an OCSP URL exists).
    aia = _ext(leaf, x509.AuthorityInformationAccess)
    summary["ocsp_urls"] = [d.access_location.value for d in aia if d.access_method == AuthorityInformationAccessOID.OCSP][:3] if aia else []
    cdp = _ext(leaf, x509.CRLDistributionPoints)
    summary["crl_urls"] = [n.value for dp in cdp for n in (dp.full_name or []) if isinstance(n, x509.UniformResourceIdentifier)][:3] if cdp else []

    if tls_version in ("TLSv1", "TLSv1.1", "SSLv3"):
        F("tls.old_protocol", f"Server negotiated obsolete {tls_version}", f"Negotiated {tls_version}.", Severity.medium, Strength.weak,
          "Old TLS versions have known weaknesses.", "Operator should enable TLS 1.2+ only.", "", {"version": tls_version})
    if full_ok and not hits:
        F("tls.valid", "Certificate is valid for this site", f"Chain verified to a trusted root; issued by {leaf.issuer.rfc4514_string()[:120]}; expires {iso(leaf.not_valid_after_utc)}.",
          Severity.info, Strength.weak, "The connection is encrypted and the certificate matches the name.",
          "A valid certificate does not mean the site is legitimate: phishing sites routinely have valid certificates.",
          "Revocation status is reported separately.", {"issuer": leaf.issuer.rfc4514_string()[:200], "expires": iso(leaf.not_valid_after_utc)})
    return findings, summary


def ocsp_request_url(chain_der: list[bytes]) -> tuple[str, bytes] | None:
    """Build an RFC 6960 GET request URL for the leaf, if it lists an OCSP responder."""
    from cryptography.x509 import ocsp

    if len(chain_der) < 2:
        return None
    leaf = x509.load_der_x509_certificate(chain_der[0])
    issuer = x509.load_der_x509_certificate(chain_der[1])
    aia = _ext(leaf, x509.AuthorityInformationAccess)
    urls = [d.access_location.value for d in aia if d.access_method == AuthorityInformationAccessOID.OCSP] if aia else []
    if not urls or not urls[0].startswith("http"):
        return None
    req = ocsp.OCSPRequestBuilder().add_certificate(leaf, issuer, hashes.SHA1()).build().public_bytes(serialization.Encoding.DER)
    from urllib.parse import quote

    return urls[0].rstrip("/") + "/" + quote(base64.b64encode(req).decode(), safe=""), req


def interpret_ocsp(chain_der: list[bytes], response_der: bytes, now: datetime | None = None) -> dict:
    from cryptography.x509 import ocsp

    now = now or datetime.now(timezone.utc)
    try:
        r = ocsp.load_der_ocsp_response(response_der)
    except ValueError:
        return {"status": "unavailable", "detail": "OCSP response could not be parsed"}
    if r.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return {"status": "unavailable", "detail": f"OCSP responder status {r.response_status.name}"}
    issuer = x509.load_der_x509_certificate(chain_der[1])
    signer_key = issuer.public_key()
    for c in r.certificates:  # delegated responder
        if c.issuer == issuer.subject:
            signer_key = c.public_key()
    try:
        if isinstance(signer_key, rsa.RSAPublicKey):
            from cryptography.hazmat.primitives.asymmetric import padding

            signer_key.verify(r.signature, r.tbs_response_bytes, padding.PKCS1v15(), r.signature_hash_algorithm)
        elif isinstance(signer_key, ec.EllipticCurvePublicKey):
            signer_key.verify(r.signature, r.tbs_response_bytes, ec.ECDSA(r.signature_hash_algorithm))
        sig_ok = True
    except Exception:
        sig_ok = False
    nu = r.next_update_utc
    fresh = nu is None or nu > now - timedelta(minutes=5)
    out = {"status": r.certificate_status.name.lower(), "signature_valid": sig_ok, "fresh": fresh,
           "this_update": iso(r.this_update_utc), "next_update": iso(nu) if nu else None}
    if r.certificate_status == ocsp.OCSPCertStatus.REVOKED:
        out["revoked_at"] = iso(r.revocation_time_utc)
        out["reason"] = r.revocation_reason.name if r.revocation_reason else None
    if not sig_ok or not fresh:
        out["status"] = "unavailable"
        out["detail"] = "response signature invalid" if not sig_ok else "response is stale"
    return out
