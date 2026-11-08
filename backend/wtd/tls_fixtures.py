"""SYNTHETIC certificate chains for tests and the offline eMudhra-like demonstration.

Nothing here is real intelligence. The "distrusted" intermediate uses a P-384 private key with a tiny
scalar (77), modelling the weakness Mozilla documented in Bugzilla 2083449, so its public key is
deterministic and can be listed in data/distrust/synthetic_demo.json (labelled synthetic).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

WEAK_SCALAR = 77


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "WTD SYNTHETIC TEST PKI")])


def _cert(subject, issuer, pub, signer, *, ca: bool, sans=None, nb=None, na=None, hash_alg=None, aki_from=None):
    now = datetime.now(timezone.utc)
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(pub).serial_number(x509.random_serial_number())
         .not_valid_before(nb or now - timedelta(days=10)).not_valid_after(na or now + timedelta(days=80)))
    b = b.add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    b = b.add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
    if aki_from is not None:
        b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(aki_from), critical=False)
    if ca:
        b = b.add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False, key_encipherment=False,
                                          data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
    else:
        b = b.add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True, key_cert_sign=False, crl_sign=False, content_commitment=False,
                                          data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in (sans or [])]), critical=False)
    return b.sign(signer, hash_alg or hashes.SHA256())


def build(kind: str = "valid", host: str = "demo.wtd.test"):
    """Return (chain_der, trusted_root_cert) for a scenario.

    kinds: valid, expired, mismatch, untrusted, self_signed, distrusted, weak_rsa
    """
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = _cert(_name("WTD Synthetic Root CA"), _name("WTD Synthetic Root CA"), root_key.public_key(), root_key, ca=True,
                 nb=datetime.now(timezone.utc) - timedelta(days=400), na=datetime.now(timezone.utc) + timedelta(days=3000))
    if kind == "distrusted":
        inter_key = ec.derive_private_key(WEAK_SCALAR, ec.SECP384R1())
        inter_name = _name("WTD Synthetic Distrusted Intermediate (weak key, DEMO)")
    else:
        inter_key = ec.generate_private_key(ec.SECP256R1())
        inter_name = _name("WTD Synthetic Intermediate CA")
    inter = _cert(inter_name, root.subject, inter_key.public_key(), root_key, ca=True, aki_from=root_key.public_key(),
                  nb=datetime.now(timezone.utc) - timedelta(days=200), na=datetime.now(timezone.utc) + timedelta(days=1500))
    leaf_key = rsa.generate_private_key(65537, 1024) if kind == "weak_rsa" else ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    nb, na = (now - timedelta(days=100), now - timedelta(days=10)) if kind == "expired" else (None, None)
    sans = ["other.wtd.test"] if kind == "mismatch" else [host]
    if kind == "self_signed":
        leaf = _cert(_name(host), _name(host), leaf_key.public_key(), leaf_key, ca=False, sans=[host])
        return [leaf.public_bytes(serialization.Encoding.DER)], root
    leaf = _cert(_name(host), inter.subject, leaf_key.public_key(), inter_key, ca=False, sans=sans, nb=nb, na=na, aki_from=inter_key.public_key())
    chain = [leaf.public_bytes(serialization.Encoding.DER), inter.public_bytes(serialization.Encoding.DER)]
    if kind == "untrusted":
        other_key = ec.generate_private_key(ec.SECP256R1())
        other_root = _cert(_name("Unknown Root"), _name("Unknown Root"), other_key.public_key(), other_key, ca=True)
        return chain, other_root
    return chain, root


def weak_intermediate_spki_sha256() -> str:
    import hashlib

    pub = ec.derive_private_key(WEAK_SCALAR, ec.SECP384R1()).public_key()
    return hashlib.sha256(pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
