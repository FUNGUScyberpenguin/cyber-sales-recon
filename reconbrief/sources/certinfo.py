"""Read a certificate from its DER bytes. Expired and self-signed certificates parse like any other."""
from __future__ import annotations

from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID


def _name(name: x509.Name, oid) -> str:
    attrs = name.get_attributes_for_oid(oid)
    return str(attrs[0].value) if attrs else ""


def host_matches(host: str, names: list[str]) -> bool:
    """RFC 6125 style: a wildcard covers exactly one left-most label."""
    host = host.lower()
    for n in names:
        n = n.lower()
        if n == host:
            return True
        if n.startswith("*.") and "." in host and host.split(".", 1)[1] == n[2:]:
            return True
    return False


def parse_certificate(der: bytes, host: str, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    cert = x509.load_der_x509_certificate(der)
    try:
        sans = list(cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    .value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        sans = []
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_type, key_bits = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_type, key_bits = "EC", key.key_size
    else:
        key_type, key_bits = type(key).__name__, None
    try:
        sig = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else ""
    except Exception:
        sig = ""
    names = sans or ([_name(cert.subject, NameOID.COMMON_NAME)] if _name(cert.subject, NameOID.COMMON_NAME) else [])
    return {
        "subject_cn": _name(cert.subject, NameOID.COMMON_NAME),
        "subject_org": _name(cert.subject, NameOID.ORGANIZATION_NAME),
        "issuer_cn": _name(cert.issuer, NameOID.COMMON_NAME),
        "issuer_org": _name(cert.issuer, NameOID.ORGANIZATION_NAME),
        "self_signed": cert.issuer == cert.subject,
        "san": sans,
        "not_before": not_before.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "not_after": not_after.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expired": not_after < now,
        "not_yet_valid": not_before > now,
        "days_left": (not_after - now).days,
        "name_matches_host": host_matches(host, names),
        "key_type": key_type,
        "key_bits": key_bits,
        "signature_hash": sig,
        "sha256": cert.fingerprint(hashes.SHA256()).hex(),
    }
