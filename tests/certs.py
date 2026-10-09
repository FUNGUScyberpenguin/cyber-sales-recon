"""Make test certificates: valid, expired, and self-signed, in DER and PEM."""
import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def make_cert(cn: str, days_from_now_start: int, days_from_now_end: int, issuer_cn: str | None = None,
              sans: list[str] | None = None):
    """Returns (der, cert_pem, key_pem). issuer_cn=None makes it self-signed."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = subject if issuer_cn is None else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
    now = dt.datetime.now(dt.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now + dt.timedelta(days=days_from_now_start))
               .not_valid_after(now + dt.timedelta(days=days_from_now_end)))
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    cert = builder.sign(key, hashes.SHA256())
    return (cert.public_bytes(serialization.Encoding.DER), cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                              serialization.NoEncryption()))
