"""Create a self-signed DDNS TLS certificate for optional RSX3 Direct-QUIC.

Usage:
  py scripts/create_direct_quic_cert.py --hostname rsx3.example.com \
      --cert C:\\rsx3\\quic-cert.pem --key C:\\rsx3\\quic-key.pem

Requires: pip install -r requirements-direct-quic.txt
Does not overwrite an existing certificate/key.
"""
import argparse
import datetime as dt
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def create(hostname: str, cert_path: Path, key_path: Path):
    if not hostname or "/" in hostname or ":" in hostname or hostname.count(".") < 1:
        raise ValueError("a DDNS hostname is required")
    for path in (cert_path, key_path):
        if path.exists():
            raise FileExistsError(f"refusing to overwrite {path}")
        if not path.parent.is_dir():
            raise FileNotFoundError(f"parent directory does not exist: {path.parent}")
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return cert.fingerprint(hashes.SHA256()).hex()


def main():
    parser = argparse.ArgumentParser(description="RSX3 Direct-QUIC pinned TLS certificate")
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    args = parser.parse_args()
    pin = create(args.hostname, args.cert, args.key)
    print("Cert SHA256 (paste into x-ui IPv6 DDNS page):", pin)
    print("Keep the private key out of Git and limit filesystem access.")


if __name__ == "__main__":
    main()
