"""
Generate self-signed TLS certificates for testing.

Creates:
  certs/ca.crt / ca.key         – root CA (signs all other certs)
  certs/as.crt / as.key         – Authorization Server cert
  certs/rs.crt / rs.key         – Resource Server (telescope) cert
  certs/idevid.crt / idevid.key – manufacturer IDevID (BRSKI, RFC 8995)
  certs/ldevid.crt / ldevid.key – domain LDevID issued by the CA

All keys are ECDSA P-256 (secp256r1) – compact and appropriate for
constrained devices (RFC 7228).  Certificates carry a SubjectAlternativeName
as required by RFC 2818 §3.1.

Usage:
  python scripts/generate_certs.py [--out-dir certs]
"""

from __future__ import annotations

import datetime
import ipaddress
from pathlib import Path

import click
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _gen_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _save_key(key: ec.EllipticCurvePrivateKey, path: Path) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)


def _save_cert(cert: x509.Certificate, path: Path) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _subject(cn: str, org: str = "MinimalSecureProtocol") -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def _san(dns_names: list[str], ip_addresses: list[str] | None = None) -> x509.SubjectAlternativeName:
    entries: list = [x509.DNSName(n) for n in dns_names]
    for ip in ip_addresses or []:
        entries.append(x509.IPAddress(ipaddress.ip_address(ip)))
    return x509.SubjectAlternativeName(entries)


# ---------------------------------------------------------------------------
# Certificate builders
# ---------------------------------------------------------------------------

def generate_ca(out_dir: Path) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Generate a self-signed root CA certificate."""
    key = _gen_key()
    name = _subject("Minimal Secure Protocol Test CA")
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now())
        .not_valid_after(_now() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    _save_key(key, out_dir / "ca.key")
    _save_cert(cert, out_dir / "ca.crt")
    return key, cert


def generate_end_entity(
    out_dir: Path,
    name: str,
    filename: str,
    dns_names: list[str],
    ip_addresses: list[str],
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    server_auth: bool = True,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Generate an end-entity certificate signed by the CA."""
    key = _gen_key()
    subject = _subject(name)

    eku = (
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])
        if server_auth
        else x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now())
        .not_valid_after(_now() + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(eku, critical=False)
        .add_extension(
            _san(dns_names, ip_addresses),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    _save_key(key, out_dir / f"{filename}.key")
    _save_cert(cert, out_dir / f"{filename}.crt")
    return key, cert


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@click.command()
@click.option("--out-dir", default="certs", show_default=True, type=click.Path(),
              help="Directory to write certificates into")
@click.option("--host", default="localhost", show_default=True,
              help="Hostname to include in SANs for AS and RS certs")
def main(out_dir, host):
    """
    Generate self-signed TLS certificates for the minimal-secure-protocol demo.

    All keys are ECDSA P-256 (RFC 7518 §3.4); all certs carry SubjectAlternativeNames
    (RFC 2818 §3.1).  Not for production use.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    click.echo("Generating CA …")
    ca_key, ca_cert = generate_ca(out)

    extra_ips = ["127.0.0.1"]
    for fname, cn, server in [
        ("as", f"AS {host}", True),
        ("rs", f"RS {host}", True),
        ("idevid", "IDevID mount-001", True),
        ("ldevid", "LDevID mount-001", True),
    ]:
        click.echo(f"Generating {fname}.crt …")
        generate_end_entity(
            out_dir=out,
            name=cn,
            filename=fname,
            dns_names=[host, "localhost"],
            ip_addresses=extra_ips,
            ca_key=ca_key,
            ca_cert=ca_cert,
            server_auth=server,
        )

    click.echo(f"\nCertificates written to {out}/")
    click.echo("  ca.crt     – root CA (trust anchor)")
    click.echo("  as.crt     – Authorization Server")
    click.echo("  rs.crt     – Resource Server (telescope mount)")
    click.echo("  idevid.crt – Manufacturer IDevID (BRSKI pledge)")
    click.echo("  ldevid.crt – Domain LDevID (BRSKI after enrolment)")


if __name__ == "__main__":
    main()
