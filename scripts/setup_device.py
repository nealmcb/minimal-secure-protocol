"""
BRSKI-inspired device bootstrap (RFC 8995).

BRSKI (Bootstrapping Remote Secure Key Infrastructure) solves the "first-contact"
problem: how does a brand-new device securely join a network domain without any
pre-shared keys?

Full BRSKI uses:
  1. Pledge – the new device (has a manufacturer-signed IDevID cert).
  2. Join Proxy – a relay that bridges the pledge onto the registrar network.
  3. Registrar – the domain authority that enrols the pledge.
  4. MASA (Manufacturer Authorized Signing Authority) – vouches for pledge identity.

This script implements a simplified version:
  1. The "pledge" reads its IDevID certificate.
  2. It presents the IDevID to the local "registrar" (this script, playing both roles).
  3. The registrar verifies the IDevID against a simulated MASA (checks the CA).
  4. The registrar issues a locally-signed LDevID using the domain CA.
  5. The device writes a device config file that points to the AS/RS.

Usage:
  python scripts/setup_device.py --device-id mount-001 \\
      --idevid-cert certs/idevid.crt --idevid-key certs/idevid.key \\
      --ca-cert certs/ca.crt --ca-key certs/ca.key \\
      --as-url https://localhost:8444 --rs-url https://localhost:8443
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path

import click
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from telescope.protocol import DeviceConfig


# ---------------------------------------------------------------------------
# Simulated MASA verification
# ---------------------------------------------------------------------------

def verify_idevid(
    idevid_cert: x509.Certificate,
    ca_cert: x509.Certificate,
) -> bool:
    """
    Simulate MASA verification: confirm the IDevID was signed by the manufacturer CA.

    In real BRSKI the MASA is an external service; here we simply verify the
    certificate chain locally.
    """
    try:
        # Verify the IDevID is signed by the CA public key
        ca_cert.public_key().verify(
            idevid_cert.signature,
            idevid_cert.tbs_certificate_bytes,
            ec.ECDSA(hashes.SHA256()),
        )
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# LDevID issuance (domain operational certificate)
# ---------------------------------------------------------------------------

def issue_ldevid(
    device_id: str,
    idevid_cert: x509.Certificate,
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    out_dir: Path,
) -> tuple[Path, Path]:
    """
    Issue a domain LDevID for the device, signed by the local CA.

    The LDevID replaces the IDevID for all ongoing TLS connections within
    the domain (RFC 8995 §2.6.1).
    """
    # Generate a fresh key pair for the LDevID
    ldevid_key = ec.generate_private_key(ec.SECP256R1())

    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MinimalSecureProtocol"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"LDevID {device_id}"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(ldevid_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        )
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
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName(device_id),
            ]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    ldevid_cert_path = out_dir / "ldevid.crt"
    ldevid_key_path = out_dir / "ldevid.key"

    ldevid_cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    ldevid_key_path.write_bytes(
        ldevid_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    ldevid_key_path.chmod(0o600)

    return ldevid_cert_path, ldevid_key_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@click.command()
@click.option("--device-id", required=True, help="Device identifier (e.g. mount-001)")
@click.option("--idevid-cert", default="certs/idevid.crt", show_default=True,
              type=click.Path(exists=True), help="Manufacturer IDevID certificate (PEM)")
@click.option("--idevid-key", default="certs/idevid.key", show_default=True,
              type=click.Path(exists=True), help="Manufacturer IDevID private key (PEM)")
@click.option("--ca-cert", default="certs/ca.crt", show_default=True,
              type=click.Path(exists=True), help="Domain CA certificate (PEM)")
@click.option("--ca-key", default="certs/ca.key", show_default=True,
              type=click.Path(exists=True), help="Domain CA private key (PEM)")
@click.option("--as-url", default="https://localhost:8444", show_default=True)
@click.option("--rs-url", default="https://localhost:8443", show_default=True)
@click.option("--out-dir", default="certs", show_default=True, type=click.Path())
@click.option("--config-out", default="device_config.json", show_default=True, type=click.Path())
def main(device_id, idevid_cert, idevid_key, ca_cert, ca_key, as_url, rs_url, out_dir, config_out):
    """
    BRSKI-inspired device bootstrap (RFC 8995).

    Verifies the device IDevID, issues a domain LDevID, and writes a device
    configuration file ready for use with telescope-server.
    """
    click.echo(f"\n=== BRSKI-Inspired Device Bootstrap for {device_id} ===\n")

    # Step 1: Load IDevID
    click.echo("Step 1: Loading IDevID certificate …")
    idevid_cert_obj = x509.load_pem_x509_certificate(Path(idevid_cert).read_bytes())
    click.echo(f"  IDevID subject: {idevid_cert_obj.subject.rfc4514_string()}")

    # Step 2: Load domain CA
    click.echo("Step 2: Loading domain CA …")
    ca_cert_obj = x509.load_pem_x509_certificate(Path(ca_cert).read_bytes())
    ca_key_obj = serialization.load_pem_private_key(Path(ca_key).read_bytes(), password=None)
    click.echo(f"  CA subject: {ca_cert_obj.subject.rfc4514_string()}")

    # Step 3: Simulated MASA verification
    click.echo("Step 3: Verifying IDevID against MASA (simulated) …")
    if not verify_idevid(idevid_cert_obj, ca_cert_obj):
        click.echo("  ERROR: IDevID verification failed. Aborting.", err=True)
        raise SystemExit(1)
    click.echo("  IDevID verified successfully.")

    # Step 4: Issue LDevID
    click.echo("Step 4: Issuing domain LDevID …")
    out = Path(out_dir)
    ldevid_cert_path, ldevid_key_path = issue_ldevid(
        device_id, idevid_cert_obj, ca_key_obj, ca_cert_obj, out
    )
    click.echo(f"  LDevID written to {ldevid_cert_path}")

    # Step 5: Write device configuration
    click.echo("Step 5: Writing device configuration …")
    config = DeviceConfig(
        device_id=device_id,
        registrar_url=as_url,
        resource_server_port=int(rs_url.rsplit(":", 1)[-1]) if ":" in rs_url else 8443,
        auth_server_port=int(as_url.rsplit(":", 1)[-1]) if ":" in as_url else 8444,
        mud_url=f"{rs_url}/mud",
        idevid_cert_path=str(Path(idevid_cert).resolve()),
        ldevid_cert_path=str(ldevid_cert_path.resolve()),
        ldevid_key_path=str(ldevid_key_path.resolve()),
    )
    Path(config_out).write_text(json.dumps(config.model_dump(), indent=2))
    click.echo(f"  Configuration written to {config_out}")

    click.echo("\n=== Bootstrap Complete ===")
    click.echo(f"Start the telescope server with:")
    click.echo(
        f"  python -m telescope.server --cert {ldevid_cert_path} "
        f"--key {ldevid_key_path} --as-cert {ca_cert} --as-url {as_url}"
    )


if __name__ == "__main__":
    main()
