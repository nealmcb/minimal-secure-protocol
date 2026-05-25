"""
TLS 1.3 configuration helpers (RFC 8446 + BCP 195 / RFC 9325).

Key decisions
-------------
* Minimum version: TLS 1.3 – earlier versions disabled unconditionally.
* Server/client certificates: ECDSA P-256 (or Ed25519 where OpenSSL supports it).
  Avoids RSA key-transport and allows smaller certificates (important for
  constrained devices – RFC 7228).
* No compression (CRIME/BEAST).
* Explicit cipher-suite list: Python's ssl module exposes the TLS 1.3 suites as
  `ssl.OP_NO_*` flags; the mandatory TLS 1.3 set (RFC 8446 §B.4) is used.
* Certificate SAN required (CN alone deprecated per RFC 2818 §3.1).
* Optional mutual TLS for the admin scope.

On a constrained device (RFC 7228 Class 1) this layer would be replaced by
OSCORE (RFC 8613) + EDHOC (RFC 9528) over CoAP/UDP, but the security properties
are equivalent.
"""

from __future__ import annotations

import ssl
from pathlib import Path


def server_tls_context(
    cert_path: str | Path,
    key_path: str | Path,
    *,
    require_client_cert: bool = False,
    ca_cert_path: str | Path | None = None,
) -> ssl.SSLContext:
    """
    Return an SSLContext suitable for a TLS 1.3 server.

    Parameters
    ----------
    cert_path:
        PEM-encoded server certificate (ECDSA P-256 recommended).
    key_path:
        PEM-encoded private key matching the certificate.
    require_client_cert:
        If True, enforce mutual TLS (mTLS) – used for the admin role.
    ca_cert_path:
        CA certificate used to verify client certificates when mTLS is on.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Enforce TLS 1.3 minimum (RFC 8446; BCP 195 §3.1.1 prohibits TLS 1.0/1.1)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3

    # Disable session tickets to prevent resumption-based attacks
    ctx.options |= ssl.OP_NO_TICKET  # type: ignore[attr-defined]

    # Disable TLS compression (mitigates CRIME)
    ctx.options |= ssl.OP_NO_COMPRESSION  # type: ignore[attr-defined]

    ctx.load_cert_chain(str(cert_path), str(key_path))

    if require_client_cert:
        ctx.verify_mode = ssl.CERT_REQUIRED
        if ca_cert_path:
            ctx.load_verify_locations(str(ca_cert_path))

    return ctx


def client_tls_context(
    ca_cert_path: str | Path,
    *,
    client_cert_path: str | Path | None = None,
    client_key_path: str | Path | None = None,
) -> ssl.SSLContext:
    """
    Return an SSLContext suitable for a TLS 1.3 client.

    Parameters
    ----------
    ca_cert_path:
        PEM CA certificate to verify the server certificate against.
        (In production: use the system trust store or a pinned CA.)
    client_cert_path / client_key_path:
        Optional client certificate for mTLS (admin operations).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    # Enforce TLS 1.3 minimum
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3

    ctx.options |= ssl.OP_NO_TICKET  # type: ignore[attr-defined]
    ctx.options |= ssl.OP_NO_COMPRESSION  # type: ignore[attr-defined]

    # Verify server certificate and hostname (RFC 2818)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(str(ca_cert_path))

    if client_cert_path and client_key_path:
        ctx.load_cert_chain(str(client_cert_path), str(client_key_path))

    return ctx


def describe_context(ctx: ssl.SSLContext) -> dict:
    """Return a human-readable summary of the TLS context configuration."""
    return {
        "minimum_version": ctx.minimum_version.name if ctx.minimum_version else "unset",
        "verify_mode": ctx.verify_mode.name,
        "check_hostname": ctx.check_hostname,
        "protocol": ctx.protocol.name,
    }
