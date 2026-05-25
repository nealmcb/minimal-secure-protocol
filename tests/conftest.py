"""
Shared pytest fixtures: generate TLS certificates and spin up Flask test clients
for the Authorization Server and Resource Server.
"""

from __future__ import annotations

import datetime
import ipaddress
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from telescope.auth import create_auth_app
from telescope.server import TelescopeMountState, create_resource_server_app


# ---------------------------------------------------------------------------
# Key / cert helpers (in-memory, no files)
# ---------------------------------------------------------------------------

def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _make_ca():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now())
        .not_valid_after(_now() + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _make_ee(ca_key, ca_cert, cn="test"):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now())
        .not_valid_after(_now() + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def ca_key_cert():
    """Return (ca_key, ca_cert) for the test session."""
    return _make_ca()


@pytest.fixture(scope="session")
def as_signing_key(ca_key_cert):
    """EC private key used by the AS for signing tokens (same as AS TLS key)."""
    ca_key, ca_cert = ca_key_cert
    key, _ = _make_ee(ca_key, ca_cert, cn="AS")
    return key


@pytest.fixture(scope="session")
def as_url():
    return "https://localhost:8444"


@pytest.fixture(scope="session")
def rs_url():
    return "https://localhost:8443"


@pytest.fixture(scope="session")
def auth_app(as_signing_key, as_url, rs_url):
    """Flask test client for the Authorization Server."""
    app = create_auth_app(
        signing_key=as_signing_key,
        as_url=as_url,
        rs_url=rs_url,
        token_lifetime=3600,
    )
    app.config["TESTING"] = True
    return app


@pytest.fixture
def auth_client(auth_app):
    with auth_app.test_client() as client:
        yield client


@pytest.fixture(scope="session")
def resource_server_app(as_signing_key, as_url, rs_url):
    """Flask test client for the Resource Server."""
    public_key = as_signing_key.public_key()
    mount = TelescopeMountState(device_id="test-mount")
    app = create_resource_server_app(mount, public_key, as_url, rs_url)
    app.config["TESTING"] = True
    return app, mount


@pytest.fixture
def rs_client(resource_server_app):
    app, mount = resource_server_app
    with app.test_client() as client:
        yield client, mount
