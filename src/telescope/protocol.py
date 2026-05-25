"""
Telescope protocol data models (Pydantic v2).

These define the wire format for all messages exchanged between the tracking
software (client) and the telescope mount (resource server).
"""

from __future__ import annotations

import re
import time
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Coordinate helpers
# ---------------------------------------------------------------------------

def _validate_ra(value: float) -> float:
    """Right Ascension in decimal hours: [0, 24)."""
    if not 0.0 <= value < 24.0:
        raise ValueError(f"RA must be in [0, 24), got {value}")
    return value


def _validate_dec(value: float) -> float:
    """Declination in decimal degrees: [-90, 90]."""
    if not -90.0 <= value <= 90.0:
        raise ValueError(f"Dec must be in [-90, 90], got {value}")
    return value


# ---------------------------------------------------------------------------
# Telescope protocol models
# ---------------------------------------------------------------------------

class Position(BaseModel):
    """Current telescope pointing position."""

    ra: float = Field(..., description="Right Ascension (decimal hours, 0–24)")
    dec: float = Field(..., description="Declination (decimal degrees, -90–90)")
    timestamp: float = Field(default_factory=time.time, description="Unix timestamp of reading")

    @field_validator("ra")
    @classmethod
    def validate_ra(cls, v: float) -> float:
        return _validate_ra(v)

    @field_validator("dec")
    @classmethod
    def validate_dec(cls, v: float) -> float:
        return _validate_dec(v)


class SlewCommand(BaseModel):
    """Command to slew the telescope to a new RA/Dec target."""

    ra: float = Field(..., description="Target Right Ascension (decimal hours, 0–24)")
    dec: float = Field(..., description="Target Declination (decimal degrees, -90–90)")

    @field_validator("ra")
    @classmethod
    def validate_ra(cls, v: float) -> float:
        return _validate_ra(v)

    @field_validator("dec")
    @classmethod
    def validate_dec(cls, v: float) -> float:
        return _validate_dec(v)


class TrackingMode(str, Enum):
    SIDEREAL = "sidereal"
    LUNAR = "lunar"
    SOLAR = "solar"
    NONE = "none"


class DeviceStatus(BaseModel):
    """Overall device status report."""

    device_id: str
    is_slewing: bool = False
    is_tracking: bool = True
    tracking_mode: TrackingMode = TrackingMode.SIDEREAL
    position: Position
    firmware_version: str = "0.1.0"
    uptime_seconds: float = 0.0


class SlewResponse(BaseModel):
    """Response to a slew command."""

    accepted: bool
    message: str
    target_ra: float
    target_dec: float


class ErrorResponse(BaseModel):
    """Standard error envelope."""

    error: str
    description: str = ""
    status_code: int


# ---------------------------------------------------------------------------
# ACE-OAuth / token models (RFC 9200)
# ---------------------------------------------------------------------------

# Valid OAuth 2.0 scopes for this resource server
VALID_SCOPES = {"telescope:read", "telescope:slew", "telescope:admin"}


class TokenRequest(BaseModel):
    """OAuth 2.0 client-credentials token request (RFC 6749 §4.4)."""

    grant_type: str = Field(..., pattern=r"^client_credentials$")
    client_id: str = Field(..., min_length=1, max_length=64)
    client_secret: str = Field(..., min_length=8)
    scope: str = Field(default="telescope:read")

    @field_validator("scope")
    @classmethod
    def validate_scope(cls, v: str) -> str:
        requested = set(v.split())
        unknown = requested - VALID_SCOPES
        if unknown:
            raise ValueError(f"Unknown scopes: {unknown}")
        return v


class TokenResponse(BaseModel):
    """OAuth 2.0 token response (RFC 6749 §5.1)."""

    access_token: str
    token_type: str = "Bearer"
    expires_in: int = 3600
    scope: str


class IntrospectionResponse(BaseModel):
    """RFC 7662 token introspection response."""

    active: bool
    scope: Optional[str] = None
    client_id: Optional[str] = None
    exp: Optional[int] = None
    iat: Optional[int] = None
    iss: Optional[str] = None
    aud: Optional[str] = None
    jti: Optional[str] = None


# ---------------------------------------------------------------------------
# Device configuration (BRSKI-adjacent, RFC 8995)
# ---------------------------------------------------------------------------

class DeviceConfig(BaseModel):
    """Persistent device configuration written during bootstrap."""

    device_id: str
    domain: str = "local"
    registrar_url: str = "https://localhost:8444"
    resource_server_port: int = 8443
    auth_server_port: int = 8444
    mud_url: str = ""
    idevid_cert_path: str = ""
    ldevid_cert_path: str = ""
    ldevid_key_path: str = ""
