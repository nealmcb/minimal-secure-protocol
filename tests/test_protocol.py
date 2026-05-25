"""Tests for the telescope protocol data models (pydantic validation)."""

import pytest
from pydantic import ValidationError

from telescope.protocol import (
    Position,
    SlewCommand,
    DeviceStatus,
    TrackingMode,
    TokenRequest,
    VALID_SCOPES,
)


class TestPosition:
    def test_valid_position(self):
        pos = Position(ra=5.575, dec=-5.39)
        assert pos.ra == 5.575
        assert pos.dec == -5.39

    def test_ra_lower_bound(self):
        pos = Position(ra=0.0, dec=0.0)
        assert pos.ra == 0.0

    def test_ra_upper_bound_exclusive(self):
        with pytest.raises(ValidationError, match="RA must be in"):
            Position(ra=24.0, dec=0.0)

    def test_ra_negative(self):
        with pytest.raises(ValidationError, match="RA must be in"):
            Position(ra=-1.0, dec=0.0)

    def test_dec_lower_bound(self):
        pos = Position(ra=0.0, dec=-90.0)
        assert pos.dec == -90.0

    def test_dec_upper_bound(self):
        pos = Position(ra=0.0, dec=90.0)
        assert pos.dec == 90.0

    def test_dec_out_of_range(self):
        with pytest.raises(ValidationError, match="Dec must be in"):
            Position(ra=0.0, dec=91.0)

    def test_timestamp_set_automatically(self):
        pos = Position(ra=1.0, dec=1.0)
        assert pos.timestamp > 0


class TestSlewCommand:
    def test_valid_slew(self):
        cmd = SlewCommand(ra=10.68, dec=41.27)
        assert cmd.ra == 10.68
        assert cmd.dec == 41.27

    def test_andromeda_galaxy(self):
        # M31 – RA 0.712 h, Dec +41.27°
        cmd = SlewCommand(ra=0.712, dec=41.27)
        assert cmd.ra == pytest.approx(0.712)

    def test_invalid_ra(self):
        with pytest.raises(ValidationError):
            SlewCommand(ra=25.0, dec=0.0)

    def test_invalid_dec(self):
        with pytest.raises(ValidationError):
            SlewCommand(ra=0.0, dec=-91.0)


class TestDeviceStatus:
    def test_defaults(self):
        pos = Position(ra=5.575, dec=-5.39)
        status = DeviceStatus(device_id="mount-001", position=pos)
        assert status.is_slewing is False
        assert status.is_tracking is True
        assert status.tracking_mode == TrackingMode.SIDEREAL

    def test_serialisation(self):
        pos = Position(ra=5.575, dec=-5.39)
        status = DeviceStatus(device_id="mount-001", position=pos)
        data = status.model_dump()
        assert data["device_id"] == "mount-001"
        assert data["position"]["ra"] == pytest.approx(5.575)


class TestTokenRequest:
    def test_valid_token_request(self):
        req = TokenRequest(
            grant_type="client_credentials",
            client_id="tracker",
            client_secret="secretpassword",
            scope="telescope:read",
        )
        assert req.scope == "telescope:read"

    def test_multiple_scopes(self):
        req = TokenRequest(
            grant_type="client_credentials",
            client_id="tracker",
            client_secret="secretpassword",
            scope="telescope:read telescope:slew",
        )
        assert "telescope:slew" in req.scope

    def test_unknown_scope_rejected(self):
        with pytest.raises(ValidationError, match="Unknown scopes"):
            TokenRequest(
                grant_type="client_credentials",
                client_id="tracker",
                client_secret="secretpassword",
                scope="telescope:read telescope:destroy",
            )

    def test_invalid_grant_type(self):
        with pytest.raises(ValidationError):
            TokenRequest(
                grant_type="password",
                client_id="tracker",
                client_secret="secretpassword",
            )

    def test_short_client_secret_rejected(self):
        with pytest.raises(ValidationError):
            TokenRequest(
                grant_type="client_credentials",
                client_id="tracker",
                client_secret="short",  # < 8 chars
            )


class TestValidScopes:
    def test_known_scopes(self):
        assert "telescope:read" in VALID_SCOPES
        assert "telescope:slew" in VALID_SCOPES
        assert "telescope:admin" in VALID_SCOPES
