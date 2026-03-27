#!/usr/bin/env python3
"""
Unit tests for key revocation owner check (Finding #11).

Verifies defense-in-depth: even with a valid revocation signature,
only the key owner (or keys with no owner set) can revoke a key.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openssl_encrypt_server.modules.keyserver.schemas import RevocationRequest


class TestRevocationOwnerCheck:
    """Tests for owner_client_id validation in revoke_key (#11)."""

    @pytest.fixture
    def mock_db(self):
        db = AsyncMock()
        db.commit = AsyncMock()
        db.execute = AsyncMock()
        return db

    @pytest.fixture
    def service(self, mock_db):
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService
        return KeyserverService(mock_db)

    def _make_key(self, fingerprint="abc123", owner_client_id=None, revoked=False):
        key = MagicMock()
        key.fingerprint = fingerprint
        key.revoked = revoked
        key.owner_client_id = owner_client_id
        key.bundle_json = json.dumps({
            "signing_public_key": "dGVzdA==",
            "signing_algorithm": "ML-DSA-65",
        })
        return key

    @pytest.mark.asyncio
    async def test_non_owner_cannot_revoke_key(self, service, mock_db):
        """Authenticated client that is not the key owner must get 403."""
        from fastapi import HTTPException

        key = self._make_key(owner_client_id="owner_abc")
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = key
        mock_db.execute.return_value = mock_result

        revocation = RevocationRequest(signature="deadbeef")

        with pytest.raises(HTTPException) as exc_info:
            await service.revoke_key("abc123", revocation, client_id="attacker_xyz")

        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_owner_can_revoke_key(self, service, mock_db):
        """Key owner with valid signature should succeed."""
        key = self._make_key(owner_client_id="owner_abc")
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = key
        mock_db.execute.return_value = mock_result

        revocation = RevocationRequest(signature="deadbeef")

        with patch(
            "openssl_encrypt_server.modules.keyserver.service.verify_revocation_signature"
        ):
            result = await service.revoke_key("abc123", revocation, client_id="owner_abc")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_no_owner_set_allows_revocation(self, service, mock_db):
        """Keys with no owner_client_id set (legacy) can be revoked by anyone with valid sig."""
        key = self._make_key(owner_client_id=None)
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = key
        mock_db.execute.return_value = mock_result

        revocation = RevocationRequest(signature="deadbeef")

        with patch(
            "openssl_encrypt_server.modules.keyserver.service.verify_revocation_signature"
        ):
            result = await service.revoke_key("abc123", revocation, client_id="any_client")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_owner_check_before_signature_verification(self):
        """Owner check must happen before the (expensive) signature verification."""
        from pathlib import Path
        service_path = Path(__file__).parent.parent / "modules" / "keyserver" / "service.py"
        with open(service_path) as f:
            source = f.read()
        idx = source.index("async def revoke_key")
        next_method = source.index("\n    async def ", idx + 1)
        method_body = source[idx:next_method]

        owner_check_pos = method_body.index("owner_client_id")
        sig_verify_pos = method_body.index("verify_revocation_signature")
        assert owner_check_pos < sig_verify_pos, \
            "Owner check must come before signature verification for defense-in-depth"

    @pytest.mark.asyncio
    async def test_owner_check_error_message_is_generic(self, service, mock_db):
        """403 error should not leak the actual owner_client_id."""
        from fastapi import HTTPException

        key = self._make_key(owner_client_id="owner_abc")
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = key
        mock_db.execute.return_value = mock_result

        revocation = RevocationRequest(signature="deadbeef")

        with pytest.raises(HTTPException) as exc_info:
            await service.revoke_key("abc123", revocation, client_id="attacker_xyz")

        assert "owner_abc" not in str(exc_info.value.detail)
