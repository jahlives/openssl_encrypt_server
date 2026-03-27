#!/usr/bin/env python3
"""
Unit tests for password-based authentication (security finding #1).

Tests the addition of password as a second authentication factor alongside client_id.
Covers: model changes, schema validation, password hashing/verification,
login flow changes, confirmation flow with password, legacy client migration.
"""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# --- Layer 1: Model Tests ---


class TestKSClientPasswordColumn:
    """Verify KSClient model has password_hash column."""

    def test_password_hash_column_exists(self):
        """KSClient must have a password_hash column."""
        from openssl_encrypt_server.modules.keyserver.models import KSClient

        assert hasattr(KSClient, "password_hash"), "KSClient missing password_hash column"

    def test_password_hash_column_is_nullable(self):
        """password_hash must be nullable for legacy client support."""
        from openssl_encrypt_server.modules.keyserver.models import KSClient

        col = KSClient.__table__.columns["password_hash"]
        assert col.nullable is True

    def test_password_hash_column_is_string_255(self):
        """password_hash must be String(255) for Argon2 hashes."""
        from openssl_encrypt_server.modules.keyserver.models import KSClient

        col = KSClient.__table__.columns["password_hash"]
        assert col.type.length == 255


# --- Layer 2: Schema Tests ---


class TestLoginRequestSchema:
    """Verify LoginRequest schema accepts optional password."""

    def test_login_request_without_password(self):
        """LoginRequest must accept client_id alone (legacy flow)."""
        from openssl_encrypt_server.modules.keyserver.schemas import LoginRequest

        req = LoginRequest(client_id="abc123")
        assert req.client_id == "abc123"
        assert req.password is None

    def test_login_request_with_password(self):
        """LoginRequest must accept client_id with password."""
        from openssl_encrypt_server.modules.keyserver.schemas import LoginRequest

        req = LoginRequest(client_id="abc123", password="securepassword12")
        assert req.password == "securepassword12"

    def test_login_request_rejects_short_password(self):
        """LoginRequest must reject password shorter than 8 characters."""
        from pydantic import ValidationError

        from openssl_encrypt_server.modules.keyserver.schemas import LoginRequest

        with pytest.raises(ValidationError):
            LoginRequest(client_id="abc123", password="short")

    def test_login_request_rejects_long_password(self):
        """LoginRequest must reject password longer than 128 characters."""
        from pydantic import ValidationError

        from openssl_encrypt_server.modules.keyserver.schemas import LoginRequest

        with pytest.raises(ValidationError):
            LoginRequest(client_id="abc123", password="x" * 129)


class TestConfirmWithPasswordRequestSchema:
    """Verify ConfirmWithPasswordRequest schema."""

    def test_requires_password(self):
        """ConfirmWithPasswordRequest requires a password."""
        from pydantic import ValidationError

        from openssl_encrypt_server.modules.keyserver.schemas import ConfirmWithPasswordRequest

        with pytest.raises(ValidationError):
            ConfirmWithPasswordRequest()

    def test_accepts_valid_password(self):
        """ConfirmWithPasswordRequest accepts a valid password."""
        from openssl_encrypt_server.modules.keyserver.schemas import ConfirmWithPasswordRequest

        req = ConfirmWithPasswordRequest(password="securepassword12")
        assert req.password == "securepassword12"

    def test_rejects_short_password(self):
        """ConfirmWithPasswordRequest rejects password shorter than 12 characters."""
        from pydantic import ValidationError

        from openssl_encrypt_server.modules.keyserver.schemas import ConfirmWithPasswordRequest

        with pytest.raises(ValidationError):
            ConfirmWithPasswordRequest(password="short123")

    def test_rejects_empty_password(self):
        """ConfirmWithPasswordRequest rejects empty password."""
        from pydantic import ValidationError

        from openssl_encrypt_server.modules.keyserver.schemas import ConfirmWithPasswordRequest

        with pytest.raises(ValidationError):
            ConfirmWithPasswordRequest(password="")


class TestSetPasswordRequestSchema:
    """Verify SetPasswordRequest schema."""

    def test_requires_client_id_and_password(self):
        """SetPasswordRequest requires both client_id and password."""
        from pydantic import ValidationError

        from openssl_encrypt_server.modules.keyserver.schemas import SetPasswordRequest

        with pytest.raises(ValidationError):
            SetPasswordRequest(client_id="abc123")

    def test_accepts_valid_fields(self):
        """SetPasswordRequest accepts valid client_id and password."""
        from openssl_encrypt_server.modules.keyserver.schemas import SetPasswordRequest

        req = SetPasswordRequest(client_id="abc123", password="securepassword12")
        assert req.client_id == "abc123"
        assert req.password == "securepassword12"

    def test_rejects_short_password(self):
        """SetPasswordRequest rejects password shorter than 12 characters."""
        from pydantic import ValidationError

        from openssl_encrypt_server.modules.keyserver.schemas import SetPasswordRequest

        with pytest.raises(ValidationError):
            SetPasswordRequest(client_id="abc123", password="short")


class TestPasswordRequiredResponseSchema:
    """Verify PasswordRequiredResponse schema."""

    def test_has_correct_defaults(self):
        """PasswordRequiredResponse has correct default status and message."""
        from openssl_encrypt_server.modules.keyserver.schemas import PasswordRequiredResponse

        resp = PasswordRequiredResponse()
        assert resp.status == "password_required"
        assert "password" in resp.message.lower()


# --- Layer 3: Service Tests ---


class TestPasswordHashing:
    """Test Argon2 password hashing in KeyserverService."""

    def test_hash_password_returns_argon2_format(self):
        """hash_password must return an Argon2id hash string."""
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService

        hashed = KeyserverService.hash_password("securepassword12")
        assert hashed.startswith("$argon2")

    def test_hash_password_different_for_same_input(self):
        """hash_password must produce different hashes for the same password (random salt)."""
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService

        h1 = KeyserverService.hash_password("securepassword12")
        h2 = KeyserverService.hash_password("securepassword12")
        assert h1 != h2


class TestVerifyClientPassword:
    """Test password verification in KeyserverService."""

    @pytest.fixture
    def mock_db(self):
        db = AsyncMock()
        db.commit = AsyncMock()
        return db

    @pytest.fixture
    def service(self, mock_db):
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService
        return KeyserverService(mock_db)

    @pytest.mark.asyncio
    async def test_correct_password_returns_true(self, service):
        """verify_client_password returns True for correct password."""
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService

        client = MagicMock()
        client.password_hash = KeyserverService.hash_password("correctpassword")

        result = await service.verify_client_password(client, "correctpassword")
        assert result is True

    @pytest.mark.asyncio
    async def test_wrong_password_returns_false(self, service):
        """verify_client_password returns False for wrong password."""
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService

        client = MagicMock()
        client.password_hash = KeyserverService.hash_password("correctpassword")

        result = await service.verify_client_password(client, "wrongpassword")
        assert result is False

    @pytest.mark.asyncio
    async def test_no_password_hash_returns_false(self, service):
        """verify_client_password returns False for client with no password_hash (legacy)."""
        client = MagicMock()
        client.password_hash = None

        result = await service.verify_client_password(client, "anypassword")
        assert result is False


class TestSetClientPassword:
    """Test setting password for a client."""

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

    @pytest.mark.asyncio
    async def test_set_password_stores_argon2_hash(self, service, mock_db):
        """set_client_password stores an Argon2 hash on the client."""
        client = MagicMock()
        client.password_hash = None
        client.client_id = "test_id"

        mock_result = MagicMock()
        mock_result.scalars.return_value.first.return_value = client
        mock_db.execute.return_value = mock_result

        with patch.object(service, "get_client_by_id", return_value=client):
            result = await service.set_client_password("test_id", "securepassword12", "secret")
        assert result is True
        assert client.password_hash.startswith("$argon2")
        mock_db.commit.assert_called()


class TestConfirmRegistrationWithPassword:
    """Test confirmation flow with password."""

    @pytest.fixture
    def mock_db(self):
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.execute = AsyncMock()
        return db

    @pytest.fixture
    def service(self, mock_db):
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService
        return KeyserverService(mock_db)

    @pytest.mark.asyncio
    async def test_confirm_with_password_creates_client_with_hash(self, service, mock_db):
        """confirm_registration_with_password creates a client with a password hash."""
        from datetime import datetime, timedelta, timezone

        pending = MagicMock()
        pending.status = "pending"
        pending.email = "user@example.com"
        pending.confirmation_token = "valid_token"
        pending.expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = pending
        mock_db.execute.return_value = mock_result

        mock_auth = MagicMock()
        mock_auth.generate_client_id.return_value = "generated_client_id"
        mock_auth.secret = "test_secret"

        mock_email = AsyncMock()

        result = await service.confirm_registration_with_password(
            "valid_token", "securepassword12", mock_auth, mock_email
        )

        assert result["client_id"] == "generated_client_id"
        # Check that the KSClient was created with a password_hash
        added_obj = mock_db.add.call_args[0][0]
        assert added_obj.password_hash is not None
        assert added_obj.password_hash.startswith("$argon2")

    @pytest.mark.asyncio
    async def test_confirm_with_password_rejects_expired_token(self, service, mock_db):
        """confirm_registration_with_password raises 410 for expired token."""
        from datetime import datetime, timedelta, timezone

        from fastapi import HTTPException

        pending = MagicMock()
        pending.status = "pending"
        pending.confirmation_token = "expired_token"
        pending.expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = pending
        mock_db.execute.return_value = mock_result

        mock_auth = MagicMock()
        mock_auth.secret = "test_secret"
        mock_email = AsyncMock()

        with pytest.raises(HTTPException) as exc_info:
            await service.confirm_registration_with_password(
                "expired_token", "securepassword12", mock_auth, mock_email
            )
        assert exc_info.value.status_code == 410

    @pytest.mark.asyncio
    async def test_confirm_with_password_rejects_invalid_token(self, service, mock_db):
        """confirm_registration_with_password raises 404 for invalid token."""
        from fastapi import HTTPException

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result

        mock_auth = MagicMock()
        mock_auth.secret = "test_secret"
        mock_email = AsyncMock()

        with pytest.raises(HTTPException) as exc_info:
            await service.confirm_registration_with_password(
                "bad_token", "securepassword12", mock_auth, mock_email
            )
        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_already_confirmed_returns_client_id(self, service, mock_db):
        """Already-confirmed token returns existing client_id without creating new account."""
        pending = MagicMock()
        pending.status = "confirmed"
        pending.client_id = "existing_client_id"
        pending.confirmation_token = "valid_token"

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = pending
        mock_db.execute.return_value = mock_result

        mock_auth = MagicMock()
        mock_auth.secret = "test_secret"
        mock_email = AsyncMock()

        result = await service.confirm_registration_with_password(
            "valid_token", "securepassword12", mock_auth, mock_email
        )
        assert result["client_id"] == "existing_client_id"
        mock_db.add.assert_not_called()


class TestValidateConfirmationToken:
    """Test token validation (separated from account creation)."""

    @pytest.fixture
    def mock_db(self):
        db = AsyncMock()
        db.execute = AsyncMock()
        return db

    @pytest.fixture
    def service(self, mock_db):
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService
        return KeyserverService(mock_db)

    @pytest.mark.asyncio
    async def test_valid_token_returns_pending(self, service, mock_db):
        """validate_confirmation_token returns pending record for valid token."""
        from datetime import datetime, timedelta, timezone

        pending = MagicMock()
        pending.status = "pending"
        pending.confirmation_token = "valid_token"
        pending.expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = pending
        mock_db.execute.return_value = mock_result

        result = await service.validate_confirmation_token("valid_token", "test_secret")
        assert result == pending

    @pytest.mark.asyncio
    async def test_invalid_token_raises_404(self, service, mock_db):
        """validate_confirmation_token raises 404 for non-existent token."""
        from fastapi import HTTPException

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result

        with pytest.raises(HTTPException) as exc_info:
            await service.validate_confirmation_token("bad_token", "test_secret")
        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_expired_token_raises_410(self, service, mock_db):
        """validate_confirmation_token raises 410 for expired token."""
        from datetime import datetime, timedelta, timezone

        from fastapi import HTTPException

        pending = MagicMock()
        pending.status = "pending"
        pending.confirmation_token = "expired_token"
        pending.expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = pending
        mock_db.execute.return_value = mock_result

        with pytest.raises(HTTPException) as exc_info:
            await service.validate_confirmation_token("expired_token", "test_secret")
        assert exc_info.value.status_code == 410


# --- Layer 4: Route/Integration Tests ---


class TestLoginEndpointPasswordAuth:
    """Test login endpoint with password authentication."""

    def test_login_route_source_checks_password(self):
        """Login route must reference password verification."""
        routes_path = Path(__file__).parent.parent / "modules" / "keyserver" / "routes.py"
        with open(routes_path) as f:
            source = f.read()
        login_idx = source.index("async def login")
        login_fn = source[login_idx:login_idx + 1500]
        assert "password" in login_fn, "Login endpoint must handle password"

    def test_login_route_handles_legacy_clients(self):
        """Login route must handle legacy clients (no password hash)."""
        routes_path = Path(__file__).parent.parent / "modules" / "keyserver" / "routes.py"
        with open(routes_path) as f:
            source = f.read()
        login_idx = source.index("async def login")
        login_fn = source[login_idx:login_idx + 1500]
        assert "password_required" in login_fn, "Login must signal legacy clients to set password"


class TestConfirmEndpointPasswordForm:
    """Test that confirm endpoint serves password form on GET."""

    def test_confirm_get_serves_password_form(self):
        """GET /confirm/{token} must render a password form for browsers."""
        routes_path = Path(__file__).parent.parent / "modules" / "keyserver" / "routes.py"
        with open(routes_path) as f:
            source = f.read()
        assert "_render_password_form_html" in source, \
            "Must have password form HTML renderer"

    def test_password_form_html_has_password_field(self):
        """Password form HTML must contain a password input."""
        import importlib
        import sys

        routes_path = Path(__file__).parent.parent / "modules" / "keyserver" / "routes.py"
        with open(routes_path) as f:
            source = f.read()

        assert 'type="password"' in source or "type=\\\"password\\\"" in source or \
               'type=\\"password\\"' in source or "new-password" in source, \
            "Password form must have a password input field"

    def test_confirm_post_endpoint_exists(self):
        """POST /confirm/{token} endpoint must exist."""
        routes_path = Path(__file__).parent.parent / "modules" / "keyserver" / "routes.py"
        with open(routes_path) as f:
            source = f.read()
        assert "confirm_registration_with_password" in source or \
               "confirm_with_password" in source, \
            "POST confirm endpoint must exist"


class TestSetPasswordEndpoint:
    """Test set-password endpoint for legacy migration."""

    def test_set_password_route_exists(self):
        """POST /set-password route must exist."""
        routes_path = Path(__file__).parent.parent / "modules" / "keyserver" / "routes.py"
        with open(routes_path) as f:
            source = f.read()
        assert "set-password" in source or "set_password" in source, \
            "set-password endpoint must exist"

    def test_set_password_is_rate_limited(self):
        """set-password must have aggressive rate limiting."""
        routes_path = Path(__file__).parent.parent / "modules" / "keyserver" / "routes.py"
        with open(routes_path) as f:
            source = f.read()
        # Find the set_password function and check for rate limiting
        if "async def set_password" in source:
            idx = source.index("async def set_password")
            preceding = source[max(0, idx - 200):idx]
            assert "limiter.limit" in preceding, "set-password must be rate-limited"


# --- Layer 5: Security Tests ---


class TestPasswordSecurityProperties:
    """Security-specific tests for password handling."""

    def test_password_hash_is_argon2id(self):
        """Password hashing must use Argon2id variant."""
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService

        hashed = KeyserverService.hash_password("testpassword12")
        assert "$argon2id$" in hashed, "Must use Argon2id variant"

    def test_password_never_in_register_response(self):
        """RegisterResponse schema must not contain a password field."""
        from openssl_encrypt_server.modules.keyserver.schemas import RegisterResponse

        fields = RegisterResponse.model_fields
        assert "password" not in fields
        assert "password_hash" not in fields

    def test_dummy_hash_exists_for_timing_protection(self):
        """Service must have a dummy hash for timing attack prevention."""
        service_path = Path(__file__).parent.parent / "modules" / "keyserver" / "service.py"
        with open(service_path) as f:
            source = f.read()
        assert "_DUMMY_HASH" in source or "_dummy_hash" in source, \
            "Must have a dummy hash for constant-time behavior on invalid client_id"


# --- Layer 6: Migration Tests ---


class TestPasswordMigration:
    """Test that migration file exists for password_hash column."""

    def test_migration_file_exists(self):
        """Migration 005_password_hash.sql must exist."""
        migration_path = Path(__file__).parent.parent / "migrations" / "005_password_hash.sql"
        assert migration_path.exists(), "Migration SQL file must exist"

    def test_migration_adds_password_hash_column(self):
        """Migration must add password_hash column."""
        migration_path = Path(__file__).parent.parent / "migrations" / "005_password_hash.sql"
        with open(migration_path) as f:
            sql = f.read()
        assert "password_hash" in sql
        assert "ALTER TABLE" in sql or "ADD COLUMN" in sql

    def test_python_migration_exists(self):
        """Migration 005_password_hash.py must exist."""
        migration_path = Path(__file__).parent.parent / "migrations" / "005_password_hash.py"
        assert migration_path.exists(), "Migration Python file must exist"
