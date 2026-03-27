#!/usr/bin/env python3
"""
Unit tests for email-confirmed keyserver registration.

Tests the email verification flow:
1. User submits email → pending registration created
2. Confirmation link clicked → account activated, client_id returned
3. Welcome email sent with client_id

Covers: happy path, expiry, duplicates, validation, config, cleanup.
"""

import secrets
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openssl_encrypt_server.modules.keyserver.models import KSClient, KSPendingRegistration
from openssl_encrypt_server.modules.keyserver.schemas import (
    ConfirmationResponse,
    EmailRegisterRequest,
    EmailRegisterResponse,
    RegistrationStatusResponse,
)


# ---------------------------------------------------------------------------
# Model Tests
# ---------------------------------------------------------------------------

class TestKSPendingRegistrationModel:
    """Tests for the KSPendingRegistration database model."""

    def test_model_has_required_columns(self):
        """Pending registration model has all required columns."""
        columns = {c.name for c in KSPendingRegistration.__table__.columns}
        assert "id" in columns
        assert "email" in columns
        assert "confirmation_token" in columns
        assert "registration_id" in columns
        assert "status" in columns
        assert "client_id" in columns
        assert "created_at" in columns
        assert "expires_at" in columns
        assert "confirmed_at" in columns

    def test_registration_id_column_is_unique(self):
        """Registration ID column has unique constraint."""
        col = KSPendingRegistration.__table__.columns["registration_id"]
        assert col.unique is True

    def test_registration_id_hmac_column_is_indexed(self):
        """Registration ID HMAC column is indexed for constant-time lookup."""
        col = KSPendingRegistration.__table__.columns["registration_id_hmac"]
        assert col.index is True

    def test_table_name(self):
        """Table uses ks_ prefix per project convention."""
        assert KSPendingRegistration.__tablename__ == "ks_pending_registrations"

    def test_email_column_is_unique(self):
        """Email column has unique constraint (one account per email)."""
        email_col = KSPendingRegistration.__table__.columns["email"]
        assert email_col.unique is True

    def test_confirmation_token_column_is_unique(self):
        """Confirmation token column has unique constraint."""
        token_col = KSPendingRegistration.__table__.columns["confirmation_token"]
        assert token_col.unique is True

    def test_email_column_is_indexed(self):
        """Email column is indexed for fast lookup."""
        email_col = KSPendingRegistration.__table__.columns["email"]
        assert email_col.index is True

    def test_confirmation_token_hmac_column_is_indexed(self):
        """Confirmation token HMAC column is indexed for constant-time lookup."""
        token_col = KSPendingRegistration.__table__.columns["confirmation_token_hmac"]
        assert token_col.index is True


class TestKSClientEmailColumn:
    """Tests for the email column added to KSClient."""

    def test_client_has_email_column(self):
        """KSClient model has an email column."""
        columns = {c.name for c in KSClient.__table__.columns}
        assert "email" in columns

    def test_email_column_is_nullable(self):
        """Email is nullable (for anonymous registration and existing clients)."""
        email_col = KSClient.__table__.columns["email"]
        assert email_col.nullable is True

    def test_email_column_is_unique(self):
        """Email column has unique constraint (one account per email)."""
        email_col = KSClient.__table__.columns["email"]
        assert email_col.unique is True


# ---------------------------------------------------------------------------
# Schema Tests
# ---------------------------------------------------------------------------

class TestEmailRegisterRequest:
    """Tests for the email registration request schema."""

    def test_valid_email_accepted(self):
        """Valid email address is accepted."""
        req = EmailRegisterRequest(email="user@example.com")
        assert req.email == "user@example.com"

    def test_invalid_email_rejected(self):
        """Invalid email format is rejected."""
        with pytest.raises(Exception):
            EmailRegisterRequest(email="not-an-email")

    def test_empty_email_rejected(self):
        """Empty email is rejected."""
        with pytest.raises(Exception):
            EmailRegisterRequest(email="")

    def test_email_max_length(self):
        """Email exceeding max length is rejected."""
        long_email = "a" * 250 + "@example.com"
        with pytest.raises(Exception):
            EmailRegisterRequest(email=long_email)


class TestEmailRegisterResponse:
    """Tests for the email registration response schema."""

    def test_response_has_message(self):
        """Response contains a message field."""
        resp = EmailRegisterResponse(registration_id="reg123", message="Check your email")
        assert resp.message == "Check your email"

    def test_response_has_registration_id(self):
        """Response contains a registration_id field for polling."""
        resp = EmailRegisterResponse(registration_id="reg123", message="Check your email")
        assert resp.registration_id == "reg123"


class TestRegistrationStatusResponse:
    """Tests for the registration status polling response."""

    def test_pending_status(self):
        """Pending status response has no tokens."""
        resp = RegistrationStatusResponse(status="pending")
        assert resp.status == "pending"
        assert resp.client_id is None
        assert resp.access_token is None

    def test_confirmed_status_with_tokens(self):
        """Confirmed status response includes tokens."""
        resp = RegistrationStatusResponse(
            status="confirmed",
            client_id="abc123",
            access_token="tok_access",
            refresh_token="tok_refresh",
            expires_at="2026-03-26T12:00:00Z",
            refresh_expires_at="2026-04-02T12:00:00Z",
            token_type="Bearer",
        )
        assert resp.status == "confirmed"
        assert resp.client_id == "abc123"
        assert resp.access_token == "tok_access"


class TestConfirmationResponse:
    """Tests for the confirmation response schema."""

    def test_response_has_client_id(self):
        """Confirmation response contains client_id."""
        resp = ConfirmationResponse(client_id="abc123", message="Account activated")
        assert resp.client_id == "abc123"

    def test_response_has_message(self):
        """Confirmation response contains message."""
        resp = ConfirmationResponse(client_id="abc123", message="Account activated")
        assert resp.message == "Account activated"


# ---------------------------------------------------------------------------
# Service Tests
# ---------------------------------------------------------------------------

class TestCreatePendingRegistration:
    """Tests for creating a pending email registration."""

    @pytest.fixture
    def mock_db(self):
        """Create a mock async database session."""
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.execute = AsyncMock()
        db.delete = AsyncMock()
        return db

    @pytest.fixture
    def service(self, mock_db):
        """Create a KeyserverService with mock DB."""
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService
        return KeyserverService(mock_db)

    @pytest.mark.asyncio
    async def test_creates_pending_record(self, service, mock_db):
        """Submitting an email creates a pending registration record."""
        # Mock: no existing client, no existing pending
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result

        mock_email_service = AsyncMock()

        result = await service.create_pending_registration(
            "user@example.com", "https://keys.example.com", mock_email_service
        )

        assert "registration_id" in result
        assert len(result["registration_id"]) > 20
        assert "token" in result
        mock_db.add.assert_called_once()
        mock_db.commit.assert_called()

    @pytest.mark.asyncio
    async def test_sends_confirmation_email(self, service, mock_db):
        """Creating a pending registration sends a confirmation email."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result

        mock_email_service = AsyncMock()

        await service.create_pending_registration(
            "user@example.com", "https://keys.example.com", mock_email_service
        )

        mock_email_service.send_confirmation_email.assert_called_once()
        call_args = mock_email_service.send_confirmation_email.call_args
        assert call_args[0][0] == "user@example.com"  # email
        assert "https://keys.example.com" in call_args[0][2]  # base_url in link

    @pytest.mark.asyncio
    async def test_existing_account_returns_opaque_response(self, service, mock_db):
        """Existing account returns same 202-shaped response to prevent email enumeration (#5)."""
        # First query (KSClient) returns an existing client
        existing_client = MagicMock()
        existing_client.email = "user@example.com"

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = existing_client
        mock_db.execute.return_value = mock_result

        mock_email_service = AsyncMock()

        # Should NOT raise — returns opaque response indistinguishable from success
        result = await service.create_pending_registration(
            "user@example.com", "https://keys.example.com", mock_email_service
        )
        assert "registration_id" in result

    @pytest.mark.asyncio
    async def test_existing_account_does_not_send_confirmation_email(self, service, mock_db):
        """Existing account must not send a confirmation email."""
        existing_client = MagicMock()
        existing_client.email = "user@example.com"

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = existing_client
        mock_db.execute.return_value = mock_result

        mock_email_service = AsyncMock()

        await service.create_pending_registration(
            "user@example.com", "https://keys.example.com", mock_email_service
        )
        mock_email_service.send_confirmation_email.assert_not_called()

    @pytest.mark.asyncio
    async def test_existing_account_sends_notification_email(self, service, mock_db):
        """Existing account sends a notification that someone tried to register."""
        existing_client = MagicMock()
        existing_client.email = "user@example.com"

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = existing_client
        mock_db.execute.return_value = mock_result

        mock_email_service = AsyncMock()

        await service.create_pending_registration(
            "user@example.com", "https://keys.example.com", mock_email_service
        )
        mock_email_service.send_duplicate_registration_notice.assert_called_once_with(
            "user@example.com"
        )

    @pytest.mark.asyncio
    async def test_resends_email_for_existing_pending(self, service, mock_db):
        """Re-submitting same email updates the pending record and re-sends email."""
        # First query (KSClient): no existing client
        # Second query (KSPendingRegistration): existing pending record
        existing_pending = MagicMock()
        existing_pending.email = "user@example.com"
        existing_pending.confirmation_token = "old_token"

        results = [
            MagicMock(scalar_one_or_none=MagicMock(return_value=None)),       # KSClient lookup
            MagicMock(scalar_one_or_none=MagicMock(return_value=existing_pending)),  # Pending lookup
        ]
        mock_db.execute.side_effect = results

        mock_email_service = AsyncMock()

        result = await service.create_pending_registration(
            "user@example.com", "https://keys.example.com", mock_email_service
        )

        # Token should be refreshed
        assert result["token"] != "old_token"
        mock_email_service.send_confirmation_email.assert_called_once()
        mock_db.commit.assert_called()

    @pytest.mark.asyncio
    async def test_expiry_is_30_minutes(self, service, mock_db):
        """Pending registration expires after 30 minutes."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result

        mock_email_service = AsyncMock()

        await service.create_pending_registration(
            "user@example.com", "https://keys.example.com", mock_email_service
        )

        # Check the model that was added to db
        added_obj = mock_db.add.call_args[0][0]
        time_diff = added_obj.expires_at - added_obj.created_at
        assert timedelta(minutes=29) < time_diff <= timedelta(minutes=31)


class TestConfirmRegistration:
    """Tests for confirming a registration via token."""

    @pytest.fixture
    def mock_db(self):
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.execute = AsyncMock()
        db.delete = AsyncMock()
        return db

    @pytest.fixture
    def service(self, mock_db):
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService
        return KeyserverService(mock_db)

    @pytest.mark.asyncio
    async def test_valid_token_creates_account(self, service, mock_db):
        """Valid, non-expired token creates a KSClient account."""
        pending = MagicMock()
        pending.email = "user@example.com"
        pending.confirmation_token = "valid_token"
        pending.status = "pending"
        pending.expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = pending
        mock_db.execute.return_value = mock_result

        mock_email_service = AsyncMock()
        mock_auth = MagicMock()
        mock_auth.generate_client_id.return_value = "abc123def456"
        mock_auth.secret = "test_secret_key"

        result = await service.confirm_registration(
            "valid_token", mock_auth, mock_email_service
        )

        assert result["client_id"] == "abc123def456"
        mock_db.add.assert_called_once()  # KSClient added
        # Pending record is now marked confirmed, not deleted
        assert pending.status == "confirmed"
        assert pending.client_id == "abc123def456"

    @pytest.mark.asyncio
    async def test_sends_welcome_email_with_client_id(self, service, mock_db):
        """Confirming sends a welcome email containing the client_id."""
        pending = MagicMock()
        pending.email = "user@example.com"
        pending.confirmation_token = "valid_token"
        pending.status = "pending"
        pending.expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = pending
        mock_db.execute.return_value = mock_result

        mock_email_service = AsyncMock()
        mock_auth = MagicMock()
        mock_auth.generate_client_id.return_value = "abc123def456"
        mock_auth.secret = "test_secret_key"

        await service.confirm_registration("valid_token", mock_auth, mock_email_service)

        mock_email_service.send_welcome_email.assert_called_once_with(
            "user@example.com", "abc123def456"
        )

    @pytest.mark.asyncio
    async def test_expired_token_returns_410(self, service, mock_db):
        """Expired confirmation token returns 410 Gone."""
        from fastapi import HTTPException

        pending = MagicMock()
        pending.email = "user@example.com"
        pending.confirmation_token = "expired_token"
        pending.status = "pending"
        pending.expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = pending
        mock_db.execute.return_value = mock_result

        mock_email_service = AsyncMock()
        mock_auth = MagicMock()

        with pytest.raises(HTTPException) as exc_info:
            await service.confirm_registration(
                "expired_token", mock_auth, mock_email_service
            )
        assert exc_info.value.status_code == 410

    @pytest.mark.asyncio
    async def test_invalid_token_returns_404(self, service, mock_db):
        """Unknown confirmation token returns 404."""
        from fastapi import HTTPException

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result

        mock_email_service = AsyncMock()
        mock_auth = MagicMock()

        with pytest.raises(HTTPException) as exc_info:
            await service.confirm_registration(
                "nonexistent_token", mock_auth, mock_email_service
            )
        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_confirmation_marks_record_confirmed(self, service, mock_db):
        """Successful confirmation marks the pending record as confirmed."""
        pending = MagicMock()
        pending.email = "user@example.com"
        pending.confirmation_token = "valid_token"
        pending.status = "pending"
        pending.expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = pending
        mock_db.execute.return_value = mock_result

        mock_email_service = AsyncMock()
        mock_auth = MagicMock()
        mock_auth.generate_client_id.return_value = "abc123"
        mock_auth.secret = "test_secret_key"

        await service.confirm_registration("valid_token", mock_auth, mock_email_service)

        # Record should be marked confirmed, not deleted
        assert pending.status == "confirmed"
        assert pending.confirmed_at is not None
        mock_db.delete.assert_not_called()

    @pytest.mark.asyncio
    async def test_already_confirmed_returns_client_id(self, service, mock_db):
        """Clicking the confirmation link again returns the existing client_id."""
        pending = MagicMock()
        pending.email = "user@example.com"
        pending.confirmation_token = "valid_token"
        pending.status = "confirmed"
        pending.client_id = "existing_client_123"

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = pending
        mock_db.execute.return_value = mock_result

        mock_email_service = AsyncMock()
        mock_auth = MagicMock()

        result = await service.confirm_registration("valid_token", mock_auth, mock_email_service)

        assert result["client_id"] == "existing_client_123"
        mock_auth.generate_client_id.assert_not_called()  # No new client created


class TestCleanupExpiredRegistrations:
    """Tests for cleanup of expired pending registrations."""

    @pytest.fixture
    def mock_db(self):
        db = AsyncMock()
        db.execute = AsyncMock()
        db.commit = AsyncMock()
        return db

    @pytest.fixture
    def service(self, mock_db):
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService
        return KeyserverService(mock_db)

    @pytest.mark.asyncio
    async def test_cleanup_deletes_expired_records(self, service, mock_db):
        """Cleanup removes expired pending registrations."""
        mock_result = MagicMock()
        mock_result.rowcount = 3
        mock_db.execute.return_value = mock_result

        count = await service.cleanup_expired_registrations()

        assert count == 3
        mock_db.execute.assert_called_once()
        mock_db.commit.assert_called_once()


# ---------------------------------------------------------------------------
# Configuration Tests
# ---------------------------------------------------------------------------

class TestEmailVerificationConfig:
    """Tests for email verification configuration settings."""

    def test_settings_has_email_verification_flag(self):
        """Settings has KEYSERVER_REQUIRE_EMAIL_VERIFICATION field."""
        from openssl_encrypt_server.config import Settings
        field_names = set(Settings.model_fields.keys())
        assert "keyserver_require_email_verification" in field_names

    def test_email_verification_default_false(self):
        """Email verification is disabled by default."""
        from openssl_encrypt_server.config import Settings
        field = Settings.model_fields["keyserver_require_email_verification"]
        assert field.default is False

    def test_settings_has_smtp_host(self):
        """Settings has SMTP_HOST field."""
        from openssl_encrypt_server.config import Settings
        assert "smtp_host" in Settings.model_fields

    def test_settings_has_smtp_port(self):
        """Settings has SMTP_PORT field."""
        from openssl_encrypt_server.config import Settings
        assert "smtp_port" in Settings.model_fields

    def test_smtp_port_default_587(self):
        """SMTP port defaults to 587 (STARTTLS)."""
        from openssl_encrypt_server.config import Settings
        assert Settings.model_fields["smtp_port"].default == 587

    def test_settings_has_smtp_use_tls(self):
        """Settings has SMTP_USE_TLS field."""
        from openssl_encrypt_server.config import Settings
        assert "smtp_use_tls" in Settings.model_fields

    def test_smtp_use_tls_default_true(self):
        """SMTP TLS defaults to true."""
        from openssl_encrypt_server.config import Settings
        assert Settings.model_fields["smtp_use_tls"].default is True

    def test_settings_has_smtp_from_address(self):
        """Settings has SMTP_FROM_ADDRESS field."""
        from openssl_encrypt_server.config import Settings
        assert "smtp_from_address" in Settings.model_fields

    def test_settings_has_keyserver_base_url(self):
        """Settings has KEYSERVER_BASE_URL field."""
        from openssl_encrypt_server.config import Settings
        assert "keyserver_base_url" in Settings.model_fields


class TestSMTPConfigValidation:
    """Tests for SMTP config validation when email verification is enabled."""

    def test_smtp_required_when_email_verification_enabled(self):
        """Validation fails if email verification enabled without SMTP config."""
        from openssl_encrypt_server.config import Settings, validate_config

        test_settings = Settings(
            keyserver_enabled=True,
            keyserver_token_secret="a" * 32,
            telemetry_enabled=False,
            postgres_password="strong-password-here-1234",
            keyserver_require_email_verification=True,
            smtp_host="",
            keyserver_base_url="https://keys.example.com",
        )

        with pytest.raises(ValueError, match="SMTP"):
            validate_config(test_settings)

    def test_base_url_required_when_email_verification_enabled(self):
        """Validation fails if email verification enabled without base URL."""
        from openssl_encrypt_server.config import Settings, validate_config

        test_settings = Settings(
            keyserver_enabled=True,
            keyserver_token_secret="a" * 32,
            telemetry_enabled=False,
            postgres_password="strong-password-here-1234",
            keyserver_require_email_verification=True,
            smtp_host="smtp.example.com",
            smtp_from_address="noreply@example.com",
            keyserver_base_url="",
        )

        with pytest.raises(ValueError, match="KEYSERVER_BASE_URL"):
            validate_config(test_settings)

    def test_smtp_from_address_required_when_email_verification_enabled(self):
        """Validation fails if email verification enabled without from address."""
        from openssl_encrypt_server.config import Settings, validate_config

        test_settings = Settings(
            keyserver_enabled=True,
            keyserver_token_secret="a" * 32,
            telemetry_enabled=False,
            postgres_password="strong-password-here-1234",
            keyserver_require_email_verification=True,
            smtp_host="smtp.example.com",
            smtp_from_address="",
            keyserver_base_url="https://keys.example.com",
        )

        with pytest.raises(ValueError, match="SMTP_FROM_ADDRESS"):
            validate_config(test_settings)

    def test_validation_passes_when_email_verification_disabled(self):
        """Validation passes without SMTP config when verification disabled."""
        from openssl_encrypt_server.config import Settings, validate_config

        test_settings = Settings(
            keyserver_enabled=True,
            keyserver_token_secret="a" * 32,
            telemetry_enabled=False,
            postgres_password="strong-password-here-1234",
            keyserver_require_email_verification=False,
        )

        # Should not raise
        validate_config(test_settings)


# ---------------------------------------------------------------------------
# Email Service Tests
# ---------------------------------------------------------------------------

class TestEmailService:
    """Tests for the email service."""

    def test_email_service_can_be_instantiated(self):
        """EmailService can be created with SMTP config."""
        from openssl_encrypt_server.core.email import EmailService

        service = EmailService(
            smtp_host="smtp.example.com",
            smtp_port=587,
            smtp_username="user",
            smtp_password="pass",
            smtp_use_tls=True,
            from_address="noreply@example.com",
        )
        assert service.smtp_host == "smtp.example.com"
        assert service.from_address == "noreply@example.com"

    @pytest.mark.asyncio
    async def test_send_confirmation_email_calls_send(self):
        """send_confirmation_email composes and sends an email."""
        from openssl_encrypt_server.core.email import EmailService

        service = EmailService(
            smtp_host="smtp.example.com",
            smtp_port=587,
            from_address="noreply@example.com",
        )

        with patch.object(service, "_send_email", new_callable=AsyncMock) as mock_send:
            await service.send_confirmation_email(
                "user@example.com", "test_token_123", "https://keys.example.com"
            )

            mock_send.assert_called_once()
            call_args = mock_send.call_args
            assert call_args[0][0] == "user@example.com"  # to
            assert "confirm" in call_args[0][1].lower()  # subject
            assert "test_token_123" in call_args[0][2]  # body contains token
            assert "https://keys.example.com" in call_args[0][2]  # body contains URL

    @pytest.mark.asyncio
    async def test_send_welcome_email_contains_client_id(self):
        """send_welcome_email includes the client_id in the email body."""
        from openssl_encrypt_server.core.email import EmailService

        service = EmailService(
            smtp_host="smtp.example.com",
            smtp_port=587,
            from_address="noreply@example.com",
        )

        with patch.object(service, "_send_email", new_callable=AsyncMock) as mock_send:
            await service.send_welcome_email("user@example.com", "abc123def456")

            mock_send.assert_called_once()
            call_args = mock_send.call_args
            assert call_args[0][0] == "user@example.com"
            assert "abc123def456" in call_args[0][2]  # client_id in body

    @pytest.mark.asyncio
    async def test_confirmation_email_has_30min_notice(self):
        """Confirmation email mentions 30-minute expiry."""
        from openssl_encrypt_server.core.email import EmailService

        service = EmailService(
            smtp_host="smtp.example.com",
            smtp_port=587,
            from_address="noreply@example.com",
        )

        with patch.object(service, "_send_email", new_callable=AsyncMock) as mock_send:
            await service.send_confirmation_email(
                "user@example.com", "token", "https://keys.example.com"
            )

            body = mock_send.call_args[0][2]
            assert "30" in body  # mentions 30 minutes


class TestEmailHtmlEscaping:
    """Tests for HTML escaping in email templates (finding #7)."""

    @pytest.mark.asyncio
    async def test_welcome_email_escapes_client_id(self):
        """send_welcome_email HTML-escapes client_id to prevent injection."""
        from openssl_encrypt_server.core.email import EmailService

        service = EmailService(
            smtp_host="smtp.example.com",
            smtp_port=587,
            from_address="noreply@example.com",
        )

        malicious_id = '<script>alert("xss")</script>'

        with patch.object(service, "_send_email", new_callable=AsyncMock) as mock_send:
            await service.send_welcome_email("user@example.com", malicious_id)

            body = mock_send.call_args[0][2]
            assert "<script>" not in body
            assert "&lt;script&gt;" in body

    @pytest.mark.asyncio
    async def test_confirmation_email_escapes_base_url(self):
        """send_confirmation_email HTML-escapes base_url to prevent injection."""
        from openssl_encrypt_server.core.email import EmailService

        service = EmailService(
            smtp_host="smtp.example.com",
            smtp_port=587,
            from_address="noreply@example.com",
        )

        malicious_url = 'https://evil.com"><script>alert(1)</script><a href="'

        with patch.object(service, "_send_email", new_callable=AsyncMock) as mock_send:
            await service.send_confirmation_email(
                "user@example.com", "safe_token", malicious_url
            )

            body = mock_send.call_args[0][2]
            assert "<script>" not in body
            assert "&lt;script&gt;" in body

    @pytest.mark.asyncio
    async def test_confirmation_email_escapes_token(self):
        """send_confirmation_email HTML-escapes token to prevent injection."""
        from openssl_encrypt_server.core.email import EmailService

        service = EmailService(
            smtp_host="smtp.example.com",
            smtp_port=587,
            from_address="noreply@example.com",
        )

        malicious_token = '"><script>alert(1)</script>'

        with patch.object(service, "_send_email", new_callable=AsyncMock) as mock_send:
            await service.send_confirmation_email(
                "user@example.com", malicious_token, "https://keys.example.com"
            )

            body = mock_send.call_args[0][2]
            assert "<script>" not in body

    @pytest.mark.asyncio
    async def test_welcome_email_preserves_safe_values(self):
        """HTML escaping does not corrupt normal hex client_ids."""
        from openssl_encrypt_server.core.email import EmailService

        service = EmailService(
            smtp_host="smtp.example.com",
            smtp_port=587,
            from_address="noreply@example.com",
        )

        safe_id = "abc123def456"

        with patch.object(service, "_send_email", new_callable=AsyncMock) as mock_send:
            await service.send_welcome_email("user@example.com", safe_id)

            body = mock_send.call_args[0][2]
            assert safe_id in body


# ---------------------------------------------------------------------------
# Constant-Time Token Lookup Tests (Finding #6)
# ---------------------------------------------------------------------------


class TestConstantTimeTokenLookup:
    """Verify confirmation_token and registration_id use HMAC-indexed lookup (#6)."""

    def test_pending_registration_has_token_hmac_column(self):
        """KSPendingRegistration must have confirmation_token_hmac column."""
        from openssl_encrypt_server.modules.keyserver.models import KSPendingRegistration

        assert hasattr(KSPendingRegistration, "confirmation_token_hmac")

    def test_pending_registration_has_regid_hmac_column(self):
        """KSPendingRegistration must have registration_id_hmac column."""
        from openssl_encrypt_server.modules.keyserver.models import KSPendingRegistration

        assert hasattr(KSPendingRegistration, "registration_id_hmac")

    def test_validate_token_uses_hmac_compare(self):
        """validate_confirmation_token must use hmac.compare_digest."""
        from pathlib import Path
        service_path = Path(__file__).parent.parent / "modules" / "keyserver" / "service.py"
        with open(service_path) as f:
            source = f.read()
        # Find the validate_confirmation_token method and check for constant-time compare
        idx = source.index("async def validate_confirmation_token")
        method_end = source.index("\n    async def ", idx + 1)
        method_body = source[idx:method_end]
        assert "hmac.compare_digest" in method_body, \
            "validate_confirmation_token must use constant-time comparison"

    def test_check_registration_status_uses_hmac_compare(self):
        """check_registration_status must use hmac.compare_digest."""
        from pathlib import Path
        service_path = Path(__file__).parent.parent / "modules" / "keyserver" / "service.py"
        with open(service_path) as f:
            source = f.read()
        idx = source.index("async def check_registration_status")
        # Get a reasonable chunk of the method body
        method_body = source[idx:idx + 1500]
        assert "hmac.compare_digest" in method_body, \
            "check_registration_status must use constant-time comparison"

    def test_create_pending_stores_token_hmac(self):
        """create_pending_registration must compute and store token HMAC."""
        from pathlib import Path
        service_path = Path(__file__).parent.parent / "modules" / "keyserver" / "service.py"
        with open(service_path) as f:
            source = f.read()
        idx = source.index("async def create_pending_registration")
        method_body = source[idx:idx + 2000]
        assert "confirmation_token_hmac" in method_body, \
            "create_pending_registration must store confirmation_token_hmac"
        assert "registration_id_hmac" in method_body, \
            "create_pending_registration must store registration_id_hmac"

    def test_migration_006_exists(self):
        """Migration 006 for token HMAC columns must exist."""
        from pathlib import Path
        migration_path = Path(__file__).parent.parent / "migrations" / "006_token_hmac.sql"
        assert migration_path.exists(), "Migration 006_token_hmac.sql must exist"


# ---------------------------------------------------------------------------
# Registration Status Polling Tests
# ---------------------------------------------------------------------------

class TestCheckRegistrationStatus:
    """Tests for the registration status polling endpoint."""

    @pytest.fixture
    def mock_db(self):
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.execute = AsyncMock()
        db.delete = AsyncMock()
        return db

    @pytest.fixture
    def service(self, mock_db):
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService
        return KeyserverService(mock_db)

    @pytest.mark.asyncio
    async def test_pending_status_returned(self, service, mock_db):
        """Status returns 'pending' when registration not yet confirmed."""
        pending = MagicMock()
        pending.status = "pending"
        pending.registration_id = "reg_id_123"
        pending.expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = pending
        mock_db.execute.return_value = mock_result

        mock_auth = MagicMock()
        mock_auth.secret = "test_secret"
        result = await service.check_registration_status("reg_id_123", mock_auth)

        assert result["status"] == "pending"
        assert "client_id" not in result

    @pytest.mark.asyncio
    async def test_confirmed_status_returns_tokens(self, service, mock_db):
        """Status returns tokens when registration is confirmed."""
        pending = MagicMock()
        pending.status = "confirmed"
        pending.client_id = "client_abc123"
        pending.registration_id = "reg_id_123"

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = pending
        mock_db.execute.return_value = mock_result

        mock_auth = MagicMock()
        mock_auth.secret = "test_secret"
        mock_auth.create_token_pair.return_value = {
            "access_token": "tok_access",
            "refresh_token": "tok_refresh",
            "access_token_expires_at": "2026-03-26T13:00:00Z",
            "refresh_token_expires_at": "2026-04-02T12:00:00Z",
            "token_type": "Bearer",
        }

        result = await service.check_registration_status("reg_id_123", mock_auth)

        assert result["status"] == "confirmed"
        assert result["client_id"] == "client_abc123"
        assert result["access_token"] == "tok_access"
        assert result["refresh_token"] == "tok_refresh"
        mock_auth.create_token_pair.assert_called_once_with("client_abc123")

    @pytest.mark.asyncio
    async def test_confirmed_deletes_pending_record(self, service, mock_db):
        """Picking up confirmed tokens deletes the pending record."""
        pending = MagicMock()
        pending.status = "confirmed"
        pending.client_id = "client_abc123"
        pending.registration_id = "reg_id_123"

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = pending
        mock_db.execute.return_value = mock_result

        mock_auth = MagicMock()
        mock_auth.secret = "test_secret"
        mock_auth.create_token_pair.return_value = {
            "access_token": "tok", "refresh_token": "ref",
            "access_token_expires_at": "x", "refresh_token_expires_at": "x",
            "token_type": "Bearer",
        }

        await service.check_registration_status("reg_id_123", mock_auth)

        mock_db.delete.assert_called_once_with(pending)

    @pytest.mark.asyncio
    async def test_unknown_registration_id_returns_404(self, service, mock_db):
        """Unknown registration_id returns 404."""
        from fastapi import HTTPException

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result

        mock_auth = MagicMock()
        mock_auth.secret = "test_secret"

        with pytest.raises(HTTPException) as exc_info:
            await service.check_registration_status("nonexistent", mock_auth)
        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_expired_pending_returns_410(self, service, mock_db):
        """Expired pending registration returns 410."""
        from fastapi import HTTPException

        pending = MagicMock()
        pending.status = "pending"
        pending.registration_id = "expired_reg"
        pending.expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = pending
        mock_db.execute.return_value = mock_result

        mock_auth = MagicMock()
        mock_auth.secret = "test_secret"

        with pytest.raises(HTTPException) as exc_info:
            await service.check_registration_status("expired_reg", mock_auth)
        assert exc_info.value.status_code == 410


# ---------------------------------------------------------------------------
# Route-Level Tests
# ---------------------------------------------------------------------------

class TestRegistrationRouteConfig:
    """Tests for registration route behavior based on config."""

    def test_register_endpoint_exists(self):
        """The email registration endpoint is defined."""
        from openssl_encrypt_server.modules.keyserver.routes import router

        paths = [route.path for route in router.routes]
        assert "/register/email" in paths

    def test_confirm_endpoint_exists(self):
        """The confirmation endpoint is defined."""
        from openssl_encrypt_server.modules.keyserver.routes import router

        paths = [route.path for route in router.routes]
        assert "/confirm/{token}" in paths

    def test_register_email_is_post(self):
        """Email registration endpoint uses POST method."""
        from openssl_encrypt_server.modules.keyserver.routes import router

        for route in router.routes:
            if hasattr(route, "path") and route.path == "/register/email":
                assert "POST" in route.methods
                break

    def test_confirm_is_get(self):
        """Confirmation endpoint uses GET method."""
        from openssl_encrypt_server.modules.keyserver.routes import router

        for route in router.routes:
            if hasattr(route, "path") and route.path == "/confirm/{token}":
                assert "GET" in route.methods
                break

    def test_status_endpoint_exists(self):
        """The registration status polling endpoint is defined."""
        from openssl_encrypt_server.modules.keyserver.routes import router

        paths = [route.path for route in router.routes]
        assert "/register/status/{registration_id}" in paths

    def test_status_is_get(self):
        """Status endpoint uses GET method."""
        from openssl_encrypt_server.modules.keyserver.routes import router

        for route in router.routes:
            if hasattr(route, "path") and route.path == "/register/status/{registration_id}":
                assert "GET" in route.methods
                break


# ---------------------------------------------------------------------------
# HTML Rendering Tests
# ---------------------------------------------------------------------------

class TestConfirmationHtmlRendering:
    """Tests for browser-friendly HTML responses."""

    def test_confirmation_html_contains_client_id(self):
        """HTML confirmation page contains the client_id."""
        from openssl_encrypt_server.modules.keyserver.routes import _render_confirmation_html

        html = _render_confirmation_html("abc123def456")
        assert "abc123def456" in html

    def test_confirmation_html_has_copy_button(self):
        """HTML confirmation page has a copy-to-clipboard button."""
        from openssl_encrypt_server.modules.keyserver.routes import _render_confirmation_html

        html = _render_confirmation_html("abc123")
        assert "Copy to Clipboard" in html
        assert "copyClientId" in html

    def test_confirmation_html_escapes_client_id(self):
        """Client ID is HTML-escaped to prevent XSS."""
        from openssl_encrypt_server.modules.keyserver.routes import _render_confirmation_html

        html = _render_confirmation_html('<img onerror="alert(1)">')
        assert 'onerror="alert(1)"' not in html
        assert "&lt;img onerror=" in html

    def test_confirmation_html_is_valid_document(self):
        """HTML page is a complete document with proper structure."""
        from openssl_encrypt_server.modules.keyserver.routes import _render_confirmation_html

        html = _render_confirmation_html("test123")
        assert "<!DOCTYPE html>" in html
        assert "<html" in html
        assert "</html>" in html
        assert "Registration Confirmed" in html

    def test_error_html_expired_token(self):
        """HTML error page for expired token shows appropriate message."""
        from openssl_encrypt_server.modules.keyserver.routes import _render_error_html

        html = _render_error_html(410, "Confirmation link has expired. Please register again.")
        assert "Link Expired" in html
        assert "expired" in html.lower()

    def test_error_html_invalid_token(self):
        """HTML error page for invalid token shows appropriate message."""
        from openssl_encrypt_server.modules.keyserver.routes import _render_error_html

        html = _render_error_html(404, "Invalid confirmation token")
        assert "Invalid Link" in html

    def test_error_html_escapes_detail(self):
        """Error detail is HTML-escaped to prevent XSS."""
        from openssl_encrypt_server.modules.keyserver.routes import _render_error_html

        html = _render_error_html(400, '<script>alert("xss")</script>')
        assert "<script>" not in html
        assert "&lt;script&gt;" in html


# ---------------------------------------------------------------------------
# Finding #8 — SMTP TLS Verification Guardrails
# ---------------------------------------------------------------------------


class TestSmtpTlsHostnameOverride:
    """Tests for SMTP TLS hostname override (finding #8, LAN IP scenario)."""

    def test_settings_has_smtp_tls_hostname_field(self):
        """Settings must expose smtp_tls_hostname for TLS SNI override."""
        from openssl_encrypt_server.config import Settings

        assert hasattr(Settings, "model_fields")
        assert "smtp_tls_hostname" in Settings.model_fields

    def test_smtp_tls_hostname_defaults_to_none(self):
        """smtp_tls_hostname should default to None (use smtp_host)."""
        from openssl_encrypt_server.config import Settings

        fields = Settings.model_fields
        assert fields["smtp_tls_hostname"].default is None

    def test_email_service_accepts_tls_hostname(self):
        """EmailService constructor must accept smtp_tls_hostname parameter."""
        from openssl_encrypt_server.core.email import EmailService

        service = EmailService(
            smtp_host="192.168.1.50",
            smtp_port=2525,
            smtp_tls_hostname="mail.example.com",
            from_address="noreply@example.com",
        )
        assert service.smtp_tls_hostname == "mail.example.com"

    def test_email_service_tls_hostname_defaults_to_none(self):
        """EmailService smtp_tls_hostname defaults to None."""
        from openssl_encrypt_server.core.email import EmailService

        service = EmailService(
            smtp_host="smtp.example.com",
            smtp_port=587,
            from_address="noreply@example.com",
        )
        assert service.smtp_tls_hostname is None

    @pytest.mark.asyncio
    async def test_tls_hostname_sets_server_hostname_in_send(self):
        """When smtp_tls_hostname is set, _send_email passes server_hostname to aiosmtplib."""
        from openssl_encrypt_server.core.email import EmailService

        service = EmailService(
            smtp_host="192.168.1.50",
            smtp_port=2525,
            smtp_use_tls=True,
            smtp_verify_tls=True,
            smtp_tls_hostname="mail.example.com",
            from_address="noreply@example.com",
        )

        with patch("openssl_encrypt_server.core.email.aiosmtplib.send", new_callable=AsyncMock) as mock_send:
            await service._send_email("user@example.com", "Test", "<p>test</p>")

            mock_send.assert_called_once()
            call_kwargs = mock_send.call_args[1]
            assert call_kwargs.get("server_hostname") == "mail.example.com"
            # Should NOT disable verification
            if "tls_context" in call_kwargs:
                import ssl
                assert call_kwargs["tls_context"].check_hostname is not False

    @pytest.mark.asyncio
    async def test_no_tls_hostname_does_not_set_server_hostname(self):
        """When smtp_tls_hostname is None, server_hostname is not passed."""
        from openssl_encrypt_server.core.email import EmailService

        service = EmailService(
            smtp_host="smtp.example.com",
            smtp_port=587,
            smtp_use_tls=True,
            smtp_verify_tls=True,
            from_address="noreply@example.com",
        )

        with patch("openssl_encrypt_server.core.email.aiosmtplib.send", new_callable=AsyncMock) as mock_send:
            await service._send_email("user@example.com", "Test", "<p>test</p>")

            call_kwargs = mock_send.call_args[1]
            assert "server_hostname" not in call_kwargs


class TestSmtpTlsVerifyGuardrail:
    """Tests for SMTP_VERIFY_TLS=false requiring ALLOW_INSECURE_DEFAULTS (#8)."""

    def test_verify_tls_false_without_insecure_defaults_raises(self):
        """Disabling TLS verification without ALLOW_INSECURE_DEFAULTS must raise."""
        from openssl_encrypt_server.config import Settings, validate_config

        s = Settings(
            keyserver_token_secret="a" * 48,
            telemetry_token_secret="b" * 48,
            postgres_password="strong_password_here",
            keyserver_require_email_verification=True,
            smtp_host="mail.example.com",
            smtp_from_address="noreply@example.com",
            keyserver_base_url="https://keys.example.com",
            smtp_use_tls=True,
            smtp_verify_tls=False,
            allow_insecure_defaults=False,
        )
        with pytest.raises(ValueError, match="SMTP_VERIFY_TLS"):
            validate_config(s)

    def test_verify_tls_false_with_insecure_defaults_passes(self):
        """Disabling TLS verification with ALLOW_INSECURE_DEFAULTS should pass."""
        from openssl_encrypt_server.config import Settings, validate_config

        s = Settings(
            keyserver_token_secret="a" * 48,
            telemetry_token_secret="b" * 48,
            postgres_password="strong_password_here",
            keyserver_require_email_verification=True,
            smtp_host="mail.example.com",
            smtp_from_address="noreply@example.com",
            keyserver_base_url="https://keys.example.com",
            smtp_use_tls=True,
            smtp_verify_tls=False,
            allow_insecure_defaults=True,
        )
        # Should not raise
        validate_config(s)

    def test_verify_tls_true_does_not_require_insecure_defaults(self):
        """Normal TLS verification should not require ALLOW_INSECURE_DEFAULTS."""
        from openssl_encrypt_server.config import Settings, validate_config

        s = Settings(
            keyserver_token_secret="a" * 48,
            telemetry_token_secret="b" * 48,
            postgres_password="strong_password_here",
            keyserver_require_email_verification=True,
            smtp_host="mail.example.com",
            smtp_from_address="noreply@example.com",
            keyserver_base_url="https://keys.example.com",
            smtp_use_tls=True,
            smtp_verify_tls=True,
            allow_insecure_defaults=False,
        )
        # Should not raise
        validate_config(s)

    def test_verify_tls_false_logs_warning(self):
        """Disabling TLS verification should log a security warning."""
        from openssl_encrypt_server.config import Settings, validate_config

        s = Settings(
            keyserver_token_secret="a" * 48,
            telemetry_token_secret="b" * 48,
            postgres_password="strong_password_here",
            smtp_use_tls=True,
            smtp_verify_tls=False,
            allow_insecure_defaults=True,
        )
        import logging
        with patch.object(logging.getLogger("openssl_encrypt_server.config"), "warning") as mock_warn:
            validate_config(s)
            # Check that at least one warning mentions SMTP TLS
            smtp_warnings = [
                call for call in mock_warn.call_args_list
                if "SMTP" in str(call) and "TLS" in str(call)
            ]
            assert len(smtp_warnings) >= 1

    @pytest.mark.asyncio
    async def test_verify_tls_false_logs_per_send_warning(self):
        """Each send with verify_tls=False should log a warning."""
        from openssl_encrypt_server.core.email import EmailService

        service = EmailService(
            smtp_host="192.168.1.50",
            smtp_port=2525,
            smtp_use_tls=True,
            smtp_verify_tls=False,
            from_address="noreply@example.com",
        )

        with patch("openssl_encrypt_server.core.email.aiosmtplib.send", new_callable=AsyncMock):
            import logging
            with patch.object(logging.getLogger("openssl_encrypt_server.core.email"), "warning") as mock_warn:
                await service._send_email("user@example.com", "Test", "<p>test</p>")

                smtp_warnings = [
                    call for call in mock_warn.call_args_list
                    if "TLS" in str(call) and "verification" in str(call).lower()
                ]
                assert len(smtp_warnings) >= 1


class TestSmtpTlsHostnameInRoutes:
    """Verify routes pass smtp_tls_hostname to EmailService."""

    def test_routes_pass_tls_hostname_to_email_service(self):
        """Routes source code must pass smtp_tls_hostname when constructing EmailService."""
        from pathlib import Path
        routes_path = Path(__file__).parent.parent / "modules" / "keyserver" / "routes.py"
        with open(routes_path) as f:
            source = f.read()
        assert "smtp_tls_hostname" in source, \
            "routes.py must pass smtp_tls_hostname to EmailService"


# ---------------------------------------------------------------------------
# Finding #9 — Race Condition in Email Registration
# ---------------------------------------------------------------------------


class TestRegistrationRaceCondition:
    """Tests for IntegrityError handling in create_pending_registration (#9)."""

    @pytest.fixture
    def mock_db(self):
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.execute = AsyncMock()
        db.rollback = AsyncMock()
        return db

    @pytest.fixture
    def service(self, mock_db):
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService
        return KeyserverService(mock_db)

    @pytest.mark.asyncio
    async def test_integrity_error_returns_opaque_response(self, service, mock_db):
        """Concurrent duplicate email insert must return opaque 202, not 500."""
        from sqlalchemy.exc import IntegrityError

        # First execute: no existing client
        # Second execute: no existing pending
        mock_result_none = MagicMock()
        mock_result_none.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result_none

        # commit raises IntegrityError (concurrent insert won the race)
        mock_db.commit.side_effect = IntegrityError(
            "duplicate key", params=None, orig=Exception("unique constraint")
        )

        mock_email_service = AsyncMock()

        # Should NOT raise — should return opaque response
        result = await service.create_pending_registration(
            "user@example.com", "https://keys.example.com", mock_email_service, "test_secret"
        )

        assert "registration_id" in result
        mock_db.rollback.assert_called_once()

    @pytest.mark.asyncio
    async def test_integrity_error_does_not_send_confirmation_email(self, service, mock_db):
        """On IntegrityError, confirmation email must NOT be sent."""
        from sqlalchemy.exc import IntegrityError

        mock_result_none = MagicMock()
        mock_result_none.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result_none
        mock_db.commit.side_effect = IntegrityError(
            "duplicate key", params=None, orig=Exception("unique constraint")
        )

        mock_email_service = AsyncMock()

        await service.create_pending_registration(
            "user@example.com", "https://keys.example.com", mock_email_service, "test_secret"
        )

        mock_email_service.send_confirmation_email.assert_not_called()

    @pytest.mark.asyncio
    async def test_service_code_catches_integrity_error(self):
        """The service source must handle IntegrityError in create_pending_registration."""
        from pathlib import Path
        service_path = Path(__file__).parent.parent / "modules" / "keyserver" / "service.py"
        with open(service_path) as f:
            source = f.read()
        idx = source.index("async def create_pending_registration")
        # Find the next method
        next_method = source.index("\n    async def ", idx + 1)
        method_body = source[idx:next_method]
        assert "IntegrityError" in method_body, \
            "create_pending_registration must catch IntegrityError for race condition handling"
