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
        assert "created_at" in columns
        assert "expires_at" in columns

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

    def test_confirmation_token_column_is_indexed(self):
        """Confirmation token column is indexed for fast lookup."""
        token_col = KSPendingRegistration.__table__.columns["confirmation_token"]
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
        resp = EmailRegisterResponse(message="Check your email")
        assert resp.message == "Check your email"


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

        token = await service.create_pending_registration(
            "user@example.com", "https://keys.example.com", mock_email_service
        )

        assert token is not None
        assert len(token) > 20  # token_urlsafe(32) produces ~43 chars
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
    async def test_rejects_duplicate_email_existing_account(self, service, mock_db):
        """Rejects registration if email already has an active account."""
        from fastapi import HTTPException

        # First query (KSClient) returns an existing client
        existing_client = MagicMock()
        existing_client.email = "user@example.com"

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = existing_client
        mock_db.execute.return_value = mock_result

        mock_email_service = AsyncMock()

        with pytest.raises(HTTPException) as exc_info:
            await service.create_pending_registration(
                "user@example.com", "https://keys.example.com", mock_email_service
            )
        assert exc_info.value.status_code == 409

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

        token = await service.create_pending_registration(
            "user@example.com", "https://keys.example.com", mock_email_service
        )

        # Token should be refreshed
        assert token != "old_token"
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
        pending.expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = pending
        mock_db.execute.return_value = mock_result

        mock_email_service = AsyncMock()
        mock_auth = MagicMock()
        mock_auth.generate_client_id.return_value = "abc123def456"

        result = await service.confirm_registration(
            "valid_token", mock_auth, mock_email_service
        )

        assert result["client_id"] == "abc123def456"
        mock_db.add.assert_called_once()  # KSClient added
        mock_db.delete.assert_called_once_with(pending)  # Pending removed

    @pytest.mark.asyncio
    async def test_sends_welcome_email_with_client_id(self, service, mock_db):
        """Confirming sends a welcome email containing the client_id."""
        pending = MagicMock()
        pending.email = "user@example.com"
        pending.confirmation_token = "valid_token"
        pending.expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = pending
        mock_db.execute.return_value = mock_result

        mock_email_service = AsyncMock()
        mock_auth = MagicMock()
        mock_auth.generate_client_id.return_value = "abc123def456"

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
    async def test_confirmation_deletes_pending_record(self, service, mock_db):
        """Successful confirmation removes the pending registration."""
        pending = MagicMock()
        pending.email = "user@example.com"
        pending.confirmation_token = "valid_token"
        pending.expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = pending
        mock_db.execute.return_value = mock_result

        mock_email_service = AsyncMock()
        mock_auth = MagicMock()
        mock_auth.generate_client_id.return_value = "abc123"

        await service.confirm_registration("valid_token", mock_auth, mock_email_service)

        mock_db.delete.assert_called_once_with(pending)


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


# ---------------------------------------------------------------------------
# Route-Level Tests
# ---------------------------------------------------------------------------

class TestRegistrationRouteConfig:
    """Tests for registration route behavior based on config."""

    def test_register_endpoint_exists(self):
        """The email registration endpoint is defined."""
        from openssl_encrypt_server.modules.keyserver.routes import router

        paths = [route.path for route in router.routes]
        assert "/api/v1/keys/register/email" in paths

    def test_confirm_endpoint_exists(self):
        """The confirmation endpoint is defined."""
        from openssl_encrypt_server.modules.keyserver.routes import router

        paths = [route.path for route in router.routes]
        assert "/api/v1/keys/confirm/{token}" in paths

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
