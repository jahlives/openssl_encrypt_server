#!/usr/bin/env python3
"""
Unit tests for Proof of Possession (PoP) challenge-response upload flow.

Tests the PoP verification that ensures a public key can only be uploaded
by a client that proves real-time access to the corresponding private key.

Upload flow with PoP:
1. Client → POST /api/v1/keys/challenge  (auth required)
            ← { challenge_id, nonce, expires_at }
2. Client signs: b"POP:" + nonce_hex.encode("ascii") + b":" + fingerprint.encode("utf-8")
   with ML-DSA private key → base64 pop_signature
3. Client → POST /api/v1/keys/  (auth required)
            body includes: existing bundle fields + challenge_id + pop_signature
4. Server: atomic challenge consumption → PoP verify → bundle verify → store

Covers: model structure, schemas, verification function, service logic (generate,
cleanup, upload PoP validation), route inspection, migration file.
"""

import asyncio
import base64
import inspect
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run_async(coro):
    """Run an async coroutine synchronously (no pytest-asyncio required)."""
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Model Tests
# ---------------------------------------------------------------------------


class TestKSChallengeModel:
    """Tests for the KSChallenge database model."""

    def test_table_name(self):
        """Table uses ks_ prefix per project convention."""
        from openssl_encrypt_server.modules.keyserver.models import KSChallenge
        assert KSChallenge.__tablename__ == "ks_challenges"

    def test_model_has_required_columns(self):
        """KSChallenge model has all required columns."""
        from openssl_encrypt_server.modules.keyserver.models import KSChallenge
        columns = {c.name for c in KSChallenge.__table__.columns}
        assert "id" in columns
        assert "nonce" in columns
        assert "client_id" in columns
        assert "fingerprint_hint" in columns
        assert "created_at" in columns
        assert "expires_at" in columns
        assert "used" in columns

    def test_nonce_column_is_unique(self):
        """Nonce column has unique constraint to prevent collisions being exploitable."""
        from openssl_encrypt_server.modules.keyserver.models import KSChallenge
        col = KSChallenge.__table__.columns["nonce"]
        assert col.unique is True

    def test_nonce_column_length(self):
        """Nonce column is VARCHAR(64) to hold 32-byte hex string."""
        from openssl_encrypt_server.modules.keyserver.models import KSChallenge
        col = KSChallenge.__table__.columns["nonce"]
        assert col.type.length == 64

    def test_client_id_column_is_indexed(self):
        """client_id column is indexed for fast cleanup queries."""
        from openssl_encrypt_server.modules.keyserver.models import KSChallenge
        col = KSChallenge.__table__.columns["client_id"]
        assert col.index is True

    def test_fingerprint_hint_is_nullable(self):
        """fingerprint_hint is nullable — it is a logging hint, not a security field."""
        from openssl_encrypt_server.modules.keyserver.models import KSChallenge
        col = KSChallenge.__table__.columns["fingerprint_hint"]
        assert col.nullable is True

    def test_used_column_default_false(self):
        """used column defaults to False (challenge is fresh on creation)."""
        from openssl_encrypt_server.modules.keyserver.models import KSChallenge
        col = KSChallenge.__table__.columns["used"]
        assert col.default.arg is False

    def test_used_column_not_nullable(self):
        """used column is NOT NULL — ambiguous null would allow replay."""
        from openssl_encrypt_server.modules.keyserver.models import KSChallenge
        col = KSChallenge.__table__.columns["used"]
        assert col.nullable is False

    def test_expires_at_column_not_nullable(self):
        """expires_at is NOT NULL — every challenge must have an expiry."""
        from openssl_encrypt_server.modules.keyserver.models import KSChallenge
        col = KSChallenge.__table__.columns["expires_at"]
        assert col.nullable is False

    def test_expires_at_is_indexed(self):
        """expires_at is indexed for efficient cleanup queries."""
        from openssl_encrypt_server.modules.keyserver.models import KSChallenge
        col = KSChallenge.__table__.columns["expires_at"]
        assert col.index is True

    def test_id_is_uuid_primary_key(self):
        """id column is a UUID primary key."""
        from openssl_encrypt_server.modules.keyserver.models import KSChallenge
        col = KSChallenge.__table__.columns["id"]
        assert col.primary_key is True

    def test_repr_contains_class_name(self):
        """KSChallenge __repr__ method references the class name."""
        from openssl_encrypt_server.modules.keyserver.models import KSChallenge
        assert "KSChallenge" in inspect.getsource(KSChallenge.__repr__)


# ---------------------------------------------------------------------------
# Schema Tests
# ---------------------------------------------------------------------------


class TestChallengeRequestSchema:
    """Tests for ChallengeRequest schema."""

    def test_schema_is_importable(self):
        """ChallengeRequest schema exists and is importable."""
        from openssl_encrypt_server.modules.keyserver.schemas import ChallengeRequest
        assert ChallengeRequest is not None

    def test_fingerprint_is_optional(self):
        """Fingerprint field is optional — it is a logging hint only."""
        from openssl_encrypt_server.modules.keyserver.schemas import ChallengeRequest
        req = ChallengeRequest()
        assert req.fingerprint is None

    def test_fingerprint_can_be_provided(self):
        """Fingerprint hint is accepted when provided."""
        from openssl_encrypt_server.modules.keyserver.schemas import ChallengeRequest
        fp = "3a:4b:5c:6d"
        req = ChallengeRequest(fingerprint=fp)
        assert req.fingerprint == fp

    def test_fingerprint_max_length_100(self):
        """Fingerprint field has max_length=100 constraint."""
        from openssl_encrypt_server.modules.keyserver.schemas import ChallengeRequest
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            ChallengeRequest(fingerprint="a" * 101)


class TestChallengeResponseSchema:
    """Tests for ChallengeResponse schema."""

    def test_schema_is_importable(self):
        """ChallengeResponse schema exists and is importable."""
        from openssl_encrypt_server.modules.keyserver.schemas import ChallengeResponse
        assert ChallengeResponse is not None

    def test_required_fields_present(self):
        """ChallengeResponse requires challenge_id, nonce, and expires_at."""
        from openssl_encrypt_server.modules.keyserver.schemas import ChallengeResponse
        resp = ChallengeResponse(
            challenge_id=str(uuid.uuid4()),
            nonce="a" * 64,
            expires_at="2026-03-26T10:00:00+00:00",
        )
        assert resp.challenge_id is not None
        assert resp.nonce is not None
        assert resp.expires_at is not None

    def test_challenge_id_is_string(self):
        """challenge_id is a plain string (UUID serialized as string)."""
        from openssl_encrypt_server.modules.keyserver.schemas import ChallengeResponse
        resp = ChallengeResponse(
            challenge_id=str(uuid.uuid4()),
            nonce="b" * 64,
            expires_at="2026-03-26T10:00:00+00:00",
        )
        assert isinstance(resp.challenge_id, str)


class TestKeyUploadWithPoPSchema:
    """Tests for KeyUploadWithPoP schema."""

    def _valid_data(self):
        return {
            "name": "Test User",
            "email": None,
            "fingerprint": "3a:4b:5c",
            "created_at": "2026-03-26T00:00:00Z",
            "encryption_public_key": "dGVzdA==",
            "signing_public_key": "dGVzdA==",
            "encryption_algorithm": "ML-KEM-768",
            "signing_algorithm": "ML-DSA-65",
            "self_signature": "dGVzdA==",
            "challenge_id": str(uuid.uuid4()),
            "pop_signature": "dGVzdA==",
        }

    def test_schema_is_importable(self):
        """KeyUploadWithPoP schema exists and is importable."""
        from openssl_encrypt_server.modules.keyserver.schemas import KeyUploadWithPoP
        assert KeyUploadWithPoP is not None

    def test_inherits_from_key_bundle_schema(self):
        """KeyUploadWithPoP inherits from KeyBundleSchema (no field duplication)."""
        from openssl_encrypt_server.modules.keyserver.schemas import (
            KeyBundleSchema,
            KeyUploadWithPoP,
        )
        assert issubclass(KeyUploadWithPoP, KeyBundleSchema)

    def test_challenge_id_is_required(self):
        """challenge_id is a required field — upload cannot proceed without it."""
        from openssl_encrypt_server.modules.keyserver.schemas import KeyUploadWithPoP
        from pydantic import ValidationError
        data = self._valid_data()
        del data["challenge_id"]
        with pytest.raises(ValidationError):
            KeyUploadWithPoP(**data)

    def test_pop_signature_is_required(self):
        """pop_signature is a required field."""
        from openssl_encrypt_server.modules.keyserver.schemas import KeyUploadWithPoP
        from pydantic import ValidationError
        data = self._valid_data()
        del data["pop_signature"]
        with pytest.raises(ValidationError):
            KeyUploadWithPoP(**data)

    def test_valid_data_is_accepted(self):
        """Complete valid KeyUploadWithPoP data is accepted without error."""
        from openssl_encrypt_server.modules.keyserver.schemas import KeyUploadWithPoP
        data = self._valid_data()
        bundle = KeyUploadWithPoP(**data)
        assert bundle.challenge_id == data["challenge_id"]
        assert bundle.pop_signature == data["pop_signature"]

    def test_algorithm_whitelist_still_enforced(self):
        """Algorithm whitelist inherited from KeyBundleSchema is still applied."""
        from openssl_encrypt_server.modules.keyserver.schemas import KeyUploadWithPoP
        from pydantic import ValidationError
        data = self._valid_data()
        data["signing_algorithm"] = "RSA-2048"
        with pytest.raises(ValidationError):
            KeyUploadWithPoP(**data)

    def test_model_dump_can_exclude_pop_fields(self):
        """
        model_dump(exclude=...) strips PoP fields for bundle signature verification.

        This is critical: challenge_id/pop_signature must NOT appear in the
        message passed to verify_bundle_signature, or the signature check will
        fail for every upload.
        """
        from openssl_encrypt_server.modules.keyserver.schemas import KeyUploadWithPoP
        data = self._valid_data()
        bundle = KeyUploadWithPoP(**data)
        bundle_dict = bundle.model_dump(exclude={"challenge_id", "pop_signature"})
        assert "challenge_id" not in bundle_dict
        assert "pop_signature" not in bundle_dict
        # Core bundle fields are preserved
        assert "self_signature" in bundle_dict
        assert "fingerprint" in bundle_dict
        assert "name" in bundle_dict


# ---------------------------------------------------------------------------
# Verification Tests
# ---------------------------------------------------------------------------


class TestVerifyPopSignature:
    """Tests for verify_pop_signature function."""

    def test_function_is_importable(self):
        """verify_pop_signature is importable from verification module."""
        from openssl_encrypt_server.modules.keyserver.verification import verify_pop_signature
        assert callable(verify_pop_signature)

    def test_raises_when_liboqs_unavailable(self):
        """Raises VerificationError immediately when liboqs is not available."""
        from openssl_encrypt_server.modules.keyserver.verification import (
            VerificationError,
            verify_pop_signature,
        )
        with patch(
            "openssl_encrypt_server.modules.keyserver.verification.LIBOQS_AVAILABLE", False
        ):
            with pytest.raises(VerificationError, match="liboqs not available"):
                verify_pop_signature(
                    nonce_hex="a" * 64,
                    fingerprint="3a:4b:5c",
                    pop_signature_b64=base64.b64encode(b"sig").decode(),
                    signing_public_key_b64=base64.b64encode(b"pubkey").decode(),
                    signing_algorithm="ML-DSA-65",
                )

    def test_raises_value_error_on_unsupported_algorithm(self):
        """Raises ValueError for algorithms outside the ML-DSA whitelist."""
        from openssl_encrypt_server.modules.keyserver.verification import verify_pop_signature
        with patch(
            "openssl_encrypt_server.modules.keyserver.verification.LIBOQS_AVAILABLE", True
        ):
            with pytest.raises(ValueError, match="Unsupported signing algorithm"):
                verify_pop_signature(
                    nonce_hex="a" * 64,
                    fingerprint="3a:4b:5c",
                    pop_signature_b64=base64.b64encode(b"sig").decode(),
                    signing_public_key_b64=base64.b64encode(b"pubkey").decode(),
                    signing_algorithm="RSA-2048",
                )

    def test_canonical_message_uses_hex_string_nonce_not_raw_bytes(self):
        """
        PoP canonical message encodes the nonce as its hex string representation.

        The message MUST be:
            b"POP:" + nonce_hex.encode("ascii") + b":" + fingerprint.encode("utf-8")

        NOT:
            b"POP:" + bytes.fromhex(nonce_hex) + b":" + fingerprint.encode("utf-8")

        This choice must match the client-side construction exactly; it is the
        protocol contract between server and client.
        """
        from openssl_encrypt_server.modules.keyserver.verification import verify_pop_signature

        nonce_hex = "a" * 64
        fingerprint = "3a:4b:5c"
        expected_message = (
            b"POP:" + nonce_hex.encode("ascii") + b":" + fingerprint.encode("utf-8")
        )

        captured_messages = []

        mock_verifier = MagicMock()
        def capture_verify(message, sig, pubkey):
            captured_messages.append(message)
            return True
        mock_verifier.verify.side_effect = capture_verify

        mock_oqs = MagicMock()
        mock_oqs.Signature.return_value = mock_verifier

        with patch(
            "openssl_encrypt_server.modules.keyserver.verification.LIBOQS_AVAILABLE", True
        ):
            with patch(
                "openssl_encrypt_server.modules.keyserver.verification.oqs", mock_oqs
            ):
                verify_pop_signature(
                    nonce_hex=nonce_hex,
                    fingerprint=fingerprint,
                    pop_signature_b64=base64.b64encode(b"sig").decode(),
                    signing_public_key_b64=base64.b64encode(b"pubkey").decode(),
                    signing_algorithm="ML-DSA-65",
                )

        assert len(captured_messages) == 1
        assert captured_messages[0] == expected_message

    def test_ml_dsa_65_maps_to_dilithium3(self):
        """ML-DSA-65 maps to Dilithium3 in liboqs algorithm naming."""
        from openssl_encrypt_server.modules.keyserver.verification import verify_pop_signature

        mock_oqs = MagicMock()
        mock_verifier = MagicMock()
        mock_verifier.verify.return_value = True
        mock_oqs.Signature.return_value = mock_verifier

        with patch(
            "openssl_encrypt_server.modules.keyserver.verification.LIBOQS_AVAILABLE", True
        ):
            with patch(
                "openssl_encrypt_server.modules.keyserver.verification.oqs", mock_oqs
            ):
                verify_pop_signature(
                    nonce_hex="a" * 64,
                    fingerprint="fp",
                    pop_signature_b64=base64.b64encode(b"sig").decode(),
                    signing_public_key_b64=base64.b64encode(b"pubkey").decode(),
                    signing_algorithm="ML-DSA-65",
                )

        mock_oqs.Signature.assert_called_once_with("Dilithium3")

    def test_ml_dsa_44_maps_to_dilithium2(self):
        """ML-DSA-44 maps to Dilithium2 in liboqs."""
        from openssl_encrypt_server.modules.keyserver.verification import verify_pop_signature

        mock_oqs = MagicMock()
        mock_verifier = MagicMock()
        mock_verifier.verify.return_value = True
        mock_oqs.Signature.return_value = mock_verifier

        with patch(
            "openssl_encrypt_server.modules.keyserver.verification.LIBOQS_AVAILABLE", True
        ):
            with patch(
                "openssl_encrypt_server.modules.keyserver.verification.oqs", mock_oqs
            ):
                verify_pop_signature(
                    nonce_hex="a" * 64,
                    fingerprint="fp",
                    pop_signature_b64=base64.b64encode(b"sig").decode(),
                    signing_public_key_b64=base64.b64encode(b"pubkey").decode(),
                    signing_algorithm="ML-DSA-44",
                )

        mock_oqs.Signature.assert_called_once_with("Dilithium2")

    def test_ml_dsa_87_maps_to_dilithium5(self):
        """ML-DSA-87 maps to Dilithium5 in liboqs."""
        from openssl_encrypt_server.modules.keyserver.verification import verify_pop_signature

        mock_oqs = MagicMock()
        mock_verifier = MagicMock()
        mock_verifier.verify.return_value = True
        mock_oqs.Signature.return_value = mock_verifier

        with patch(
            "openssl_encrypt_server.modules.keyserver.verification.LIBOQS_AVAILABLE", True
        ):
            with patch(
                "openssl_encrypt_server.modules.keyserver.verification.oqs", mock_oqs
            ):
                verify_pop_signature(
                    nonce_hex="a" * 64,
                    fingerprint="fp",
                    pop_signature_b64=base64.b64encode(b"sig").decode(),
                    signing_public_key_b64=base64.b64encode(b"pubkey").decode(),
                    signing_algorithm="ML-DSA-87",
                )

        mock_oqs.Signature.assert_called_once_with("Dilithium5")

    def test_raises_verification_error_when_signature_invalid(self):
        """Raises VerificationError when liboqs returns False for signature."""
        from openssl_encrypt_server.modules.keyserver.verification import (
            VerificationError,
            verify_pop_signature,
        )

        mock_oqs = MagicMock()
        mock_verifier = MagicMock()
        mock_verifier.verify.return_value = False  # Invalid signature
        mock_oqs.Signature.return_value = mock_verifier

        with patch(
            "openssl_encrypt_server.modules.keyserver.verification.LIBOQS_AVAILABLE", True
        ):
            with patch(
                "openssl_encrypt_server.modules.keyserver.verification.oqs", mock_oqs
            ):
                with pytest.raises(VerificationError):
                    verify_pop_signature(
                        nonce_hex="a" * 64,
                        fingerprint="fp",
                        pop_signature_b64=base64.b64encode(b"wrong").decode(),
                        signing_public_key_b64=base64.b64encode(b"pubkey").decode(),
                        signing_algorithm="ML-DSA-65",
                    )

    def test_returns_true_on_valid_signature(self):
        """Returns True when liboqs confirms the signature is valid."""
        from openssl_encrypt_server.modules.keyserver.verification import verify_pop_signature

        mock_oqs = MagicMock()
        mock_verifier = MagicMock()
        mock_verifier.verify.return_value = True
        mock_oqs.Signature.return_value = mock_verifier

        with patch(
            "openssl_encrypt_server.modules.keyserver.verification.LIBOQS_AVAILABLE", True
        ):
            with patch(
                "openssl_encrypt_server.modules.keyserver.verification.oqs", mock_oqs
            ):
                result = verify_pop_signature(
                    nonce_hex="a" * 64,
                    fingerprint="fp",
                    pop_signature_b64=base64.b64encode(b"valid").decode(),
                    signing_public_key_b64=base64.b64encode(b"pubkey").decode(),
                    signing_algorithm="ML-DSA-65",
                )

        assert result is True

    def test_wraps_liboqs_exceptions_in_verification_error(self):
        """Unexpected exceptions from liboqs are wrapped in VerificationError."""
        from openssl_encrypt_server.modules.keyserver.verification import (
            VerificationError,
            verify_pop_signature,
        )

        mock_oqs = MagicMock()
        mock_verifier = MagicMock()
        mock_verifier.verify.side_effect = RuntimeError("liboqs internal crash")
        mock_oqs.Signature.return_value = mock_verifier

        with patch(
            "openssl_encrypt_server.modules.keyserver.verification.LIBOQS_AVAILABLE", True
        ):
            with patch(
                "openssl_encrypt_server.modules.keyserver.verification.oqs", mock_oqs
            ):
                with pytest.raises(VerificationError):
                    verify_pop_signature(
                        nonce_hex="a" * 64,
                        fingerprint="fp",
                        pop_signature_b64=base64.b64encode(b"sig").decode(),
                        signing_public_key_b64=base64.b64encode(b"pubkey").decode(),
                        signing_algorithm="ML-DSA-65",
                    )


# ---------------------------------------------------------------------------
# Service: generate_challenge
# ---------------------------------------------------------------------------


class TestGenerateChallenge:
    """Tests for KeyserverService.generate_challenge."""

    def _make_db(self):
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock()
        return db

    def test_method_exists_on_service(self):
        """generate_challenge method exists on KeyserverService."""
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService
        assert hasattr(KeyserverService, "generate_challenge")

    def test_method_is_async(self):
        """generate_challenge is an async method."""
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService
        assert inspect.iscoroutinefunction(KeyserverService.generate_challenge)

    def test_generates_64_char_hex_nonce(self):
        """Generated nonce is 64 lowercase hex characters (32 random bytes)."""
        from openssl_encrypt_server.modules.keyserver.models import KSChallenge
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService

        db = self._make_db()
        captured = []

        def capture_add(obj):
            if isinstance(obj, KSChallenge):
                captured.append(obj)

        db.add.side_effect = capture_add

        run_async(KeyserverService(db).generate_challenge(client_id="client123"))

        assert len(captured) == 1
        nonce = captured[0].nonce
        assert len(nonce) == 64
        assert all(c in "0123456789abcdef" for c in nonce)

    def test_expires_in_10_minutes_by_default(self):
        """Challenge expires 10 minutes after creation when ttl_minutes not specified."""
        from openssl_encrypt_server.modules.keyserver.models import KSChallenge
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService

        db = self._make_db()
        captured = []

        def capture_add(obj):
            if isinstance(obj, KSChallenge):
                captured.append(obj)

        db.add.side_effect = capture_add

        before = datetime.now(timezone.utc)
        run_async(KeyserverService(db).generate_challenge(client_id="client123"))
        after = datetime.now(timezone.utc)

        challenge = captured[0]
        assert before + timedelta(minutes=10) <= challenge.expires_at <= after + timedelta(minutes=10)

    def test_ttl_is_configurable(self):
        """Challenge TTL is configurable via ttl_minutes parameter."""
        from openssl_encrypt_server.modules.keyserver.models import KSChallenge
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService

        db = self._make_db()
        captured = []

        def capture_add(obj):
            if isinstance(obj, KSChallenge):
                captured.append(obj)

        db.add.side_effect = capture_add

        before = datetime.now(timezone.utc)
        run_async(KeyserverService(db).generate_challenge(client_id="client123", ttl_minutes=5))
        after = datetime.now(timezone.utc)

        challenge = captured[0]
        assert before + timedelta(minutes=5) <= challenge.expires_at <= after + timedelta(minutes=5)

    def test_stores_client_id(self):
        """Challenge is stored with the requesting client's client_id."""
        from openssl_encrypt_server.modules.keyserver.models import KSChallenge
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService

        db = self._make_db()
        captured = []

        def capture_add(obj):
            if isinstance(obj, KSChallenge):
                captured.append(obj)

        db.add.side_effect = capture_add

        run_async(KeyserverService(db).generate_challenge(client_id="myclient42"))

        assert captured[0].client_id == "myclient42"

    def test_stores_fingerprint_hint_when_provided(self):
        """Fingerprint hint is stored for operator log visibility."""
        from openssl_encrypt_server.modules.keyserver.models import KSChallenge
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService

        db = self._make_db()
        captured = []

        def capture_add(obj):
            if isinstance(obj, KSChallenge):
                captured.append(obj)

        db.add.side_effect = capture_add

        run_async(
            KeyserverService(db).generate_challenge(
                client_id="client123",
                fingerprint_hint="3a:4b:5c",
            )
        )

        assert captured[0].fingerprint_hint == "3a:4b:5c"

    def test_returns_challenge_id_nonce_expires_at(self):
        """Return value contains challenge_id, nonce, and expires_at keys."""
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService

        db = self._make_db()
        challenge_uuid = uuid.uuid4()

        async def mock_refresh(obj):
            obj.id = challenge_uuid

        db.refresh.side_effect = mock_refresh

        result = run_async(KeyserverService(db).generate_challenge(client_id="client123"))

        assert "challenge_id" in result
        assert "nonce" in result
        assert "expires_at" in result
        assert result["challenge_id"] == str(challenge_uuid)

    def test_nonces_are_unique_across_calls(self):
        """Each call generates a cryptographically unique nonce."""
        from openssl_encrypt_server.modules.keyserver.models import KSChallenge
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService

        db = self._make_db()
        captured = []

        def capture_add(obj):
            if isinstance(obj, KSChallenge):
                captured.append(obj)

        db.add.side_effect = capture_add

        for _ in range(10):
            run_async(KeyserverService(db).generate_challenge(client_id="client123"))

        nonces = {c.nonce for c in captured}
        assert len(nonces) == 10


# ---------------------------------------------------------------------------
# Service: cleanup_expired_challenges
# ---------------------------------------------------------------------------


class TestCleanupExpiredChallenges:
    """Tests for KeyserverService.cleanup_expired_challenges."""

    def test_method_exists_on_service(self):
        """cleanup_expired_challenges method exists on KeyserverService."""
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService
        assert hasattr(KeyserverService, "cleanup_expired_challenges")

    def test_method_is_async(self):
        """cleanup_expired_challenges is an async method."""
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService
        assert inspect.iscoroutinefunction(KeyserverService.cleanup_expired_challenges)

    def test_returns_deleted_count(self):
        """Returns the number of records deleted."""
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService

        db = AsyncMock()
        mock_result = MagicMock()
        mock_result.rowcount = 7
        db.execute = AsyncMock(return_value=mock_result)
        db.commit = AsyncMock()

        count = run_async(KeyserverService(db).cleanup_expired_challenges())

        assert count == 7

    def test_executes_delete_statement(self):
        """cleanup_expired_challenges executes a DELETE SQL statement."""
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService

        db = AsyncMock()
        mock_result = MagicMock()
        mock_result.rowcount = 0
        db.execute = AsyncMock(return_value=mock_result)
        db.commit = AsyncMock()

        run_async(KeyserverService(db).cleanup_expired_challenges())

        db.execute.assert_called_once()

    def test_cleanup_called_opportunistically_from_generate_challenge(self):
        """
        cleanup_expired_challenges is called from generate_challenge (lazy cleanup).

        This prevents unbounded table growth without requiring a background scheduler.
        """
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService

        source = inspect.getsource(KeyserverService.generate_challenge)
        assert "cleanup_expired_challenges" in source


# ---------------------------------------------------------------------------
# Service: upload_key with PoP validation
# ---------------------------------------------------------------------------


class TestUploadKeyWithPoP:
    """Tests for PoP validation in KeyserverService.upload_key."""

    def test_upload_key_accepts_key_upload_with_pop_schema(self):
        """upload_key type annotation uses KeyUploadWithPoP (not KeyBundleSchema)."""
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService

        source = inspect.getsource(KeyserverService.upload_key)
        assert "KeyUploadWithPoP" in source

    def test_upload_key_uses_atomic_challenge_consumption(self):
        """
        upload_key uses an atomic UPDATE...WHERE...RETURNING pattern to consume
        the challenge in a single SQL statement, preventing TOCTOU race conditions.
        """
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService

        source = inspect.getsource(KeyserverService.upload_key)
        # Must use SQLAlchemy update with .returning() for atomic consumption
        assert "sa_update" in source or "update(" in source
        assert ".returning(" in source or "returning(" in source

    def test_pop_verification_before_bundle_verification(self):
        """
        PoP verification runs before bundle self-signature verification.

        This ordering is important: fail fast on PoP so a stolen public bundle
        cannot be probed for validity before the PoP is checked.
        """
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService

        source = inspect.getsource(KeyserverService.upload_key)
        pop_pos = source.find("verify_pop_signature")
        bundle_pos = source.find("verify_bundle_signature")
        assert pop_pos != -1, "verify_pop_signature not found in upload_key"
        assert bundle_pos != -1, "verify_bundle_signature not found in upload_key"
        assert pop_pos < bundle_pos, "PoP verification must precede bundle verification"

    def test_upload_key_excludes_pop_fields_from_bundle_dict(self):
        """
        bundle.model_dump(exclude={"challenge_id", "pop_signature"}) is used
        so that PoP fields don't appear in the reconstructed bundle message
        passed to verify_bundle_signature.
        """
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService

        source = inspect.getsource(KeyserverService.upload_key)
        assert "challenge_id" in source
        assert "pop_signature" in source
        assert "exclude" in source

    def test_invalid_challenge_uuid_returns_400(self):
        """Invalid challenge_id format raises 400 immediately."""
        from fastapi import HTTPException
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService

        db = AsyncMock()
        db.execute = AsyncMock()
        db.commit = AsyncMock()
        service = KeyserverService(db)

        bundle = MagicMock()
        bundle.challenge_id = "not-a-uuid-at-all"
        bundle.fingerprint = "3a:4b"
        bundle.name = "Test"
        bundle.signing_public_key = base64.b64encode(b"pubkey").decode()
        bundle.signing_algorithm = "ML-DSA-65"
        bundle.pop_signature = base64.b64encode(b"sig").decode()

        with pytest.raises(HTTPException) as exc_info:
            run_async(service.upload_key("client123", bundle))

        assert exc_info.value.status_code == 400

    def test_challenge_not_found_expired_or_used_returns_400(self):
        """
        When atomic UPDATE returns no row (challenge not found / expired / used /
        wrong client), raises 400.
        """
        from fastapi import HTTPException
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService

        db = AsyncMock()
        mock_result = MagicMock()
        mock_result.fetchone.return_value = None  # Nothing matched the WHERE clause
        db.execute = AsyncMock(return_value=mock_result)
        db.commit = AsyncMock()

        service = KeyserverService(db)

        bundle = MagicMock()
        bundle.challenge_id = str(uuid.uuid4())
        bundle.fingerprint = "3a:4b"
        bundle.name = "Test"
        bundle.signing_public_key = base64.b64encode(b"pubkey").decode()
        bundle.signing_algorithm = "ML-DSA-65"
        bundle.pop_signature = base64.b64encode(b"sig").decode()

        with pytest.raises(HTTPException) as exc_info:
            run_async(service.upload_key("client123", bundle))

        assert exc_info.value.status_code == 400

    def test_challenge_error_message_is_generic(self):
        """
        The 400 error for invalid challenge does not reveal whether the
        challenge was not found vs expired vs owned by another client.
        (No enumeration of challenge ownership.)
        """
        from fastapi import HTTPException
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService

        db = AsyncMock()
        mock_result = MagicMock()
        mock_result.fetchone.return_value = None
        db.execute = AsyncMock(return_value=mock_result)
        db.commit = AsyncMock()

        service = KeyserverService(db)

        bundle = MagicMock()
        bundle.challenge_id = str(uuid.uuid4())
        bundle.fingerprint = "3a:4b"
        bundle.name = "Test"
        bundle.signing_public_key = base64.b64encode(b"pubkey").decode()
        bundle.signing_algorithm = "ML-DSA-65"
        bundle.pop_signature = base64.b64encode(b"sig").decode()

        with pytest.raises(HTTPException) as exc_info:
            run_async(service.upload_key("client123", bundle))

        detail = exc_info.value.detail.lower()
        # Must mention the generic outcome, not specific reason
        assert any(kw in detail for kw in ("not found", "expired", "used", "invalid"))

    def test_pop_verification_failure_returns_400(self):
        """Failed PoP signature verification raises 400."""
        from fastapi import HTTPException
        from openssl_encrypt_server.modules.keyserver.service import KeyserverService
        from openssl_encrypt_server.modules.keyserver.verification import VerificationError

        db = AsyncMock()
        nonce = secrets.token_hex(32)
        mock_result = MagicMock()
        mock_result.fetchone.return_value = (nonce,)  # Challenge consumed successfully
        db.execute = AsyncMock(return_value=mock_result)
        db.commit = AsyncMock()

        service = KeyserverService(db)

        bundle = MagicMock()
        bundle.challenge_id = str(uuid.uuid4())
        bundle.fingerprint = "3a:4b"
        bundle.name = "Test"
        bundle.signing_public_key = base64.b64encode(b"pubkey").decode()
        bundle.signing_algorithm = "ML-DSA-65"
        bundle.pop_signature = base64.b64encode(b"badsig").decode()

        with patch(
            "openssl_encrypt_server.modules.keyserver.service.verify_pop_signature",
            side_effect=VerificationError("bad signature"),
        ):
            with pytest.raises(HTTPException) as exc_info:
                run_async(service.upload_key("client123", bundle))

        assert exc_info.value.status_code == 400


# ---------------------------------------------------------------------------
# Route Tests
# ---------------------------------------------------------------------------


class TestChallengeRoute:
    """Tests for POST /api/v1/keys/challenge route (source inspection)."""

    def _routes_source(self):
        return (
            Path(__file__).parent.parent / "modules" / "keyserver" / "routes.py"
        ).read_text()

    def test_challenge_endpoint_is_defined(self):
        """POST /challenge endpoint is defined in routes.py."""
        assert '"/challenge"' in self._routes_source()

    def test_challenge_endpoint_requires_authentication(self):
        """Challenge endpoint requires Bearer token (uses get_current_client)."""
        source = self._routes_source()
        # Find the challenge route section and verify auth dependency follows
        challenge_pos = source.find('"/challenge"')
        assert challenge_pos != -1
        # get_current_client must appear within a reasonable window after the route
        after_challenge = source[challenge_pos : challenge_pos + 600]
        assert "get_current_client" in after_challenge

    def test_challenge_endpoint_is_rate_limited(self):
        """Challenge endpoint has rate limiting to prevent nonce flooding."""
        source = self._routes_source()
        challenge_pos = source.find('"/challenge"')
        surrounding = source[max(0, challenge_pos - 200) : challenge_pos + 500]
        assert "limiter.limit" in surrounding

    def test_challenge_response_model_used(self):
        """Challenge route declares ChallengeResponse as response_model."""
        source = self._routes_source()
        assert "ChallengeResponse" in source

    def test_upload_route_uses_key_upload_with_pop(self):
        """Upload route parameter is KeyUploadWithPoP (not the old KeyBundleSchema)."""
        source = self._routes_source()
        assert "KeyUploadWithPoP" in source

    def test_challenge_schemas_are_imported_in_routes(self):
        """ChallengeRequest and ChallengeResponse are imported at the top of routes.py."""
        source = self._routes_source()
        assert "ChallengeRequest" in source
        assert "ChallengeResponse" in source

    def test_key_upload_with_pop_is_imported_in_routes(self):
        """KeyUploadWithPoP is imported in routes.py."""
        assert "KeyUploadWithPoP" in self._routes_source()


# ---------------------------------------------------------------------------
# Migration Tests
# ---------------------------------------------------------------------------


class TestPopMigration:
    """Tests for the 003_pop_challenges.py migration script."""

    def _migration_path(self):
        return Path(__file__).parent.parent / "migrations" / "003_pop_challenges.py"

    def _migration_source(self):
        return self._migration_path().read_text()

    def test_migration_file_exists(self):
        """Migration 003_pop_challenges.py file exists."""
        assert self._migration_path().exists()

    def test_migration_reads_database_url_from_env_var(self):
        """Migration reads DATABASE_URL from environment (not CLI only)."""
        source = self._migration_source()
        assert 'os.environ' in source
        assert "DATABASE_URL" in source

    def test_migration_does_not_require_cli_database_url(self):
        """--database-url CLI argument is optional (not required=True)."""
        source = self._migration_source()
        assert "required=False" in source

    def test_migration_creates_ks_challenges_table(self):
        """Migration SQL creates the ks_challenges table."""
        source = self._migration_source()
        assert "ks_challenges" in source
        assert "CREATE TABLE" in source

    def test_migration_adds_expires_at_index(self):
        """Migration creates an index on expires_at for efficient cleanup."""
        source = self._migration_source()
        assert "expires_at" in source
        assert "INDEX" in source

    def test_migration_adds_client_id_index(self):
        """Migration creates an index on client_id."""
        source = self._migration_source()
        assert "client_id" in source
        assert "INDEX" in source

    def test_migration_includes_nonce_unique_constraint(self):
        """Migration defines nonce column as UNIQUE."""
        source = self._migration_source()
        assert "nonce" in source
        assert "UNIQUE" in source
