#!/usr/bin/env python3
"""
Keyserver database models.

Table prefix: ks_ (keyserver)
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSON, UUID

from ...core.database import Base


class KSClient(Base):
    """
    Keyserver client (API token authenticated).

    Each client receives a unique JWT token for accessing keyserver endpoints.
    """

    __tablename__ = "ks_clients"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    client_id = Column(String(64), unique=True, nullable=False, index=True)
    client_id_hmac = Column(String(64), nullable=True, index=True)  # HMAC(server_secret, client_id) for indexed lookup
    password_hash = Column(String(255), nullable=True)  # Argon2id hash; NULL = legacy client (no password set yet)
    email = Column(String(255), unique=True, nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    last_seen_at = Column(DateTime(timezone=True), nullable=True)
    client_metadata = Column(JSON, nullable=True)  # Optional client info

    def __repr__(self):
        return f"<KSClient(client_id={self.client_id})>"


class KSPendingRegistration(Base):
    """
    Pending email registration awaiting confirmation.

    Records are created when a user submits their email for registration
    and deleted upon successful confirmation or expiry cleanup.
    """

    __tablename__ = "ks_pending_registrations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    confirmation_token = Column(String(64), unique=True, nullable=False, index=True)
    registration_id = Column(String(64), unique=True, nullable=False, index=True)
    status = Column(String(20), nullable=False, default="pending")  # "pending" or "confirmed"
    client_id = Column(String(64), nullable=True)  # Set on confirmation
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True), nullable=False)
    confirmed_at = Column(DateTime(timezone=True), nullable=True)

    def __repr__(self):
        return f"<KSPendingRegistration(email={self.email}, status={self.status})>"


class KSKey(Base):
    """
    Public key storage.

    Stores post-quantum public keys with metadata and verification status.
    """

    __tablename__ = "ks_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    fingerprint = Column(String(100), unique=True, nullable=False, index=True)  # SHA-256 with colons: 95 chars
    name = Column(String(255), nullable=True, index=True)
    email = Column(String(255), nullable=True, index=True)
    bundle_json = Column(Text, nullable=False)  # Complete PublicKeyBundle JSON
    encryption_algorithm = Column(String(50), nullable=False)  # e.g., "ML-KEM-768"
    signing_algorithm = Column(String(50), nullable=False)  # e.g., "ML-DSA-65"
    revoked = Column(Boolean, nullable=False, default=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revocation_reason = Column(Text, nullable=True)
    owner_client_id = Column(String(64), nullable=True)  # Optional: track uploader
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    upload_count = Column(Integer, nullable=False, default=1)

    def __repr__(self):
        return f"<KSKey(fingerprint={self.fingerprint[:20]}..., name={self.name})>"


class KSChallenge(Base):
    """
    Single-use Proof of Possession challenge for key upload.

    Lifecycle: created (used=False) → consumed (used=True) → cleaned up.
    Challenges are single-use and expire after KEYSERVER_CHALLENGE_TTL_MINUTES.
    The nonce is UNIQUE to prevent any collision from being exploitable.
    """

    __tablename__ = "ks_challenges"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    nonce = Column(String(64), unique=True, nullable=False)  # 32-byte hex = 64 chars
    client_id = Column(String(64), nullable=False, index=True)
    fingerprint_hint = Column(String(100), nullable=True)  # For logging only — NOT validated
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    used = Column(Boolean, nullable=False, default=False)

    def __repr__(self):
        return f"<KSChallenge(id={self.id}, client_id={self.client_id[:8]}..., used={self.used})>"


class KSAccessLog(Base):
    """
    Access log for keyserver operations.

    Tracks key uploads, downloads, searches, and revocations.
    """

    __tablename__ = "ks_access_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    key_fingerprint = Column(String(100), nullable=False)  # SHA-256 with colons: 95 chars
    action = Column(String(20), nullable=False)  # 'upload', 'download', 'search', 'revoke'
    client_id = Column(String(64), nullable=True)
    ip_address = Column(String(45), nullable=True)  # IPv4/IPv6
    timestamp = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True)

    def __repr__(self):
        return f"<KSAccessLog(action={self.action}, fingerprint={self.key_fingerprint[:20]}...)>"
