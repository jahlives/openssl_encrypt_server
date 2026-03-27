#!/usr/bin/env python3
"""
Keyserver business logic.

Handles key upload, search, and revocation operations.
"""

import hashlib
import hmac
import json
import logging
import secrets
import uuid as _uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import HTTPException, status
from sqlalchemy import delete, or_, select, update as sa_update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from .models import KSAccessLog, KSChallenge, KSClient, KSKey, KSPendingRegistration
from .schemas import KeyBundleSchema, KeyUploadWithPoP, RevocationRequest
from .verification import (
    FingerprintMismatchError,
    VerificationError,
    verify_bundle_signature,
    verify_pop_signature,
    verify_revocation_signature,
)

logger = logging.getLogger(__name__)

_ph = PasswordHasher()
# Dummy hash for constant-time behavior when client_id is invalid.
# Prevents timing oracle that distinguishes "invalid client_id" (fast)
# from "valid client_id, wrong password" (slow Argon2 verify).
_DUMMY_HASH = _ph.hash("dummy_timing_protection")


class KeyserverService:
    """Service for keyserver operations"""

    def __init__(self, db: AsyncSession):
        self.db = db

    @staticmethod
    def compute_client_id_hmac(secret: str, client_id: str) -> str:
        """
        Compute a deterministic HMAC of a client_id for indexed DB lookup.

        Uses HMAC-SHA256 keyed with the server's token secret, producing a
        hex digest that can be stored in the client_id_hmac column and queried
        via a normal WHERE clause — avoiding a full table scan.

        Args:
            secret: The server's KEYSERVER_TOKEN_SECRET
            client_id: The client identifier to hash

        Returns:
            str: 64-character hex digest
        """
        return hmac.new(
            secret.encode("utf-8"),
            client_id.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    async def get_client_by_id(self, client_id: str, secret: str) -> Optional[KSClient]:
        """
        Look up a client by client_id using indexed HMAC column.

        Computes HMAC(secret, client_id) and queries the client_id_hmac column
        directly (O(1) indexed lookup). Then verifies with constant-time
        comparison as defense-in-depth against hash collisions.

        Args:
            client_id: The client identifier to look up
            secret: The server's KEYSERVER_TOKEN_SECRET for HMAC computation

        Returns:
            KSClient if found, None otherwise
        """
        id_hmac = self.compute_client_id_hmac(secret, client_id)
        stmt = select(KSClient).where(KSClient.client_id_hmac == id_hmac)
        result = await self.db.execute(stmt)
        client = result.scalars().first()

        if client and hmac.compare_digest(client.client_id, client_id):
            return client

        return None

    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash a password using Argon2id.

        Args:
            password: The plaintext password to hash

        Returns:
            str: Argon2id encoded hash string
        """
        return _ph.hash(password)

    async def verify_client_password(self, client: KSClient, password: str) -> bool:
        """
        Verify a password against a client's stored hash.

        Handles Argon2 parameter upgrades transparently via check_needs_rehash.

        Args:
            client: The KSClient record
            password: The plaintext password to verify

        Returns:
            bool: True if password matches, False otherwise
        """
        if client.password_hash is None:
            return False
        try:
            _ph.verify(client.password_hash, password)
            if _ph.check_needs_rehash(client.password_hash):
                client.password_hash = _ph.hash(password)
                await self.db.commit()
            return True
        except VerifyMismatchError:
            return False

    async def set_client_password(self, client_id: str, password: str, secret: str) -> bool:
        """
        Set or update a client's password.

        Args:
            client_id: The client identifier
            password: The new plaintext password
            secret: Server token secret for client lookup

        Returns:
            bool: True if password was set, False if client not found
        """
        client = await self.get_client_by_id(client_id, secret)
        if not client:
            return False
        client.password_hash = _ph.hash(password)
        await self.db.commit()
        return True

    async def validate_confirmation_token(self, token: str, secret: str = "") -> KSPendingRegistration:
        """
        Validate a confirmation token without creating the account.

        Uses HMAC-indexed lookup + constant-time comparison to prevent
        timing attacks on token values.

        Args:
            token: Confirmation token from email link
            secret: Server token secret for HMAC computation

        Returns:
            KSPendingRegistration: The pending registration record

        Raises:
            HTTPException: 404 if token not found, 410 if expired
        """
        token_hmac = self.compute_client_id_hmac(secret, token)
        stmt = select(KSPendingRegistration).where(
            KSPendingRegistration.confirmation_token_hmac == token_hmac
        )
        result = await self.db.execute(stmt)
        pending = result.scalar_one_or_none()

        if not pending or not hmac.compare_digest(pending.confirmation_token, token):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Invalid confirmation token",
            )

        if pending.status == "confirmed":
            return pending

        if pending.expires_at < datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail="Confirmation link has expired. Please register again.",
            )

        return pending

    async def confirm_registration_with_password(
        self, token: str, password: str, auth, email_service
    ) -> dict:
        """
        Confirm a pending registration with a password and create the account.

        Args:
            token: Confirmation token from email link
            password: User-chosen password to hash and store
            auth: TokenAuth instance for generating client_id
            email_service: EmailService instance for sending welcome email

        Returns:
            dict: Contains client_id

        Raises:
            HTTPException: 404 if token not found, 410 if expired
        """
        pending = await self.validate_confirmation_token(token, auth.secret)

        if pending.status == "confirmed":
            return {"client_id": pending.client_id}

        # Create the client account with password hash
        client_id = auth.generate_client_id()
        client_id_hmac = self.compute_client_id_hmac(auth.secret, client_id)
        password_hash = _ph.hash(password)
        client = KSClient(
            client_id=client_id,
            client_id_hmac=client_id_hmac,
            password_hash=password_hash,
            email=pending.email,
        )
        self.db.add(client)

        # Mark pending record as confirmed (keep for polling endpoint)
        pending.status = "confirmed"
        pending.client_id = client_id
        pending.confirmed_at = datetime.now(timezone.utc)

        await self.db.commit()

        # Send welcome email with client_id
        await email_service.send_welcome_email(pending.email, client_id)

        logger.info(f"Registration confirmed for {pending.email}, client_id: {client_id[:8]}...")

        return {"client_id": client_id}

    async def generate_challenge(
        self,
        client_id: str,
        fingerprint_hint: Optional[str] = None,
        ttl_minutes: int = 10,
    ) -> dict:
        """
        Generate a single-use Proof of Possession challenge for key upload.

        Args:
            client_id:        Authenticated client requesting the challenge.
            fingerprint_hint: Optional fingerprint for operator logging (not validated).
            ttl_minutes:      Challenge lifetime in minutes (default: 10).

        Returns:
            dict with challenge_id (str), nonce (str), expires_at (ISO 8601 str).
        """
        # Lazy cleanup: prune expired/used challenges before issuing a new one
        try:
            await self.cleanup_expired_challenges()
        except Exception:
            pass  # Never block challenge issuance on cleanup failure

        nonce = secrets.token_hex(32)  # 32 bytes → 64 hex chars
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=ttl_minutes)

        challenge = KSChallenge(
            nonce=nonce,
            client_id=client_id,
            fingerprint_hint=fingerprint_hint,
            expires_at=expires_at,
        )
        self.db.add(challenge)
        await self.db.commit()
        await self.db.refresh(challenge)  # Populate server-generated UUID

        logger.info(
            f"Challenge issued to client {client_id[:8]}... "
            f"(id: {challenge.id}, hint: {fingerprint_hint or 'none'})"
        )

        return {
            "challenge_id": str(challenge.id),
            "nonce": nonce,
            "expires_at": expires_at.isoformat(),
        }

    async def cleanup_expired_challenges(self) -> int:
        """
        Delete expired and used challenges to prevent unbounded table growth.

        Retains unexpired, unused challenges so in-flight uploads are unaffected.

        Returns:
            int: Number of records deleted.
        """
        now = datetime.now(timezone.utc)
        stmt = delete(KSChallenge).where(
            or_(
                KSChallenge.expires_at < now,   # All expired (used or not)
                KSChallenge.used.is_(True),      # All used (even if not yet expired)
            )
        )
        result = await self.db.execute(stmt)
        await self.db.commit()

        count = result.rowcount
        if count > 0:
            logger.info(f"Cleaned up {count} expired/used challenges")
        return count

    async def upload_key(
        self, client_id: str, bundle: KeyUploadWithPoP, ip_address: Optional[str] = None
    ) -> dict:
        """
        Upload public key bundle with Proof of Possession verification.

        Two-step PoP flow:
        1. Client must first call POST /challenge to obtain a nonce.
        2. Client signs b"POP:" + nonce + b":" + fingerprint with ML-DSA private key.
        3. challenge_id + pop_signature are submitted alongside the key bundle.

        Args:
            client_id: Client identifier
            bundle: Public key bundle with PoP fields
            ip_address: Client IP address (optional)

        Returns:
            dict: Upload response

        Raises:
            HTTPException: If PoP/bundle verification fails or key exists
        """
        logger.info(
            f"Upload request from client {client_id[:8]}... for key '{bundle.name}' (fp: {bundle.fingerprint[:20]}...)"
        )

        # --- Step 1: Validate challenge_id format ---
        try:
            challenge_uuid = _uuid.UUID(bundle.challenge_id)
        except (ValueError, AttributeError):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid challenge_id format",
            )

        # --- Step 2: Atomic challenge consumption (TOCTOU-safe) ---
        # A single UPDATE...WHERE...RETURNING atomically verifies the challenge
        # is valid (not expired, not used, correct client) and marks it used.
        # If nothing matches, the challenge was not found / expired / used /
        # owned by a different client — all return the same generic 400.
        now = datetime.now(timezone.utc)
        stmt = (
            sa_update(KSChallenge)
            .where(KSChallenge.id == challenge_uuid)
            .where(KSChallenge.used.is_(False))
            .where(KSChallenge.expires_at > now)
            .where(KSChallenge.client_id == client_id)
            .values(used=True)
            .returning(KSChallenge.nonce)
        )
        result = await self.db.execute(stmt)
        row = result.fetchone()

        if not row:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Challenge not found, expired, or already used",
            )

        nonce = row[0]
        await self.db.commit()

        # --- Step 3: Verify Proof of Possession ---
        try:
            verify_pop_signature(
                nonce_hex=nonce,
                fingerprint=bundle.fingerprint,
                pop_signature_b64=bundle.pop_signature,
                signing_public_key_b64=bundle.signing_public_key,
                signing_algorithm=bundle.signing_algorithm,
            )
        except (VerificationError, ValueError) as e:
            logger.error(f"PoP verification failed for client {client_id[:8]}...: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Proof of Possession verification failed",
            )

        # --- Step 4: Verify bundle self-signature and fingerprint ---
        # Exclude PoP-specific fields so they don't corrupt the reconstructed message.
        try:
            bundle_dict = bundle.model_dump(exclude={"challenge_id", "pop_signature"})
            verify_bundle_signature(bundle_dict)
        except (VerificationError, FingerprintMismatchError) as e:
            logger.error(f"Bundle verification failed: {e}")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
        except Exception as e:
            logger.error(f"Unexpected verification error: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Verification failed"
            )

        # Check if client already has an active key with the same email
        if bundle.email:
            stmt = (
                select(KSKey)
                .where(
                    KSKey.owner_client_id == client_id,
                    KSKey.email == bundle.email,
                    KSKey.revoked.is_(False),
                )
            )
            result = await self.db.execute(stmt)
            duplicate_email_key = result.scalars().first()
            if duplicate_email_key:
                logger.info(
                    f"Client {client_id} already has an active key for email {bundle.email}"
                )
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"An active key for email {bundle.email} already exists",
                )

        # Check if key already exists (by fingerprint)
        stmt = select(KSKey).where(KSKey.fingerprint == bundle.fingerprint)
        result = await self.db.execute(stmt)
        existing_key = result.scalar_one_or_none()

        if existing_key:
            if not existing_key.revoked:
                # Key exists and is not revoked - return conflict
                logger.info(f"Key already exists: {bundle.fingerprint}")
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Key with fingerprint {bundle.fingerprint} already exists",
                )
            else:
                # Key was revoked - allow re-upload (un-revoke)
                logger.info(f"Re-uploading previously revoked key: {bundle.fingerprint}")
                existing_key.bundle_json = json.dumps(bundle_dict)
                existing_key.name = bundle.name
                existing_key.email = bundle.email
                existing_key.encryption_algorithm = bundle.encryption_algorithm
                existing_key.signing_algorithm = bundle.signing_algorithm
                existing_key.revoked = False
                existing_key.revoked_at = None
                existing_key.upload_count += 1
                existing_key.updated_at = datetime.now(timezone.utc)
                existing_key.owner_client_id = client_id
                await self.db.commit()

                # Log access
                await self._log_access(
                    bundle.fingerprint, "upload", client_id, ip_address
                )

                return {
                    "success": True,
                    "fingerprint": bundle.fingerprint,
                    "message": "Key re-uploaded successfully (un-revoked)",
                }

        # Store new key
        new_key = KSKey(
            fingerprint=bundle.fingerprint,
            name=bundle.name,
            email=bundle.email,
            encryption_algorithm=bundle.encryption_algorithm,
            signing_algorithm=bundle.signing_algorithm,
            bundle_json=json.dumps(bundle_dict),
            owner_client_id=client_id,
            revoked=False,
        )

        self.db.add(new_key)
        await self.db.commit()

        # Log access
        await self._log_access(bundle.fingerprint, "upload", client_id, ip_address)

        logger.info(
            f"Key uploaded successfully: {bundle.name} (fp: {bundle.fingerprint[:20]}...)"
        )

        return {
            "success": True,
            "fingerprint": bundle.fingerprint,
            "message": "Key uploaded successfully",
        }

    async def search_key(
        self, query: str, client_id: Optional[str] = None, ip_address: Optional[str] = None
    ) -> dict:
        """
        Search for public key by fingerprint, name, or email.

        Search priority:
        1. Exact fingerprint match
        2. Fingerprint prefix match
        3. Exact name match
        4. Exact email match

        Args:
            query: Search query string
            client_id: Optional client ID
            ip_address: Optional client IP

        Returns:
            dict: Search response with key bundle

        Raises:
            HTTPException: If key not found
        """
        logger.info(f"Search request for: '{query}'")

        # Search by fingerprint, name, or email
        stmt = (
            select(KSKey)
            .where(
                or_(
                    KSKey.fingerprint == query,
                    KSKey.fingerprint.startswith(query),
                    KSKey.name == query,
                    KSKey.email == query,
                )
            )
            .where(KSKey.revoked.is_(False))
            .order_by(KSKey.created_at.desc())
        )

        result = await self.db.execute(stmt)
        keys = result.scalars().all()

        if len(keys) == 0:
            logger.info(f"Key not found for query: '{query}'")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Key not found"
            )

        # Log access for each key found
        for key in keys:
            await self._log_access(key.fingerprint, "search", client_id, ip_address)

        logger.info(f"Found {len(keys)} key(s) for query: '{query}'")

        return {
            "keys": [KeyBundleSchema(**json.loads(k.bundle_json)) for k in keys],
            "count": len(keys),
        }

    async def get_key_by_fingerprint(
        self, fingerprint: str, client_id: Optional[str] = None, ip_address: Optional[str] = None
    ) -> dict:
        """
        Fetch public key by exact fingerprint.

        Args:
            fingerprint: Exact fingerprint to look up
            client_id: Optional client ID
            ip_address: Optional client IP

        Returns:
            dict: Response with single key bundle

        Raises:
            HTTPException: If key not found
        """
        logger.info(f"Fingerprint lookup for: '{fingerprint}'")

        stmt = (
            select(KSKey)
            .where(KSKey.fingerprint == fingerprint, KSKey.revoked.is_(False))
        )

        result = await self.db.execute(stmt)
        key = result.scalar_one_or_none()

        if not key:
            logger.info(f"Key not found for fingerprint: '{fingerprint}'")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Key not found"
            )

        # Log access
        await self._log_access(key.fingerprint, "search", client_id, ip_address)

        logger.info(f"Key found: {key.name} (fp: {key.fingerprint[:20]}...)")

        return {"key": KeyBundleSchema(**json.loads(key.bundle_json)), "message": "Key found"}

    async def revoke_key(
        self,
        fingerprint: str,
        revocation: RevocationRequest,
        client_id: str,
        ip_address: Optional[str] = None,
    ) -> dict:
        """
        Revoke public key.

        Args:
            fingerprint: Fingerprint of key to revoke
            revocation: Revocation request with signature
            client_id: Client identifier
            ip_address: Client IP address (optional)

        Returns:
            dict: Revocation response

        Raises:
            HTTPException: If key not found or signature invalid
        """
        logger.info(f"Revocation request for fingerprint: {fingerprint[:20]}...")

        # Find key
        stmt = select(KSKey).where(KSKey.fingerprint == fingerprint)
        result = await self.db.execute(stmt)
        key = result.scalar_one_or_none()

        if not key:
            logger.error(f"Key not found for revocation: {fingerprint}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Key not found"
            )

        if key.revoked:
            logger.info(f"Key already revoked: {fingerprint}")
            return {
                "success": True,
                "fingerprint": fingerprint,
                "message": "Key already revoked",
            }

        # Defense-in-depth: verify the requesting client owns this key (#11)
        if key.owner_client_id and key.owner_client_id != client_id:
            logger.warning(
                "Revocation denied: client %s is not the owner of key %s",
                client_id[:8],
                fingerprint[:20],
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to revoke this key",
            )

        # Parse bundle to get signing public key
        bundle_data = json.loads(key.bundle_json)

        # Verify revocation signature
        try:
            verify_revocation_signature(
                fingerprint=fingerprint,
                signature_hex=revocation.signature,
                signing_public_key_b64=bundle_data["signing_public_key"],
                signing_algorithm=bundle_data["signing_algorithm"],
            )
        except VerificationError as e:
            logger.error(f"Revocation signature verification failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid revocation signature: {e}",
            )

        # Mark as revoked
        key.revoked = True
        key.revoked_at = datetime.now(timezone.utc)
        await self.db.commit()

        # Log access
        await self._log_access(fingerprint, "revoke", client_id, ip_address)

        logger.info(f"Key revoked successfully: {fingerprint}")

        return {
            "success": True,
            "fingerprint": fingerprint,
            "message": "Key revoked successfully",
        }

    async def create_pending_registration(
        self, email: str, base_url: str, email_service, secret: str = ""
    ) -> dict:
        """
        Create a pending registration and send a confirmation email.

        Args:
            email: Email address to register
            base_url: Base URL for confirmation link
            email_service: EmailService instance for sending emails
            secret: Server token secret for computing HMAC indexes

        Returns:
            dict: Contains registration_id (opaque, always returned to prevent
            email enumeration)
        """
        # Check if email already has an active account
        stmt = select(KSClient).where(KSClient.email == email)
        result = await self.db.execute(stmt)
        existing_client = result.scalar_one_or_none()

        if existing_client:
            # Return opaque response to prevent email enumeration (#5).
            # Send notification to existing account holder instead.
            await email_service.send_duplicate_registration_notice(email)
            logger.info("Registration attempt for existing email (opaque response returned)")
            return {
                "registration_id": secrets.token_urlsafe(32),
                "token": secrets.token_urlsafe(32),
            }

        # Check for existing pending registration
        stmt = select(KSPendingRegistration).where(KSPendingRegistration.email == email)
        result = await self.db.execute(stmt)
        existing_pending = result.scalar_one_or_none()

        token = secrets.token_urlsafe(32)
        registration_id = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=30)

        confirmation_token_hmac = self.compute_client_id_hmac(secret, token)
        registration_id_hmac = self.compute_client_id_hmac(secret, registration_id)

        if existing_pending:
            # Update existing pending registration with new token and expiry
            existing_pending.confirmation_token = token
            existing_pending.confirmation_token_hmac = confirmation_token_hmac
            existing_pending.registration_id = registration_id
            existing_pending.registration_id_hmac = registration_id_hmac
            existing_pending.status = "pending"
            existing_pending.client_id = None
            existing_pending.confirmed_at = None
            existing_pending.created_at = now
            existing_pending.expires_at = expires_at
        else:
            # Create new pending registration
            pending = KSPendingRegistration(
                email=email,
                confirmation_token=token,
                confirmation_token_hmac=confirmation_token_hmac,
                registration_id=registration_id,
                registration_id_hmac=registration_id_hmac,
                created_at=now,
                expires_at=expires_at,
            )
            self.db.add(pending)

        try:
            await self.db.commit()
        except IntegrityError:
            # Race condition: concurrent request inserted the same email (#9).
            # Return opaque response to prevent email enumeration.
            await self.db.rollback()
            logger.info("Registration race condition handled (opaque response returned)")
            return {
                "registration_id": secrets.token_urlsafe(32),
                "token": secrets.token_urlsafe(32),
            }

        # Send confirmation email
        await email_service.send_confirmation_email(email, token, base_url)

        logger.info(f"Pending registration created for {email}")
        return {"registration_id": registration_id, "token": token}

    async def confirm_registration(
        self, token: str, auth, email_service
    ) -> dict:
        """
        Confirm a pending registration and create the account.

        Keeps the pending record with status="confirmed" so the polling
        endpoint can deliver JWT tokens to the client that initiated registration.

        Args:
            token: Confirmation token from email link
            auth: TokenAuth instance for generating client_id
            email_service: EmailService instance for sending welcome email

        Returns:
            dict: Contains client_id

        Raises:
            HTTPException: 404 if token not found, 410 if expired
        """
        stmt = select(KSPendingRegistration).where(
            KSPendingRegistration.confirmation_token == token
        )
        result = await self.db.execute(stmt)
        pending = result.scalar_one_or_none()

        if not pending:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Invalid confirmation token",
            )

        if pending.status == "confirmed":
            return {"client_id": pending.client_id}

        if pending.expires_at < datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail="Confirmation link has expired. Please register again.",
            )

        # Create the client account
        client_id = auth.generate_client_id()
        client_id_hmac = self.compute_client_id_hmac(auth.secret, client_id)
        client = KSClient(client_id=client_id, client_id_hmac=client_id_hmac, email=pending.email)
        self.db.add(client)

        # Mark pending record as confirmed (keep for polling endpoint)
        pending.status = "confirmed"
        pending.client_id = client_id
        pending.confirmed_at = datetime.now(timezone.utc)

        await self.db.commit()

        # Send welcome email with client_id
        await email_service.send_welcome_email(pending.email, client_id)

        logger.info(f"Registration confirmed for {pending.email}, client_id: {client_id[:8]}...")

        return {"client_id": client_id}

    async def check_registration_status(
        self, registration_id: str, auth
    ) -> dict:
        """
        Check the status of a pending registration (for polling).

        Uses HMAC-indexed lookup + constant-time comparison for the
        registration_id to prevent timing attacks.

        If confirmed, generates JWT tokens and deletes the pending record.

        Args:
            registration_id: The registration ID returned at registration time
            auth: TokenAuth instance for creating token pairs

        Returns:
            dict: Status and optionally tokens if confirmed

        Raises:
            HTTPException: 404 if registration_id not found
        """
        regid_hmac = self.compute_client_id_hmac(auth.secret, registration_id)
        stmt = select(KSPendingRegistration).where(
            KSPendingRegistration.registration_id_hmac == regid_hmac
        )
        result = await self.db.execute(stmt)
        pending = result.scalar_one_or_none()

        if not pending or not hmac.compare_digest(pending.registration_id, registration_id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Registration not found",
            )

        if pending.status == "pending":
            # Check if expired
            if pending.expires_at < datetime.now(timezone.utc):
                raise HTTPException(
                    status_code=status.HTTP_410_GONE,
                    detail="Registration has expired. Please register again.",
                )
            return {"status": "pending"}

        # Status is "confirmed" — issue tokens and clean up
        tokens = auth.create_token_pair(pending.client_id)
        client_id = pending.client_id

        # Delete the pending record (tokens delivered)
        await self.db.delete(pending)
        await self.db.commit()

        return {
            "status": "confirmed",
            "client_id": client_id,
            **tokens,
        }

    async def cleanup_expired_registrations(self) -> int:
        """
        Delete expired pending registrations and old confirmed records.

        Returns:
            int: Number of records deleted
        """
        now = datetime.now(timezone.utc)
        stmt = delete(KSPendingRegistration).where(
            or_(
                # Expired pending registrations
                (KSPendingRegistration.expires_at < now) & (KSPendingRegistration.status == "pending"),
                # Confirmed records older than 5 minutes (grace period for token pickup)
                (KSPendingRegistration.confirmed_at < now - timedelta(minutes=5)) & (KSPendingRegistration.status == "confirmed"),
            )
        )
        result = await self.db.execute(stmt)
        await self.db.commit()

        count = result.rowcount
        if count > 0:
            logger.info(f"Cleaned up {count} expired/old pending registrations")
        return count

    async def _log_access(
        self,
        fingerprint: str,
        action: str,
        client_id: Optional[str] = None,
        ip_address: Optional[str] = None,
    ):
        """Log access to a key"""
        log_entry = KSAccessLog(
            key_fingerprint=fingerprint,
            action=action,
            client_id=client_id,
            ip_address=ip_address,
        )
        self.db.add(log_entry)
        await self.db.commit()
