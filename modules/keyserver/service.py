#!/usr/bin/env python3
"""
Keyserver business logic.

Handles key upload, search, and revocation operations.
"""

import hmac
import json
import logging
import secrets
import uuid as _uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import HTTPException, status
from sqlalchemy import delete, or_, select, update as sa_update
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


class KeyserverService:
    """Service for keyserver operations"""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_client_by_id(self, client_id: str) -> Optional[KSClient]:
        """
        Look up a client by client_id using constant-time comparison.

        Args:
            client_id: The client identifier to look up

        Returns:
            KSClient if found, None otherwise
        """
        stmt = select(KSClient)
        result = await self.db.execute(stmt)
        clients = result.scalars().all()

        for client in clients:
            if hmac.compare_digest(client.client_id, client_id):
                return client

        return None

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

        # Check if key already exists
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
        key = result.scalar_one_or_none()

        if not key:
            logger.info(f"Key not found for query: '{query}'")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Key not found"
            )

        # Parse bundle JSON
        bundle_data = json.loads(key.bundle_json)

        # Log access
        await self._log_access(key.fingerprint, "search", client_id, ip_address)

        logger.info(f"Key found: {key.name} (fp: {key.fingerprint[:20]}...)")

        return {"key": KeyBundleSchema(**bundle_data), "message": "Key found"}

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
        self, email: str, base_url: str, email_service
    ) -> dict:
        """
        Create a pending registration and send a confirmation email.

        Args:
            email: Email address to register
            base_url: Base URL for confirmation link
            email_service: EmailService instance for sending emails

        Returns:
            dict: Contains registration_id and confirmation_token

        Raises:
            HTTPException: 409 if email already has an active account
        """
        # Check if email already has an active account
        stmt = select(KSClient).where(KSClient.email == email)
        result = await self.db.execute(stmt)
        existing_client = result.scalar_one_or_none()

        if existing_client:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An account with this email already exists",
            )

        # Check for existing pending registration
        stmt = select(KSPendingRegistration).where(KSPendingRegistration.email == email)
        result = await self.db.execute(stmt)
        existing_pending = result.scalar_one_or_none()

        token = secrets.token_urlsafe(32)
        registration_id = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=30)

        if existing_pending:
            # Update existing pending registration with new token and expiry
            existing_pending.confirmation_token = token
            existing_pending.registration_id = registration_id
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
                registration_id=registration_id,
                created_at=now,
                expires_at=expires_at,
            )
            self.db.add(pending)

        await self.db.commit()

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
        client = KSClient(client_id=client_id, email=pending.email)
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

        If confirmed, generates JWT tokens and deletes the pending record.

        Args:
            registration_id: The registration ID returned at registration time
            auth: TokenAuth instance for creating token pairs

        Returns:
            dict: Status and optionally tokens if confirmed

        Raises:
            HTTPException: 404 if registration_id not found
        """
        stmt = select(KSPendingRegistration).where(
            KSPendingRegistration.registration_id == registration_id
        )
        result = await self.db.execute(stmt)
        pending = result.scalar_one_or_none()

        if not pending:
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
