#!/usr/bin/env python3
"""
Persistent token revocation store.

Persists revoked JWT token IDs (JTIs) to the database so they survive
server restarts. Addresses security finding #4: in-memory-only revocation
store allows revoked refresh tokens to become usable again after restart.
"""

import logging
from datetime import datetime, timezone
from typing import Set

from sqlalchemy import Column, DateTime, String, delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import Base

logger = logging.getLogger(__name__)


class RevokedToken(Base):
    """
    Persistent store for revoked JWT token IDs.

    Entries are kept until their original token expiry passes,
    then cleaned up by periodic maintenance.
    """

    __tablename__ = "revoked_tokens"

    jti = Column(String(32), primary_key=True)  # JWT ID (hex, typically 16 chars)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    revoked_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    def __repr__(self):
        return f"<RevokedToken(jti={self.jti})>"


async def persist_revocation(
    db: AsyncSession, jti: str, expires_at: datetime
) -> None:
    """
    Persist a token revocation to the database.

    Args:
        db: Async database session
        jti: The JWT ID to revoke
        expires_at: When the original token expires (for cleanup scheduling)
    """
    revoked = RevokedToken(
        jti=jti,
        expires_at=expires_at,
        revoked_at=datetime.now(timezone.utc),
    )
    db.add(revoked)
    await db.commit()
    logger.info(f"Persisted token revocation: jti={jti}")


async def load_revoked_jtis(db: AsyncSession) -> Set[str]:
    """
    Load all non-expired revoked JTIs from the database.

    Called on server startup to restore the in-memory revocation set.

    Args:
        db: Async database session

    Returns:
        Set of revoked JTI strings
    """
    now = datetime.now(timezone.utc)
    stmt = select(RevokedToken.jti).where(RevokedToken.expires_at > now)
    result = await db.execute(stmt)
    jtis = {row[0] for row in result.fetchall()}
    logger.info(f"Loaded {len(jtis)} revoked token(s) from database")
    return jtis


async def cleanup_expired_revocations(db: AsyncSession) -> int:
    """
    Remove expired revocation records from the database.

    Should be called periodically (e.g., daily) to prevent table growth.

    Args:
        db: Async database session

    Returns:
        Number of expired records removed
    """
    now = datetime.now(timezone.utc)
    stmt = delete(RevokedToken).where(RevokedToken.expires_at <= now)
    result = await db.execute(stmt)
    await db.commit()
    count = result.rowcount
    if count > 0:
        logger.info(f"Cleaned up {count} expired revocation record(s)")
    return count
