#!/usr/bin/env python3
"""
Migration: Add password_hash column for password-based authentication

Date: 2026-03-27
Reason: client_id was the sole authentication factor (security finding #1).
        This migration adds a password_hash column to store Argon2id hashes,
        enabling password as a required second factor for login.

        Existing clients will have NULL password_hash and will be prompted
        to set a password on next login.

Usage:
    DATABASE_URL="postgresql+asyncpg://user:pass@host/db" \
    python3 005_password_hash.py
"""

import asyncio
import argparse
import logging
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def run_migration(database_url: str):
    """
    Run the migration to add password_hash column.

    Args:
        database_url: PostgreSQL connection URL (asyncpg format)
    """
    logger.info("Starting migration: Add password_hash column")
    logger.info(f"Database: {database_url.split('@')[1] if '@' in database_url else database_url}")

    engine = create_async_engine(database_url, echo=False)

    try:
        async with engine.begin() as conn:
            # Add column
            logger.info("Adding password_hash column to ks_clients...")
            await conn.execute(text("""
                ALTER TABLE ks_clients
                    ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255)
            """))

            # Add column comment
            await conn.execute(text(
                "COMMENT ON COLUMN ks_clients.password_hash IS "
                "'Argon2id hash of account password. NULL = legacy client requiring password setup.'"
            ))

            # Check how many legacy clients exist
            result = await conn.execute(text(
                "SELECT COUNT(*) FROM ks_clients WHERE password_hash IS NULL"
            ))
            legacy_count = result.scalar()
            if legacy_count > 0:
                logger.info(f"  {legacy_count} legacy client(s) will need to set a password on next login")
            else:
                logger.info("  No existing clients (clean install)")

            # Verify
            logger.info("Verifying migration...")
            result = await conn.execute(text("""
                SELECT column_name FROM information_schema.columns
                WHERE table_name = 'ks_clients' AND column_name = 'password_hash'
            """))
            if result.fetchone():
                logger.info("  ks_clients.password_hash column exists")
            else:
                logger.error("  ks_clients.password_hash column NOT found!")

        logger.info("Migration completed successfully")

    except Exception as e:
        logger.error(f"Migration failed: {e}")
        raise

    finally:
        await engine.dispose()


def main():
    parser = argparse.ArgumentParser(description="Run password_hash migration")
    parser.add_argument(
        "--database-url",
        required=False,
        default=None,
        help="PostgreSQL connection URL (prefer DATABASE_URL env var)",
    )

    args = parser.parse_args()

    database_url = os.environ.get("DATABASE_URL") or args.database_url
    if not database_url:
        parser.error(
            "Database URL required. Set DATABASE_URL environment variable "
            "or use --database-url (not recommended: credentials visible in process table)"
        )

    asyncio.run(run_migration(database_url))


if __name__ == "__main__":
    main()
