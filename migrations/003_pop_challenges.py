#!/usr/bin/env python3
"""
Migration: Add ks_challenges table for Proof of Possession

Date: 2026-03-26
Reason: Introduce challenge-response PoP so a public key can only be uploaded
        when the uploader proves real-time access to the corresponding private key.
        Creates ks_challenges table with nonce, client_id, expiry, and used flag.

Usage:
    DATABASE_URL="postgresql+asyncpg://user:pass@host/db" python3 003_pop_challenges.py
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
    Run the migration to add PoP challenge support.

    Args:
        database_url: PostgreSQL connection URL (asyncpg format)
    """
    logger.info("Starting migration: Add ks_challenges table for Proof of Possession")
    logger.info(f"Database: {database_url.split('@')[1] if '@' in database_url else database_url}")

    engine = create_async_engine(database_url, echo=False)

    try:
        async with engine.begin() as conn:
            # Create ks_challenges table
            logger.info("Creating ks_challenges table...")
            await conn.execute(text("""
                CREATE TABLE IF NOT EXISTS ks_challenges (
                    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
                    nonce           VARCHAR(64) NOT NULL UNIQUE,
                    client_id       VARCHAR(64) NOT NULL,
                    fingerprint_hint VARCHAR(100),
                    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    expires_at      TIMESTAMPTZ NOT NULL,
                    used            BOOLEAN     NOT NULL DEFAULT FALSE
                )
            """))

            logger.info("Creating indexes on ks_challenges...")
            await conn.execute(text("""
                CREATE INDEX IF NOT EXISTS ix_ks_challenges_client_id
                    ON ks_challenges (client_id)
            """))
            await conn.execute(text("""
                CREATE INDEX IF NOT EXISTS ix_ks_challenges_expires_at
                    ON ks_challenges (expires_at)
            """))

            # Verify
            logger.info("Verifying migration...")
            result = await conn.execute(text("""
                SELECT table_name FROM information_schema.tables
                WHERE table_name = 'ks_challenges'
            """))
            if result.fetchone():
                logger.info("  ks_challenges table exists")

            result = await conn.execute(text("""
                SELECT column_name FROM information_schema.columns
                WHERE table_name = 'ks_challenges' AND column_name = 'nonce'
            """))
            if result.fetchone():
                logger.info("  ks_challenges.nonce column exists")

        logger.info("Migration completed successfully")

    except Exception as e:
        logger.error(f"Migration failed: {e}")
        raise

    finally:
        await engine.dispose()


def main():
    parser = argparse.ArgumentParser(description="Run PoP challenges migration")
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
