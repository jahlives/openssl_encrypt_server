#!/usr/bin/env python3
"""
Migration: Create persistent token revocation table

Date: 2026-03-27
Reason: Revoked JTIs were stored in an in-memory Python set (finding #4).
        On server restart, all revocation records were lost, allowing
        revoked refresh tokens (7-day lifetime) to become usable again.

Usage:
    DATABASE_URL="postgresql+asyncpg://user:pass@host/db" \
    python3 007_revoked_tokens.py
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
    """Run the migration to create the revoked_tokens table."""
    logger.info("Starting migration: Create revoked_tokens table")

    engine = create_async_engine(database_url, echo=False)

    try:
        async with engine.begin() as conn:
            logger.info("Creating revoked_tokens table...")
            await conn.execute(text("""
                CREATE TABLE IF NOT EXISTS revoked_tokens (
                    jti VARCHAR(32) PRIMARY KEY,
                    expires_at TIMESTAMPTZ NOT NULL,
                    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """))

            await conn.execute(text("""
                CREATE INDEX IF NOT EXISTS ix_revoked_tokens_expires_at
                    ON revoked_tokens (expires_at)
            """))

            await conn.execute(text(
                "COMMENT ON TABLE revoked_tokens IS "
                "'Persistent store for revoked JWT token IDs. "
                "Entries kept until original token expiry, then cleaned up.'"
            ))

            # Verify
            result = await conn.execute(text("""
                SELECT table_name FROM information_schema.tables
                WHERE table_name = 'revoked_tokens'
            """))
            if result.fetchone():
                logger.info("  revoked_tokens table created successfully")
            else:
                logger.error("  revoked_tokens table NOT found!")

        logger.info("Migration completed successfully")

    except Exception as e:
        logger.error(f"Migration failed: {e}")
        raise

    finally:
        await engine.dispose()


def main():
    parser = argparse.ArgumentParser(description="Run revoked_tokens migration")
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
            "or use --database-url"
        )

    asyncio.run(run_migration(database_url))


if __name__ == "__main__":
    main()
