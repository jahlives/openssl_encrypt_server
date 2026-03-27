#!/usr/bin/env python3
"""
Migration: Add HMAC columns for constant-time token lookups

Date: 2026-03-27
Reason: confirmation_token and registration_id lookups used direct SQL WHERE
        equality, which is not constant-time (security finding #6). This adds
        HMAC columns following the same pattern as client_id_hmac (migration 004).

Usage:
    DATABASE_URL="postgresql+asyncpg://user:pass@host/db" \
    KEYSERVER_TOKEN_SECRET="your-secret" \
    python3 006_token_hmac.py
"""

import asyncio
import argparse
import hashlib
import hmac
import logging
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def compute_hmac(secret: str, value: str) -> str:
    """Compute HMAC-SHA256 for indexed DB lookup."""
    return hmac.new(
        secret.encode("utf-8"),
        value.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


async def run_migration(database_url: str, token_secret: str):
    """
    Run the migration to add HMAC columns and backfill existing rows.

    Args:
        database_url: PostgreSQL connection URL (asyncpg format)
        token_secret: KEYSERVER_TOKEN_SECRET for computing HMACs
    """
    logger.info("Starting migration: Add token HMAC columns")

    engine = create_async_engine(database_url, echo=False)

    try:
        async with engine.begin() as conn:
            # Add columns
            logger.info("Adding HMAC columns to ks_pending_registrations...")
            await conn.execute(text("""
                ALTER TABLE ks_pending_registrations
                    ADD COLUMN IF NOT EXISTS confirmation_token_hmac VARCHAR(64)
            """))
            await conn.execute(text("""
                ALTER TABLE ks_pending_registrations
                    ADD COLUMN IF NOT EXISTS registration_id_hmac VARCHAR(64)
            """))

            # Create indexes
            logger.info("Creating indexes...")
            await conn.execute(text("""
                CREATE INDEX IF NOT EXISTS ix_ks_pending_confirmation_token_hmac
                    ON ks_pending_registrations (confirmation_token_hmac)
            """))
            await conn.execute(text("""
                CREATE INDEX IF NOT EXISTS ix_ks_pending_registration_id_hmac
                    ON ks_pending_registrations (registration_id_hmac)
            """))

            # Backfill existing rows
            logger.info("Backfilling HMACs for existing pending registrations...")
            result = await conn.execute(text(
                "SELECT id, confirmation_token, registration_id FROM ks_pending_registrations "
                "WHERE confirmation_token_hmac IS NULL OR registration_id_hmac IS NULL"
            ))
            rows = result.fetchall()

            if rows:
                for row in rows:
                    token_hmac = compute_hmac(token_secret, row[1])
                    regid_hmac = compute_hmac(token_secret, row[2])
                    await conn.execute(
                        text(
                            "UPDATE ks_pending_registrations "
                            "SET confirmation_token_hmac = :th, registration_id_hmac = :rh "
                            "WHERE id = :id"
                        ),
                        {"th": token_hmac, "rh": regid_hmac, "id": row[0]},
                    )
                logger.info(f"  Backfilled {len(rows)} record(s)")
            else:
                logger.info("  No existing records to backfill")

        logger.info("Migration completed successfully")

    except Exception as e:
        logger.error(f"Migration failed: {e}")
        raise

    finally:
        await engine.dispose()


def main():
    parser = argparse.ArgumentParser(description="Run token HMAC migration")
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

    token_secret = os.environ.get("KEYSERVER_TOKEN_SECRET")
    if not token_secret:
        parser.error("KEYSERVER_TOKEN_SECRET environment variable is required")

    asyncio.run(run_migration(database_url, token_secret))


if __name__ == "__main__":
    main()
