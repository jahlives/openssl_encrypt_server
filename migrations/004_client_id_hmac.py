#!/usr/bin/env python3
"""
Migration: Add client_id_hmac column for indexed constant-time lookups

Date: 2026-03-27
Reason: The previous get_client_by_id implementation fetched ALL client rows
        into memory to perform hmac.compare_digest on each one — a DoS vector
        that worsens linearly with user count.  This migration adds a
        client_id_hmac column (HMAC-SHA256 keyed with KEYSERVER_TOKEN_SECRET)
        that enables direct indexed lookups.

Usage:
    DATABASE_URL="postgresql+asyncpg://user:pass@host/db" \
    KEYSERVER_TOKEN_SECRET="your-secret" \
    python3 004_client_id_hmac.py
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


def compute_client_id_hmac(secret: str, client_id: str) -> str:
    """Compute HMAC-SHA256 of client_id for indexed DB lookup."""
    return hmac.new(
        secret.encode("utf-8"),
        client_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


async def run_migration(database_url: str, token_secret: str):
    """
    Run the migration to add client_id_hmac column and backfill existing rows.

    Args:
        database_url: PostgreSQL connection URL (asyncpg format)
        token_secret: KEYSERVER_TOKEN_SECRET for computing HMACs
    """
    logger.info("Starting migration: Add client_id_hmac column")
    logger.info(f"Database: {database_url.split('@')[1] if '@' in database_url else database_url}")

    engine = create_async_engine(database_url, echo=False)

    try:
        async with engine.begin() as conn:
            # Add column
            logger.info("Adding client_id_hmac column to ks_clients...")
            await conn.execute(text("""
                ALTER TABLE ks_clients
                    ADD COLUMN IF NOT EXISTS client_id_hmac VARCHAR(64)
            """))

            # Create index
            logger.info("Creating index on client_id_hmac...")
            await conn.execute(text("""
                CREATE INDEX IF NOT EXISTS ix_ks_clients_client_id_hmac
                    ON ks_clients (client_id_hmac)
            """))

            # Add column comment
            await conn.execute(text(
                "COMMENT ON COLUMN ks_clients.client_id_hmac IS "
                "'HMAC-SHA256(server_secret, client_id) for indexed lookup without full table scan'"
            ))

            # Backfill existing rows
            logger.info("Backfilling client_id_hmac for existing clients...")
            result = await conn.execute(text(
                "SELECT id, client_id FROM ks_clients WHERE client_id_hmac IS NULL"
            ))
            rows = result.fetchall()

            if rows:
                for row in rows:
                    id_hmac = compute_client_id_hmac(token_secret, row[1])
                    await conn.execute(
                        text("UPDATE ks_clients SET client_id_hmac = :hmac WHERE id = :id"),
                        {"hmac": id_hmac, "id": row[0]},
                    )
                logger.info(f"  Backfilled {len(rows)} client(s)")
            else:
                logger.info("  No existing clients to backfill")

            # Verify
            logger.info("Verifying migration...")
            result = await conn.execute(text("""
                SELECT column_name FROM information_schema.columns
                WHERE table_name = 'ks_clients' AND column_name = 'client_id_hmac'
            """))
            if result.fetchone():
                logger.info("  ks_clients.client_id_hmac column exists")

            result = await conn.execute(text("""
                SELECT COUNT(*) FROM ks_clients WHERE client_id_hmac IS NULL
            """))
            null_count = result.scalar()
            if null_count == 0:
                logger.info("  All clients have client_id_hmac populated")
            else:
                logger.warning(f"  {null_count} client(s) still have NULL client_id_hmac")

        logger.info("Migration completed successfully")

    except Exception as e:
        logger.error(f"Migration failed: {e}")
        raise

    finally:
        await engine.dispose()


def main():
    parser = argparse.ArgumentParser(description="Run client_id_hmac migration")
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

    token_secret = os.environ.get("KEYSERVER_TOKEN_SECRET")
    if not token_secret:
        parser.error(
            "KEYSERVER_TOKEN_SECRET environment variable is required "
            "for computing HMAC values during backfill"
        )

    asyncio.run(run_migration(database_url, token_secret))


if __name__ == "__main__":
    main()
