#!/usr/bin/env python3
"""
Migration: Add email-confirmed registration support

Date: 2026-03-26
Reason: Add email verification flow for keyserver registration.
        Creates ks_pending_registrations table and adds email column to ks_clients.

Usage:
    DATABASE_URL="postgresql+asyncpg://user:pass@host/db" python3 002_email_registration.py
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
    Run the migration to add email registration support.

    Args:
        database_url: PostgreSQL connection URL (asyncpg format)
    """
    logger.info("Starting migration: Add email-confirmed registration")
    logger.info(f"Database: {database_url.split('@')[1] if '@' in database_url else database_url}")

    engine = create_async_engine(database_url, echo=False)

    try:
        async with engine.begin() as conn:
            # Create pending registrations table
            logger.info("Creating ks_pending_registrations table...")
            await conn.execute(text("""
                CREATE TABLE IF NOT EXISTS ks_pending_registrations (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    email VARCHAR(255) NOT NULL UNIQUE,
                    confirmation_token VARCHAR(64) NOT NULL UNIQUE,
                    registration_id VARCHAR(64) NOT NULL UNIQUE,
                    status VARCHAR(20) NOT NULL DEFAULT 'pending',
                    client_id VARCHAR(64),
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    expires_at TIMESTAMPTZ NOT NULL,
                    confirmed_at TIMESTAMPTZ
                )
            """))

            logger.info("Creating indexes on ks_pending_registrations...")
            await conn.execute(text("""
                CREATE INDEX IF NOT EXISTS ix_ks_pending_registrations_email
                    ON ks_pending_registrations (email)
            """))
            await conn.execute(text("""
                CREATE INDEX IF NOT EXISTS ix_ks_pending_registrations_confirmation_token
                    ON ks_pending_registrations (confirmation_token)
            """))
            await conn.execute(text("""
                CREATE INDEX IF NOT EXISTS ix_ks_pending_registrations_registration_id
                    ON ks_pending_registrations (registration_id)
            """))

            # Add email column to ks_clients
            logger.info("Adding email column to ks_clients...")
            await conn.execute(text("""
                ALTER TABLE ks_clients
                    ADD COLUMN IF NOT EXISTS email VARCHAR(255) UNIQUE
            """))

            await conn.execute(text("""
                CREATE INDEX IF NOT EXISTS ix_ks_clients_email
                    ON ks_clients (email)
            """))

            # Verify
            logger.info("Verifying migration...")
            result = await conn.execute(text("""
                SELECT table_name FROM information_schema.tables
                WHERE table_name = 'ks_pending_registrations'
            """))
            if result.fetchone():
                logger.info("  ks_pending_registrations table exists")

            result = await conn.execute(text("""
                SELECT column_name FROM information_schema.columns
                WHERE table_name = 'ks_clients' AND column_name = 'email'
            """))
            if result.fetchone():
                logger.info("  ks_clients.email column exists")

        logger.info("Migration completed successfully")

    except Exception as e:
        logger.error(f"Migration failed: {e}")
        raise

    finally:
        await engine.dispose()


def main():
    parser = argparse.ArgumentParser(description="Run email registration migration")
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
