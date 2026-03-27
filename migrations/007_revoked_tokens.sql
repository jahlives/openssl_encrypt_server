-- Migration 007: Create persistent token revocation table
-- Addresses finding #4: in-memory revocation store lost on server restart.
-- Revoked JTIs are now persisted to survive restarts.

CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti VARCHAR(32) PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for efficient cleanup of expired records
CREATE INDEX IF NOT EXISTS ix_revoked_tokens_expires_at
    ON revoked_tokens (expires_at);

COMMENT ON TABLE revoked_tokens IS 'Persistent store for revoked JWT token IDs. Entries kept until original token expiry, then cleaned up.';
