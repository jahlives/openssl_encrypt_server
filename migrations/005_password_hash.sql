-- Migration 005: Add password_hash column for password-based authentication
-- Adds a second authentication factor (password) alongside client_id.
-- NULL values indicate legacy clients that need to set a password on next login.

-- Add password_hash column (nullable for legacy client migration)
ALTER TABLE ks_clients
    ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255);

COMMENT ON COLUMN ks_clients.password_hash IS 'Argon2id hash of account password. NULL = legacy client requiring password setup.';
