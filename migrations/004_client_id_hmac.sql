-- Migration 004: Add client_id_hmac column for indexed constant-time lookups
-- Replaces full table scan in get_client_by_id with indexed HMAC-SHA256 lookup.
-- After migration, run the backfill Python script to populate existing rows.

-- Add HMAC column (nullable during migration; backfill sets values)
ALTER TABLE ks_clients
    ADD COLUMN IF NOT EXISTS client_id_hmac VARCHAR(64);

-- Index for O(1) lookups by HMAC
CREATE INDEX IF NOT EXISTS ix_ks_clients_client_id_hmac
    ON ks_clients (client_id_hmac);

COMMENT ON COLUMN ks_clients.client_id_hmac IS 'HMAC-SHA256(server_secret, client_id) for indexed lookup without full table scan';
