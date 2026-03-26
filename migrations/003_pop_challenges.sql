-- Migration 003: Proof of Possession challenge-response for key upload
-- Adds ks_challenges table so public keys can only be uploaded after the
-- uploader proves real-time access to the corresponding ML-DSA private key.

-- Challenges are single-use and expire after KEYSERVER_CHALLENGE_TTL_MINUTES (default 10 min).
-- Consumed atomically via UPDATE...WHERE used=FALSE AND expires_at>NOW()...RETURNING nonce.
CREATE TABLE IF NOT EXISTS ks_challenges (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    nonce            VARCHAR(64) NOT NULL UNIQUE,   -- 32-byte hex; UNIQUE prevents collision reuse
    client_id        VARCHAR(64) NOT NULL,
    fingerprint_hint VARCHAR(100),                  -- logging only, not validated
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at       TIMESTAMPTZ NOT NULL,
    used             BOOLEAN     NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS ix_ks_challenges_client_id
    ON ks_challenges (client_id);

-- Indexed for efficient lazy cleanup: DELETE WHERE expires_at < NOW() OR used = TRUE
CREATE INDEX IF NOT EXISTS ix_ks_challenges_expires_at
    ON ks_challenges (expires_at);
