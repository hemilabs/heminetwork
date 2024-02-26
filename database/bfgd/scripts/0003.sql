BEGIN;

UPDATE version SET version = 3;

CREATE TABLE access_public_keys (
    public_key BYTEA NOT NULL PRIMARY KEY CHECK (LENGTH(public_key) = 33),
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

COMMIT;
