BEGIN;

-- Create database version
CREATE TABLE version (version INTEGER UNIQUE NOT NULL);

-- Populate version
INSERT INTO version (version) VALUES (1);

-- btc hash height maps blocks to their height to potentially multiple hashes
CREATE TABLE btc_hash_height (
	hash		BYTEA PRIMARY KEY UNIQUE NOT NULL,
	height		BIGINT NOT NULL,
	created_at	TIMESTAMP NOT NULL DEFAULT NOW(),

	CONSTRAINT btc_hash_height_contraint UNIQUE (hash, height),
	CONSTRAINT btc_hash_height_hash_length CHECK (octet_length(hash) = 32)
);
CREATE INDEX btc_hash_height_index  ON btc_hash_height (height);

COMMIT;
