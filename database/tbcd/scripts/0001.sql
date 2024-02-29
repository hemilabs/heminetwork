BEGIN;

-- Create database version
CREATE TABLE version (version INTEGER UNIQUE NOT NULL);

-- Populate version
INSERT INTO version (version) VALUES (1);

-- btc hash height maps blocks to their height to potentially multiple hashes
CREATE TABLE block_headers (
	hash		BYTEA PRIMARY KEY UNIQUE NOT NULL,
	height		BIGINT NOT NULL,
	header		BYTEA UNIQUE NOT NULL,
	created_at	TIMESTAMP NOT NULL DEFAULT NOW(),

	CONSTRAINT block_headers_hash_height UNIQUE (hash, height),
	CONSTRAINT block_headers_hash_length CHECK (octet_length(hash) = 32),
	CONSTRAINT block_headers_header_length CHECK (octet_length(header) = 80)
);
CREATE INDEX block_headers_height_index  ON block_headers (height);

COMMIT;
