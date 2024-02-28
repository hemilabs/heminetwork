BEGIN;

UPDATE version SET version = 7;

-- btc header hashs maps block height to potentially multiple hashes
CREATE TABLE btc_header_hash (
	hash		BYTEA PRIMARY KEY UNIQUE NOT NULL,
	height		BIGINT NOT NULL,
	created_at	TIMESTAMP NOT NULL DEFAULT NOW(),

	CONSTRAINT btc_header_hash UNIQUE (hash, header),
	CONSTRAINT btc_header_hash_hash_length CHECK (octet_length(hash) = 32),
);
CREATE INDEX btc_header_hash_height  ON btc_header_hash (height);

COMMIT;
