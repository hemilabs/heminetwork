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
CREATE INDEX block_headers_height_index ON block_headers (height);

-- blocks table
CREATE TABLE blocks (
	hash		BYTEA PRIMARY KEY UNIQUE NOT NULL,
	block		BYTEA NOT NULL,
	created_at	TIMESTAMP NOT NULL DEFAULT NOW(),

	CONSTRAINT blocks_foreign FOREIGN KEY(hash) REFERENCES block_headers(hash),
	CONSTRAINT blocks_hash_length CHECK (octet_length(hash) = 32)
);

-- peers table
-- probably add a score based on throughput/latency/misbehavior/flapping etc
CREATE TABLE peers (
	address		TEXT NOT NULL,
	port		TEXT NOT NULL,
	last_at		TIMESTAMP,
	created_at	TIMESTAMP NOT NULL DEFAULT NOW(),

	CONSTRAINT address_length CHECK (octet_length(address) < 80)
);
CREATE INDEX peers_index ON peers (address);

COMMIT;
