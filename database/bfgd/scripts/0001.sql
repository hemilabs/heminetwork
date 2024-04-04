-- Copyright (c) 2024 Hemi Labs, Inc.
-- Use of this source code is governed by the MIT License,
-- which can be found in the LICENSE file.

BEGIN;

-- Create database version
CREATE TABLE version (version INTEGER UNIQUE NOT NULL);

-- Populate version
INSERT INTO version (version) VALUES (1);

-- Create L2 keystone table
CREATE TABLE l2_keystones(
	l2_keystone_abrev_hash	BYTEA PRIMARY KEY NOT NULL,
	version			INTEGER NOT NULL,
	l1_block_number		BIGINT NOT NULL,
	l2_block_number		BIGINT NOT NULL,
	parent_ep_hash		BYTEA NOT NULL,
	prev_keystone_ep_hash	BYTEA NOT NULL,
	state_root		BYTEA NOT NULL,
	ep_hash			BYTEA NOT NULL,
	created_at		TIMESTAMP NOT NULL DEFAULT NOW(),
	updated_at		TIMESTAMP,

	CONSTRAINT l2_keystone_abrev_hash_length CHECK (octet_length(l2_keystone_abrev_hash) = 32),
	CONSTRAINT parent_ep_hash_length CHECK (octet_length(parent_ep_hash) = 32),
	CONSTRAINT prev_keystone_ep_hash_length CHECK (octet_length( prev_keystone_ep_hash) = 32),
	CONSTRAINT state_root_length CHECK (octet_length(state_root) = 32),
	CONSTRAINT ep_hash_length CHECK (octet_length(ep_hash) = 32)
);

-- Create btc blocks table
CREATE TABLE btc_blocks(
	hash		BYTEA PRIMARY KEY UNIQUE NOT NULL,
	header		BYTEA NOT NULL,
	height		BIGINT NOT NULL,
	created_at	TIMESTAMP NOT NULL DEFAULT NOW(),
	updated_at	TIMESTAMP,

	CONSTRAINT btc_blocks_hash UNIQUE (hash, header),
	CONSTRAINT hash_length CHECK (octet_length(hash) = 32),
	CONSTRAINT header_length CHECK (octet_length(header) = 80)
);

-- Create pop data table
CREATE TABLE pop_basis(
	id			BIGSERIAL PRIMARY KEY NOT NULL,
        btc_txid                BYTEA NOT NULL,
        btc_raw_tx              BYTEA NOT NULL,
        btc_block_hash          BYTEA REFERENCES btc_blocks(hash) DEFAULT NULL,
        btc_tx_index            BIGINT DEFAULT NULL,
        btc_merkle_path         JSON DEFAULT NULL,
        pop_txid                BYTEA DEFAULT NULL,
        l2_keystone_abrev_hash  BYTEA NOT NULL,
        pop_miner_public_key    BYTEA NOT NULL,
        created_at              TIMESTAMP NOT NULL DEFAULT NOW(),
        updated_at              TIMESTAMP,

        UNIQUE (btc_txid, btc_raw_tx, btc_block_hash, btc_tx_index),

        CONSTRAINT btc_txid_length CHECK (octet_length(btc_txid) = 32),
        CONSTRAINT pop_txid_length CHECK (pop_txid IS NOT NULL OR octet_length(pop_txid) = 32)
);

CREATE UNIQUE INDEX btc_txid_unconfirmed ON pop_basis (btc_txid) WHERE (btc_block_hash IS NULL);

COMMIT;
