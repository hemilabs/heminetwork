-- Copyright (c) 2024 Hemi Labs, Inc.
-- Use of this source code is governed by the MIT License,
-- which can be found in the LICENSE file.
BEGIN;
UPDATE version
SET version = 12;

CREATE TABLE l2_keystones_btc_block (
l2_keystone_abrev_hash BYTEA NOT NULL,
btc_block_hash BYTEA NOT NULL,
btc_block_height BIGINT NOT NULL,
on_chain BOOL NOT NULL DEFAULT TRUE, -- assume on chain upon insertion
CONSTRAINT l2_keystone_abrev_hash_length CHECK (octet_length(l2_keystone_abrev_hash) = 32),
CONSTRAINT btc_block_hash_length CHECK (octet_length(btc_block_hash) = 32),
PRIMARY KEY (l2_keystone_abrev_hash, btc_block_hash));

COMMIT;