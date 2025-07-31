-- Copyright (c) 2025 Hemi Labs, Inc.
-- Use of this source code is governed by the MIT License,
-- which can be found in the LICENSE file.

BEGIN;

UPDATE version SET version = 13;

CREATE TABLE l2_keystones_lowest_btc_block (
    l2_keystone_abrev_hash BYTEA NOT NULL PRIMARY KEY REFERENCES l2_keystones(l2_keystone_abrev_hash),
    btc_block_hash BYTEA REFERENCES btc_blocks(hash) DEFAULT NULL,
    btc_block_height BIGINT NULL
);

CREATE TRIGGER pop_basis_upsert AFTER INSERT OR DELETE OR UPDATE
	ON pop_basis FOR EACH ROW EXECUTE PROCEDURE notify_event();

COMMIT;
