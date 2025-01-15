-- Copyright (c) 2025 Hemi Labs, Inc.
-- Use of this source code is governed by the MIT License,
-- which can be found in the LICENSE file.

BEGIN;

UPDATE version SET version = 15;

DROP TRIGGER btc_blocks_canonical_refresh_btc_blocks ON btc_blocks;

DROP FUNCTION refresh_btc_blocks_can();

-- no longer have BFG responsible for the canonical chain
DROP MATERIALIZED VIEW btc_blocks_can;


-- we now trust electrs/bitcoind to maintain the best chain, height becomes
-- unique in this table
ALTER TABLE btc_blocks ADD UNIQUE (height);

-- when a btc block becomes "invalid" (orphaned), delete it and all pop_bases 
-- that referenced it
ALTER TABLE pop_basis DROP CONSTRAINT pop_basis_btc_block_hash_fkey;
ALTER TABLE pop_basis ADD CONSTRAINT pop_basis_btc_block_hash_fkey FOREIGN KEY (btc_block_hash) REFERENCES btc_blocks (hash) ON UPDATE CASCADE;

COMMIT;