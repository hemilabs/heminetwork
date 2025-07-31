-- Copyright (c) 2025 Hemi Labs, Inc.
-- Use of this source code is governed by the MIT License,
-- which can be found in the LICENSE file.

BEGIN;

UPDATE version SET version = 16;

ALTER TABLE pop_basis DROP CONSTRAINT pop_basis_btc_block_hash_fkey;

-- upon a re-org, set all references to deleted btc block to NULL, then delete those rows via a trigger

ALTER TABLE pop_basis ADD CONSTRAINT pop_basis_btc_block_hash_fkey FOREIGN KEY (btc_block_hash) REFERENCES btc_blocks (hash) ON UPDATE SET NULL;

CREATE FUNCTION clean_pop_basis() RETURNS TRIGGER AS $clean_pop_basis$
    BEGIN
        DELETE FROM pop_basis WHERE btc_block_hash IS NULL;
        RETURN NULL;
    END;
$clean_pop_basis$ LANGUAGE plpgsql;

CREATE TRIGGER btc_blocks_clean AFTER INSERT OR UPDATE OR DELETE 
	ON btc_blocks EXECUTE FUNCTION clean_pop_basis();

COMMIT;
