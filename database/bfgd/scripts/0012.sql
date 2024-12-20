-- Copyright (c) 2024 Hemi Labs, Inc.
-- Use of this source code is governed by the MIT License,
-- which can be found in the LICENSE file.

BEGIN;

UPDATE version SET version = 12;

-- this materialized view represents the canonical btc_blocks as we know it
CREATE MATERIALIZED VIEW l2_keystone_lowest_btc_block AS 

SELECT l2_keystone_abrev_hash, hash, height
FROM l2_keystones
LEFT JOIN LATERAL (
    SELECT hash, height FROM btc_blocks_can
    INNER JOIN pop_basis
    ON btc_blocks_can.hash = pop_basis.btc_block_hash
    AND l2_keystone_abrev_hash = l2_keystones.l2_keystone_abrev_hash
    ORDER BY height ASC LIMIT 1
);


CREATE INDEX l2_keystone_lowest_btc_block_l2_keystone_abrev_hash_idx on l2_keystone_lowest_btc_block (l2_keystone_abrev_hash);

CREATE FUNCTION refresh_l2_keystone_lowest_btc_block()
    RETURNS TRIGGER
    LANGUAGE PLPGSQL
AS
$$
BEGIN
    REFRESH MATERIALIZED VIEW l2_keystone_lowest_btc_block;
    RETURN NEW;
END;
$$;

CREATE TRIGGER btc_blocks_canonical_refresh_pop_basis AFTER INSERT OR UPDATE
	ON pop_basis FOR EACH STATEMENT EXECUTE PROCEDURE refresh_l2_keystone_lowest_btc_block();

COMMIT;
