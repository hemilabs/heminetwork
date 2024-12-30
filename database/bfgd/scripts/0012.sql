-- Copyright (c) 2024 Hemi Labs, Inc.
-- Use of this source code is governed by the MIT License,
-- which can be found in the LICENSE file.
BEGIN;
UPDATE version
SET version = 12;
CREATE MATERIALIZED VIEW btc_finality AS
SELECT btc_blocks_can.hash,
    COALESCE(btc_blocks_can.height, 0) AS height,
    l2_keystones.l2_keystone_abrev_hash,
    l2_keystones.l1_block_number,
    l2_keystones.l2_block_number,
    l2_keystones.parent_ep_hash,
    l2_keystones.prev_keystone_ep_hash,
    l2_keystones.state_root,
    l2_keystones.ep_hash,
    l2_keystones.version,
    COALESCE(
        (
            SELECT height
            FROM (
                    SELECT height
                    FROM btc_blocks_can
                        INNER JOIN pop_basis ON pop_basis.btc_block_hash = btc_blocks_can.hash
                        INNER JOIN l2_keystones ll ON ll.l2_keystone_abrev_hash = pop_basis.l2_keystone_abrev_hash
                    WHERE ll.l2_block_number >= l2_keystones.l2_block_number
                        AND height > (
                            SELECT height
                            FROM btc_blocks_can
                            ORDER BY height DESC
                            LIMIT 1
                        ) - 100
                    ORDER BY height ASC
                    LIMIT 1
                )
        ), 0
    ) AS effective_height, COALESCE(
        (
            SELECT height
            FROM btc_blocks_can
            ORDER BY height DESC
            LIMIT 1
        ), 0
    ) AS tip_height
FROM l2_keystones
    LEFT JOIN LATERAL (
        SELECT hash,
            height
        FROM btc_blocks_can
            INNER JOIN pop_basis ON btc_blocks_can.hash = pop_basis.btc_block_hash
            AND pop_basis.l2_keystone_abrev_hash = l2_keystones.l2_keystone_abrev_hash
        ORDER BY btc_blocks_can.height ASC
        LIMIT 1
    ) AS btc_blocks_can ON TRUE;
CREATE INDEX btc_finality_l2_keystone_abrev_hash  ON btc_finality (l2_keystone_abrev_hash);

CREATE FUNCTION refresh_btc_finality()
    RETURNS TRIGGER
    LANGUAGE PLPGSQL
AS
$$
BEGIN
    REFRESH MATERIALIZED VIEW btc_finality;
    RETURN NEW;
END;
$$;

CREATE TRIGGER btc_finality_refresh_btc_blocks AFTER INSERT OR UPDATE
	ON btc_blocks FOR EACH STATEMENT EXECUTE PROCEDURE refresh_btc_finality();

CREATE TRIGGER btc_finality_refresh_l2_keystones AFTER INSERT OR UPDATE
	ON l2_keystones FOR EACH STATEMENT EXECUTE PROCEDURE refresh_btc_finality();

CREATE TRIGGER btc_finality_refresh_pop_basis AFTER INSERT OR UPDATE
	ON pop_basis FOR EACH STATEMENT EXECUTE PROCEDURE refresh_btc_finality();


ALTER TABLE l2_keystones 
ADD COLUMN oldest_published_btc_block_hash BYTEA NULL,
ADD CONSTRAINT oldest_published_btc_block_hash CHECK (octet_length(oldest_published_btc_block_hash) = 32);

COMMIT;