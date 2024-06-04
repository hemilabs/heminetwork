-- Copyright (c) 2024 Hemi Labs, Inc.
-- Use of this source code is governed by the MIT License,
-- which can be found in the LICENSE file.
BEGIN;

UPDATE version
SET version = 9;

DROP MATERIALIZED VIEW btc_blocks_can;
-- this materialized view represents the canonical btc_blocks as we know it
CREATE MATERIALIZED VIEW btc_blocks_can AS WITH RECURSIVE bb AS (
	-- define the tip as the highest block in __highest, look below 
	-- for definition of this result set
	SELECT hash,
		header,
		height
	FROM btc_blocks
	WHERE height = (
			-- give me the block at the max height with only 1 block at
			-- that height
			SELECT MAX(height) as height
			FROM __highest
			WHERE c = 1
		)
	UNION
	SELECT btc_blocks.hash,
		btc_blocks.header,
		btc_blocks.height
	FROM btc_blocks,
		bb
	WHERE -- find the parent block via header -> parent hash
		(
			substr(bb.header, 5, 32) = btc_blocks.hash
		)
),
__highest AS (
	-- use this to find the tip, creates "__highest" result set:
	-- give me the count of blocks at each height
	SELECT height,
		count(*) AS c
	FROM btc_blocks bbo -- where there exists a parent
	WHERE EXISTS (
			SELECT *
			FROM btc_blocks bbi
			WHERE substr(bbo.header, 5, 32) = bbi.hash
		) -- unless there are no parents for ANY block
		OR NOT EXISTS (
			SELECT *
			FROM btc_blocks bb1
				INNER JOIN btc_blocks bb2 ON substr(bb1.header, 5, 32) = bb2.hash
		)
	GROUP BY height
)
SELECT *
FROM bb;


-- create view to return all heights that have no children
CREATE VIEW heights_with_no_children AS
SELECT height
FROM btc_blocks bb1 
-- for all blocks, check if there exists no children
WHERE NOT EXISTS (
		SELECT *
		FROM btc_blocks bb2
		WHERE substr(bb2.header, 5, 32) = bb1.hash
	) -- then, check if there exist no other blocks at this height with children
	AND NOT EXISTS (
		SELECT *
		FROM btc_blocks bb3
		WHERE bb1.height = bb3.height
			AND EXISTS (
				SELECT *
				FROM btc_blocks bb4
				WHERE substr(bb4.header, 5, 32) = bb3.hash
			)
	) -- exclude the tip, as it will have no children by its nature
ORDER BY height DESC OFFSET 1;

-- only refresh materialized view if there are no heights without children
CREATE OR REPLACE FUNCTION refresh_btc_blocks_can() RETURNS TRIGGER LANGUAGE PLPGSQL AS $$ BEGIN IF NOT EXISTS(
		SELECT *
		FROM heights_with_no_children
	) THEN REFRESH MATERIALIZED VIEW btc_blocks_can;
END IF;
RETURN NEW;
END;
$$;
COMMIT;