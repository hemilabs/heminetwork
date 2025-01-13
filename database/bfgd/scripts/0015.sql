-- Copyright (c) 2025 Hemi Labs, Inc.
-- Use of this source code is governed by the MIT License,
-- which can be found in the LICENSE file.

BEGIN;

UPDATE version SET version = 15;

-- this sql file updates the materialized view that represents the 
-- canonical chain in BFG.  we redefine the materialized view, but the change is very
-- small, I will leave a comment

DROP MATERIALIZED VIEW btc_blocks_can;

CREATE MATERIALIZED VIEW btc_blocks_can AS 

WITH RECURSIVE bb AS (
			SELECT hash, header, height FROM btc_blocks
			WHERE height = (
				SELECT MAX(height) as height
				FROM __highest
				WHERE c = 1
			)
		
			UNION 
		
			SELECT 
				btc_blocks.hash, 
				btc_blocks.header,
				btc_blocks.height
			FROM btc_blocks, bb
			WHERE 

			(
				substr(bb.header, 5, 32) = btc_blocks.hash 
				AND bb.height > btc_blocks.height
			)
			OR

			(
				btc_blocks.hash = (
				SELECT hash FROM btc_blocks 
				WHERE height < bb.height ORDER BY height DESC LIMIT 1)

                -- this is the change; ensure that we can't connect a block
                -- before resorting to the fallback.  this ensures that 
                -- BOTH results don't get included in the canonical chain
				AND NOT EXISTS (
					SELECT * FROM btc_blocks WHERE
					substr(bb.header, 5, 32) = btc_blocks.hash 
					AND bb.height > btc_blocks.height
				)
			)
		), __highest AS (
			SELECT height, count(*) AS c
			FROM btc_blocks
			GROUP BY height
		)
SELECT * FROM bb;

COMMIT;
