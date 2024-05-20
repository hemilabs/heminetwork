-- Copyright (c) 2024 Hemi Labs, Inc.
-- Use of this source code is governed by the MIT License,
-- which can be found in the LICENSE file.

BEGIN;

UPDATE version SET version = 8;

DROP MATERIALIZED VIEW btc_blocks_can;

-- this materialized view represents the canonical btc_blocks as we know it
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

            -- try to find the parent block via header -> parent hash
			(
				substr(bb.header, 5, 32) = btc_blocks.hash 
				AND bb.height > btc_blocks.height
			)
		), __highest AS (
			SELECT height, count(*) AS c
			FROM btc_blocks
			GROUP BY height
		)
SELECT * FROM bb;

COMMIT;
