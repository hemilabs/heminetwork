-- Copyright (c) 2025 Hemi Labs, Inc.
-- Use of this source code is governed by the MIT License,
-- which can be found in the LICENSE file.

BEGIN;

UPDATE version SET version = 18;

-- height is unique in BFG as of now; we use electrs as our "source-of-truth"
-- for the canonical chain
ALTER TABLE l2_keystones ADD COLUMN lowest_btc_block_effective_height INT NOT NULL DEFAULT 0;
ALTER TABLE l2_keystones ADD COLUMN lowest_btc_block_hash BYTEA NULL;

COMMIT;

