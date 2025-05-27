-- Copyright (c) 2025 Hemi Labs, Inc.
-- Use of this source code is governed by the MIT License,
-- which can be found in the LICENSE file.

BEGIN;

UPDATE version SET version = 18;

ALTER TABLE l2_keystones ADD COLUMN lowest_btc_block_effective_height INT NOT NULL DEFAULT 0;
ALTER TABLE l2_keystones ADD COLUMN lowest_btc_block_hash BYTEA NULL REFERENCES btc_blocks (hash) ON DELETE SET NULL ON UPDATE SET NULL;

COMMIT;

