-- Copyright (c) 2024 Hemi Labs, Inc.
-- Use of this source code is governed by the MIT License,
-- which can be found in the LICENSE file.

BEGIN;

UPDATE version SET version = 9;

CREATE INDEX btc_blocks_can_hash_idx ON btc_blocks_can (hash);
CREATE INDEX btc_blocks_can_height_idx ON btc_blocks_can (height);

COMMIT;
