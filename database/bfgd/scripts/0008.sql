-- Copyright (c) 2024 Hemi Labs, Inc.
-- Use of this source code is governed by the MIT License,
-- which can be found in the LICENSE file.

BEGIN;

UPDATE version SET version = 8;

CREATE INDEX btc_blocks_header_prev_hash_idx ON btc_blocks (substr(header, 5, 32));

COMMIT;
