-- Copyright (c) 2024 Hemi Labs, Inc.
-- Use of this source code is governed by the MIT License,
-- which can be found in the LICENSE file.

BEGIN;

UPDATE version SET version = 7;

DROP TRIGGER btc_blocks_canonical_refresh_l2_keystones ON l2_keystones;

DROP TRIGGER btc_blocks_canonical_refresh_pop_basis ON pop_basis;

COMMIT;
