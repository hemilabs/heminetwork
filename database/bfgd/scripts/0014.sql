-- Copyright (c) 2025 Hemi Labs, Inc.
-- Use of this source code is governed by the MIT License,
-- which can be found in the LICENSE file.

BEGIN;

UPDATE version SET version = 14;

DROP TABLE l2_keystones_lowest_btc_block;

DROP TRIGGER pop_basis_upsert ON pop_basis;

COMMIT;
