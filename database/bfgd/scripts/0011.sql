
-- Copyright (c) 2024 Hemi Labs, Inc.
-- Use of this source code is governed by the MIT License,
-- which can be found in the LICENSE file.

BEGIN;

UPDATE version SET version = 11;

CREATE INDEX pop_pasis_published_pop_txs_desc_idx ON pop_basis (l2_keystone_abrev_hash, id DESC) WHERE btc_block_hash IS NOT NULL;

COMMIT;
