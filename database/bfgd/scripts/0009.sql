-- Copyright (c) 2024 Hemi Labs, Inc.
-- Use of this source code is governed by the MIT License,
-- which can be found in the LICENSE file.

BEGIN;

UPDATE version SET version = 9;

CREATE INDEX btc_blocks_can_hash_idx ON btc_blocks_can (hash);
CREATE INDEX btc_blocks_can_height_idx ON btc_blocks_can (height);

CREATE TABLE btc_transaction_broadcast_request (
    tx_id			            TEXT PRIMARY KEY NOT NULL,
    serialized_tx               BYTEA NOT NULL,
    broadcast_at                TIMESTAMP,
    last_broadcast_attempt_at   TIMESTAMP,
    next_broadcast_attempt_at   TIMESTAMP,
    created_at                  TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX ON btc_transaction_broadcast_request (last_broadcast_attempt_at) WHERE  broadcast_at IS NULL;

COMMIT;
