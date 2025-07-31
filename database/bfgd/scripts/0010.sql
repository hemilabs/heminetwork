-- Copyright (c) 2024 Hemi Labs, Inc.
-- Use of this source code is governed by the MIT License,
-- which can be found in the LICENSE file.

BEGIN;

UPDATE version SET version = 10;

CREATE INDEX IF NOT EXISTS btc_transaction_broadcast_request_created_at_retry_desc 
    ON btc_transaction_broadcast_request  (last_broadcast_attempt_at, created_at DESC) WHERE next_broadcast_attempt_at IS NOT NULL AND broadcast_at IS NULL;

COMMIT;
