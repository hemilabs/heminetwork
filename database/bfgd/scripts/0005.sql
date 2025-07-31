-- Copyright (c) 2024 Hemi Labs, Inc.
-- Use of this source code is governed by the MIT License,
-- which can be found in the LICENSE file.

BEGIN;

UPDATE version SET version = 5;

CREATE FUNCTION refresh_btc_blocks_can()
    RETURNS TRIGGER
    LANGUAGE PLPGSQL
AS
$$
BEGIN
    REFRESH MATERIALIZED VIEW btc_blocks_can;
    RETURN NEW;
END;
$$;

CREATE TRIGGER btc_blocks_canonical_refresh_btc_blocks AFTER INSERT OR UPDATE
	ON btc_blocks FOR EACH STATEMENT EXECUTE PROCEDURE refresh_btc_blocks_can();

CREATE TRIGGER btc_blocks_canonical_refresh_l2_keystones AFTER INSERT OR UPDATE
	ON l2_keystones FOR EACH STATEMENT EXECUTE PROCEDURE refresh_btc_blocks_can();

CREATE TRIGGER btc_blocks_canonical_refresh_pop_basis AFTER INSERT OR UPDATE
	ON pop_basis FOR EACH STATEMENT EXECUTE PROCEDURE refresh_btc_blocks_can();


CREATE TRIGGER access_public_keys_delete AFTER DELETE
	ON access_public_keys FOR EACH ROW EXECUTE PROCEDURE notify_event();

COMMIT;
