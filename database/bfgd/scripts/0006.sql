-- Copyright (c) 2024 Hemi Labs, Inc.
-- Use of this source code is governed by the MIT License,
-- which can be found in the LICENSE file.

BEGIN;

UPDATE version SET version = 6;

CREATE TRIGGER l2_keystones_changed AFTER INSERT
	ON l2_keystones FOR EACH STATEMENT EXECUTE PROCEDURE notify_event();

COMMIT;