-- Copyright (c) 2024 Hemi Labs, Inc.
-- Use of this source code is governed by the MIT License,
-- which can be found in the LICENSE file.

BEGIN;

UPDATE version SET version = 4;

-- Notification stored procedure
CREATE FUNCTION notify_event() RETURNS TRIGGER AS $$
	DECLARE
		data_old json;
		data_new json;
		notification json;

	BEGIN
		data_old = row_to_json(OLD);
		data_new = row_to_json(NEW);

		-- Contruct the notification as a JSON string.
		notification = json_build_object(
			'table', TG_TABLE_NAME,
			'action', TG_OP,
			'data_new', data_new,
			'data_old', data_old);

		-- Execute pg_notify(channel, notification)
		PERFORM pg_notify('events', notification::text);

		-- Result is ignored since this is an AFTER trigger
		RETURN NULL;
	END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER btc_blocks_event AFTER INSERT OR UPDATE
	ON btc_blocks FOR EACH ROW EXECUTE PROCEDURE notify_event();

COMMIT;
