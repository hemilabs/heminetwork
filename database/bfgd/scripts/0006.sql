BEGIN;

UPDATE version SET version = 6;

CREATE TRIGGER l2_keystones_changed AFTER INSERT
	ON l2_keystones FOR EACH STATEMENT EXECUTE PROCEDURE notify_event();

COMMIT;