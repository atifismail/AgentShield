-- See postgresql/V5__audit_hash_chain.sql for rationale.
ALTER TABLE audit_events ADD COLUMN event_hash VARCHAR(64);
ALTER TABLE audit_events ADD COLUMN previous_event_hash VARCHAR(64);
ALTER TABLE audit_events ADD COLUMN hash_algorithm VARCHAR(32);
