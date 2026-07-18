-- Tamper-evident audit log (improvement_plan.md #4): each event's hash covers its own content
-- plus the previous event's hash, forming a chain. Modifying or deleting a historical row
-- breaks the chain from that point forward, which AuditIntegrityService.verifyChain() detects.
ALTER TABLE audit_events ADD COLUMN event_hash VARCHAR(64);
ALTER TABLE audit_events ADD COLUMN previous_event_hash VARCHAR(64);
ALTER TABLE audit_events ADD COLUMN hash_algorithm VARCHAR(32);
