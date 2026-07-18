-- IncidentStatus is renamed: INVESTIGATING -> ACKNOWLEDGED, CLOSED -> RESOLVED, plus a new
-- FALSE_POSITIVE state for incidents that turn out not to be real (improvement_plan.md #11).
UPDATE incidents SET status = 'ACKNOWLEDGED' WHERE status = 'INVESTIGATING';
UPDATE incidents SET status = 'RESOLVED' WHERE status = 'CLOSED';
