-- request_summary stays as a truncated, UI-friendly preview. request_body_json holds the
-- complete, untruncated normalized input so approval replay never executes a different or
-- incomplete payload than what the agent originally sent (improvement_plan.md #1).
ALTER TABLE gateway_requests ADD COLUMN request_body_json TEXT;
