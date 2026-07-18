-- See postgresql/V3__add_request_body_json.sql for rationale.
ALTER TABLE gateway_requests ADD COLUMN request_body_json LONGTEXT;
