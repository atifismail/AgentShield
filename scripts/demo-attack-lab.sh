#!/usr/bin/env bash
# Walks through the demo attack scenarios described in docs/demo-lab.md against a
# running AgentShield instance. Requires curl and jq.
#
# Usage: ./scripts/demo-attack-lab.sh [base_url]
set -euo pipefail

BASE_URL="${1:-http://localhost:8080}"
CODING_AGENT_TOKEN="demo-token-coding-agent-01"
SUPPORT_AGENT_TOKEN="demo-token-support-assistant-01"
RETIRED_AGENT_TOKEN="demo-token-retired-agent-01"

section() { echo; echo "=== $1 ==="; }

invoke() {
  local token="$1"; shift
  curl -s -X POST "$BASE_URL/api/gateway/invoke" \
    -H "Authorization: Bearer $token" \
    -H "Content-Type: application/json" \
    -d "$1"
}

section "Scenario 0: allowed baseline call (mock-git commit)"
invoke "$CODING_AGENT_TOKEN" '{
  "toolId": "mock-git", "action": "commit", "actionCategory": "WRITE", "targetEnvironment": "DEV",
  "input": {"message": "demo commit"}, "context": {"userId": "demo-user"}
}' | jq .

section "Scenario 1: tool schema drift is detected and blocked"
TOOL_ID=$(curl -s "$BASE_URL/api/tools" -u admin:changeit | jq '.[] | select(.name=="mock-git") | .id')
curl -s -X POST "$BASE_URL/api/tools/$TOOL_ID/refresh" -u admin:changeit -H "Content-Type: application/json" \
  -d '{"schemaJson": "{\"actions\":[\"commit\",\"push\",\"createBranch\",\"forcePush\"]}", "description": "Mock Git tool (schema changed)"}' | jq .
echo "-- now the same call is denied for drift --"
invoke "$CODING_AGENT_TOKEN" '{
  "toolId": "mock-git", "action": "commit", "actionCategory": "WRITE", "targetEnvironment": "DEV",
  "input": {"message": "demo commit"}, "context": {"userId": "demo-user"}
}' | jq .
echo "-- re-approve the new version to unblock it --"
curl -s -X POST "$BASE_URL/api/tools/$TOOL_ID/approve" -u admin:changeit -H "Content-Type: application/json" \
  -d '{"decidedBy": "demo-admin"}' | jq .

section "Scenario 2: production destructive action is denied outright"
invoke "$CODING_AGENT_TOKEN" '{
  "toolId": "mock-database", "action": "deleteRecords", "actionCategory": "DESTRUCTIVE", "targetEnvironment": "PROD",
  "input": {"table": "users", "where": "status = '"'"'inactive'"'"'"}, "context": {"userId": "demo-user"}
}' | jq .

section "Scenario 3: secret-like response is blocked (after approval, on execution)"
RESP=$(invoke "$CODING_AGENT_TOKEN" '{
  "toolId": "mock-database", "action": "query", "actionCategory": "EXTERNAL_TRANSFER", "targetEnvironment": "DEV",
  "input": {"table": "internal_credentials"}, "context": {"userId": "demo-user"}
}')
echo "$RESP" | jq .
APPROVAL_ID=$(echo "$RESP" | jq -r '.approvalRequestId')
echo "-- security analyst approves, execution then gets blocked by the secret scanner --"
curl -s -X POST "$BASE_URL/api/approvals/$APPROVAL_ID/approve" -u admin:changeit -H "Content-Type: application/json" \
  -d '{"decidedBy": "demo-security-analyst"}' | jq .

section "Scenario 4: prompt-injected tool response is blocked"
invoke "$CODING_AGENT_TOKEN" '{
  "toolId": "mock-filesystem", "action": "readFile", "actionCategory": "READ", "targetEnvironment": "DEV",
  "input": {"path": "notes/shared-todo.txt"}, "context": {"userId": "demo-user"}
}' | jq .

section "Scenario 5: external transfer requires human approval"
invoke "$SUPPORT_AGENT_TOKEN" '{
  "toolId": "mock-saas-crm", "action": "exportRecords", "actionCategory": "EXTERNAL_TRANSFER", "targetEnvironment": "PROD",
  "input": {"segment": "all-customers"}, "context": {"userId": "demo-user"}
}' | jq .

section "Scenario 6: tool misuse — agent calls a tool outside its allowed group"
echo "-- support-assistant-01 is only allowed the 'saas' tool group; it tries mock-git ('source-control') --"
invoke "$SUPPORT_AGENT_TOKEN" '{
  "toolId": "mock-git", "action": "push", "actionCategory": "WRITE", "targetEnvironment": "DEV",
  "input": {}, "context": {"userId": "demo-user"}
}' | jq .

section "Scenario 7: identity and privilege abuse — a disabled agent's credential is still rejected"
echo "-- retired-agent-01 is DISABLED; its credential still hashes correctly but the agent status blocks it --"
invoke "$RETIRED_AGENT_TOKEN" '{
  "toolId": "mock-filesystem", "action": "readFile", "actionCategory": "READ", "targetEnvironment": "DEV",
  "input": {"path": "notes/shared-todo.txt"}, "context": {"userId": "demo-user"}
}' | jq .

section "Scenario 8: agentic supply-chain vulnerability — provenance record for a tool"
TOOL_ID=$(curl -s "$BASE_URL/api/tools" -u admin:changeit | jq '.[] | select(.name=="mock-git") | .id')
echo "-- every tool version gets an automatic Level-1 checksum record on discovery, regardless of source type --"
curl -s "$BASE_URL/api/tools/$TOOL_ID/provenance" -u admin:changeit | jq .
echo "-- Level 2 (Sigstore signature verification) is opt-in per ToolSourceType (agentshield.provenance.require-signature-for)"
echo "   and out of scope for a scripted demo without a real signing key — see docs/api.md 'Supply-chain provenance'."

section "Scenario 9: unexpected code execution attempt — stdio MCP transport is closed by default"
echo "-- registering a STDIO-transport MCP server (local subprocess execution) is rejected unless"
echo "   agentshield.stdio.enabled=true is explicitly set, which this demo deployment does not set --"
curl -s -X POST "$BASE_URL/api/mcp-servers" -u admin:changeit -H "Content-Type: application/json" \
  -d '{"name": "attempted-stdio-server", "transportType": "STDIO", "command": "bash", "args": "-c \"echo pwned\"", "toolGroup": "mcp"}' | jq .

echo
echo "Done. Check the Incidents and Audit pages in the UI to see what these scenarios recorded."
