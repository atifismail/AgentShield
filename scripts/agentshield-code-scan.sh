#!/usr/bin/env bash
# Thin CLI client for AgentShield's AI-coding-assistant risk manager (improvement_plan.md A4).
#
# This is NOT a SAST engine and does not try to be one. It does two narrow things:
#   1. Greps the target directory for a small set of secret-shaped patterns (kept in sync by hand
#      with com.agentshield.risk.SecretDetector's patterns — if that class gains a pattern, add
#      the equivalent grep here too).
#   2. Parses one dependency manifest (package.json, pom.xml, or build.gradle/build.gradle.kts —
#      whichever is found first, in that order) for a flat list of declared dependencies.
# It then POSTs a scan-result "assessment" to AgentShield, which applies policy (block on any
# HIGH/CRITICAL finding — a found secret is always HIGH) and, if the assessment passes, issues a
# signed receipt. Real SAST, license-compliance checking, and dependency-vulnerability scanning
# are out of scope for this script — wire a real scanner's output into the same
# POST /api/codetrust/assessments payload shape if you need that.
#
# Usage: ./scripts/agentshield-code-scan.sh [target_dir] [base_url]
# Env:   AGENTSHIELD_USER / AGENTSHIELD_PASSWORD (Basic Auth; defaults to the demo admin/changeit)
#        AGENTSHIELD_REPO, AGENTSHIELD_BRANCH, AGENTSHIELD_COMMIT_SHA, AGENTSHIELD_AUTHOR
#        (default to values read from git in target_dir, where available)
set -euo pipefail

TARGET_DIR="${1:-.}"
BASE_URL="${2:-http://localhost:8080}"
AUTH_USER="${AGENTSHIELD_USER:-admin}"
AUTH_PASSWORD="${AGENTSHIELD_PASSWORD:-changeit}"

cd "$TARGET_DIR"

REPO="${AGENTSHIELD_REPO:-$(git config --get remote.origin.url 2>/dev/null || basename "$(pwd)")}"
BRANCH="${AGENTSHIELD_BRANCH:-$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)}"
COMMIT_SHA="${AGENTSHIELD_COMMIT_SHA:-$(git rev-parse HEAD 2>/dev/null || echo unknown)}"
AUTHOR="${AGENTSHIELD_AUTHOR:-$(git log -1 --format='%ae' 2>/dev/null || echo unknown)}"

echo "Scanning $(pwd) (repo=$REPO branch=$BRANCH commit=$COMMIT_SHA)"

FINDINGS_JSON="[]"
add_finding() {
  local file="$1" line="$2" category="$3" severity="$4" rule_id="$5" message="$6"
  FINDINGS_JSON=$(printf '%s' "$FINDINGS_JSON" | python3 -c "
import json, sys
findings = json.load(sys.stdin)
findings.append({
    'filePath': '$file', 'line': $line, 'category': '$category', 'severity': '$severity',
    'ruleId': '$rule_id', 'message': '$message'
})
print(json.dumps(findings))
" 2>/dev/null || echo "$FINDINGS_JSON")
}

# --- 1. Secret-shaped pattern grep (kept in sync by hand with SecretDetector's patterns) ---
declare -A SECRET_PATTERNS=(
  ["AKIA[0-9A-Z]{16}"]="aws-access-key-id"
  ["-----BEGIN[A-Z ]*PRIVATE KEY-----"]="pem-private-key"
  ["ghp_[A-Za-z0-9]{36}"]="github-token-like"
  ["eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"]="jwt-like"
)
echo "-- secret-pattern scan --"
for pattern in "${!SECRET_PATTERNS[@]}"; do
  rule_id="${SECRET_PATTERNS[$pattern]}"
  while IFS=: read -r file line _rest; do
    [ -z "${file:-}" ] && continue
    echo "  SECRET finding: $file:$line ($rule_id)"
    add_finding "$file" "$line" "SECRET" "CRITICAL" "$rule_id" "matched secret-shaped pattern $rule_id"
  done < <(grep -rEn --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=build --exclude-dir=target \
    "$pattern" . 2>/dev/null || true)
done

# --- 2. Dependency manifest parse (first match wins: package.json, pom.xml, build.gradle*) ---
DEP_COUNT=0
if [ -f package.json ]; then
  DEP_COUNT=$(python3 -c "
import json
data = json.load(open('package.json'))
deps = list(data.get('dependencies', {}).keys()) + list(data.get('devDependencies', {}).keys())
print(len(deps))
" 2>/dev/null || echo 0)
  echo "-- found package.json: $DEP_COUNT declared dependencies --"
elif [ -f pom.xml ]; then
  DEP_COUNT=$(grep -c '<artifactId>' pom.xml 2>/dev/null || echo 0)
  echo "-- found pom.xml: ~$DEP_COUNT declared artifacts --"
elif ls build.gradle build.gradle.kts >/dev/null 2>&1; then
  DEP_COUNT=$(grep -cE "(implementation|api|testImplementation)\(" build.gradle build.gradle.kts 2>/dev/null | awk -F: '{s+=$2} END {print s+0}')
  echo "-- found build.gradle(.kts): ~$DEP_COUNT dependency declarations --"
else
  echo "-- no recognized dependency manifest found (package.json/pom.xml/build.gradle) --"
fi

# --- 3. Submit the assessment ---
PAYLOAD=$(cat <<JSON
{
  "repo": "$REPO",
  "commitSha": "$COMMIT_SHA",
  "branch": "$BRANCH",
  "author": "$AUTHOR",
  "source": "CLI",
  "requiresRescan": false,
  "requestedBy": "$AUTHOR",
  "findings": $FINDINGS_JSON
}
JSON
)

echo "-- submitting assessment to $BASE_URL/api/codetrust/assessments --"
curl -s -X POST "$BASE_URL/api/codetrust/assessments" \
  -u "$AUTH_USER:$AUTH_PASSWORD" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD"
echo
