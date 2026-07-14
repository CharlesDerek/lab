#!/usr/bin/env bash
set -euo pipefail

API_BASE="${PAPERCLIP_API_BASE:-http://127.0.0.1:3100}"
COMPANY_ID="${PAPERCLIP_COMPANY_ID:-42dfe421-d219-47df-8f22-6a1785ddbdd5}"
NEUROPLEXIS_AGENT_ID="${NEUROPLEXIS_AGENT_ID:-7dff9753-4fdf-431d-8a92-5b94c740e11b}"
ROUTINE_TEMPLATE="${ROUTINE_TEMPLATE:-paperclip/routines/neuroplexis-lab-maintenance-routine.json}"
TRIGGER_TEMPLATE="${TRIGGER_TEMPLATE:-paperclip/routines/neuroplexis-lab-maintenance-trigger.json}"

tmp_payload="$(mktemp)"
create_output="$(mktemp)"
trap 'rm -f "$tmp_payload" "$create_output"' EXIT

python3 - "$ROUTINE_TEMPLATE" "$NEUROPLEXIS_AGENT_ID" >"$tmp_payload" <<'PY'
import json
import sys

template_path, agent_id = sys.argv[1], sys.argv[2]
with open(template_path, "r", encoding="utf-8") as handle:
    payload = json.load(handle)
payload["assigneeAgentId"] = agent_id
json.dump(payload, sys.stdout)
PY

npx --registry https://registry.npmjs.org paperclipai routine create \
  --api-base "$API_BASE" \
  --company-id "$COMPANY_ID" \
  --payload-json "$(cat "$tmp_payload")" \
  --json | tee "$create_output"

routine_id="$(python3 - "$create_output" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    data = json.load(handle)

for key in ("id", "routineId"):
    value = data.get(key)
    if value:
        print(value)
        raise SystemExit

routine = data.get("routine")
if isinstance(routine, dict) and routine.get("id"):
    print(routine["id"])
    raise SystemExit

raise SystemExit("could not find routine id in create response")
PY
)"

npx --registry https://registry.npmjs.org paperclipai routine trigger:create "$routine_id" \
  --api-base "$API_BASE" \
  --payload-json "$(cat "$TRIGGER_TEMPLATE")" \
  --json

printf '\nCreated Neuroplexis routine %s with a 6-hour schedule.\n' "$routine_id"

