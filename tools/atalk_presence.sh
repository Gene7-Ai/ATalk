#!/bin/bash
# ATalk presence heartbeat. A peer periodically broadcasts a liveness event so others
# can show it online. Disable with: systemctl --user disable --now atalk-presence.timer
AGENT="${ATALK_AGENT:?set ATALK_AGENT}"
set -a; . "/etc/atalk/atalk-$AGENT.env"; set +a
BASE=$(echo "$ATALK_URL" | cut -d, -f1)
DEPTH=$(curl -s -m 5 "$BASE/health" -H "Authorization: Bearer $ATALK_TOKEN" | python3 -c "import json,sys;print(json.load(sys.stdin)['inbox_depths'].get('$AGENT',0))" 2>/dev/null || echo "?")
curl -s -m 8 -X POST "$BASE/events" -H "Authorization: Bearer $ATALK_TOKEN" -H 'Content-Type: application/json' -d "{
  \"source\":\"$AGENT\",\"target\":\"*\",\"type\":\"presence\",\"requires_ack\":false,
  \"payload\":{\"kind\":\"heartbeat\",\"host\":\"$(hostname)\",\"runtime\":\"claude-code\",\"model\":\"\",
    \"paths\":[\"hs\",\"lan\"],\"backlog\":{\"depth\":$DEPTH},
    \"capabilities\":{\"read\":true,\"write\":true,\"exec\":true}}}" >/dev/null
