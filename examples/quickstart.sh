#!/usr/bin/env bash
# Single-node quickstart: SQLite backend, two peers, one message, two ACKs.
set -euo pipefail
export PYTHONPATH="$(cd "$(dirname "$0")/.." && pwd)"
DB=${DB:-/tmp/atalk-quickstart.db}; PORT=${PORT:-7070}
rm -f "$DB"; python3 -m atalk.cli --db "$DB" init
python3 -m atalk.cli --db "$DB" peer-add alice --token tok-alice --role agent --platform demo
python3 -m atalk.cli --db "$DB" peer-add bob   --token tok-bob   --role agent --platform demo
python3 -m atalk.server --db "$DB" --host 127.0.0.1 --port "$PORT" & SRV=$!; sleep 1
trap 'kill $SRV 2>/dev/null' EXIT
curl -s -X POST "http://127.0.0.1:$PORT/events" -H "Authorization: Bearer tok-alice" -H 'Content-Type: application/json' \
  -d '{"source":"alice","target":"bob","type":"message","event_id":"11111111-1111-4111-8111-111111111111","payload":{"text":"hello bob"}}'; echo
curl -s "http://127.0.0.1:$PORT/events?target=bob&since_id=0&limit=10&state=pending" -H "Authorization: Bearer tok-bob"; echo
curl -s -X POST "http://127.0.0.1:$PORT/ack" -H "Authorization: Bearer tok-bob" -H 'Content-Type: application/json' -d '{"agent_id":"bob","event_id":"11111111-1111-4111-8111-111111111111","ack_type":"received"}'; echo
curl -s -X POST "http://127.0.0.1:$PORT/ack" -H "Authorization: Bearer tok-bob" -H 'Content-Type: application/json' -d '{"agent_id":"bob","event_id":"11111111-1111-4111-8111-111111111111","ack_type":"applied"}'; echo
curl -s "http://127.0.0.1:$PORT/acks?event_id=11111111-1111-4111-8111-111111111111&agent=alice" -H "Authorization: Bearer tok-alice"; echo
