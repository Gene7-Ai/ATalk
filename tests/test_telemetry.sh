#!/bin/bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
HELPER=$ROOT/deploy/telemetry.sh
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/state"

cat > "$TMP/bin/curl" <<'MOCK'
#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in
    --data) shift; printf '%s\n' "$1" > "$MOCK_CURL_PAYLOAD" ;;
    https://*) printf '%s\n' "$1" >> "$MOCK_CURL_LOG" ;;
  esac
  shift
done
exit "${MOCK_CURL_EXIT:-0}"
MOCK
chmod +x "$TMP/bin/curl"

export PATH="$TMP/bin:$PATH"
export MOCK_CURL_LOG="$TMP/curl.log"
export MOCK_CURL_PAYLOAD="$TMP/payload.json"
export _ATALK_TELEMETRY_ID_FILE="$TMP/state/install_id"
unset ATALK_TELEMETRY ATALK_TELEMETRY_MODE

run() { "$HELPER" "$@" >"$TMP/stdout" 2>"$TMP/stderr"; }
count() { [ -f "$MOCK_CURL_LOG" ] && wc -l < "$MOCK_CURL_LOG" || printf '0\n'; }
clear_log() { : > "$MOCK_CURL_LOG"; }
assert_count() { [ "$(count)" -eq "$1" ] || { echo "expected $1 posts, got $(count)"; exit 1; }; }

# Default is off.
run i v0.3.0a4
assert_count 0

# Explicit flags outrank the environment, and --no-telemetry always wins.
ATALK_TELEMETRY=1 run i v0.3.0a4 --no-telemetry
assert_count 0
run i v0.3.0a4 --telemetry --no-telemetry
assert_count 0
run i v0.3.0a4 --telemetry
assert_count 1
clear_log
ATALK_TELEMETRY=1 run i v0.3.0a4
assert_count 1

# Fresh and upgrade events use distinct endpoints.
grep -q 'https://t.atalk.ai/i' "$MOCK_CURL_LOG"
clear_log
run u v0.3.0a4 --telemetry
assert_count 1
grep -q 'https://t.atalk.ai/u' "$MOCK_CURL_LOG"

# A failed telemetry request is silent and returns success to its installer caller.
clear_log
MOCK_CURL_EXIT=28 run i v0.3.0a4 --telemetry
assert_count 1
[ ! -s "$TMP/stdout" ] && [ ! -s "$TMP/stderr" ]

# Inspect the mocked request without using a network.
python3 - "$MOCK_CURL_PAYLOAD" "$TMP/state/install_id" <<'PY'
import json, pathlib, stat, sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert set(payload) == {"version", "platform", "install_id", "mode"}, payload
assert payload["version"] == "v0.3.0a4"
assert "/" in payload["platform"]
assert payload["mode"] == "script-tar"
id_path = pathlib.Path(sys.argv[2])
assert payload["install_id"] == id_path.read_text().strip()
assert stat.S_IMODE(id_path.stat().st_mode) == 0o600
PY

# The persistent identifier must never be printed.
install_id=$(cat "$TMP/state/install_id")
! grep -R -F "$install_id" "$TMP/stdout" "$TMP/stderr"

# Docker consumers reuse the same implementation and change only the mode.
clear_log
ATALK_TELEMETRY_MODE=docker run i v0.3.0a4 --telemetry
grep -q '"mode":"docker"' "$MOCK_CURL_PAYLOAD"

echo "telemetry tests: ok"
