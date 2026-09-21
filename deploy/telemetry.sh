#!/bin/sh
# Best-effort, opt-in ATalk installation telemetry.
# Usage: telemetry.sh i|u VERSION [--telemetry|--no-telemetry]

event=${1:-}
version=${2:-}
shift 2 2>/dev/null || exit 0

case "$event" in i|u) ;; *) exit 0 ;; esac

telemetry_yes=0
telemetry_no=0
for arg in "$@"; do
  case "$arg" in
    --telemetry) telemetry_yes=1 ;;
    --no-telemetry) telemetry_no=1 ;;
  esac
done

# Precedence: --no-telemetry, --telemetry, ATALK_TELEMETRY=1, default off.
if [ "$telemetry_no" = 1 ]; then
  exit 0
elif [ "$telemetry_yes" != 1 ] && [ "${ATALK_TELEMETRY:-}" != 1 ]; then
  exit 0
fi

# This private override exists only so offline tests never touch host state.
if [ -n "${_ATALK_TELEMETRY_ID_FILE:-}" ]; then
  id_file=$_ATALK_TELEMETRY_ID_FILE
elif mkdir -p /etc/atalk 2>/dev/null && [ -w /etc/atalk ]; then
  id_file=/etc/atalk/install_id
else
  state_home=${XDG_STATE_HOME:-${HOME:-}/.local/state}
  [ -n "$state_home" ] || exit 0
  id_file=$state_home/atalk/install_id
fi

umask 077
mkdir -p "$(dirname "$id_file")" 2>/dev/null || exit 0
install_id=
if [ -f "$id_file" ]; then
  IFS= read -r install_id < "$id_file" || true
fi
if ! printf '%s\n' "$install_id" | grep -Eq \
  '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'; then
    if [ -r /proc/sys/kernel/random/uuid ]; then
      IFS= read -r install_id < /proc/sys/kernel/random/uuid || exit 0
    elif command -v uuidgen >/dev/null 2>&1; then
      install_id=$(uuidgen) || exit 0
    elif command -v python3 >/dev/null 2>&1; then
      install_id=$(python3 -c 'import uuid; print(uuid.uuid4())') || exit 0
    else
      exit 0
    fi
    (umask 077; printf '%s\n' "$install_id" > "$id_file") 2>/dev/null || exit 0
fi
chmod 600 "$id_file" 2>/dev/null || exit 0

os=$(uname -s 2>/dev/null | tr '[:upper:]' '[:lower:]') || exit 0
arch=$(uname -m 2>/dev/null) || exit 0
platform=$os/$arch
mode=${ATALK_TELEMETRY_MODE:-script-tar}
case "$mode" in script-tar|docker) ;; *) mode=script-tar ;; esac

# Installer tags and uname values are constrained to JSON-safe characters; the UUID
# and mode are generated/allowlisted above. There are intentionally only four keys.
payload=$(printf '{"version":"%s","platform":"%s","install_id":"%s","mode":"%s"}' \
  "$version" "$platform" "$install_id" "$mode")

curl --max-time 3 --retry 0 -sS -o /dev/null \
  -H 'Content-Type: application/json' -X POST \
  --data "$payload" "https://t.atalk.ai/$event" >/dev/null 2>&1 || true
exit 0
