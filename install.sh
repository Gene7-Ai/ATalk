#!/bin/bash
# ATalk Community one-command installer (Linux + systemd, Python >= 3.11).
#   Install: curl -fsSL https://atalk.ai/install.sh | sudo bash -s -- [tag]
#   Uninstall and keep the ledger: sudo bash install.sh --uninstall
#   Purge including the ledger: sudo bash install.sh --purge
# Downloads and verifies the release, installs it under /opt/atalk/<tag>,
# initializes the ledger once, and requires HTTP 200 from /readiness.
set -euo pipefail
DL=${ATALK_DL:-https://atalk.ai/dl}; MODE=install; TAG=; TELEMETRY_FLAGS=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --uninstall) MODE=uninstall ;;
    --purge) MODE=purge ;;
    --telemetry|--no-telemetry) TELEMETRY_FLAGS+=("$1") ;;
    --*) echo "unknown option: $1"; exit 2 ;;
    *) [ -z "$TAG" ] || { echo "unexpected argument: $1"; exit 2; }; TAG=$1 ;;
  esac
  shift
done
TAG=${TAG:-v0.3.0a6}
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([a-z][a-z0-9]*|-rc[0-9]+)?$ ]] || { echo "invalid tag: $TAG"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }
TELEMETRY_ON=0
if [[ " ${TELEMETRY_FLAGS[*]} " == *" --no-telemetry "* ]]; then
  TELEMETRY_ON=0
elif [[ " ${TELEMETRY_FLAGS[*]} " == *" --telemetry "* ]] || [ "${ATALK_TELEMETRY:-}" = 1 ]; then
  TELEMETRY_ON=1
fi
if [ "$MODE" = install ] && [ "$TELEMETRY_ON" = 1 ]; then
  echo "telemetry: ON — sends version/platform/random install id (pseudonymous) to https://t.atalk.ai once; disable with --no-telemetry"
fi
diag(){ echo "--- diagnostics"; systemctl status atalk --no-pager 2>&1 | tail -5; journalctl -u atalk -n 20 --no-pager 2>&1 | tail -20; }
if [ "$MODE" != install ]; then
  if [ -d /run/systemd/system ]; then systemctl disable --now atalk 2>/dev/null || true; fi
  rm -f /etc/systemd/system/atalk.service; if [ -d /run/systemd/system ]; then systemctl daemon-reload; fi; rm -rf /opt/atalk
  if [ "$MODE" = purge ]; then rm -rf /var/lib/atalk; userdel atalk 2>/dev/null || true; echo "ATalk purged (ledger deleted)"; else echo "ATalk uninstalled; ledger kept at /var/lib/atalk (use --purge to delete)"; fi; exit 0
fi
python3 -c 'import sys; sys.exit(0 if sys.version_info>=(3,11) else 1)' || { echo "need python3 >= 3.11"; exit 2; }
command -v curl >/dev/null && command -v sha256sum >/dev/null || { echo "need curl and sha256sum"; exit 2; }
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
curl -fsSL "$DL/atalk-community-$TAG.tar.gz" -o "$W/atalk-community-$TAG.tar.gz"
curl -fsSL "$DL/SHA256SUMS" -o "$W/SHA256SUMS"
( cd "$W" && grep " atalk-community-$TAG.tar.gz\$" SHA256SUMS > SUMS.one && sha256sum -c --quiet SUMS.one ) || { echo "checksum verification FAILED for atalk-community-$TAG.tar.gz — aborting, nothing installed"; exit 3; }
echo "checksum ok"
id atalk >/dev/null 2>&1 || useradd -r -d /var/lib/atalk -s /usr/sbin/nologin atalk
install -d -m 750 -o atalk -g atalk /var/lib/atalk; install -d -m 755 /opt/atalk
WAS_INSTALLED=0; [ -L /opt/atalk/current ] && WAS_INSTALLED=1
rm -rf "/opt/atalk/$TAG.new"; mkdir -p "/opt/atalk/$TAG.new"; tar -xzf "$W/atalk-community-$TAG.tar.gz" --strip-components=1 -C "/opt/atalk/$TAG.new"
[ -f "/opt/atalk/$TAG.new/atalk/server.py" ] || { echo "unexpected archive layout"; exit 3; }
rm -rf "/opt/atalk/$TAG"; mv "/opt/atalk/$TAG.new" "/opt/atalk/$TAG"; chown -R root:root "/opt/atalk/$TAG"; chmod -R a+rX,go-w "/opt/atalk/$TAG"
PREV=$(readlink /opt/atalk/current 2>/dev/null || true); ln -sfn "/opt/atalk/$TAG" /opt/atalk/current
# run a command as the atalk user: runuser (util-linux) if present, else su. AS_ATALK_HINT mirrors it for printed commands.
if command -v runuser >/dev/null 2>&1; then as_atalk() { runuser -u atalk -- "$@"; }; AS_ATALK_HINT="runuser -u atalk -- "
else as_atalk() { su -s /bin/sh atalk -c "$*"; }; AS_ATALK_HINT="su -s /bin/sh atalk -c '"; fi
hint() { if [ "$AS_ATALK_HINT" = "runuser -u atalk -- " ]; then echo "runuser -u atalk -- $*"; else echo "su -s /bin/sh atalk -c '$*'"; fi; }
[ -f /var/lib/atalk/atalk.db ] || as_atalk env PYTHONPATH=/opt/atalk/current python3 -m atalk.cli --db /var/lib/atalk/atalk.db init >/dev/null
send_telemetry() {
  local event=i helper=/opt/atalk/current/deploy/telemetry.sh
  [ "$WAS_INSTALLED" = 1 ] && event=u
  if [ ! -f "$helper" ]; then
    local script_dir
    script_dir=$(cd "$(dirname "$0")" 2>/dev/null && pwd || true)
    helper=$script_dir/deploy/telemetry.sh
  fi
  [ -f "$helper" ] && /bin/sh "$helper" "$event" "$TAG" "${TELEMETRY_FLAGS[@]}" >/dev/null 2>&1 || true
}
if [ ! -d /run/systemd/system ]; then
  echo "ATalk $TAG files installed (/opt/atalk/current, ledger /var/lib/atalk/atalk.db) but systemd is not running here (container?)."
  echo "Start manually: $(hint env PYTHONPATH=/opt/atalk/current python3 -m atalk.server --backend sqlite --db /var/lib/atalk/atalk.db --host 127.0.0.1 --port 7070)"
  # Files-only setup has not passed /readiness, so it is not counted as a
  # successful installation event.
  exit 0
fi
cat > /etc/systemd/system/atalk.service <<UNIT
[Unit]
Description=ATalk Community server (single node, SQLite)
After=network-online.target
[Service]
User=atalk
Group=atalk
Environment=PYTHONPATH=/opt/atalk/current
ExecStart=/usr/bin/python3 -m atalk.server --backend sqlite --db /var/lib/atalk/atalk.db --host 127.0.0.1 --port 7070
Restart=always
RestartSec=3
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/atalk
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload && systemctl enable --now atalk >/dev/null 2>&1; systemctl restart atalk
for i in $(seq 1 20); do R=$(curl -s -m 2 -o /dev/null -w '%{http_code}' http://127.0.0.1:7070/readiness || true); [ "$R" = 200 ] && break; sleep 0.5; done
if [ "${R:-}" != 200 ]; then echo "install FAILED: /readiness returned ${R:-none}"; diag; if [ -n "$PREV" ] && [ -d "$PREV" ]; then ln -sfn "$PREV" /opt/atalk/current; systemctl restart atalk; echo "rolled back to $PREV (ledger untouched)"; fi; exit 4; fi
send_telemetry
echo "ATalk $TAG installed: readiness 200 on 127.0.0.1:7070. Ledger: /var/lib/atalk/atalk.db. Add a peer: $(hint env PYTHONPATH=/opt/atalk/current python3 -m atalk.cli --db /var/lib/atalk/atalk.db peer-add '<name>' --token '<token>' --role agent --platform '<platform>')"
