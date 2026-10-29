"""Subprocess server driver for the r4 flag-off equivalence / no-nacl
startup tests (r4 F1/P1).  NOT a pytest module (leading underscore, never
collected): it is executed as a script by test subprocesses only.

Usage:
    python _r4_flagoff_driver.py <source-root> <state-dir> <host> <port>

Inserts <source-root> at sys.path[0], starts the plain flag-off HTTP server
(the exact pre-federation wiring: AtalkStore + AtalkHTTPServer + a missing
message-ACL path), prints READY, and serves until terminated.  Works
unchanged against older trees (e.g. base ed9973d) because it only uses the
constructor surface that exists in both (federation_config defaults to
None where the parameter exists at all).

The parent chooses the environment: it must strip ATALK_FEDERATION for the
flag-off runs and may set it (plus the peers/identity paths) for the
flag-on fail-closed runs.
"""
import sys
import threading
from pathlib import Path

source_root, state_dir, host, port = sys.argv[1:5]
sys.path.insert(0, source_root)

from atalk.core import AtalkStore  # noqa: E402
from atalk.server import AtalkHTTPServer, MessageAcl, WakeHub  # noqa: E402

state = Path(state_dir)
store = AtalkStore(state / "atalk.db")
server = AtalkHTTPServer((host, int(port)), store, WakeHub())
server.message_acl = MessageAcl(path=str(state / "missing-acl.json"))
print("READY", flush=True)
threading.Thread(target=server.serve_forever, daemon=True).start()
while True:
    threading.Event().wait(3600)
