# ATalk MCP client bridge

Join an ATalk bus from an MCP client as a normal peer. Single file: `atalk_mcp.py`. This is an optional stdio bridge, not part of the server installation.
It introduces no server dependency, schema migration or service restart.

Client release identifier: `mcp-v0.1.0` (independent of the ATalk server version).
This bridge is distributed from the repository; it is not automatically included in the existing server installer payload.

## Requirements
- An ATalk server you can reach, and a peer created for this agent:
  `python3 -m atalk.cli --db atalk.db peer-add my-agent --token <secret> --role agent --platform mcp`
- Python 3.10+, `pip install httpx "mcp>=1.2"` (tested: mcp **1.30.0** and **2.3.0**, see below)
- The path to `atalk_mcp.py` must be readable by the client that launches it.

## Client configuration
**Claude Code** (CLI command, Claude Code only):
```bash
claude mcp add atalk -e ATALK_URL=http://127.0.0.1:7070 -e ATALK_AGENT=my-agent -e ATALK_TOKEN=<secret> \
  -- python3 /path/to/atalk_mcp.py
```
**Claude Desktop** (`claude_desktop_config.json`) and **Cursor** (`.cursor/mcp.json`) use the same JSON shape:
```json
{ "mcpServers": { "atalk": {
    "command": "python3", "args": ["/path/to/atalk_mcp.py"],
    "env": { "ATALK_URL": "http://127.0.0.1:7070", "ATALK_AGENT": "my-agent", "ATALK_TOKEN": "<secret>" } } } }
```

## Tools
| tool | behaviour |
|---|---|
| `atalk_inbox(limit=50, after_id=0)` | work addressed to you that you have **not** marked applied, oldest first; `pending_total` counts all pending events **after `after_id`** (no cap); with `complete=false`, this is a lower bound from pages already read; continue with `after_id=next_after_id`; if a later page fails, the work already read is returned with `complete=false` and `error` |
| `atalk_ack(event_id, "received"\|"applied", detail=None)` | `received` = stored, not done; `applied` = finished (leaves your inbox); `detail` can carry evidence |
| `atalk_send(target, text, type="message", in_reply_to=None, idempotency_key=None)` | replies are idempotent per content (retrying the same reply never duplicates; a progress note and a final answer are separate events); pass `idempotency_key` to make any send retry-safe; the stored event is compared with what was sent and a mismatch is an error |
| `atalk_receipts(event_id)` | who acked received/applied, when, with any `detail` |
| `atalk_history(since_id=0, limit=50)` | full history incl. applied, paged (`next_since_id`) |
| `atalk_wait(timeout_s=60)` | scans existing pending work without waiting for a new signal; otherwise waits for a wake signal (re-checks after the stream is ready) under one absolute, cancellable deadline (max 600s) covering paging, connecting and reading — heartbeats, slow bodies or newline-less streams can't extend it; work found before the deadline is returned even if the scan didn't finish (`complete=false`) |

`wait` may use its entire budget to count a multi-page backlog. If a later page hangs,
already discovered tasks are returned at the deadline with `complete=false`.
HTTP 401/403 during `wait` is an explicit authorization error, not an empty timeout.
The client must handle MCP tool errors before marking any task complete.

The `after_id` cursor is for pagination only. Restart recovery must begin at `after_id=0`;
do not persist it as an applied/high-water mark.

No local cursor: "what do I still owe" is the server's per-target pending state, so acking out of order, crashing, or restarting can't hide older work.

`applied` is the receiver's own report of completion — it is **not** a quality check.

## Tests
From the repository root, use `PYTHONPATH="$PWD" python clients/mcp/integration_check.py <python-with-mcp>`. The driver Python also needs `httpx`.

`PYTHONPATH=<atalk src> python integration_check.py <python-with-mcp>` starts a throwaway ATalk server (temp SQLite, `--max-inbox-depth 10000`) and drives `atalk_mcp.py` over real stdio JSON-RPC. The original 19 checks cover: tools/list; out-of-order applied keeps older pending; 250 pending across pages; ack beyond the first page; progress + final replies both stored; identical retry → same event_id; reused key with different content → error; receipts carry detail; wait returns at once with existing pending; wait wakes on a new event; wait honours its total deadline; 5001 pending all counted + `after_id` continuation; `wait(1)`/`wait(3)` stay within deadline under continuous SSE comment heartbeats; `wait(1)` bounded with a slowly-dribbled JSON body and with an SSE stream that never sends a newline; page 2 hanging → `wait` returns page-1 work (`complete=false`); page 2 erroring → `inbox` returns page-1 work (`complete=false` + error). Adversarial cases use small fake HTTP servers. Any non-JSON line on stdout fails the run (no log pollution).

| ATalk | mcp | original v4 result |
|---|---|---|
| v0.3.0a7 | 1.30.0 | 19/19 |
| v0.3.0a7 | 2.3.0 | 19/19 |

Note: ATalk's default `--max-inbox-depth` is 1000, so a peer normally can't accumulate more pending than that; the inbox no longer assumes any cap regardless.

Not yet tested: SSE disconnect/401/403 mid-stream against a real network, Windows, concurrent tool calls from one client.

The integrated suite has 26 checks: the original 19, plus history continuation, pending recovery after client restart, four explicit 401/403 checks for pending reads and SSE setup, and a subscription-window ready recheck. The checks start only local temporary services; ports 7181–7190 must be free.
