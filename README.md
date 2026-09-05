<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/atalk-lockup-dark.svg">
    <img src="docs/brand/atalk-lockup-light.svg" width="560" alt="ATalk — Agent 协作通信">
  </picture>
</p>

# ATalk

*by Gene7 — a message bus built for a family of AI agents.*

ATalk is a small, reliable message bus for AI agents (and the humans who run them).
It is built for the case where several agents live on different machines, must never
silently lose a message, and must be able to prove to each other that a message was
not only delivered but actually acted on.

**Status: early-stage / pre-release (0.3.0a1).** The server, protocol, adapters and
tooling are in daily production use by the authors. The human-facing clients are still
under development and are published here for reference only.

## What is done

- **Core communication** — JSON over HTTP, a durable event log, a server-assigned
  `id` recovery cursor, a per-source monotonic `seq`, idempotent `event_id`, and an
  SSE wake stream (`GET /stream`) so online agents react immediately while polling is
  only a recovery path.
- **`received` / `applied` dual ACK** — every event carries two acknowledgements:
  *received* (it landed in the target's inbox) and *applied* (the target actually did
  the work). Senders can query `GET /acks` for either. This is the distinction that
  makes "did you get it" and "did you do it" two different, auditable questions.
- **Raft high availability** — the `rqlite` backend runs the event log on a three-node
  Raft ledger; the SQLite backend is for single-node and development use. Both expose
  the same API and pass the same tests.
- **Authentication and authority** — per-peer tokens, token rotation with a grace
  window, device tokens with `full` or `notify` scope and single-token revocation,
  command tokens with an explicit grant table, an audit log, and an outbound target ACL
  for restricted peers.
- **Adapters** — a generic HTTP adapter, a file-inbox adapter for agents that read a
  directory, adapters for OpenClaw runtimes (persistent thread or one-shot), a
  chat-HTTP adapter for simple `/chat` services, a tmux adapter, and a stdout adapter.
  An optional `--wait-event-driven` mode keeps waiting tasks durable without polling
  the model.
- **Task, rescue and presence tooling** — a task-ledger helper (`tools/tasklib.py`),
  a whitelist-driven rescue executor (`tools/rescue_executor.py`) that runs recovery
  commands on behalf of a peer that has lost its own agent, and a presence heartbeat
  (`tools/atalk_presence.sh`). The detailed written conventions are being generalized
  and are held back from this snapshot.

## What is not done

- **Human client.** `clients/web` (a PWA) works against a running server but is
  unpolished, has no packaging, and changes often. A desktop (Electron) client
  exists in the private tree and is held back from this snapshot until generalized.
- Push notifications, multi-device UX, sent-history views, federation between
  independent ATalk deployments, and a hosted-service story. See `STATUS.md`.

## Quick start (single node, SQLite)

```bash
git clone <this repo> atalk && cd atalk
python3 -m atalk.cli --db /tmp/atalk.db init
python3 -m atalk.cli --db /tmp/atalk.db peer-add alice --token tok-alice --role agent --platform demo
python3 -m atalk.cli --db /tmp/atalk.db peer-add bob   --token tok-bob   --role agent --platform demo
python3 -m atalk.server --db /tmp/atalk.db --host 127.0.0.1 --port 7070
```

Then send, receive and acknowledge one message (the same flow is scripted in
`examples/quickstart.sh`):

```bash
curl -X POST http://127.0.0.1:7070/events -H 'Authorization: Bearer tok-alice' \
  -H 'Content-Type: application/json' \
  -d '{"source":"alice","target":"bob","type":"message","event_id":"<uuid>","payload":{"text":"hello"}}'
curl 'http://127.0.0.1:7070/events?target=bob&since_id=0&limit=10&state=pending' -H 'Authorization: Bearer tok-bob'
curl -X POST http://127.0.0.1:7070/ack -H 'Authorization: Bearer tok-bob' -H 'Content-Type: application/json' \
  -d '{"agent_id":"bob","event_id":"<uuid>","ack_type":"received"}'
```

Requires Python 3.11+ and no third-party packages. For the Raft backend install
[rqlite](https://rqlite.io), initialize the cluster schema once (see
`docs/OPERATIONS.md`), then start the server with
`--backend rqlite --rqlite-endpoints https://n1:4001,https://n2:4001,https://n3:4001`.

## Layout

| Path | Contents |
|---|---|
| `atalk/` | server, storage backends (`storage.py` SQLite, `raftsql.py` rqlite), core logic, CLI, adapters, inbox tool, `migration.py` (SQLite→rqlite tool), `schema.sql` |
| `docs/PROTOCOL.md` | wire protocol and endpoint reference |
| `docs/OPERATIONS.md` | running it as a service, backups, token rotation |
| `deploy/` | sample systemd units and timers |
| `examples/` | example env, ACL, whitelist and the quick-start script |
| `tools/` | rescue executor, task ledger helpers, presence heartbeat |
| `tests/` | unit and adapter tests (`python3 -m unittest discover -s tests`) |
| `clients/web` | early-stage human client (PWA) |

## Security

Tokens are bearer secrets: keep them in `0600` env files, never on a command line.
See `SECURITY.md` for the threat model, what is and is not protected, and how to
report a vulnerability.

## License

MIT, Copyright (c) 2026 Gene7. See `LICENSE`.
