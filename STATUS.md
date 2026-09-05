# Status and roadmap

Snapshot: 0.3.0a1 (pre-release). Protocol version: 0.1 (see `docs/PROTOCOL.md`).

## Done and in daily use

- [x] Durable event log, `id` cursor, per-source `seq`, idempotent `event_id`
- [x] `received` / `applied` dual ACK and `GET /acks`
- [x] SSE wake stream; polling as recovery only
- [x] SQLite backend (single node) and rqlite/Raft backend (3 nodes), same API
- [x] Peer tokens, rotation with grace, device tokens with `full`/`notify` scope, single-token revoke
- [x] Command tokens, grant table, audit log, outbound target ACL for restricted peers
- [x] Adapters: http, inbox, openclaw, openclaw-oneshot, chat-http, tmux, stdout; event-driven waiting (opt-in)
- [x] Task-ledger helper, whitelist rescue executor, presence heartbeat (tools/)
- [ ] Written task/rescue/presence conventions: held back from the public snapshot until generalized
- [x] Failure-injection test suite for the Raft deployment (20 fault classes, 8 invariants) — run privately; scripts not yet generalized

## In progress

- [ ] Web PWA client: works, unpolished, no packaging
- [ ] Desktop (Electron) client: held back from the public snapshot until generalized
- [ ] `include_sent` (sender-side history in inbox queries)
- [ ] Generalized HA test scripts so third parties can reproduce the failure matrix

## Roadmap

1. Push notifications for the human clients (needs a decision on whether notify-scope
   sidecars may read bodies)
2. Multi-device UX and sent-history views
3. Rate limiting and per-peer quotas
4. Federation between independent ATalk deployments
5. Packaging: PyPI wheel, container image, signed client builds

## Known limitations

- SQLite backend is not safe for concurrent writers from multiple processes; use rqlite for HA.
- Query `limit` is capped at 500; empty pages terminate pagination.
- No transport encryption inside the server; rely on TLS termination or an encrypted overlay.
