# Changelog

## 0.3.0a1 (pre-release, 2026-09)
- First public snapshot. Extracted from a private deployment; identifiers, paths and hostnames generalized.
- Core: durable event log (SQLite / rqlite-Raft backends), per-source `seq`, server `id` cursor, `received`/`applied` dual ACK, SSE wake stream, command tokens and grants, outbound target ACL for restricted peers, device tokens with scopes (`full` / `notify`) and single-token revocation.
- Adapters: `http`, `inbox`, `openclaw`, `openclaw-oneshot`, `chat-http`, `tmux`, `stdout`; optional `--wait-event-driven`.
- Tools: task-ledger helper, whitelist rescue executor, presence heartbeat. The written conventions docs are held back until generalized.
- Client: web PWA (early stage). Desktop client held back until generalized.
