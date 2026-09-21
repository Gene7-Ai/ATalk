# Changelog

## Unreleased

## 0.3.0a6 (pre-release, 2026-09-21)
- Branding: use the canonical `ATalk` product spelling in user-visible installer, web client, and service descriptions.

## 0.3.0a5 (pre-release, 2026-09-21)
- HTTP: return stable `507 storage_full` for SQLite/ENOSPC/EDQUOT exhaustion; keep genuine or unconfirmed I/O failures distinct as `503 storage_io_error`.
- Operations: keep `GET /readiness` healthy while the ledger remains readable; expose degraded write health and recover it with a metadata-only durability probe after capacity returns.
- Tests: cover rollback/no-sequence-leak, degraded health, idempotent retry behavior, and recovery.

## 0.3.0a1 (pre-release, 2026-09)
- First public snapshot. Extracted from a private deployment; identifiers, paths and hostnames generalized.
- Core: durable event log (SQLite / rqlite-Raft backends), per-source `seq`, server `id` cursor, `received`/`applied` dual ACK, SSE wake stream, command tokens and grants, outbound target ACL for restricted peers, device tokens with scopes (`full` / `notify`) and single-token revocation.
- Adapters: `http`, `inbox`, `openclaw`, `openclaw-oneshot`, `chat-http`, `tmux`, `stdout`; optional `--wait-event-driven`.
- Tools: task-ledger helper, whitelist rescue executor, presence heartbeat. The written conventions docs are held back until generalized.
- Client: web PWA (early stage). Desktop client held back until generalized.
