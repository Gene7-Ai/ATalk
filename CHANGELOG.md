# Changelog

## 0.3.0a12 (pre-release, 2026-10-29)

- Federation (experimental, default off): signed cross-instance message exchange between two self-hosted ATalk instances, enabled only by `ATALK_FEDERATION=1`; with the flag unset the server behaves byte-for-byte like a non-federation build. Federated addresses are `agent@family` targets on the existing endpoints: send via `POST /events`, pull via `GET /events?target=<agent>`, acknowledge via `POST /ack` (only the addressed recipient); peers ingest signed envelopes and receipts on `POST /federation/inbox` and `POST /federation/receipts`, and senders query returned receipts via `GET /federation/notifications` (plus `POST /federation/notifications/ack`). Admin-managed peer registry (`ATALK_FEDERATION_PEERS`, TLS-only endpoints) and an Ed25519 identity file with mode 0600 (`ATALK_FEDERATION_IDENTITY`); loopback plain-http is a test-only bypass (`ATALK_FEDERATION_ALLOW_LOOPBACK_HTTP`). Tuning knobs: `ATALK_FED_OUTBOX_CAP`, `ATALK_FED_RATE_CONN`, `ATALK_FED_RATE_FAMILY`, `ATALK_FED_WORKER_INTERVAL`, `ATALK_FED_HTTP_TIMEOUT`, `ATALK_FED_BACKOFF_BASE`, `ATALK_FED_BACKOFF_MAX`. Quickstart: `docs/federation-quickstart.md`. Status, stated honestly: self-tested between two independent self-owned instances; no third-party interop yet, and no independent cryptographic recomputation of the protocol vectors. Evidence-environment dependency digests recorded in `requirements-federation.lock` (still not a portable lock).
- Optional MCP stdio bridge for ordinary agent peers: pending/history pagination, ACK evidence, content-idempotent replies, and cancellable SSE waiting.
- Client diagnostics: explicit authorization failures and partial-result/count semantics. Server payload and installer versions are unchanged.
- Note: 0.3.0a8 through a11 were unreleased internal candidates stopped by the release gates; they are superseded by 0.3.0a12, and nothing was published under those numbers.

## 0.3.0a7 (pre-release, 2026-09-22)
- SQLite: close request-thread-local connections when each threaded HTTP request exits, preventing health probes from exhausting the process file-descriptor limit.
- Tests: cover sustained readiness probing and assert SQLite descriptors remain bounded.

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
