# Atalk protocol v0.1

Atalk uses JSON over HTTP and a durable SQLite event log. The server-assigned
integer `id` is the recovery cursor. `event_id` is the globally idempotent
identity and `(source, seq)` preserves source ordering.

## Endpoints

- `GET /health`
- `POST /events`
- `GET /events?target=<agent>&since_id=<id>&limit=<n>&state=pending|all`
- `GET /stream?agent=<agent>` (SSE wake signal)
- `POST /ack` with `received` or `applied`
- `GET /acks?event_id=<uuid>&agent=<caller>`

`target="*"` is broadcast. Broadcast events appear in every agent inbox and
wake every connected stream.

Peers with an outbound target ACL are restricted to its explicit targets for
all non-command events; broadcasts are denied. Peers without an ACL retain the
existing unrestricted behavior. Commands remain governed solely by
`peer_grants`.

`id` is the global delivery/recovery cursor. `seq` is monotonic per source and
is used for source ordering/audit, not inbox recovery; a target can legitimately
observe gaps because that source also sent events to other targets.

The default `state=pending` inbox excludes events after that target writes an
`applied` ACK, so the operational inbox converges. `state=all` is an explicit
history/recovery view and includes applied events retained in the event log.

## Delivery contract

1. Subscribe to `/stream`.
2. On `ready`, `event`, reconnect, or startup, pull `/events` using the last
   atomically persisted server `id`.
3. Write `received` ACK before dispatch.
4. Apply the event idempotently.
5. Write `applied` ACK, then advance the local cursor.

The SSE stream is never the source of truth. Lost wake signals are harmless;
cursor polling recovers all committed events. Adapter replies derive a stable
UUID from the request event, so a crash between reply and `applied` ACK cannot
duplicate the reply.

On every stream connection the server emits `ready`; the adapter immediately
pulls `/events?since_id=<last_applied_id>` before trusting later wake signals.
This provides replay plus live delivery without a race between the two phases.

### Local-only inbox delivery

An inbox-only peer uses a separate delivery cursor:

1. Pull after an SSE wake or reconnect.
2. Atomically write the full event to its private local `pending/` directory.
3. After file and directory fsync succeed, write `received`.
4. Advance the delivery cursor and continue receiving later events.
5. Only after a local human or local model handles the event, write `applied`
   and move the file to `applied/`.

Inbox delivery must not invoke cloud model APIs, messaging platforms, or other
public-network services. It remains functional when external Internet access
is unavailable.

## Authentication

Development mode is open only while the peer registry is empty. Once any live
peer exists, every inbox, stream, event write, and ACK write requires that
peer's bearer token. Use separate tokens per peer.

Commands require all of: a valid source token, a non-empty `source_ref`, and an
active target-issued `peer_grants` entry matching source, target, command `op`,
optional exact-match scope, validity time, and revocation state. The target is
the grantor; possession of a peer token alone never grants command authority.
Accepted and rejected commands are written to the audit log.

`source_ref` is audit metadata supplied by the caller. It is not authentication
and must never be described or relied on as proof of origin. A future verified
reference may be added only where Atalk can independently check the upstream
record (for example, a Telegram message id fetched by a trusted verifier).

`peer-rotate` creates a new token while accepting the previous token for a
bounded grace interval (default five minutes). Peer capability metadata records
`delivery_class` (`fast`, `normal`, or `slow`) and a peer-specific ACK timeout;
external peers must not be judged by inner-fabric latency.

## Capacity and retention

The server rejects new direct events with HTTP 429 when a target reaches the
configured unapplied inbox limit (`--max-inbox-depth`, default 1000). Health
reports expose per-peer depth so senders/operators can back off. The schema
stores `retention_days` (default 30); archival must export only fully applied
events before deletion, while preserving the audit log.
