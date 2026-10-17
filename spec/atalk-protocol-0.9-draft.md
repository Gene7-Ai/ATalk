# ATalk Protocol 0.9 (Draft for Comment)

Status: **draft for public comment**. Not frozen. Version 1.0 will be frozen only after
the spec, the reference implementation and the conformance suite agree, and
comments received during the comment period have documented resolutions.

License: this specification text is licensed under CC BY 4.0
(https://creativecommons.org/licenses/by/4.0/). Code, examples and tests in the ATalk
repository, including code snippets embedded in this document, are MIT
(https://opensource.org/license/mit). Neither license provides an additional express
patent grant or any trademark license; the "ATalk" name and marks are not covered.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as
described in RFC 2119. Every normative requirement in sections 3 to 10 carries an
identifier (for example `ATP-DLV-03`) that the conformance suite references. Text
without an identifier, including the Overview, tables, Section 11, Section 12 and the
appendices, is informative.

## 1. Scope

ATalk is a durable message bus for software agents. This document specifies the
wire behavior between a **peer** (an agent or client) and an ATalk **server**:
how events are written, read, acknowledged and recovered.

Out of scope for 0.9:

- federation between independently owned servers;
- human-facing clients;
- server internals such as storage engines and consensus.

A server may be a single node or a replicated cluster (informative).

- `ATP-GEN-01` The wire behavior in this document MUST be the same whether the server is a single node or a replicated cluster.

## 2. Terms

- **Peer**: a named identity (for example `alice`) that writes and reads events.
- **Event**: an immutable record written by one peer (the source) for one peer or for all peers (the target).
- **Ledger**: the server's durable, append-only store of events and acknowledgements.
- **Cursor**: the server-assigned integer `id` of an event, used to resume reading.
- **Receipt / ACK**: a record that a peer has `received` or `applied` an event.

## 3. Event model

An event as returned by the server is a JSON object with these fields:

| Field | Type | Meaning |
|---|---|---|
| `id` | integer | Server-assigned cursor. Strictly increasing in commit order. |
| `event_id` | string | Globally unique, caller-chosen or server-generated idempotency key. |
| `source` | string | Writing peer. |
| `target` | string | Receiving peer, or `"*"` for broadcast. |
| `type` | string | Default `"message"`. `"command"` has extra rules (§7). |
| `seq` | integer | Per-source sequence number. |
| `created_at` | string | Caller-supplied creation time (ISO 8601), if any. |
| `stored_at` | string | Server commit time (ISO 8601). |
| `payload` | object | Application content. |
| `requires_ack` | boolean | Whether the event counts toward the target's backlog. Default `true`. |
| `source_ref` | string or null | Caller-supplied audit metadata. **Not** proof of origin. |
| `auth_actor` | string or null | Identity the server authenticated for authorized commands. |

- `ATP-EVT-01` `id` MUST be strictly increasing in commit order across the whole ledger.
- `ATP-EVT-02` `event_id` MUST identify at most one event in the ledger.
- `ATP-EVT-03` `seq` MUST be monotonic per source. A target MAY observe gaps, because the same source also writes to other targets. `seq` is for ordering and audit, not for recovery.
- `ATP-EVT-04` Once committed, an event's fields MUST NOT change. The protocol has no delete operation.
- `ATP-EVT-05` `source_ref` MUST NOT be treated by the server or by peers as authentication.

## 4. Endpoints

All bodies are JSON (UTF-8).

- `ATP-GEN-02` Request bodies MUST be JSON objects; anything else MUST be rejected with HTTP 400.

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Operator health snapshot |
| GET | `/readiness` | Orchestrator readiness |
| POST | `/events` | Write an event |
| GET | `/events?target=&since_id=&limit=&state=` | Read events for a target |
| GET | `/stream?agent=` | Server-Sent Events wake channel |
| POST | `/ack` | Write a receipt |
| GET | `/acks?event_id=&agent=` | Read receipts for an event |

### 4.1 POST /events

Request: `source`, `target` (required, non-empty strings), and optionally `type`, `payload` (object), `event_id`, `seq`, `created_at`, `requires_ack`, `source_ref`.

- `ATP-WR-01` On success the server MUST return HTTP 201 with the stored event. 201 means the event is durably committed to the ledger.
- `ATP-WR-02` If `event_id` already exists with the same `source`, `target` and `type`, the server MUST return the originally stored event and MUST NOT create a second one (idempotent retry).
- `ATP-WR-03` If `event_id` already exists with a different `source`, `target` or `type`, the server MUST reject with HTTP 409 and MUST NOT reveal the existing event's content.
- `ATP-WR-04` A rejected write MUST NOT create a partial event, consume a `seq`, or produce a receipt.
- `ATP-WR-05` A non-object `payload` or an empty `source`/`target` MUST be rejected with HTTP 400.
- `ATP-WR-06` A request body larger than the server's limit MUST be rejected with HTTP 413. The reference limit is 1 MiB.

### 4.2 GET /events

Parameters: `target`, `since_id` (default 0), `limit` (default 100, accepted range 1–1000; the reference server returns at most 500 per page), `state` = `pending` (default) or `all`.

- `ATP-RD-01` The server MUST return events with `id > since_id` whose target is `target` or `"*"`, in ascending `id` order.
- `ATP-RD-02` With `state=pending`, the server MUST exclude events for which `target` has written an `applied` receipt. With `state=all`, it MUST include them.
- `ATP-RD-03` The server MAY return fewer events than `limit`. Peers MUST page by advancing `since_id` to the last returned `id`, and MUST NOT treat a short page as "no more events" unless it is empty.
- `ATP-RD-04` Unknown query parameters MUST be rejected with HTTP 400.
- `ATP-RD-05` When authentication is enabled, `target` MUST be present and MUST match the token's peer; otherwise the server MUST reject with HTTP 403.
- `ATP-RD-06` A server MAY allow `GET /events` without `target` only in development mode (no peer has ever been registered); it then lists the whole ledger in `id` order and treats `state` as `all`. This mode MUST NOT be reachable once authentication is enabled.

### 4.3 GET /stream (wake channel)

The stream is `text/event-stream`. Each message is one `data:` line holding a JSON object with a `kind` field:

- `ready`: sent once, immediately after the connection opens;
- `event`: a new event for this agent (carries `event`);
- `keepalive`: sent when idle (the reference server sends one about every 25 s);
- `revoked`: the agent's token is no longer valid; the server then closes the stream.

- `ATP-SSE-01` The server MUST send `ready` before any other message on a new connection.
- `ATP-SSE-02` The stream is a hint only. The server MAY drop `event` messages, for example to a slow consumer. Peers MUST NOT rely on the stream for delivery.
- `ATP-SSE-03` If the agent's token is revoked or expires, the server MUST stop delivering and SHOULD send `revoked` before closing.

### 4.4 POST /ack and GET /acks

`POST /ack` body: `agent_id`, `event_id`, `ack_type` (`received` or `applied`), optional `detail` (object).

- `ATP-ACK-01` `ack_type` values other than `received` and `applied` MUST be rejected with HTTP 400.
- `ATP-ACK-02` Writing the same (`event_id`, `agent_id`, `ack_type`) again MUST NOT create a second receipt. The server MAY update its time and detail.
- `ATP-ACK-03` `received` means the peer has durably taken custody of the event. `applied` means the peer has finished handling it. Peers MUST NOT write `applied` before the work is done.
- `ATP-ACK-04` When authentication is enabled, `GET /acks` MUST return receipts only to a party of the event: its source, its target, or any peer for a broadcast. (This governs reading receipts, not writing them.)
- `ATP-ACK-05` A receipt MUST be written only by the event's target, or by any peer for a broadcast event. A receipt for an event that does not exist MUST be rejected with HTTP 404; a receipt from a peer that is not a recipient MUST be rejected with HTTP 403. A rejected receipt MUST have no side effects.

## 5. Delivery contract (peer side)

A conforming peer:

Conforming peers MUST satisfy each of `ATP-DLV-01` through `ATP-DLV-06`.

1. `ATP-DLV-01` subscribes to `/stream`;
2. `ATP-DLV-02` on `ready`, on any `event`, on reconnect and on startup, pulls `/events` from its last persisted cursor before trusting later wake messages; **and also reconciles periodically with `GET /events` even when no wake message arrives**, draining pages until an empty page;
3. `ATP-DLV-03` writes `received` before dispatching an event to its handler;
4. `ATP-DLV-04` handles each event idempotently, keyed by `event_id`;
5. `ATP-DLV-05` writes `applied` after handling, then advances and atomically persists its cursor. Advancing the cursor MUST NOT skip any earlier delivered event unless that event is durably kept locally for recovery (for example a local inbox with its own handling cursor); peers are not required to handle events one at a time;
6. `ATP-DLV-06` derives any reply's `event_id` deterministically from the request, so that a crash between replying and acknowledging cannot produce two different replies.

Together these give at-least-once delivery with idempotent handling, **provided** the server is eventually reachable, the peer keeps retrying, unhandled events stay within retention, and the peer does not lose its persisted recovery state. **The protocol does not promise exactly-once delivery.**

## 6. Authentication

- `ATP-AUTH-01` Once any peer is registered, every event write, ACK write, inbox read and stream connection MUST present that peer's bearer token in `Authorization: Bearer <token>`. Otherwise the server MUST reject with HTTP 403.
- `ATP-AUTH-02` A token authenticates exactly one peer. A write whose `source` (or ACK whose `agent_id`) is not the token's peer MUST be rejected.
- `ATP-AUTH-03` A server MAY run without authentication only while no peer is registered (development mode).
- `ATP-AUTH-04` A server MAY restrict which targets a source may write to (an outbound allowlist). A restricted source MUST NOT be allowed to broadcast. If the allowlist configuration exists but cannot be read, the server MUST deny writes (fail closed).

## 7. Commands

An event with `type: "command"` asks the target to perform an action.

- `ATP-CMD-01` A command MUST carry a non-empty `source_ref` and a valid source token.
- `ATP-CMD-02` A command MUST be accepted only if the target has issued an active grant to the source for the command's `payload.op` (or for all ops). The grant must not be revoked, must be within its validity time, and every key/value constraint in the grant's scope MUST equal the corresponding payload value; additional payload keys are permitted. How grants are issued is out of band in 0.9.
- `ATP-CMD-03` A token alone MUST NOT grant command authority.
- `ATP-CMD-04` Every command that reaches the authorization decision MUST be audited, whether accepted or rejected. For an accepted command, the authorization check, the event write and the accept audit record MUST commit in one atomic transaction. A rejected command MUST NOT write an event; its reject audit record is written separately. (Requests rejected earlier for format, authentication, ACL or capacity reasons are not required to produce a command audit record in 0.9.)

## 8. Errors

Error responses are JSON objects with an `error` string. Storage errors also carry `code` and `retryable`.

| Status | Meaning | Peer action |
|---|---|---|
| 400 | Malformed request | Fix the request. Do not retry unchanged. |
| 403 | Not authenticated, not authorized, or rejected by ACL/grant | Do not retry unchanged. |
| 404 | Unknown path or event | Do not retry. |
| 409 | `event_id` reused for a different event | Choose a new `event_id`. |
| 413 | Body too large | Shrink the payload. |
| 429 | Target backlog limit reached | Keep the event with its original `event_id`; back off and retry. |
| 503 | Ledger unreadable, storage I/O error (`storage_io_error`), or no quorum in a replicated server | Retry later with the same `event_id`. |
| 507 | Storage full (`storage_full`) | Retry later with the same `event_id`. |

- `ATP-ERR-01` When the server returns 429, or returns 503/507 for a failure it detected before commit, it MUST NOT have committed the event. In every uncertain case (timeouts, lost responses, other 5xx), peers MUST retry with the same `event_id`, and such a retry MUST be safe.
- `ATP-ERR-02` A replicated server that cannot reach a majority MUST refuse writes (503). It MUST NOT accept a write that could later be lost.

## 9. Capacity and retention

- `ATP-CAP-01` A server MAY limit each target's backlog: events with `requires_ack: true` that the target has not `applied`. Writes over the limit MUST be rejected with 429. An idempotent retry of an already-stored event MUST NOT be rejected by this limit.
- `ATP-CAP-02` A server MAY archive old events. It MUST NOT archive or delete an event before every expected `applied` receipt exists, and MUST keep the audit log.
- The reference server's backlog limit is 1000 and its retention setting defaults to 30 days.

## 10. Health

- `ATP-HLT-01` `GET /health` SHOULD always return 200 while the process can answer, and report `ok: false` / `status: "degraded"` when writes are failing.
- `ATP-HLT-02` `GET /readiness` MUST return 503 only when the ledger cannot be read. A readable server with full storage stays ready, so that orchestrators do not restart it in a loop.

## 11. Versioning

- The protocol version is independent of software versions. ATalk 0.3.0a7 (commit dec3312) is the implementation baseline used to inform this draft; **it is not certified conformant**. Known deviations and proposed changes are listed in Appendix A.
- The 14-day comment rule applies from the publication of this 0.9 draft onward.
- Breaking changes happen only in a major version. Changes are proposed as public issues and stay open for comment for at least 14 days.

## 12. Security considerations

- The ledger records what peers said, not what they did. An `applied` receipt is the receiver's authenticated claim. It is not cryptographically signed in 0.9, and it is not proof of execution. Applications that need proof should attach evidence signed by a third party (for example a CI system or sandbox attestation) and verify it on the requester side.
- Treat `payload` from other peers as untrusted input, especially when it is an instruction.
- Bearer tokens should be rotated. The reference server accepts a previous token for a short grace period after rotation.

## Appendix A. Reference implementation vs. this draft (informative)

Baseline: ATalk 0.3.0a7, commit dec3312, SQLite backend. Items were checked by reading the source and by isolated core-level probes, not by an HTTP black-box suite. Other backends were not checked.

### A.1 Actual deviations (implementation does not meet this draft)

1. **Receipt writes are not checked against the recipient (`ATP-ACK-05`).** The server authenticates `agent_id` but does not verify that the event exists or that the agent is a recipient. On SQLite, a receipt for a non-existent event is blocked by a foreign key, but the server answers HTTP 500 instead of 404. A receipt for an existing event from a non-recipient is accepted. To be fixed in code.
2. **Caller-supplied `seq` is not checked (`ATP-EVT-03`).** A source can write `seq` 10 and then 5. Options: enforce, inside the write transaction, that a new `seq` exceeds the source's high-water mark (idempotent retries excepted), or let only the server assign `seq`. Open for comment.
3. **`payload: null` is accepted (`ATP-WR-05`)** and stored as `{}`. Either reject it or define `null` as equivalent to omitting the field.
4. **Token in the request body.** The server also accepts the token as a `token` field in the request body and does not strictly require the `Bearer` prefix. This is a non-standard legacy extension; conforming peers use the `Authorization` header (see `ATP-AUTH-01`).
5. **Invalid numeric or `state` query values** can raise an unhandled error instead of a stable HTTP 400.

### A.2 Proposed changes for 1.0 (current draft and implementation agree)

1. **Idempotency including payload.** Today a retry with the same `event_id`, `source`, `target` and `type` but a different `payload` returns the original event, which matches `ATP-WR-02`. Proposal: compare the payload too and return 409 on mismatch. This needs a definition of JSON equality (key order, number forms) and of which metadata takes part.
2. **Page size.** The HTTP layer accepts `limit` up to 1000 while the reference server returns at most 500. This is allowed by `ATP-RD-03`. Proposal: document a single maximum.

### A.3 Not yet specified

- Archival boundaries: which recipients count as "expected" for broadcasts, peers registered later, revoked peers and `requires_ack: false`; and what a peer gets back when its cursor points before the archive boundary.
- Commit certainty after network failure in replicated deployments, where the server may have committed but the response was lost. Peers should always retry with the same `event_id`.

## Appendix B. Conformance suite (planned, first batch)

A black-box HTTP test suite will reference the IDs above. Inputs are a server URL and two peer tokens. Every test reports exactly one of PASS, FAIL, or NOT RUN (with a reason). Passing the first batch does not mean full compatibility. A report must list which IDs were covered and which were not.

Tests for 429, 503 and 507 need fixtures (a target with a small backlog limit, a small storage quota, a three-node cluster with a stoppable node). Where no fixture is available, the test is NOT RUN.
