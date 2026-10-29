# ATalk federation v0

Implements design draft v0.4.3 (§3–§9; section numbers are stable since
v0.4.1): strict parsing, canonical bytes, strict signatures, envelope
schema, peer registry (round 1) plus endpoints, outbound delivery,
receipts, dedup/conflict/recovery and the config switch (round 2).

> "Local /ack not validating the recipient remains a known deviation of
> the 0.9 appendix A; this branch fixes it only on the ACK path for
> federated inbound events (only the addressed recipient may ACK);
> local event behavior is unchanged."
>
> Honesty statement: the tests are two self-owned instances self-tested
> over in-process loopback (loopback HTTP, two complete instances inside
> one process), not two real families in production use; no closed-loop
> verification is claimed until the tests pass and the evidence is kept.

## Module map

- `canonical.py` — `FederationError(layer, category)`; `parse_strict` (strict
  UTF-8, duplicate-key rejection, no lone surrogates, objects+strings domain,
  `[a-z_]+` keys only); `canonical_bytes` = JCS / RFC 8785 on the narrowed
  domain; canonical base64url `encode` / `decode_strict`.
- `ed25519strict.py` — `sign(seed|SigningKey, msg)`, `verify(pubkey, msg, sig)`
  with the strict acceptance list below; `FROZEN_VERSIONS` for the evidence pack.
- `schema.py` — address grammar helpers, `validate_event_envelope` /
  `validate_receipt_envelope` (§4.2–§4.3), envelope + `sig` handling (§4.4),
  `REQUEST_BODY_LIMIT` / `check_body_size` / `content_encoding_rejected`,
  and `parse_event(raw)` / `parse_receipt(raw)` (raw bytes → `Envelope`).
- `registry.py` — `federation_peers.json` loader; `PeerRegistry.lookup(family,
  key_id)` and `.receipts_peer(family)`; `load_peers` raises on any problem,
  `safe_load_peers` fails closed to an empty registry.
- `store.py` (round 2) — all federation tables, written in single immediate
  transactions; the dedup arbiter is the DB unique constraint
  (`UNIQUE(origin, event_id)`), never check-then-insert.
- `runtime.py` (round 2) — activation, local identity, token-bucket rate
  limits, the outbox/receipt worker (backoff + jitter, honors valid
  `Retry-After`, TLS verification always on, redirects never followed).

## Activation and configuration

Federation is active ONLY when **all** of these hold (fail closed; anything
else leaves `/federation/*` as unknown paths and `/events`, `/ack`, `/stream`
byte-identical to the pre-federation server, with no worker thread started):

1. env `ATALK_FEDERATION=1` (exactly `1`);
2. the peers file loads (`registry.load_peers`, raising variant — a broken
   file disables federation entirely);
3. the local identity file loads and is EXACTLY mode 600 (r4 F8: group/
   world bits AND over/under-restricted owner bits like 0400 or 0700 all
   disable federation; the JSON is parsed strictly and bounded, and every
   malformed identity file collapses to federation-off with the ordinary
   service still serving);
4. the store backend is the SQLite store (`atalk.core.AtalkStore`) — the
   rqlite backend has no federation tables; federation stays off there.

### Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `ATALK_FEDERATION` | unset | `1` enables federation (everything else = off) |
| `ATALK_FEDERATION_PEERS` | `/etc/atalk/federation_peers.json` | peer registry file (§3 format: `{family, key_id, public_key, inbox_url, receipts_url}`) |
| `ATALK_FEDERATION_IDENTITY` | `/etc/atalk/federation_identity.json` | local family identity: `{"family", "key_id", "seed"}`, seed = canonical base64url of the 32-byte Ed25519 seed; file must be exactly mode 600 (§4.7.1/§9: private key never leaves the bus host, never enters the ledger or logs) |
| `ATALK_FEDERATION_ALLOW_LOOPBACK_HTTP` | unset | `1` enables the explicit TEST-ONLY endpoint bypass: plain `http` is admitted for loopback hosts (`127.0.0.1`, `localhost`, `::1`, `*.localhost`) in the registry and the transport. Unavailable by default (r4 F2); never use outside self-owned loopback test fixtures | |
| `ATALK_FED_RATE_CONN` | `300` | connection-level inbound rate limit, requests/minute (§5.3.1, §9) |
| `ATALK_FED_RATE_FAMILY` | `60` | per registered family inbound rate limit, requests/minute, applied after signature verification (§5.3.4) |
| `ATALK_FED_OUTBOX_CAP` | `1000` | cap on pending outbound federation events; a full outbox rejects NEW sends with 429, receipts are never capped (§6.2, §9) |
| `ATALK_FED_WORKER_INTERVAL` | `1.0` | worker poll interval (seconds; tests use small values) |
| `ATALK_FED_HTTP_TIMEOUT` | `10.0` | outbound HTTP timeout (seconds) |
| `ATALK_FED_BACKOFF_BASE` | `2.0` | retry backoff base (seconds); exponential with jitter, capped at the max |
| `ATALK_FED_BACKOFF_MAX` | `300.0` | retry backoff ceiling (seconds) |

Rate limits are in-process token buckets (capacity = the per-minute rate,
continuous refill); they reset on restart and are per-instance, not global.

### Endpoints (flag on only)

`POST /federation/inbox` — §5.3 check order, exactly:
connection rate limit → raw body ≤ 16384 bytes BEFORE any parsing →
`Content-Encoding` rejected → parse/schema (round-1 API) → `(origin, key_id)`
registered → strict verify with the registered key → per-family rate limit →
type whitelist (`message`/`reply`; enforced at the schema layer, an allowed
earliest layer per §4.5) → target family == self AND target agent is an
accepted local member → dedup (§7).  Success is ONE atomic commit (dedup key
+ envelope original + registry snapshot + local logical event +
delivery-pending), then `200 {"status":"stored"}`.  Same content again:
`200 {"status":"duplicate"}` (no new local event; pending delivery still
progresses).  Same ID different content: `409 {"status":"conflict"}`,
original untouched, conflict-audit row written.  The local event carries the
verified `event.source` (e.g. `alice@org-a`) as its origin label — the
payload cannot override it; delivery goes through the normal bus path with
no command processing and no authorization-state creation; a `reply`'s
`in_reply_to` is copied into the local payload (conversational only, missing
parent still delivers).

`POST /federation/receipts` — §6.5, all six checks in order: body limit /
parse / schema / kind → `event_id` in OUR `federation_outbound` AND
`receipt.origin` == our family → `issuer` == the original target's family,
strict verify with that family's registered key (the issuer-binding check
runs BEFORE the registry lookup, so a valid signature from a registered but
wrong family cannot pass) → `origin_event_sig_hash` == SHA-256 of OUR stored
immutable original's signature bytes → `receipt.agent` == the original full
target → `ack_type` ∈ {received, applied}.  One atomic commit stores the
original(s), the merged state and a notification intent with a stable unique
ID (deterministic UUID5 — redeliveries reuse it, so the local logical
notification is created exactly once).

`POST /events` (extension) — a target that is a grammar-valid
`agent@family` whose family is registered and not ours is signed (schema
and type whitelist checked pre-sign, §5.1) and written to the outbox in ONE
persistent commit; the immutable envelope original is then sent by the
worker, byte-identical on every retry (§5.2).  An unregistered foreign
family target is rejected 400 with a clear reason.  Payloads must be
`{"text": ...}` (plus `in_reply_to` for replies, which is lifted into the
signed event field; the local `auto` flag is not federated).  Flag off:
today's behavior exactly (targets containing `@` are plain local strings).

`POST /ack` (extension) — a federation-inbound event may be ACKed ONLY by
its recipient (§6.1; local events keep current behavior).  The ACK and the
durable receipt-send intent are ONE transaction; if that commit fails the
ACK call fails.  Receipt declaration fields (including `at`) are fixed at
the FIRST ack and never updated; the signed original is persisted once and
reused verbatim; rebuild-from-ACK-record uses fixed fields only.

`GET /federation/notifications` / `POST /federation/notifications/ack`
(extension, flag on) — durable notification delivery (r4 F6, r5 F6).  A
notification row carries TWO independent states: `hint_sent` (a live SSE
subscriber queue accepted one push hint — best effort only) and `acked`
(durable completion).  Push hints are marked ONLY when a live subscriber
queue accepted the item: an offline agent, a queue overflow or a wake
exception leaves the hint unmarked, and operator rows (`agent IS NULL`,
e.g. permanent receipt-send failures) are never push-marked at all.  A
marked hint is still NOT a delivery: reconnects replace the SSE queue and
restarts empty every queue, so the pull path lists EVERY un-ACKed row —
including rows already push-hinted:

- `GET /federation/notifications?agent=X` with X's token lists X's
  unacknowledged notifications (pulling never mutates);
- `GET /federation/notifications?peer=Y` with a full-scope token for Y
  lists unacknowledged OPERATOR notifications;
- `POST /federation/notifications/ack` with
  `{"agent": X, "intent_ids": [...]}` (X's token) or `{"peer": Y,
  "intent_ids": [...]}` (Y's full-scope token; operator rows only) sets
  `acked=1` — the ONLY durable completion.  Repeat ACKs are idempotent.

Redelivery repeats the same stable intent id, so consumers dedupe (§6.6)
and the local logical notification stays exactly one row; an interrupted
hint (crash after push, reconnect before consume, restart after
enqueue+mark) stays recoverable through pull until a consumer ACKs it.
The push scan itself never contains operator rows (r5 #5: they are
pull-only — a LIMIT window full of never-markable operator rows used to
starve agent hints behind them) and walks pending agent rows via keyset
pagination whose cursor PERSISTS across cycles with wraparound (r6 #4;
bounded by a per-cycle safety budget of 5000 rows).  A backlog larger
than the budget resumes where the previous cycle stopped — it can delay
a newer row's push hint by at most one full sweep (an upper bound on
the order of ceil(backlog / budget) cycles, not an exact count — rows
ACKed mid-sweep and budget interactions can only shorten it), it can no
longer hide newer rows
indefinitely by keeping the scan pinned to the oldest window, and rows
already scanned that get ACKed drop out of the scan without skipping
the rows behind the cursor.

### Storage tables (schema.sql, created idempotently at boot)

`federation_outbound` (immutable envelope originals + send state),
`federation_inbound` (`UNIQUE(origin, event_id)` dedup + originals +
registry snapshot + delivery state), `federation_inbound_conflicts` (409
audit), `federation_receipt_out` (ACK-derived send intents, fixed fields,
never capped), `federation_receipt_in_originals` (every DISTINCT valid
signed original kept, variants flagged, never silently overwritten),
`federation_receipt_in` (merged state per (event_id, agent, ack_type);
stage = applied > received, never downgraded, nothing synthesized),
`federation_notifications` (exactly-once local logical notifications by
stable intent id; SSE hints may repeat and carry the intent id).

## Response contract (§8)

| Situation | Status | Body |
|---|---|---|
| stored | 200 | `{"status": "stored"}` |
| duplicate | 200 | `{"status": "duplicate"}` |
| same ID, different content | 409 | `{"status": "conflict"}` |
| parse/schema/format errors | 400 | `{"status": "rejected", "reason": <category>}` |
| `Content-Encoding` present | 400 | rejected / `content_encoding_rejected` |
| unregistered (family, key_id) | 403 | rejected / `unregistered_key` |
| strict-verify failure | 403 | rejected / `<signature category>` |
| receipt binding failures (§6.5) | 403 | rejected / `<binding category>` |
| body > 16384 bytes | 413 | rejected / `body_too_large` |
| inbound semantics (target family/member) | 422 | rejected / `target_family` \| `target_member` |
| rate limits | 429 | rejected / `rate_limited_conn` \| `rate_limited_family` |
| storage full / IO | 507 / 503 | rejected / `<storage error>` (transient) |

Design v0.4.3 pins this status mapping; the sender treats 400/401/403/409/
413/422 as permanent, everything else (429/5xx/timeout/connection) as
transient.  A 200 counts as delivered ONLY when the
body parses as `stored`/`duplicate`; blank/HTML/unknown 200 bodies are
transient failures, as are malformed-JSON or over-deep 200 bodies (r4 F3),
and ONLY the exact status 200 counts — other 2xx (201/202/206, …) are
transient failures (r4 F4).  Redirects are never followed (custom redirect
handler raises); a 3xx is treated as a permanent failure
(`redirect_not_followed`).

Endpoints are https-only (r4 F2, §8's TLS-verified prerequisite is
enforced, not assumed): the registry rejects plaintext or malformed
endpoint URLs at LOAD (`unsupported_endpoint_url` — scheme must be https,
no userinfo, no fragment, host required), the outbound opener has no
plain-HTTP handler at all, and the transport re-checks the policy before
every send.  The sole exception is the explicit, default-unavailable
loopback bypass (`ATALK_FEDERATION_ALLOW_LOOPBACK_HTTP=1` / config
`allow_insecure_loopback`) for self-owned loopback test instances; it never
admits plain http to a non-loopback host.

## Security notes (§9)

- Only registered families are accepted; the body limit applies before any
  parsing; connection-level limiting precedes verification, per-family
  limiting follows it (an unauthenticated sender cannot consume the family
  budget of a registered peer).
- Cross-family events always carry the verified `origin` label for the
  receiving agent; command types and broadcast targets are rejected at the
  schema layer, so no authorization state can be created or imported through
  `/federation/inbox`.
- The outbox cap applies only to new sends; ACKs and receipts always commit
  (`federation_receipt_out` is the durable intent).
- The private key lives only in the identity file on the bus host, mode 600
  enforced at load; it never enters the ledger, the logs, or any envelope.
- Verification keys come only from the admin-pinned registry record for the
  exact `(family, key_id)`; nothing is trusted from the envelope or the
  evidence pack.
- Dedup/conflict/outbound-association records are not cleaned during
  acceptance (§7 retention); an old signed envelope is never mistaken for a
  new event.
- Operator-notification trust boundary (r5 #5, explicit): ANY full-scope
  peer token can list and ACK operator notifications
  (`/federation/notifications?peer=…` and the `peer` ACK form).  This is
  the ESTABLISHED capability of a full-scope peer token in ATalk's token
  model (every primary peer token is full-scope; the full-scope peer is
  the operator's administrative principal) — it is NOT an operator-role
  authorization, and no separate operator role exists.  Narrower
  device-token scopes (e.g. `notify`) are rejected on these routes.  v0
  keeps this token trust model unchanged; tightening it to a dedicated
  operator capability would be a token-system change and is future work.
  The behavior is pinned by tests so it cannot change silently.

## Frozen versions and tests

- Python 3.11.0rc1, PyNaCl 1.6.2 (`FROZEN_VERSIONS`); libsodium pinned via
  the PyNaCl 1.6.2 official wheel (see round-1 section below).
- `tests/test_federation_round1.py` — wire-format core, §4.5 vectors types
  1/2/4, 8192/8193 precondition, registry key-length precondition.
- `tests/test_federation_round2.py` — all §4.5 type-3 full-inbound vectors
  through the real HTTP endpoint (per-case fresh state, zero-side-effect
  assertions), the six §11 self-tests (round trip, dup/conflict, recovery,
  forgery/binding, impersonation, privilege/limits) and the flag-off
  byte-equivalence suite (every probe byte-compared against the real base,
  with exactly ONE explicitly bounded oversize exception — r5 #6).  All
  federation tests are two self-owned in-process instances on loopback
  HTTP; no third-party host is contacted.

## Dependencies

Federation requires PyNaCl, declared as the optional extra
`atalk[federation]` in `pyproject.toml` (floor `pynacl>=1.5,<2`, matching the
portable behavior-test contract; the evidence environment is pinned exactly
by `requirements-federation.lock`).  The core `atalk` package remains
zero-dependency and the `atalk.federation` subpackage ships in wheels
(r4 F1): no federation module imports PyNaCl at import time, so a
zero-dependency install imports and starts the ordinary service with
federation off — enabling `ATALK_FEDERATION=1` without PyNaCl fails closed
at activation (`FederationRuntime.build` gates on the crypto backend), it
never crashes the worker or the server.

## Round-1 spec ambiguities and dispositions

The seven round-1 spec ambiguities and their dispositions,
listed so reviewers can find them; "§4.6" and "§4.7" refer to design draft
v0.4.3 (v0.4.2 added §4.6, v0.4.3 added the §4.7 clarifications).
The evidence-environment dependency pin for these guarantees is
`requirements-federation.lock` (`pynacl==1.6.2` plus the wheel sha256);
behavioral tests carry no version assertions, and the exact-version checks
are gated behind `ATALK_FED_EVIDENCE_ENV=1` in
`tests/test_federation_review_fixes.py`.

1. **Escaped surrogates** — a VALID escaped surrogate pair is accepted (the
   JSON decoder combines it into the scalar; JCS re-emits raw UTF-8); only
   LONE surrogates are rejected (`invalid_unicode`, layer `parse`).
   Codified in design §4.6.
2. **base64url check order** — canonicality BEFORE length: charset
   (b64url alphabet only, no padding) → mod-4 decodable length → re-encode
   byte-identical (zero trailing bits) → decoded byte length == expected.
   Codified in design §4.6 and now actually implemented in
   `canonical.decode_strict`; a string that is both non-canonical and of
   the wrong length reports `non_canonical_base64url`, never a length
   error.  Fixed reverse vectors:
   `federation-vectors/base64url_order_v0.json`.
3. **`in_reply_to`** — optional for `type=reply`, rejected on
   `type=message` (`in_reply_to_disallowed`).  Codified in design §4.6.
4. **Registry root** — `federation_peers.json` is a JSON array of records;
   anything else is `registry_format`.  Codified in design §4.6.
5. **Error category names are free-form** (the spec does not pin them).
   The normative list is THIS README: schema/request — `kind_mismatch`,
   `key_id_grammar`, `event_id_format`, `in_reply_to_format`,
   `in_reply_to_disallowed`, `timestamp_format`, `hash_format`,
   `ack_type_whitelist`, `source_family`, `invalid_json`,
   `body_too_large`; registry — `public_key_length`, `public_key_format`,
   `registry_format`, `record_format`, `duplicate_family`,
   `file_unreadable`, `unsupported_endpoint_url`, `identity_permissions`,
   `nesting_too_deep`; signature — `invalid_r`, `invalid_a`.
6. **Leap seconds** — `:60` timestamps are rejected (`timestamp_format`):
   strict real-datetime reading, no leap-second allowance.
7. **Nesting depth cap** — `NESTING_DEPTH_LIMIT = 64` in `canonical.py`,
   category `nesting_too_deep` (layer `parse` for envelope parsing, layer
   `registry` for the peers-file loader), enforced by an iterative
   pre-scan with a RecursionError backstop at the parse boundary (no
   global recursion or integer limit is raised); numbers of every shape
   are rejected in the json parse hooks as `value_domain` (layer
   `parse/schema`; the registry loader re-classifies to layer
   `registry`) without constructing big integers.
