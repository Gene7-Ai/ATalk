PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA busy_timeout=5000;

CREATE TABLE IF NOT EXISTS peers (
  peer_id TEXT PRIMARY KEY,
  token_hash TEXT,
  role TEXT,
  platform TEXT,
  endpoint TEXT,
  delivery_class TEXT NOT NULL DEFAULT 'normal',
  ack_timeout_sec INTEGER NOT NULL DEFAULT 180,
  created_at TEXT NOT NULL,
  revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS peer_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  peer_id TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  token_id TEXT UNIQUE,
  device_label TEXT,
  scope TEXT NOT NULL DEFAULT 'full',
  created_at TEXT NOT NULL,
  grace_until TEXT,
  revoked_at TEXT,
  FOREIGN KEY(peer_id) REFERENCES peers(peer_id)
);

CREATE INDEX IF NOT EXISTS idx_peer_tokens_peer ON peer_tokens(peer_id, revoked_at);

CREATE TABLE IF NOT EXISTS peer_grants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  grantor TEXT NOT NULL,
  grantee TEXT NOT NULL,
  command_type TEXT NOT NULL,
  scope_json TEXT NOT NULL DEFAULT '{}',
  granted_at TEXT NOT NULL,
  valid_until TEXT,
  revoked_at TEXT,
  FOREIGN KEY(grantor) REFERENCES peers(peer_id),
  FOREIGN KEY(grantee) REFERENCES peers(peer_id)
);

CREATE INDEX IF NOT EXISTS idx_peer_grants_lookup
  ON peer_grants(grantor, grantee, command_type, revoked_at, valid_until);

CREATE TABLE IF NOT EXISTS peer_target_acl (
  peer_id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(peer_id) REFERENCES peers(peer_id)
);

CREATE TABLE IF NOT EXISTS peer_target_acl_targets (
  peer_id TEXT NOT NULL,
  target_peer TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(peer_id, target_peer),
  FOREIGN KEY(peer_id) REFERENCES peer_target_acl(peer_id),
  FOREIGN KEY(target_peer) REFERENCES peers(peer_id)
);

CREATE INDEX IF NOT EXISTS idx_peer_target_acl_targets_peer
  ON peer_target_acl_targets(peer_id);

CREATE TABLE IF NOT EXISTS source_counters (
  source TEXT PRIMARY KEY,
  last_seq INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  source TEXT NOT NULL,
  target TEXT NOT NULL,
  type TEXT NOT NULL,
  seq INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  stored_at TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  requires_ack INTEGER NOT NULL DEFAULT 1,
  source_ref TEXT,
  auth_actor TEXT,
  UNIQUE(source, seq)
);

CREATE INDEX IF NOT EXISTS idx_events_target_id ON events(target, id);
CREATE INDEX IF NOT EXISTS idx_events_source_seq ON events(source, seq);

CREATE TABLE IF NOT EXISTS acks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  ack_type TEXT NOT NULL CHECK (ack_type IN ('received', 'applied')),
  ack_at TEXT NOT NULL,
  detail_json TEXT,
  UNIQUE(event_id, agent_id, ack_type),
  FOREIGN KEY(event_id) REFERENCES events(event_id)
);

CREATE INDEX IF NOT EXISTS idx_acks_event ON acks(event_id);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  actor TEXT,
  action TEXT NOT NULL,
  source_ref TEXT,
  target TEXT,
  event_id TEXT,
  result TEXT NOT NULL,
  detail_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_log(event_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

INSERT OR IGNORE INTO settings (key, value) VALUES ('retention_days', '30');

-- Operational metadata only.  Health recovery probes may update this row;
-- they never create or acknowledge a business event.
CREATE TABLE IF NOT EXISTS storage_metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
INSERT OR IGNORE INTO storage_metadata (key, value) VALUES ('write_probe', 'initialized');

-- ---------------------------------------------------------------------------
-- Federation v0 (design draft v0.4.1, sections 5-7).  All tables are created
-- idempotently at every boot (init_schema runs schema.sql), which is the
-- migration path for existing ledgers.  Federation is inactive unless
-- ATALK_FEDERATION=1 and the peers/identity files load (fail closed).
-- ---------------------------------------------------------------------------

-- One row per outbound federation event (spec 5.2).  After the first commit
-- the envelope is IMMUTABLE: retries resend the exact original bytes, never a
-- re-signed copy.
CREATE TABLE IF NOT EXISTS federation_outbound (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  origin TEXT NOT NULL,
  origin_key_id TEXT NOT NULL,
  source_local TEXT NOT NULL,          -- bare local sender id (agent part)
  source_addr TEXT NOT NULL,           -- full signed source address
  target TEXT NOT NULL,
  target_family TEXT NOT NULL,
  type TEXT NOT NULL,
  signed_json TEXT NOT NULL,           -- signed object, canonical JSON text
  sig TEXT NOT NULL,                   -- canonical base64url signature
  envelope_json BLOB NOT NULL,         -- exact bytes first sent (immutable)
  notify_intent_id TEXT NOT NULL,      -- stable id for the failure notification
  status TEXT NOT NULL CHECK (status IN ('pending','sent','failed_permanent')),
  attempts INTEGER NOT NULL DEFAULT 0,
  next_retry_at TEXT,                  -- NULL = due now
  last_error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fed_outbound_due ON federation_outbound(status, next_retry_at);

-- Inbound dedup + stored originals (spec 5.5, 7).  UNIQUE(origin, event_id)
-- is the dedup key: the DB unique constraint arbitrates, never check-then-insert.
CREATE TABLE IF NOT EXISTS federation_inbound (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  origin TEXT NOT NULL,
  event_id TEXT NOT NULL,
  target TEXT NOT NULL,                -- full signed target address (receipt binding)
  event_jcs BLOB NOT NULL,             -- JCS bytes of the signed `event` (dedup comparison)
  signed_json TEXT NOT NULL,           -- signed object, canonical JSON text
  sig TEXT NOT NULL,                   -- canonical base64url signature of the original
  reg_family TEXT NOT NULL,            -- registry snapshot used at verify time
  reg_key_id TEXT NOT NULL,
  reg_public_key TEXT NOT NULL,
  local_event_id TEXT NOT NULL,        -- linkage to the local logical event
  delivery_state TEXT NOT NULL CHECK (delivery_state IN ('pending','delivered')),
  created_at TEXT NOT NULL,
  UNIQUE(origin, event_id)
);
CREATE INDEX IF NOT EXISTS idx_fed_inbound_event ON federation_inbound(event_id);
CREATE INDEX IF NOT EXISTS idx_fed_inbound_delivery ON federation_inbound(delivery_state);

-- Audit trail for same-ID-different-content (409 path, spec 7).  The stored
-- original is never touched; only this audit row is appended.
CREATE TABLE IF NOT EXISTS federation_inbound_conflicts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  origin TEXT NOT NULL,
  event_id TEXT NOT NULL,
  event_jcs BLOB NOT NULL,             -- JCS bytes of the conflicting content
  signed_json TEXT NOT NULL,
  sig TEXT NOT NULL,
  reason TEXT NOT NULL,
  seen_at TEXT NOT NULL
);

-- Receipt-send intents, derived from local ACKs of federation-inbound events
-- (spec 6.1-6.2).  The declaration fields (including `at`) are fixed at the
-- FIRST ack and never updated; the signed original is persisted on first
-- generation and reused verbatim on retries; rebuild-from-ACK-record uses the
-- fixed fields only.  Receipts are never capped (the ACK must always commit).
CREATE TABLE IF NOT EXISTS federation_receipt_out (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL,
  agent TEXT NOT NULL,                 -- full target address of the original event
  ack_type TEXT NOT NULL CHECK (ack_type IN ('received','applied')),
  at TEXT NOT NULL,                    -- fixed at first ack, never updated
  origin TEXT NOT NULL,                -- receipt.origin (original sender family)
  origin_event_sig_hash TEXT NOT NULL, -- fixed at first ack
  issuer TEXT NOT NULL,                -- our family
  issuer_key_id TEXT NOT NULL,
  signed_json TEXT,                    -- persisted signed original (NULL until first generation)
  sig TEXT,                            -- persisted signature (NULL until first generation)
  status TEXT NOT NULL CHECK (status IN ('pending','sent','failed_permanent')),
  attempts INTEGER NOT NULL DEFAULT 0,
  next_retry_at TEXT,
  last_error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(event_id, agent, ack_type)
);
CREATE INDEX IF NOT EXISTS idx_fed_receipt_out_due ON federation_receipt_out(status, next_retry_at);

-- Every DISTINCT valid signed receipt original received (spec 7): different
-- sig = different row, kept and flagged, never silently overwritten.
CREATE TABLE IF NOT EXISTS federation_receipt_in_originals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL,
  agent TEXT NOT NULL,
  ack_type TEXT NOT NULL,
  issuer TEXT NOT NULL,
  issuer_key_id TEXT NOT NULL,
  signed_json TEXT NOT NULL,
  sig TEXT NOT NULL,
  is_variant INTEGER NOT NULL DEFAULT 0,  -- 1 = differs from the first original for this key
  first_seen_at TEXT NOT NULL,
  UNIQUE(event_id, agent, ack_type, sig)
);

-- Merged receipt state per (event_id, agent, ack_type); rows only appear from
-- real valid receipts (no synthesized `received`), and state never downgrades:
-- the stage is derived as applied > received over the rows present.
CREATE TABLE IF NOT EXISTS federation_receipt_in (
  event_id TEXT NOT NULL,
  agent TEXT NOT NULL,
  ack_type TEXT NOT NULL CHECK (ack_type IN ('received','applied')),
  issuer TEXT NOT NULL,
  original_id INTEGER NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (event_id, agent, ack_type)
);

-- Local logical notifications, exactly once by stable intent id (spec 6.6 and
-- section 8 "notify, never silently drop").  Push hints (SSE) may repeat;
-- consumers dedupe by intent_id.
--
-- r5 F6: hint_sent and acked are DIFFERENT states.
--   hint_sent: a live subscriber queue accepted one push hint (best effort;
--     reconnects replace queues, so this never implies anyone consumed it);
--   acked:    durable completion, set ONLY by the authenticated notification
--     ACK endpoint.  Pull lists every row with acked=0 — including rows that
--     were already push-hinted — so a queued-but-unconsumed notification is
--     always recoverable; re-pushing the same stable intent id is safe.
CREATE TABLE IF NOT EXISTS federation_notifications (
  intent_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  agent TEXT,                          -- local agent to notify (NULL = operator)
  event_id TEXT,
  detail_json TEXT NOT NULL,
  hint_sent INTEGER NOT NULL DEFAULT 0,
  acked INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
