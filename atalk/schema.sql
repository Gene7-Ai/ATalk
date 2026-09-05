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
