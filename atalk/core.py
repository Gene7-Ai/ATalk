from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def legacy_token_id(peer_id: str, digest: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"atalk-token:{peer_id}:{digest}"))


class EventIdConflict(ValueError):
    """Raised when an event_id already exists for a different (source, target, type)."""


def verify_event_identity(event, source, target, event_type):
    """Return the event only if its (source, target, type) matches the caller's
    already-authenticated request; otherwise raise EventIdConflict. This closes the
    hole where a peer reusing another peer's event_id would receive that event's body.
    """
    if (event.source, event.target, event.type) != (source, target, event_type):
        raise EventIdConflict(event.event_id)
    return event


@dataclass(frozen=True)
class Event:
    id: int
    event_id: str
    source: str
    target: str
    type: str
    seq: int
    created_at: str
    stored_at: str
    payload: dict[str, Any]
    requires_ack: bool
    source_ref: str | None
    auth_actor: str | None


class AtalkStore:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # One SQLite connection PER THREAD. A single shared connection under the
        # ThreadingHTTPServer is not thread-safe: concurrent handlers interleave on
        # the same cursor and can read another peer's row (cross-peer leak).
        self._local = threading.local()
        self.lock = threading.RLock()
        # WAL + busy_timeout let per-thread connections coexist without spurious
        # "database is locked"; the RLock still serializes multi-statement writes.
        boot = self._new_conn()
        boot.execute("PRAGMA journal_mode=WAL")
        self.init_schema()
        self._ensure_peer_capability_columns()
        self._migrate_peer_tokens()
        self._ensure_token_schema()

    def _new_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, isolation_level=None, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        self._local.conn = conn
        return conn

    @property
    def conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._new_conn()
        return conn

    def init_schema(self) -> None:
        schema = Path(__file__).with_name("schema.sql").read_text(encoding="utf-8")
        self.conn.executescript(schema)

    def _migrate_peer_tokens(self) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO peer_tokens (peer_id, token_hash, created_at) "
            "SELECT peer_id, token_hash, created_at FROM peers WHERE token_hash IS NOT NULL"
        )

    def _ensure_token_schema(self) -> None:
        columns = {row["name"] for row in self.conn.execute("PRAGMA table_info(peer_tokens)")}
        if "token_id" not in columns:
            self.conn.execute("ALTER TABLE peer_tokens ADD COLUMN token_id TEXT")
        if "device_label" not in columns:
            self.conn.execute("ALTER TABLE peer_tokens ADD COLUMN device_label TEXT")
        if "scope" not in columns:
            self.conn.execute("ALTER TABLE peer_tokens ADD COLUMN scope TEXT NOT NULL DEFAULT 'full'")
        rows = self.conn.execute(
            "SELECT id,peer_id,token_hash FROM peer_tokens WHERE token_id IS NULL OR token_id=''"
        ).fetchall()
        with self.lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                for row in rows:
                    self.conn.execute(
                        "UPDATE peer_tokens SET token_id=?,device_label=coalesce(device_label,'legacy'),"
                        "scope=coalesce(scope,'full') WHERE id=?",
                        (legacy_token_id(row["peer_id"], row["token_hash"]), row["id"]),
                    )
                self.conn.commit()
            except Exception:
                self.conn.rollback()
                raise
        self.conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_peer_tokens_token_id ON peer_tokens(token_id)")

    def _ensure_peer_capability_columns(self) -> None:
        columns = {row["name"] for row in self.conn.execute("PRAGMA table_info(peers)")}
        if "delivery_class" not in columns:
            self.conn.execute("ALTER TABLE peers ADD COLUMN delivery_class TEXT NOT NULL DEFAULT 'normal'")
        if "ack_timeout_sec" not in columns:
            self.conn.execute("ALTER TABLE peers ADD COLUMN ack_timeout_sec INTEGER NOT NULL DEFAULT 180")

    def set_target_acl(self, peer_id: str, allowed_targets) -> None:
        targets = list(dict.fromkeys(str(target) for target in allowed_targets))
        now = now_iso()
        with self.lock, self.conn:
            self.conn.execute(
                "INSERT INTO peer_target_acl(peer_id,created_at,updated_at) VALUES(?,?,?) "
                "ON CONFLICT(peer_id) DO UPDATE SET updated_at=excluded.updated_at",
                (peer_id, now, now),
            )
            self.conn.execute("DELETE FROM peer_target_acl_targets WHERE peer_id=?", (peer_id,))
            self.conn.executemany(
                "INSERT INTO peer_target_acl_targets(peer_id,target_peer,created_at) VALUES(?,?,?)",
                [(peer_id, target, now) for target in targets],
            )

    def clear_target_acl(self, peer_id: str) -> None:
        with self.lock, self.conn:
            self.conn.execute("DELETE FROM peer_target_acl_targets WHERE peer_id=?", (peer_id,))
            self.conn.execute("DELETE FROM peer_target_acl WHERE peer_id=?", (peer_id,))

    def list_target_acls(self, peer_id: str | None = None) -> list[dict[str, Any]]:
        sql, params = "SELECT peer_id,created_at,updated_at FROM peer_target_acl", ()
        if peer_id is not None:
            sql, params = sql + " WHERE peer_id=?", (peer_id,)
        rows = self.conn.execute(sql + " ORDER BY peer_id", params).fetchall()
        return [{
            "peer_id": row["peer_id"], "mode": "restricted",
            "allowed_targets": [item["target_peer"] for item in self.conn.execute(
                "SELECT target_peer FROM peer_target_acl_targets WHERE peer_id=? ORDER BY target_peer",
                (row["peer_id"],)).fetchall()],
            "created_at": row["created_at"], "updated_at": row["updated_at"],
        } for row in rows]

    def _target_acl_allows(self, source: str, target: str) -> bool:
        if not self.conn.execute("SELECT 1 FROM peer_target_acl WHERE peer_id=?", (source,)).fetchone():
            return True
        if target == "*":
            return False
        return self.conn.execute(
            "SELECT 1 FROM peer_target_acl_targets WHERE peer_id=? AND target_peer=?",
            (source, target),
        ).fetchone() is not None

    def add_peer(
        self,
        peer_id: str,
        token: str | None = None,
        role: str | None = None,
        platform: str | None = None,
        endpoint: str | None = None,
        delivery_class: str = "normal",
        ack_timeout_sec: int = 180,
    ) -> str:
        if token is None:
            token = secrets.token_urlsafe(32)
        self.conn.execute(
            """
            INSERT INTO peers
              (peer_id, token_hash, role, platform, endpoint, delivery_class, ack_timeout_sec, created_at)
            VALUES (?,?,?,?,?,?,?,?)
            ON CONFLICT(peer_id) DO UPDATE SET
              token_hash=excluded.token_hash,
              role=excluded.role,
              platform=excluded.platform,
              endpoint=excluded.endpoint,
              delivery_class=excluded.delivery_class,
              ack_timeout_sec=excluded.ack_timeout_sec,
              revoked_at=NULL
            """,
            (
                peer_id, token_hash(token), role, platform, endpoint,
                delivery_class, int(ack_timeout_sec), now_iso(),
            ),
        )
        self.conn.execute(
            "INSERT OR IGNORE INTO peer_tokens "
            "(peer_id,token_hash,token_id,device_label,scope,created_at) VALUES (?,?,?,?,?,?)",
            (peer_id, token_hash(token), str(uuid.uuid4()), "primary", "full", now_iso()),
        )
        self.conn.execute(
            "UPDATE peer_tokens SET revoked_at = ? WHERE peer_id = ? AND token_hash <> ? "
            "AND revoked_at IS NULL AND (device_label IS NULL OR device_label IN ('legacy','primary','rotation'))",
            (now_iso(), peer_id, token_hash(token)),
        )
        return token

    def rotate_peer_token(self, peer_id: str, token: str | None = None, grace_seconds: int = 300) -> str:
        token = token or secrets.token_urlsafe(32)
        grace_until = (datetime.now(timezone.utc) + timedelta(seconds=max(0, grace_seconds))).isoformat(
            timespec="seconds"
        ).replace("+00:00", "Z")
        # Only put still-valid tokens into grace. A token whose grace already expired
        # must stay expired; resetting its grace_until here would revive it.
        self.conn.execute(
            "UPDATE peer_tokens SET grace_until = ? WHERE peer_id = ? AND revoked_at IS NULL "
            "AND (device_label IS NULL OR device_label IN ('legacy','primary','rotation')) "
            "AND (grace_until IS NULL OR grace_until >= ?)",
            (grace_until, peer_id, now_iso()),
        )
        self.conn.execute(
            "INSERT INTO peer_tokens "
            "(peer_id,token_hash,token_id,device_label,scope,created_at) VALUES (?,?,?,?,?,?)",
            (peer_id, token_hash(token), str(uuid.uuid4()), "rotation", "full", now_iso()),
        )
        self.conn.execute("UPDATE peers SET token_hash = ? WHERE peer_id = ?", (token_hash(token), peer_id))
        return token

    def validate_token(self, peer_id: str, token: str | None) -> bool:
        return self.token_scope(peer_id, token) is not None

    def token_scope(self, peer_id: str, token: str | None) -> str | None:
        if not token:
            return None
        rows = self.conn.execute(
            "SELECT token_hash,grace_until,revoked_at,scope FROM peer_tokens WHERE peer_id=?",
            (peer_id,),
        ).fetchall()
        now = now_iso()
        for row in rows:
            if row["revoked_at"]:
                continue
            if row["grace_until"] and row["grace_until"] < now:
                continue
            if secrets.compare_digest(row["token_hash"], token_hash(token)):
                return str(row["scope"] or "full")
        return None

    def add_device_token(
        self, peer_id: str, device_label: str, *, token: str | None = None,
        scope: str = "full", actor: str = "operator",
    ) -> dict[str, str]:
        if device_label in {"legacy", "primary", "rotation"}:
            raise ValueError("device_label is reserved")
        if scope not in {"full", "notify"}:
            raise ValueError("scope must be full or notify")
        if not self.conn.execute(
            "SELECT 1 FROM peers WHERE peer_id=? AND revoked_at IS NULL", (peer_id,)
        ).fetchone():
            raise KeyError(peer_id)
        token = token or secrets.token_urlsafe(32)
        token_id = str(uuid.uuid4())
        now = now_iso()
        with self.lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                self.conn.execute(
                    "INSERT INTO peer_tokens "
                    "(peer_id,token_hash,token_id,device_label,scope,created_at) VALUES (?,?,?,?,?,?)",
                    (peer_id, token_hash(token), token_id, device_label, scope, now),
                )
                self.conn.execute(
                    "INSERT INTO audit_log(ts,actor,action,target,result,detail_json) VALUES(?,?,?,?,?,?)",
                    (now, actor, "device_token_add", peer_id, "accepted",
                     compact_json({"token_id": token_id, "device_label": device_label, "scope": scope})),
                )
                self.conn.commit()
            except Exception:
                self.conn.rollback()
                raise
        return {"peer_id": peer_id, "token_id": token_id, "device_label": device_label,
                "scope": scope, "token": token}

    def list_device_tokens(self, peer_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT token_id,peer_id,device_label,scope,created_at,grace_until,revoked_at "
            "FROM peer_tokens WHERE peer_id=? ORDER BY id", (peer_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def revoke_device_token(self, token_id: str, *, actor: str = "operator") -> dict[str, Any]:
        row = self.conn.execute(
            "SELECT peer_id,device_label,scope,revoked_at FROM peer_tokens WHERE token_id=?", (token_id,)
        ).fetchone()
        if not row:
            raise KeyError(token_id)
        now = now_iso()
        result = "already_revoked" if row["revoked_at"] else "accepted"
        with self.lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                if not row["revoked_at"]:
                    self.conn.execute("UPDATE peer_tokens SET revoked_at=? WHERE token_id=?", (now, token_id))
                self.conn.execute(
                    "INSERT INTO audit_log(ts,actor,action,target,result,detail_json) VALUES(?,?,?,?,?,?)",
                    (now, actor, "device_token_revoke", row["peer_id"], result,
                     compact_json({"token_id": token_id, "device_label": row["device_label"],
                                   "scope": row["scope"]})),
                )
                self.conn.commit()
            except Exception:
                self.conn.rollback()
                raise
        return {"token_id": token_id, "peer_id": row["peer_id"], "revoked": True, "result": result}

    def auth_required(self) -> bool:
        # Auth is required once any peer has ever been provisioned. Counting only
        # non-revoked peers meant revoking the last peer flipped the whole bus to
        # open (fail-open); revoking must lock out, never open up. A pristine
        # install (zero peer rows) stays open for local dev.
        row = self.conn.execute("SELECT count(*) AS n FROM peers").fetchone()
        return bool(row["n"])

    def add_grant(
        self,
        grantor: str,
        grantee: str,
        command_type: str,
        scope: dict[str, Any] | None = None,
        valid_until: str | None = None,
    ) -> int:
        cur = self.conn.execute(
            "INSERT INTO peer_grants "
            "(grantor, grantee, command_type, scope_json, granted_at, valid_until) VALUES (?,?,?,?,?,?)",
            (grantor, grantee, command_type, compact_json(scope or {}), now_iso(), valid_until),
        )
        return int(cur.lastrowid)

    def revoke_grant(self, grant_id: int) -> None:
        self.conn.execute("UPDATE peer_grants SET revoked_at=? WHERE id=?", (now_iso(), int(grant_id)))

    def command_allowed(self, source: str, target: str, payload: dict[str, Any]) -> bool:
        command_type = str(payload.get("op", "")).strip()
        if not command_type:
            return False
        rows = self.conn.execute(
            "SELECT scope_json FROM peer_grants WHERE grantor=? AND grantee=? "
            "AND command_type IN (?, '*') AND revoked_at IS NULL "
            "AND (valid_until IS NULL OR valid_until >= ?)",
            (target, source, command_type, now_iso()),
        ).fetchall()
        for row in rows:
            scope = json.loads(row["scope_json"] or "{}")
            if all(payload.get(key) == value for key, value in scope.items()):
                return True
        return False

    def next_seq(self, source: str) -> int:
        with self.lock:
            self.conn.execute(
                "INSERT INTO source_counters (source, last_seq) VALUES (?, 1) "
                "ON CONFLICT(source) DO UPDATE SET last_seq = last_seq + 1",
                (source,),
            )
            row = self.conn.execute("SELECT last_seq FROM source_counters WHERE source = ?", (source,)).fetchone()
            return int(row["last_seq"])

    def insert_event(
        self,
        source: str,
        target: str,
        event_type: str,
        payload: dict[str, Any] | None = None,
        *,
        seq: int | None = None,
        event_id: str | None = None,
        created_at: str | None = None,
        requires_ack: bool = True,
        source_ref: str | None = None,
        token: str | None = None,
    ) -> Event:
        payload = payload or {}
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")
        event_id = event_id or str(uuid.uuid4())
        created_at = created_at or now_iso()
        auth_actor = None

        # source_ref is a cheap, atomicity-independent precondition for commands.
        if event_type == "command" and not source_ref:
            self.audit(source, "command_reject", source_ref, target, event_id, "missing_source_ref")
            raise PermissionError("command requires source_ref")

        # The whole write (idempotency probe, authorization re-check, event row,
        # seq high-water and command audit) runs in ONE immediate transaction.
        # BEGIN IMMEDIATE serializes writers, so authorization (token/grant/ACL)
        # is re-evaluated atomically with the insert: a grant or token revoked
        # concurrently either commits before we take the lock (then we reject) or
        # blocks until we commit. This matches the rqlite backend's in-transaction
        # authorization guard and closes the check-then-insert TOCTOU.
        with self.lock:
            self.conn.execute("BEGIN IMMEDIATE")
            in_txn = True
            try:
                existing = self.conn.execute(
                    "SELECT id FROM events WHERE event_id = ?", (event_id,)
                ).fetchone()
                if existing:
                    ev = self.get_event_by_id(int(existing["id"]))
                    self.conn.execute("COMMIT")
                    in_txn = False
                    return verify_event_identity(ev, source, target, event_type)

                if event_type == "command":
                    if not self.validate_token(source, token):
                        self.conn.execute("ROLLBACK"); in_txn = False
                        self.audit(source, "command_reject", source_ref, target, event_id, "invalid_token")
                        raise PermissionError("command token rejected")
                    if not self.command_allowed(source, target, payload):
                        self.conn.execute("ROLLBACK"); in_txn = False
                        self.audit(source, "command_reject", source_ref, target, event_id, "grant_denied")
                        raise PermissionError("command grant rejected")
                    auth_actor = source
                elif not self._target_acl_allows(source, target):
                    self.conn.execute("ROLLBACK"); in_txn = False
                    raise PermissionError("target not allowed")

                seq_val = seq if seq is not None else self.next_seq(source)
                try:
                    cur = self.conn.execute(
                        """
                        INSERT INTO events
                          (event_id, source, target, type, seq, created_at, stored_at, payload_json,
                           requires_ack, source_ref, auth_actor)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?)
                        """,
                        (
                            event_id, source, target, event_type, seq_val, created_at,
                            now_iso(), compact_json(payload), 1 if requires_ack else 0,
                            source_ref, auth_actor,
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    self.conn.execute("ROLLBACK"); in_txn = False
                    if "events.event_id" in str(exc):
                        return verify_event_identity(
                            self.get_event(event_id), source, target, event_type
                        )
                    raise

                self.conn.execute(
                    "INSERT INTO source_counters (source, last_seq) VALUES (?, ?) "
                    "ON CONFLICT(source) DO UPDATE SET last_seq = max(last_seq, excluded.last_seq)",
                    (source, seq_val),
                )
                if event_type == "command":
                    self.audit(source, "command_accept", source_ref, target, event_id, "accepted")
                new_id = int(cur.lastrowid)
                self.conn.execute("COMMIT")
                in_txn = False
                return self.get_event_by_id(new_id)
            finally:
                if in_txn:
                    try:
                        self.conn.execute("ROLLBACK")
                    except Exception:
                        pass

    def get_event(self, event_id: str) -> Event:
        row = self.conn.execute("SELECT * FROM events WHERE event_id = ?", (event_id,)).fetchone()
        if not row:
            raise KeyError(event_id)
        return self._row_to_event(row)

    def get_event_by_id(self, event_db_id: int) -> Event:
        row = self.conn.execute("SELECT * FROM events WHERE id = ?", (event_db_id,)).fetchone()
        if not row:
            raise KeyError(event_db_id)
        return self._row_to_event(row)

    def list_events(
        self,
        target: str | None = None,
        since_id: int = 0,
        limit: int = 100,
        state: str = "pending",
    ) -> list[Event]:
        limit = max(1, min(int(limit), 500))
        if target:
            if state == "pending":
                rows = self.conn.execute(
                    "SELECT * FROM events e WHERE target IN (?, '*') AND id > ? "
                    "AND NOT EXISTS (SELECT 1 FROM acks a WHERE a.event_id=e.event_id "
                    "AND a.agent_id=? AND a.ack_type='applied') "
                    "ORDER BY id ASC LIMIT ?",
                    (target, int(since_id), target, limit),
                ).fetchall()
            elif state == "all":
                rows = self.conn.execute(
                    "SELECT * FROM events WHERE target IN (?, '*') AND id > ? ORDER BY id ASC LIMIT ?",
                    (target, int(since_id), limit),
                ).fetchall()
            else:
                raise ValueError("state must be pending or all")
        else:
            if state != "all":
                state = "all"
            rows = self.conn.execute(
                "SELECT * FROM events WHERE id > ? ORDER BY id ASC LIMIT ?",
                (int(since_id), limit),
            ).fetchall()
        return [self._row_to_event(r) for r in rows]

    def ack(
        self,
        event_id: str,
        agent_id: str,
        ack_type: str,
        detail: dict[str, Any] | None = None,
    ) -> None:
        if ack_type not in {"received", "applied"}:
            raise ValueError("ack_type must be received or applied")
        self.conn.execute(
            """
            INSERT INTO acks (event_id, agent_id, ack_type, ack_at, detail_json)
            VALUES (?,?,?,?,?)
            ON CONFLICT(event_id, agent_id, ack_type) DO UPDATE SET
              ack_at=excluded.ack_at,
              detail_json=excluded.detail_json
            """,
            (event_id, agent_id, ack_type, now_iso(), compact_json(detail or {})),
        )

    def audit(
        self,
        actor: str | None,
        action: str,
        source_ref: str | None,
        target: str | None,
        event_id: str | None,
        result: str,
        detail: dict[str, Any] | None = None,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO audit_log (ts, actor, action, source_ref, target, event_id, result, detail_json)
            VALUES (?,?,?,?,?,?,?,?)
            """,
            (now_iso(), actor, action, source_ref, target, event_id, result, compact_json(detail or {})),
        )

    def acks_for(self, event_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM acks WHERE event_id = ? ORDER BY id ASC",
            (event_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def backlog_depth(self, target: str) -> int:
        row = self.conn.execute(
            "SELECT count(*) AS n FROM events e WHERE e.requires_ack = 1 AND e.target IN (?, '*') "
            "AND NOT EXISTS (SELECT 1 FROM acks a WHERE a.event_id=e.event_id AND a.agent_id=? AND a.ack_type='applied')",
            (target, target),
        ).fetchone()
        return int(row["n"])

    def health_snapshot(self) -> dict[str, Any]:
        peers = [row["peer_id"] for row in self.conn.execute("SELECT peer_id FROM peers WHERE revoked_at IS NULL")]
        last = self.conn.execute("SELECT id, stored_at FROM events ORDER BY id DESC LIMIT 1").fetchone()
        return {
            "inbox_depths": {peer: self.backlog_depth(peer) for peer in peers},
            "outbox_pending": sum(self.backlog_depth(peer) for peer in peers),
            "last_event_id": int(last["id"]) if last else None,
            "last_event_at": last["stored_at"] if last else None,
            "retention_days": int(self.conn.execute("SELECT value FROM settings WHERE key='retention_days'").fetchone()["value"]),
        }

    def _row_to_event(self, row: sqlite3.Row) -> Event:
        return Event(
            id=int(row["id"]),
            event_id=row["event_id"],
            source=row["source"],
            target=row["target"],
            type=row["type"],
            seq=int(row["seq"]),
            created_at=row["created_at"],
            stored_at=row["stored_at"],
            payload=json.loads(row["payload_json"] or "{}"),
            requires_ack=bool(row["requires_ack"]),
            source_ref=row["source_ref"],
            auth_actor=row["auth_actor"],
        )


def event_to_dict(event: Event) -> dict[str, Any]:
    return {
        "id": event.id,
        "event_id": event.event_id,
        "source": event.source,
        "target": event.target,
        "type": event.type,
        "seq": event.seq,
        "created_at": event.created_at,
        "stored_at": event.stored_at,
        "payload": event.payload,
        "requires_ack": event.requires_ack,
        "source_ref": event.source_ref,
        "auth_actor": event.auth_actor,
    }
