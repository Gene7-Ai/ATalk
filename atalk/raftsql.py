from __future__ import annotations

import json
import base64
import os
import secrets
import ssl
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from .core import Event, compact_json, legacy_token_id, now_iso, token_hash, verify_event_identity


class RaftUnavailable(RuntimeError):
    pass


class RqliteClient:
    """Small failover client for rqlite's HTTP SQL API."""

    def __init__(self, endpoints: Iterable[str], timeout: float = 5.0):
        self.endpoints = tuple(endpoint.rstrip("/") for endpoint in endpoints)
        if not self.endpoints:
            raise ValueError("at least one rqlite endpoint is required")
        self.timeout = float(timeout)
        self._preferred = 0
        self.username = os.environ.get("RQLITE_USERNAME")
        self.password = os.environ.get("RQLITE_PASSWORD")
        ca = os.environ.get("RQLITE_CA_CERT")
        cert = os.environ.get("RQLITE_CLIENT_CERT")
        key = os.environ.get("RQLITE_CLIENT_KEY")
        self.ssl_context = ssl.create_default_context(cafile=ca) if ca else None
        if self.ssl_context and cert:
            self.ssl_context.load_cert_chain(cert, keyfile=key)

    def _request(self, path: str, body: Any | None = None, endpoints: tuple[str, ...] | None = None) -> dict[str, Any]:
        errors: list[str] = []
        pool = endpoints if endpoints is not None else self.endpoints
        for offset in range(len(pool)):
            index = (self._preferred + offset) % len(pool) if endpoints is None else offset
            endpoint = pool[index]
            raw = None if body is None else json.dumps(body, separators=(",", ":")).encode()
            headers = {"Content-Type": "application/json"}
            if self.username and self.password:
                encoded = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
                headers["Authorization"] = f"Basic {encoded}"
            request = urllib.request.Request(endpoint + path, data=raw, headers=headers)
            try:
                with urllib.request.urlopen(request, timeout=self.timeout, context=self.ssl_context) as response:
                    value = json.load(response)
                if endpoints is None:
                    self._preferred = index
                return value
            except (OSError, ValueError, urllib.error.HTTPError) as exc:
                errors.append(f"{endpoint}: {exc}")
        raise RaftUnavailable("; ".join(errors))

    @staticmethod
    def _raise_sql_errors(response: dict[str, Any]) -> None:
        # rqlite reports whole-request failures (auth, parse, not-leader, malformed
        # body) as a TOP-LEVEL "error" with no per-statement results. Ignoring it
        # made a failed write look like success. Check it first.
        top = response.get("error")
        if top:
            raise RuntimeError(str(top))
        errors = [str(result["error"]) for result in response.get("results", []) if isinstance(result, dict) and result.get("error")]
        if errors:
            raise RuntimeError("; ".join(errors))

    def transaction(self, statements: list[list[Any]]) -> list[dict[str, Any]]:
        response = self._request("/db/request?transaction&level=strong", statements)
        self._raise_sql_errors(response)
        return response.get("results", [])

    def query(self, sql: str, parameters: Iterable[Any] = ()) -> list[dict[str, Any]]:
        response = self._request("/db/query?level=strong", [[sql, *parameters]])
        self._raise_sql_errors(response)
        result = response.get("results", [{}])[0]
        columns = result.get("columns", [])
        return [dict(zip(columns, values)) for values in result.get("values", [])]

    def status(self) -> dict[str, Any]:
        return self._request("/status")

    def status_local(self) -> dict[str, Any] | None:
        """/status of the LOCAL rqlite node (no failover), for reporting this node's true raft role in health."""
        import socket
        import urllib.parse
        host = socket.gethostname().split(".")[0].lower()
        for endpoint in self.endpoints:
            ep_host = (urllib.parse.urlsplit(endpoint).hostname or "").split(".")[0].lower()
            if ep_host == host:
                try:
                    return self._request("/status", endpoints=(endpoint,))
                except RaftUnavailable:
                    return None
        return None


SCHEMA_STATEMENTS = [
    "CREATE TABLE IF NOT EXISTS peers (peer_id TEXT PRIMARY KEY,token_hash TEXT,role TEXT,platform TEXT,endpoint TEXT,delivery_class TEXT NOT NULL DEFAULT 'normal',ack_timeout_sec INTEGER NOT NULL DEFAULT 180,created_at TEXT NOT NULL,revoked_at TEXT)",
    "CREATE TABLE IF NOT EXISTS peer_tokens (id INTEGER PRIMARY KEY AUTOINCREMENT,peer_id TEXT NOT NULL,token_hash TEXT NOT NULL UNIQUE,token_id TEXT UNIQUE,device_label TEXT,scope TEXT NOT NULL DEFAULT 'full',created_at TEXT NOT NULL,grace_until TEXT,revoked_at TEXT,FOREIGN KEY(peer_id) REFERENCES peers(peer_id))",
    "CREATE INDEX IF NOT EXISTS idx_peer_tokens_peer ON peer_tokens(peer_id,revoked_at)",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_peer_tokens_token_id ON peer_tokens(token_id)",
    "CREATE TABLE IF NOT EXISTS peer_grants (id INTEGER PRIMARY KEY AUTOINCREMENT,grantor TEXT NOT NULL,grantee TEXT NOT NULL,command_type TEXT NOT NULL,scope_json TEXT NOT NULL DEFAULT '{}',granted_at TEXT NOT NULL,valid_until TEXT,revoked_at TEXT,FOREIGN KEY(grantor) REFERENCES peers(peer_id),FOREIGN KEY(grantee) REFERENCES peers(peer_id))",
    "CREATE INDEX IF NOT EXISTS idx_peer_grants_lookup ON peer_grants(grantor,grantee,command_type,revoked_at,valid_until)",
    "CREATE TABLE IF NOT EXISTS peer_target_acl (peer_id TEXT PRIMARY KEY,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,FOREIGN KEY(peer_id) REFERENCES peers(peer_id))",
    "CREATE TABLE IF NOT EXISTS peer_target_acl_targets (peer_id TEXT NOT NULL,target_peer TEXT NOT NULL,created_at TEXT NOT NULL,PRIMARY KEY(peer_id,target_peer),FOREIGN KEY(peer_id) REFERENCES peer_target_acl(peer_id),FOREIGN KEY(target_peer) REFERENCES peers(peer_id))",
    "CREATE INDEX IF NOT EXISTS idx_peer_target_acl_targets_peer ON peer_target_acl_targets(peer_id)",
    "CREATE TABLE IF NOT EXISTS source_counters (source TEXT PRIMARY KEY,last_seq INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT NOT NULL UNIQUE,source TEXT NOT NULL,target TEXT NOT NULL,type TEXT NOT NULL,seq INTEGER NOT NULL,created_at TEXT NOT NULL,stored_at TEXT NOT NULL,payload_json TEXT NOT NULL,requires_ack INTEGER NOT NULL DEFAULT 1,source_ref TEXT,auth_actor TEXT,UNIQUE(source,seq))",
    "CREATE INDEX IF NOT EXISTS idx_events_target_id ON events(target,id)",
    "CREATE INDEX IF NOT EXISTS idx_events_source_seq ON events(source,seq)",
    "CREATE TABLE IF NOT EXISTS acks (id INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT NOT NULL,agent_id TEXT NOT NULL,ack_type TEXT NOT NULL CHECK (ack_type IN ('received','applied')),ack_at TEXT NOT NULL,detail_json TEXT,UNIQUE(event_id,agent_id,ack_type),FOREIGN KEY(event_id) REFERENCES events(event_id))",
    "CREATE INDEX IF NOT EXISTS idx_acks_event ON acks(event_id)",
    "CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT,ts TEXT NOT NULL,actor TEXT,action TEXT NOT NULL,source_ref TEXT,target TEXT,event_id TEXT,result TEXT NOT NULL,detail_json TEXT)",
    "CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_log(event_id)",
    "CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts)",
    "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY,value TEXT NOT NULL)",
    "INSERT OR IGNORE INTO settings(key,value) VALUES('retention_days','30')",
]



class RaftSQLStore:
    def __init__(self, endpoints: Iterable[str], *, initialize: bool = False, timeout: float = 5.0):
        self.client = RqliteClient(endpoints, timeout=timeout)
        if initialize:
            self.client.transaction([[statement] for statement in SCHEMA_STATEMENTS])
        self._ensure_token_schema()
        self._ensure_acl_schema()

    def _ensure_acl_schema(self) -> None:
        self.client.transaction([[statement] for statement in SCHEMA_STATEMENTS[6:9]])

    def _ensure_token_schema(self) -> None:
        columns = {str(row["name"]) for row in self.client.query("PRAGMA table_info(peer_tokens)")}
        for name, definition in (
            ("token_id", "TEXT"),
            ("device_label", "TEXT"),
            ("scope", "TEXT NOT NULL DEFAULT 'full'"),
        ):
            if name not in columns:
                self.client.transaction([[f"ALTER TABLE peer_tokens ADD COLUMN {name} {definition}"]])
        rows = self.client.query(
            "SELECT id,peer_id,token_hash FROM peer_tokens WHERE token_id IS NULL OR token_id=''"
        )
        statements = [
            ["UPDATE peer_tokens SET token_id=?,device_label=coalesce(device_label,'legacy'),"
             "scope=coalesce(scope,'full') WHERE id=?",
             legacy_token_id(str(row["peer_id"]), str(row["token_hash"])), int(row["id"])]
            for row in rows
        ]
        if statements:
            self.client.transaction(statements)
        self.client.transaction([["CREATE UNIQUE INDEX IF NOT EXISTS idx_peer_tokens_token_id ON peer_tokens(token_id)"]])

    def auth_required(self) -> bool:
        # Parity with SQLite: any provisioned peer (even if later revoked) keeps auth on;
        # revoking the last peer must lock out, not fail open. Pristine cluster = open.
        return bool(self.client.query("SELECT 1 AS present FROM peers LIMIT 1"))

    def validate_token(self, peer_id: str, token: str | None) -> bool:
        return self.token_scope(peer_id, token) is not None

    def token_scope(self, peer_id: str, token: str | None) -> str | None:
        if not token:
            return None
        rows = self.client.query(
            "SELECT token_hash,grace_until,revoked_at,scope FROM peer_tokens WHERE peer_id=?",
            (peer_id,),
        )
        now = now_iso()
        for row in rows:
            if row.get("revoked_at"):
                continue
            if row.get("grace_until") and row["grace_until"] < now:
                continue
            if secrets.compare_digest(str(row["token_hash"]), token_hash(token)):
                return str(row.get("scope") or "full")
        return None

    def command_allowed(self, source: str, target: str, payload: dict[str, Any]) -> bool:
        return self._matching_grant(source, target, payload) is not None

    def _matching_grant(self, source: str, target: str, payload: dict[str, Any]) -> tuple[int, str] | None:
        operation = str(payload.get("op", "")).strip()
        if not operation:
            return None
        rows = self.client.query(
            "SELECT id,scope_json FROM peer_grants WHERE grantor=? AND grantee=? AND command_type IN (?,'*') AND revoked_at IS NULL AND (valid_until IS NULL OR valid_until>=?) ORDER BY id",
            (target, source, operation, now_iso()),
        )
        for row in rows:
            scope = json.loads(row.get("scope_json") or "{}")
            if all(payload.get(key) == value for key, value in scope.items()):
                return int(row["id"]), str(row.get("scope_json") or "{}")
        return None

    def set_target_acl(self, peer_id: str, allowed_targets) -> None:
        targets = list(dict.fromkeys(str(target) for target in allowed_targets))
        now = now_iso()
        statements = [[
            "INSERT INTO peer_target_acl(peer_id,created_at,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(peer_id) DO UPDATE SET updated_at=excluded.updated_at",
            peer_id, now, now,
        ], ["DELETE FROM peer_target_acl_targets WHERE peer_id=?", peer_id]]
        statements.extend([
            ["INSERT INTO peer_target_acl_targets(peer_id,target_peer,created_at) VALUES(?,?,?)", peer_id, target, now]
            for target in targets
        ])
        self.client.transaction(statements)

    def clear_target_acl(self, peer_id: str) -> None:
        self.client.transaction([
            ["DELETE FROM peer_target_acl_targets WHERE peer_id=?", peer_id],
            ["DELETE FROM peer_target_acl WHERE peer_id=?", peer_id],
        ])

    def list_target_acls(self, peer_id: str | None = None) -> list[dict[str, Any]]:
        sql, params = "SELECT peer_id,created_at,updated_at FROM peer_target_acl", ()
        if peer_id is not None:
            sql, params = sql + " WHERE peer_id=?", (peer_id,)
        rows = self.client.query(sql + " ORDER BY peer_id", params)
        return [{
            "peer_id": row["peer_id"], "mode": "restricted",
            "allowed_targets": [item["target_peer"] for item in self.client.query(
                "SELECT target_peer FROM peer_target_acl_targets WHERE peer_id=? ORDER BY target_peer",
                (row["peer_id"],))],
            "created_at": row["created_at"], "updated_at": row["updated_at"],
        } for row in rows]



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
        digest = token_hash(token)
        now = now_iso()
        self.client.transaction([
            [
                "INSERT INTO peers "
                "(peer_id, token_hash, role, platform, endpoint, delivery_class, ack_timeout_sec, created_at) "
                "VALUES (?,?,?,?,?,?,?,?) "
                "ON CONFLICT(peer_id) DO UPDATE SET "
                "token_hash=excluded.token_hash, role=excluded.role, platform=excluded.platform, "
                "endpoint=excluded.endpoint, delivery_class=excluded.delivery_class, "
                "ack_timeout_sec=excluded.ack_timeout_sec, revoked_at=NULL",
                peer_id, digest, role, platform, endpoint, delivery_class, int(ack_timeout_sec), now,
            ],
            ["INSERT OR IGNORE INTO peer_tokens "
             "(peer_id,token_hash,token_id,device_label,scope,created_at) VALUES (?,?,?,?,?,?)",
             peer_id, digest, str(uuid.uuid4()), "primary", "full", now],
            ["UPDATE peer_tokens SET revoked_at = ? WHERE peer_id = ? AND token_hash <> ? "
             "AND revoked_at IS NULL AND (device_label IS NULL OR device_label IN ('legacy','primary','rotation'))",
             now, peer_id, digest],
        ])
        return token

    def rotate_peer_token(self, peer_id: str, token: str | None = None, grace_seconds: int = 300) -> str:
        token = token or secrets.token_urlsafe(32)
        grace_until = (
            datetime.now(timezone.utc) + timedelta(seconds=max(0, grace_seconds))
        ).isoformat(timespec="seconds").replace("+00:00", "Z")
        digest = token_hash(token)
        self.client.transaction([
            ["UPDATE peer_tokens SET grace_until = ? WHERE peer_id = ? AND revoked_at IS NULL "
             "AND (device_label IS NULL OR device_label IN ('legacy','primary','rotation')) "
             "AND (grace_until IS NULL OR grace_until >= ?)",
             grace_until, peer_id, now_iso()],
            ["INSERT INTO peer_tokens "
             "(peer_id,token_hash,token_id,device_label,scope,created_at) VALUES (?,?,?,?,?,?)",
             peer_id, digest, str(uuid.uuid4()), "rotation", "full", now_iso()],
            ["UPDATE peers SET token_hash = ? WHERE peer_id = ?", digest, peer_id],
        ])
        return token

    def add_grant(
        self,
        grantor: str,
        grantee: str,
        command_type: str,
        scope: dict[str, Any] | None = None,
        valid_until: str | None = None,
    ) -> int:
        results = self.client.transaction([
            [
                "INSERT INTO peer_grants "
                "(grantor, grantee, command_type, scope_json, granted_at, valid_until) VALUES (?,?,?,?,?,?)",
                grantor, grantee, command_type, compact_json(scope or {}), now_iso(), valid_until,
            ],
        ])
        return int(results[0].get("last_insert_id", 0))

    def revoke_grant(self, grant_id: int) -> None:
        self.client.transaction([
            ["UPDATE peer_grants SET revoked_at = ? WHERE id = ?", now_iso(), int(grant_id)],
        ])

    def add_device_token(
        self, peer_id: str, device_label: str, *, token: str | None = None,
        scope: str = "full", actor: str = "operator",
    ) -> dict[str, str]:
        if device_label in {"legacy", "primary", "rotation"}:
            raise ValueError("device_label is reserved")
        if scope not in {"full", "notify"}:
            raise ValueError("scope must be full or notify")
        if not self.client.query(
            "SELECT 1 AS present FROM peers WHERE peer_id=? AND revoked_at IS NULL", (peer_id,)
        ):
            raise KeyError(peer_id)
        token = token or secrets.token_urlsafe(32)
        token_id = str(uuid.uuid4())
        now = now_iso()
        self.client.transaction([
            ["INSERT INTO peer_tokens "
             "(peer_id,token_hash,token_id,device_label,scope,created_at) VALUES (?,?,?,?,?,?)",
             peer_id, token_hash(token), token_id, device_label, scope, now],
            ["INSERT INTO audit_log(ts,actor,action,target,result,detail_json) VALUES(?,?,?,?,?,?)",
             now, actor, "device_token_add", peer_id, "accepted",
             compact_json({"token_id": token_id, "device_label": device_label, "scope": scope})],
        ])
        return {"peer_id": peer_id, "token_id": token_id, "device_label": device_label,
                "scope": scope, "token": token}

    def list_device_tokens(self, peer_id: str) -> list[dict[str, Any]]:
        return self.client.query(
            "SELECT token_id,peer_id,device_label,scope,created_at,grace_until,revoked_at "
            "FROM peer_tokens WHERE peer_id=? ORDER BY id", (peer_id,),
        )

    def revoke_device_token(self, token_id: str, *, actor: str = "operator") -> dict[str, Any]:
        rows = self.client.query(
            "SELECT peer_id,device_label,scope,revoked_at FROM peer_tokens WHERE token_id=?", (token_id,)
        )
        if not rows:
            raise KeyError(token_id)
        row = rows[0]
        now = now_iso()
        result = "already_revoked" if row.get("revoked_at") else "accepted"
        statements: list[list[Any]] = []
        if not row.get("revoked_at"):
            statements.append(["UPDATE peer_tokens SET revoked_at=? WHERE token_id=?", now, token_id])
        statements.append(
            ["INSERT INTO audit_log(ts,actor,action,target,result,detail_json) VALUES(?,?,?,?,?,?)",
             now, actor, "device_token_revoke", row["peer_id"], result,
             compact_json({"token_id": token_id, "device_label": row.get("device_label"),
                           "scope": row.get("scope")})]
        )
        self.client.transaction(statements)
        return {"token_id": token_id, "peer_id": row["peer_id"], "revoked": True, "result": result}

    def audit(self, actor, action, source_ref, target, event_id, result, detail=None) -> None:
        self.client.transaction([[
            "INSERT INTO audit_log(ts,actor,action,source_ref,target,event_id,result,detail_json) VALUES(?,?,?,?,?,?,?,?)",
            now_iso(), actor, action, source_ref, target, event_id, result, compact_json(detail or {}),
        ]])

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
        event_id = event_id or str(uuid.uuid4())
        created_at = created_at or now_iso()
        if event_type == "command":
            return self._insert_command(
                source, target, payload, seq=seq, event_id=event_id,
                created_at=created_at, requires_ack=requires_ack,
                source_ref=source_ref, token=token,
            )

        existing = self._event_or_none(event_id)
        if existing:
            return verify_event_identity(existing, source, target, event_type)
        stored_at = now_iso()
        acl_condition = (
            "NOT EXISTS(SELECT 1 FROM peer_target_acl WHERE peer_id=?) OR "
            "(? <> '*' AND EXISTS(SELECT 1 FROM peer_target_acl_targets WHERE peer_id=? AND target_peer=?))"
        )
        acl_params = [source, target, source, target]
        if seq is None:
            statements = [
                [f"INSERT INTO source_counters(source,last_seq) SELECT ?,1 WHERE NOT EXISTS(SELECT 1 FROM events WHERE event_id=?) AND ({acl_condition}) ON CONFLICT(source) DO UPDATE SET last_seq=last_seq+1", source, event_id, *acl_params],
                [f"INSERT OR IGNORE INTO events(event_id,source,target,type,seq,created_at,stored_at,payload_json,requires_ack,source_ref,auth_actor) SELECT ?,?,?,?,last_seq,?,?,?,?,?,? FROM source_counters WHERE source=? AND ({acl_condition})", event_id, source, target, event_type, created_at, stored_at, compact_json(payload), 1 if requires_ack else 0, source_ref, None, source, *acl_params],
            ]
        else:
            statements = [
                [f"INSERT OR IGNORE INTO events(event_id,source,target,type,seq,created_at,stored_at,payload_json,requires_ack,source_ref,auth_actor) SELECT ?,?,?,?,?,?,?,?,?,?,? WHERE ({acl_condition})", event_id, source, target, event_type, int(seq), created_at, stored_at, compact_json(payload), 1 if requires_ack else 0, source_ref, None, *acl_params],
                ["INSERT INTO source_counters(source,last_seq) SELECT ?,? WHERE EXISTS(SELECT 1 FROM events WHERE event_id=? AND source=? AND seq=?) ON CONFLICT(source) DO UPDATE SET last_seq=max(last_seq,excluded.last_seq)", source, int(seq), event_id, source, int(seq)],
            ]
        self.client.transaction(statements)
        event = self._event_or_none(event_id)
        if event:
            return verify_event_identity(event, source, target, event_type)
        raise PermissionError("target not allowed")

    def _insert_command(
        self, source: str, target: str, payload: dict[str, Any], *,
        seq: int | None, event_id: str, created_at: str,
        requires_ack: bool, source_ref: str | None, token: str | None,
    ) -> Event:
        if not source_ref:
            self.audit(source, "command_reject", source_ref, target, event_id, "missing_source_ref")
            raise PermissionError("command requires source_ref")
        existing = self._event_or_none(event_id)
        if existing:
            return verify_event_identity(existing, source, target, "command")
        grant = self._matching_grant(source, target, payload)
        if not token or grant is None:
            result = "invalid_token" if not self.validate_token(source, token) else "grant_denied"
            self.audit(source, "command_reject", source_ref, target, event_id, result)
            raise PermissionError("command token rejected" if result == "invalid_token" else "command grant rejected")

        now = now_iso()
        token_digest = token_hash(token)
        grant_id, grant_scope = grant
        operation = str(payload.get("op", "")).strip()
        condition = (
            "EXISTS(SELECT 1 FROM peer_tokens WHERE peer_id=? AND token_hash=? AND revoked_at IS NULL "
            "AND (grace_until IS NULL OR grace_until>=?)) AND "
            "EXISTS(SELECT 1 FROM peer_grants WHERE id=? AND grantor=? AND grantee=? AND scope_json=? "
            "AND command_type IN (?,'*') AND revoked_at IS NULL AND (valid_until IS NULL OR valid_until>=?))"
        )
        auth_params = [source, token_digest, now, grant_id, target, source, grant_scope, operation, now]
        if seq is None:
            statements = [
                [f"INSERT INTO source_counters(source,last_seq) SELECT ?,1 WHERE NOT EXISTS(SELECT 1 FROM events WHERE event_id=?) AND {condition} ON CONFLICT(source) DO UPDATE SET last_seq=last_seq+1", source, event_id, *auth_params],
                [f"INSERT OR IGNORE INTO events(event_id,source,target,type,seq,created_at,stored_at,payload_json,requires_ack,source_ref,auth_actor) SELECT ?,?,?, 'command',last_seq,?,?,?,?,?,? FROM source_counters WHERE source=? AND {condition}", event_id, source, target, created_at, now, compact_json(payload), 1 if requires_ack else 0, source_ref, source, source, *auth_params],
            ]
        else:
            statements = [
                [f"INSERT OR IGNORE INTO events(event_id,source,target,type,seq,created_at,stored_at,payload_json,requires_ack,source_ref,auth_actor) SELECT ?,?,?, 'command',?,?,?,?,?,?,? WHERE {condition}", event_id, source, target, int(seq), created_at, now, compact_json(payload), 1 if requires_ack else 0, source_ref, source, *auth_params],
                ["INSERT INTO source_counters(source,last_seq) SELECT ?,? WHERE EXISTS(SELECT 1 FROM events WHERE event_id=? AND source=? AND seq=?) ON CONFLICT(source) DO UPDATE SET last_seq=max(last_seq,excluded.last_seq)", source, int(seq), event_id, source, int(seq)],
            ]
        statements.append([
            "INSERT INTO audit_log(ts,actor,action,source_ref,target,event_id,result,detail_json) SELECT ?,?,?,?,?,?,'accepted','{}' WHERE EXISTS(SELECT 1 FROM events WHERE event_id=? AND source=? AND target=? AND type='command' AND auth_actor=?) AND NOT EXISTS(SELECT 1 FROM audit_log WHERE event_id=? AND action='command_accept')",
            now, source, "command_accept", source_ref, target, event_id,
            event_id, source, target, source, event_id,
        ])
        self.client.transaction(statements)
        event = self._event_or_none(event_id)
        if event:
            return verify_event_identity(event, source, target, "command")

        result = "invalid_token" if not self.validate_token(source, token) else "grant_denied"
        self.audit(source, "command_reject", source_ref, target, event_id, result)
        raise PermissionError("command authorization changed before commit")

    def _event_or_none(self, event_id: str) -> Event | None:
        rows = self.client.query("SELECT * FROM events WHERE event_id=?", (event_id,))
        return self._row_to_event(rows[0]) if rows else None

    def get_event(self, event_id: str) -> Event:
        event = self._event_or_none(event_id)
        if not event:
            raise KeyError(event_id)
        return event

    def list_events(self, target=None, since_id=0, limit=100, state="pending") -> list[Event]:
        limit = max(1, min(int(limit), 500))
        if target and state == "pending":
            sql = "SELECT * FROM events e WHERE target IN (?,'*') AND id>? AND NOT EXISTS(SELECT 1 FROM acks a WHERE a.event_id=e.event_id AND a.agent_id=? AND a.ack_type='applied') ORDER BY id ASC LIMIT ?"
            params = (target, int(since_id), target, limit)
        elif target and state == "all":
            sql = "SELECT * FROM events WHERE target IN (?,'*') AND id>? ORDER BY id ASC LIMIT ?"
            params = (target, int(since_id), limit)
        elif not target:
            sql = "SELECT * FROM events WHERE id>? ORDER BY id ASC LIMIT ?"
            params = (int(since_id), limit)
        else:
            raise ValueError("state must be pending or all")
        return [self._row_to_event(row) for row in self.client.query(sql, params)]

    def ack(self, event_id, agent_id, ack_type, detail=None) -> None:
        if ack_type not in {"received", "applied"}:
            raise ValueError("ack_type must be received or applied")
        self.client.transaction([[
            "INSERT INTO acks(event_id,agent_id,ack_type,ack_at,detail_json) VALUES(?,?,?,?,?) ON CONFLICT(event_id,agent_id,ack_type) DO UPDATE SET ack_at=excluded.ack_at,detail_json=excluded.detail_json",
            event_id, agent_id, ack_type, now_iso(), compact_json(detail or {}),
        ]])

    def acks_for(self, event_id: str) -> list[dict[str, Any]]:
        return self.client.query("SELECT * FROM acks WHERE event_id=? ORDER BY id ASC", (event_id,))

    def backlog_depth(self, target: str) -> int:
        rows = self.client.query("SELECT count(*) AS n FROM events e WHERE e.requires_ack=1 AND e.target IN (?,'*') AND NOT EXISTS(SELECT 1 FROM acks a WHERE a.event_id=e.event_id AND a.agent_id=? AND a.ack_type='applied')", (target, target))
        return int(rows[0]["n"])

    def health_snapshot(self) -> dict[str, Any]:
        peer_rows = self.client.query(
            "SELECT p.peer_id, p.revoked_at AS peer_revoked_at,"
            " EXISTS(SELECT 1 FROM peer_tokens t WHERE t.peer_id=p.peer_id AND t.revoked_at IS NULL)"
            " AS token_active FROM peers p ORDER BY p.peer_id")
        last = self.client.query("SELECT id,stored_at FROM events ORDER BY id DESC LIMIT 1")
        retention = self.client.query("SELECT value FROM settings WHERE key='retention_days'")
        depths = {row["peer_id"]: self.backlog_depth(row["peer_id"])
                  for row in peer_rows if row["token_active"]}
        orphan_rows = self.client.query(
            "SELECT e.target AS target, count(*) AS n FROM events e"
            " WHERE e.requires_ack=1 AND e.target!='*'"
            " AND e.target NOT IN (SELECT peer_id FROM peers)"
            " AND NOT EXISTS(SELECT 1 FROM acks a WHERE a.event_id=e.event_id"
            " AND a.agent_id=e.target AND a.ack_type='applied') GROUP BY e.target")
        orphans = {row["target"]: int(row["n"]) for row in orphan_rows}
        local_status = self.client.status_local()
        status = local_status if local_status is not None else self.client.status()
        store_status = status.get("store", {})
        raft = store_status.get("raft", {})
        leader = store_status.get("leader", {})
        return {
            "inbox_depths": depths,
            "outbox_pending": sum(depths.values()),
            "orphan_backlog": orphans,
            "backlog_total": sum(depths.values()) + sum(orphans.values()),
            "peers": [{"peer_id": row["peer_id"],
                       "token_active": bool(row["token_active"]),
                       "peer_revoked": row["peer_revoked_at"] is not None}
                      for row in peer_rows],
            "last_event_id": int(last[0]["id"]) if last else None,
            "last_event_at": last[0]["stored_at"] if last else None,
            "retention_days": int(retention[0]["value"]),
            "storage_backend": "rqlite",
            "raft_state": raft.get("state"),
            "raft_scope": "node-local" if local_status is not None else "cluster-fallback",
            "leader_id": leader.get("node_id") if isinstance(leader, dict) else leader,
        }

    @staticmethod
    def _row_to_event(row: dict[str, Any]) -> Event:
        return Event(
            id=int(row["id"]), event_id=row["event_id"], source=row["source"],
            target=row["target"], type=row["type"], seq=int(row["seq"]),
            created_at=row["created_at"], stored_at=row["stored_at"],
            payload=json.loads(row.get("payload_json") or "{}"),
            requires_ack=bool(row["requires_ack"]), source_ref=row.get("source_ref"),
            auth_actor=row.get("auth_actor"),
        )
