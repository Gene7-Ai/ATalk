from __future__ import annotations

import argparse
import errno
import hashlib
import json
import logging
import os
import queue
import shutil
import sqlite3
import tempfile
import threading
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .core import AtalkStore, EventIdConflict, event_to_dict
from .federation import schema as fed_schema
from .federation.canonical import FederationError, canonical_bytes, decode_strict
from .federation.runtime import FederationConfig, FederationRuntime
from .federation.store import OutboxFull
from .raftsql import RaftSQLStore
from .storage import AtalkStorage

# F1 (r4): no federation module imported here pulls in PyNaCl at import time
# (runtime.py defers its crypto imports), so the zero-dependency package
# imports and starts with federation simply off.  The strict-verify call
# sites below import ed25519strict lazily: they only execute when a
# FederationRuntime is active, and activation (FederationRuntime.build)
# already gates on the crypto backend being importable.


MESSAGE_ACL_PATH = os.environ.get("ATALK_MESSAGE_ACL", "/etc/atalk/message-acl.json")


class MessageAcl:
    """Per-source target allowlist for /events.

    Config file format: {"restricted_peers": {"<peer_id>": ["target", ...]}}
    Peers listed are default-deny: broadcast ("*") rejected, only listed
    targets allowed. Peers not listed keep existing behavior.
    Fail-closed: if the config file exists but cannot be parsed, every
    non-command send is denied (including peers that would otherwise be
    unrestricted). Peers stay unrestricted only when the config is readable
    and does not list them, or when the file is absent.
    """

    def __init__(self, path: str = MESSAGE_ACL_PATH):
        self._path = path
        self._lock = threading.Lock()
        self._mtime: float | None = None
        self._restricted: dict[str, set[str]] = {}
        self._broken = False

    def _refresh(self) -> None:
        try:
            mtime = os.stat(self._path).st_mtime
        except FileNotFoundError:
            self._mtime = None
            self._restricted = {}
            self._broken = False
            return
        if mtime == self._mtime and not self._broken:
            return
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            peers_cfg = raw.get("restricted_peers") or {}
            if not isinstance(peers_cfg, dict):
                raise ValueError("restricted_peers must be an object")
            restricted = {}
            for peer, targets in peers_cfg.items():
                # A bare string would iterate into a per-character allowlist; require a list.
                if not isinstance(targets, (list, tuple)):
                    raise ValueError(f"targets for {peer!r} must be a list of peer ids")
                restricted[str(peer)] = {str(x) for x in targets}
        except Exception:
            # Fail closed for peers we last knew as restricted; keep old map.
            self._broken = True
            return
        self._mtime = mtime
        self._restricted = restricted
        self._broken = False

    def check(self, source: str, target: str) -> str | None:
        """Return None when allowed, or a rejection reason string."""
        with self._lock:
            self._refresh()
            broken = self._broken
            allowed = self._restricted.get(source)
        if broken:
            # Present-but-unparseable config: fail closed. The operator put an ACL
            # file there on purpose; allowing everything would silently defeat it.
            return "message ACL unavailable (failing closed)"
        if allowed is None:
            return None
        if target == "*":
            return f"peer {source} may not broadcast"
        if target not in allowed:
            return f"peer {source} may not send to {target}"
        return None


class RequestTooLarge(Exception):
    """Raised when a request body exceeds the configured maximum size."""


def fed_error_status(exc: FederationError) -> int:
    """HTTP status for a federation rejection.  Design v0.4.3 pins this
    mapping (documented in atalk/federation/README.md): format/parse/schema
    -> 400, size -> 413, registry/signature/binding -> 403, inbound semantics
    -> 422.  All are permanent for the sender."""
    if exc.category == "body_too_large":
        return 413
    if exc.layer == "inbound":
        return 422
    if exc.layer in ("registry", "signature", "receipt_binding"):
        return 403
    return 400


def sqlite_primary_code(exc: BaseException) -> int | None:
    code = getattr(exc, "sqlite_errorcode", None)
    return (int(code) & 0xFF) if isinstance(code, int) else None


def probe_storage_errno(store: AtalkStorage) -> int | None:
    """Probe the SQLite directory without exposing its path to the caller.

    Project-quota exhaustion is surfaced by SQLite as SQLITE_IOERR, not
    SQLITE_FULL. A tiny sibling write lets us distinguish ENOSPC/EDQUOT from a
    genuine EIO. The temporary file is always removed when creation succeeded.
    """
    db_path = getattr(store, "db_path", None)
    if db_path is None:
        return None
    probe_path: str | None = None
    try:
        fd, probe_path = tempfile.mkstemp(prefix=".atalk-write-probe-", dir=str(Path(db_path).parent))
        try:
            os.write(fd, b"\0" * 4096)
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as probe_exc:
        return probe_exc.errno
    finally:
        if probe_path is not None:
            try:
                os.unlink(probe_path)
            except OSError:
                pass
    return None


def classify_storage_error(exc: BaseException, store: AtalkStorage) -> tuple[str, int, int | None] | None:
    """Return (public error, HTTP status, probe errno) for storage failures."""
    if not isinstance(exc, sqlite3.OperationalError):
        return None
    primary = sqlite_primary_code(exc)
    if primary == sqlite3.SQLITE_FULL:
        return ("storage_full", 507, None)
    if primary == sqlite3.SQLITE_IOERR:
        probe_errno = probe_storage_errno(store)
        if probe_errno in {errno.ENOSPC, errno.EDQUOT}:
            return ("storage_full", 507, probe_errno)
        return ("storage_io_error", 503, probe_errno)
    return None


class WakeHub:
    def __init__(self):
        self._lock = threading.Lock()
        self._queues: dict[str, set[queue.Queue[dict]]] = {}

    def subscribe(self, agent: str) -> queue.Queue[dict]:
        # Bounded: a stalled SSE consumer must not grow server memory without limit.
        # Wake items are only hints; polling is the recovery path, so dropping on
        # overflow is safe (see notify()).
        q: queue.Queue[dict] = queue.Queue(maxsize=1024)
        with self._lock:
            # One authoritative wake lane per peer. Reconnect atomically replaces
            # a stale TCP/SSE subscription that the kernel has not reaped yet.
            self._queues[agent] = {q}
        return q

    def unsubscribe(self, agent: str, q: queue.Queue[dict]) -> None:
        with self._lock:
            queues = self._queues.get(agent)
            if queues:
                queues.discard(q)
                if not queues:
                    self._queues.pop(agent, None)

    def notify(self, agent: str, item: dict) -> bool:
        """r4 F6: True ONLY when at least one live subscribed queue accepted
        the item without dropping.  A no-op (offline agent, no queue) and an
        overflow drop are never reported as a delivery; callers must not
        mark work complete on False."""
        with self._lock:
            queues = list(self._queues.get(agent, set()))
        if not queues:
            return False
        delivered = True
        for q in queues:
            try:
                q.put_nowait(item)
            except queue.Full:
                delivered = False
        return delivered

    def notify_all(self, item: dict) -> None:
        with self._lock:
            queues = [q for group in self._queues.values() for q in group]
        for q in queues:
            self._offer(q, item)

    @staticmethod
    def _offer(q: "queue.Queue[dict]", item: dict) -> None:
        # Never block a notifier on a slow/stuck subscriber; drop the wake hint on
        # overflow (the consumer recovers by polling).
        try:
            q.put_nowait(item)
        except queue.Full:
            pass

    def connected(self) -> dict[str, int]:
        with self._lock:
            return {agent: len(queues) for agent, queues in self._queues.items()}


class AtalkHandler(BaseHTTPRequestHandler):
    server: "AtalkHTTPServer"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        if parsed.path in {"/health", "/readiness"}:
            self.server.refresh_storage_health()
            readable = True
            try:
                snapshot = self.server.store.health_snapshot()
            except Exception:
                logging.exception("ledger read probe failed during GET %s", parsed.path)
                readable = False
                snapshot = {}
            storage = self.server.storage_health()
            snapshot.update({
                "ok": readable and storage["write_ready"],
                "status": "ok" if readable and storage["write_ready"] else "degraded",
                "write_ready": storage["write_ready"],
                "storage_used": storage["used"],
                "storage_limit": storage["limit"],
                "storage": storage,
                "wake_streams": self.server.wake.connected(),
                "wake_streams_scope": "node-local",
            })
            if parsed.path == "/readiness":
                snapshot["ready"] = readable
                return self.send_json(snapshot, status=200 if readable else 503)
            return self.send_json(snapshot)
        if parsed.path == "/events":
            unknown = sorted(set(qs) - {"target", "since_id", "limit", "state"})
            if unknown:
                hint = "; use since_id for the server event cursor" if "since_seq" in unknown else ""
                return self.send_error_json(
                    400,
                    f"unknown query parameter(s): {', '.join(unknown)}{hint}",
                )
            target = first(qs, "target")
            if self.server.store.auth_required():
                if not target:
                    return self.send_error_json(403, "target required when authentication is enabled")
                if not self.authorized(target):
                    return self.send_error_json(403, "target token rejected")
            since_id = int(first(qs, "since_id") or 0)
            limit = int(first(qs, "limit") or 100)
            state = first(qs, "state") or "pending"
            if since_id < 0:
                return self.send_error_json(400, "since_id must be >= 0")
            if limit < 1 or limit > 1000:
                return self.send_error_json(400, "limit must be between 1 and 1000")
            events = self.server.store.list_events(
                target=target,
                since_id=since_id,
                limit=limit,
                state=state,
            )
            return self.send_json([event_to_dict(e) for e in events])
        if parsed.path == "/device-tokens":
            peer = first(qs, "peer")
            if not peer:
                return self.send_error_json(400, "peer required")
            if self.server.store.auth_required() and not self.authorized(peer, {"full"}):
                return self.send_error_json(403, "full peer token required")
            return self.send_json(self.server.store.list_device_tokens(peer))
        if parsed.path == "/stream":
            agent = first(qs, "agent")
            if not agent:
                return self.send_error_json(400, "agent required")
            if self.server.store.auth_required() and not self.authorized(agent):
                return self.send_error_json(403, "agent token rejected")
            return self.stream(agent)
        if parsed.path == "/acks":
            event_id = first(qs, "event_id")
            agent = first(qs, "agent")
            if not event_id:
                return self.send_error_json(400, "event_id required")
            if self.server.store.auth_required():
                if not agent or not self.authorized(agent, {"full"}):
                    return self.send_error_json(403, "agent token rejected")
                # ACK detail can carry handler diagnostics; only a party to the event
                # (its source or target, or any peer for a broadcast) may read them.
                try:
                    ev = self.server.store.get_event(event_id)
                except KeyError:
                    return self.send_error_json(404, "event not found")
                if ev.target != "*" and agent not in (ev.source, ev.target):
                    return self.send_error_json(403, "not a party to this event")
            return self.send_json(self.server.store.acks_for(event_id))
        if parsed.path == "/federation/notifications":
            # r4 F6: durable pull path for federation notifications.  Flag
            # off (or an unknown path) this falls through to the same 404 as
            # every other unknown route.
            fed = self.server.federation
            if fed is None:
                return self.send_error_json(404, "not found")
            agent = first(qs, "agent")
            if agent:
                if self.server.store.auth_required() and not self.authorized(agent):
                    return self.send_error_json(403, "agent token rejected")
                return self.send_json(_notification_views(
                    fed.store.notification_hints_for(agent)))
            peer = first(qs, "peer")
            if not peer:
                return self.send_error_json(400, "agent or peer required")
            if self.server.store.auth_required() and not self.authorized(peer, {"full"}):
                return self.send_error_json(403, "full peer token required")
            return self.send_json(_notification_views(
                fed.store.operator_notification_hints()))
        return self.send_error_json(404, "not found")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        fed = self.server.federation
        if fed is not None and parsed.path in ("/federation/inbox", "/federation/receipts"):
            try:
                if parsed.path == "/federation/inbox":
                    return self.federation_inbox(fed)
                return self.federation_receipts(fed)
            except FederationError as exc:
                return self.send_json(
                    {"status": "rejected", "reason": exc.category},
                    status=fed_error_status(exc))
            except sqlite3.OperationalError as exc:
                classified = classify_storage_error(exc, self.server.store)
                if classified is None:
                    logging.exception("unhandled SQLite error in POST %s", parsed.path)
                    return self.send_json({"status": "rejected", "reason": "internal"},
                                          status=500)
                public_error, status, probe_errno = classified
                logging.warning(
                    "storage write failure during POST %s: error=%s probe_errno=%r",
                    parsed.path, public_error, probe_errno)
                self.server.mark_storage_failure(public_error)
                return self.send_json({"status": "rejected", "reason": public_error},
                                      status=status)
            except Exception:
                logging.exception("unhandled error in POST %s", parsed.path)
                return self.send_json({"status": "rejected", "reason": "internal"},
                                      status=500)
        try:
            body = self.read_json()
            if parsed.path == "/federation/notifications/ack":
                # r4 F6: acknowledge pulled notification hints.  An agent ack
                # touches only that agent's rows; an operator ack (no agent,
                # full-scope peer) touches only operator rows.
                fed = self.server.federation
                if fed is None:
                    return self.send_error_json(404, "not found")
                intent_ids = body.get("intent_ids")
                if (not isinstance(intent_ids, list) or not intent_ids
                        or len(intent_ids) > 100
                        or not all(isinstance(x, str) for x in intent_ids)):
                    raise ValueError(
                        "intent_ids must be a list of 1-100 strings")
                auth = self.headers.get("Authorization", "")
                token = auth.removeprefix("Bearer ").strip() or body.get("token")
                agent = body.get("agent")
                if agent is not None:
                    if not isinstance(agent, str) or not agent:
                        raise ValueError("agent must be a non-empty string")
                    if (self.server.store.auth_required()
                            and self.server.store.token_scope(agent, token) is None):
                        raise PermissionError("agent token rejected")
                    acked = fed.store.ack_notification_hints(intent_ids, agent)
                else:
                    peer = body.get("peer")
                    if not isinstance(peer, str) or not peer:
                        raise ValueError(
                            "peer required to ack operator notifications")
                    if (self.server.store.auth_required()
                            and not self.authorized(peer, {"full"})):
                        raise PermissionError("full peer token required")
                    acked = fed.store.ack_notification_hints(intent_ids, None)
                return self.send_json({"acked": acked})
            if parsed.path == "/device-tokens":
                peer = body["peer_id"]
                if self.server.store.auth_required() and not self.authorized(peer, {"full"}):
                    raise PermissionError("full peer token required")
                result = self.server.store.add_device_token(
                    peer, body["device_label"], token=body.get("token"),
                    scope=body.get("scope", "full"), actor=peer,
                )
                self.server.mark_storage_success()
                return self.send_json(result, status=201)
            if parsed.path == "/device-tokens/revoke":
                peer = body["peer_id"]
                if self.server.store.auth_required() and not self.authorized(peer, {"full"}):
                    raise PermissionError("full peer token required")
                rows = self.server.store.list_device_tokens(peer)
                if body["token_id"] not in {row["token_id"] for row in rows}:
                    raise PermissionError("token does not belong to authenticated peer")
                result = self.server.store.revoke_device_token(body["token_id"], actor=peer)
                self.server.mark_storage_success()
                return self.send_json(result)
            if parsed.path == "/events":
                # Reject poison inputs at the boundary: source/target/type must be
                # non-empty strings and payload, when present, an object. A non-dict
                # payload otherwise gets stored and crashes every downstream reader.
                for field in ("source", "target"):
                    val = body.get(field)
                    if not isinstance(val, str) or not val:
                        raise ValueError(f"{field} must be a non-empty string")
                if "type" in body and not isinstance(body["type"], str):
                    raise ValueError("type must be a string")
                if body.get("payload") is not None and not isinstance(body.get("payload"), dict):
                    raise ValueError("payload must be an object")
                auth = self.headers.get("Authorization", "")
                token = auth.removeprefix("Bearer ").strip() or body.get("token")
                if self.server.store.auth_required() and self.server.store.token_scope(body["source"], token) != "full":
                    raise PermissionError("source token rejected")
                acl_reason = self.server.message_acl.check(body["source"], body["target"])
                if acl_reason:
                    raise PermissionError(acl_reason)
                if fed is not None and body["target"] != "*":
                    family = fed.foreign_family(body["target"])
                    if family is not None:
                        return self.federation_send(fed, body, family)
                # An idempotent retry of an already-accepted event must not be
                # rejected by the backlog gate; only genuinely new events count
                # against the limit.
                existing_eid = body.get("event_id")
                is_retry = False
                if existing_eid:
                    try:
                        self.server.store.get_event(existing_eid)
                        is_retry = True
                    except KeyError:
                        is_retry = False
                if (body["target"] != "*" and not is_retry
                        and self.server.store.backlog_depth(body["target"]) >= self.server.max_inbox_depth):
                    return self.send_error_json(429, "target inbox backlog limit reached")
                event = self.server.store.insert_event(
                    body["source"],
                    body["target"],
                    body.get("type", "message"),
                    body.get("payload") or {},
                    seq=body.get("seq"),
                    event_id=body.get("event_id"),
                    created_at=body.get("created_at"),
                    requires_ack=body.get("requires_ack", True),
                    source_ref=body.get("source_ref"),
                    token=token,
                )
                if not is_retry:
                    self.server.mark_storage_success()
                item = event_to_dict(event)
                wake_item = {"kind": "event", "event": item}
                if event.target == "*":
                    self.server.wake.notify_all(wake_item)
                else:
                    self.server.wake.notify(event.target, wake_item)
                return self.send_json(item, status=201)
            if parsed.path == "/ack":
                auth = self.headers.get("Authorization", "")
                token = auth.removeprefix("Bearer ").strip() or body.get("token")
                if self.server.store.auth_required() and self.server.store.token_scope(body["agent_id"], token) != "full":
                    raise PermissionError("agent token rejected")
                if fed is not None:
                    inb = fed.store.get_inbound(event_id=body["event_id"])
                    if inb is not None:
                        # Spec 6.1: only the recipient of a federation-inbound
                        # event may ACK it (0.9 Appendix A deviation is fixed
                        # on this path only; local events keep current behavior).
                        # agent_id is the local peer id (it also authenticates).
                        target_agent = str(inb["target"]).rsplit("@", 1)[0]
                        if body["agent_id"] != target_agent:
                            raise PermissionError("only the recipient of a federation event may ack it")
                        if body["ack_type"] not in ("received", "applied"):
                            raise ValueError("ack_type must be received or applied")
                        stored_sig = decode_strict(inb["sig"], 64)
                        fed.store.ack_with_receipt_intent(
                            event_id=body["event_id"], agent_id=body["agent_id"],
                            ack_type=body["ack_type"], detail=body.get("detail"),
                            receipt_agent=inb["target"], origin=inb["origin"],
                            origin_event_sig_hash=hashlib.sha256(stored_sig).hexdigest(),
                            issuer=fed.identity.family,
                            issuer_key_id=fed.identity.key_id)
                        fed.run_post_commit_hook()
                        fed.hint_notifications()
                        self.server.mark_storage_success()
                        return self.send_json({"ok": True})
                self.server.store.ack(body["event_id"], body["agent_id"], body["ack_type"], body.get("detail"))
                self.server.mark_storage_success()
                return self.send_json({"ok": True})
        except EventIdConflict as exc:
            return self.send_error_json(409, f"event_id already used for a different message: {exc}")
        except PermissionError as exc:
            return self.send_error_json(403, str(exc))
        except RequestTooLarge:
            return self.send_error_json(413, "request body too large")
        except KeyError as exc:
            return self.send_error_json(400, f"missing field {exc}")
        except (ValueError, json.JSONDecodeError) as exc:
            # Domain/validation errors carry safe, caller-facing messages.
            return self.send_error_json(400, str(exc))
        except sqlite3.OperationalError as exc:
            classified = classify_storage_error(exc, self.server.store)
            if classified is None:
                logging.exception("unhandled SQLite error in POST %s", parsed.path)
                return self.send_error_json(500, "internal server error")
            public_error, status, probe_errno = classified
            logging.warning(
                "storage write failure during POST %s: error=%s sqlite_code=%r "
                "sqlite_name=%r probe_errno=%r",
                parsed.path,
                public_error,
                getattr(exc, "sqlite_errorcode", None),
                getattr(exc, "sqlite_errorname", None),
                probe_errno,
            )
            self.server.mark_storage_failure(public_error)
            return self.send_json(
                {"error": public_error, "code": public_error, "retryable": True},
                status=status,
            )
        except Exception:
            # Never leak raw internal error text (sqlite/attribute/traceback) to clients.
            logging.exception("unhandled error in POST %s", parsed.path)
            return self.send_error_json(500, "internal server error")
        return self.send_error_json(404, "not found")

    def stream(self, agent: str) -> None:
        auth = self.headers.get("Authorization", "")
        token = auth.removeprefix("Bearer ").strip()
        q = self.server.wake.subscribe(agent)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        def still_authorized() -> bool:
            # A stream authenticated at connect must not keep flowing after its
            # token is revoked/expired. Re-check on every tick; if auth turned on
            # after connect (dev->prod) require a token from then on too.
            if not self.server.store.auth_required():
                return True
            return self.server.store.token_scope(agent, token) is not None

        try:
            self.write_sse({"kind": "ready", "agent": agent})
            while True:
                try:
                    item = q.get(timeout=25)
                    if not still_authorized():
                        self.write_sse({"kind": "revoked", "agent": agent})
                        break
                    self.write_sse(item)
                except queue.Empty:
                    if not still_authorized():
                        self.write_sse({"kind": "revoked", "agent": agent})
                        break
                    self.write_sse({"kind": "keepalive"})
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            self.server.wake.unsubscribe(agent, q)

    max_body_bytes = 1 << 20  # 1 MiB cap on request bodies

    # ------------------------------------------------- federation endpoints
    # Spec 4.4/5.3/6.5: the raw-byte limit applies BEFORE any parsing, and
    # compression is rejected, so these endpoints never use read_json().

    def read_fed_body(self) -> bytes:
        length_header = self.headers.get("Content-Length")
        if length_header is None:
            raise FederationError("request", "length_required")
        try:
            length = int(length_header)
        except ValueError:
            raise FederationError("request", "invalid_length") from None
        if length < 0:
            raise FederationError("request", "invalid_length")
        if length > fed_schema.REQUEST_BODY_LIMIT:
            raise FederationError("request", "body_too_large")
        # Bound the raw read: a sender that gives up mid-body must not leave a
        # handler thread blocked forever.  Federation paths only; restored
        # immediately after the read so the rest of the connection is untouched.
        self.connection.settimeout(30)
        try:
            raw = self.rfile.read(length)
        except OSError:
            raise FederationError("request", "invalid_json", "truncated body") from None
        finally:
            try:
                self.connection.settimeout(None)
            except OSError:
                pass
        if len(raw) < length:
            raise FederationError("request", "invalid_json", "truncated body")
        return raw

    def _reject_encoding(self) -> bool:
        if fed_schema.content_encoding_rejected(self.headers.get("Content-Encoding")):
            self.send_json({"status": "rejected", "reason": "content_encoding_rejected"},
                           status=400)
            return True
        return False

    def federation_inbox(self, fed: FederationRuntime) -> None:
        if not fed.allow_conn():
            return self.send_json({"status": "rejected", "reason": "rate_limited_conn"},
                                  status=429)
        try:
            raw = self.read_fed_body()
        except FederationError as exc:
            return self.send_json({"status": "rejected", "reason": exc.category},
                                  status=fed_error_status(exc))
        if self._reject_encoding():
            return
        try:
            env = fed_schema.parse_event(raw)
        except FederationError as exc:
            return self.send_json({"status": "rejected", "reason": exc.category},
                                  status=fed_error_status(exc))
        signed = env.signed
        record = fed.registry.lookup(signed["origin"], signed["key_id"])
        if record is None:
            return self.send_json({"status": "rejected", "reason": "unregistered_key"},
                                  status=403)
        try:
            from .federation import ed25519strict  # lazy: see module note (F1)

            ed25519strict.verify(record.public_key_bytes, env.signed_bytes, env.sig)
        except FederationError as exc:
            return self.send_json({"status": "rejected", "reason": exc.category}, status=403)
        origin = signed["origin"]
        if not fed.allow_family(origin):
            return self.send_json({"status": "rejected", "reason": "rate_limited_family"},
                                  status=429)
        ev = signed["event"]
        # Grammar-validated by the schema; exactly one "@".
        agent, family = ev["target"].split("@")
        if family != fed.identity.family:
            return self.send_json({"status": "rejected", "reason": "target_family"},
                                  status=422)
        if not fed.store.is_local_member(agent):
            return self.send_json({"status": "rejected", "reason": "target_member"},
                                  status=422)
        # source family == verified origin is enforced at the schema layer
        # (allowed earliest layer per spec 4.5).
        status, row = fed.store.receive_event(
            origin=origin, event_id=ev["event_id"],
            event_jcs=canonical_bytes(ev),
            signed_json=canonical_bytes(signed).decode("utf-8"), sig=env.sig_str,
            reg_family=record.family, reg_key_id=record.key_id,
            reg_public_key=record.public_key, source_addr=ev["source"],
            target_addr=ev["target"], target_local=agent, type=ev["type"],
            payload={"text": ev["payload"]["text"]}, created_at=ev["created_at"])
        if status == "conflict":
            return self.send_json({"status": "conflict"}, status=409)
        # Crash seam: raising here leaves the commit in place and the sender
        # sees a transient failure; the retry is absorbed by dedup (spec 6.6/7).
        fed.run_post_commit_hook()
        if row["delivery_state"] == "pending":
            fed.deliver_pending()
        return self.send_json({"status": "stored" if status == "stored" else "duplicate"},
                              status=200)

    def federation_receipts(self, fed: FederationRuntime) -> None:
        if not fed.allow_conn():
            return self.send_json({"status": "rejected", "reason": "rate_limited_conn"},
                                  status=429)
        try:
            raw = self.read_fed_body()
        except FederationError as exc:
            return self.send_json({"status": "rejected", "reason": exc.category},
                                  status=fed_error_status(exc))
        if self._reject_encoding():
            return
        try:
            env = fed_schema.parse_receipt(raw)
        except FederationError as exc:
            return self.send_json({"status": "rejected", "reason": exc.category},
                                  status=fed_error_status(exc))
        rc = env.signed["receipt"]
        # Spec 6.5.2: the event must be one WE sent, and receipt.origin is us.
        out = fed.store.get_outbound(rc["event_id"])
        if out is None:
            return self.send_json({"status": "rejected", "reason": "unknown_event"},
                                  status=403)
        if rc["origin"] != fed.identity.family:
            return self.send_json({"status": "rejected", "reason": "origin_mismatch"},
                                  status=403)
        # Spec 6.5.3: issuer must equal the original target's family, verified
        # with that family's registered key.  Checked BEFORE the registry so a
        # valid signature from a registered-but-wrong family cannot pass.
        # (`issuer` is a top-level signed field, not inside `receipt`, §4.3.)
        issuer = env.signed["issuer"]
        target_family = str(out["target"]).rsplit("@", 1)[1]
        if issuer != target_family:
            return self.send_json(
                {"status": "rejected", "reason": "issuer_not_target_family"}, status=403)
        record = fed.registry.lookup(issuer, env.signed["key_id"])
        if record is None:
            return self.send_json({"status": "rejected", "reason": "unregistered_key"},
                                  status=403)
        try:
            from .federation import ed25519strict  # lazy: see module note (F1)

            ed25519strict.verify(record.public_key_bytes, env.signed_bytes, env.sig)
        except FederationError as exc:
            return self.send_json({"status": "rejected", "reason": exc.category}, status=403)
        if not fed.allow_family(issuer):
            return self.send_json({"status": "rejected", "reason": "rate_limited_family"},
                                  status=429)
        # Spec 6.5.4: hash of OUR immutable stored original's signature bytes.
        stored_sig = decode_strict(out["sig"], 64)
        if rc["origin_event_sig_hash"] != hashlib.sha256(stored_sig).hexdigest():
            return self.send_json({"status": "rejected", "reason": "hash_mismatch"},
                                  status=403)
        # Spec 6.5.5: the receipt names the original event's full target.
        if rc["agent"] != out["target"]:
            return self.send_json({"status": "rejected", "reason": "agent_mismatch"},
                                  status=403)
        status, _notification = fed.store.record_receipt_in(
            event_id=rc["event_id"], agent=rc["agent"], ack_type=rc["ack_type"],
            issuer=issuer, issuer_key_id=env.signed["key_id"],
            signed_json=canonical_bytes(env.signed).decode("utf-8"), sig=env.sig_str,
            notify_agent=out["source_local"],
            notify_detail={"origin": out["origin"], "target": out["target"],
                           "origin_event_sig_hash": rc["origin_event_sig_hash"]})
        fed.run_post_commit_hook()
        fed.hint_notifications()
        return self.send_json({"status": status}, status=200)

    def federation_send(self, fed: FederationRuntime, body: dict, family: str) -> None:
        """Outbound federation path of POST /events (flag on only, spec 5.1)."""
        record = fed.registry.receipts_peer(family)
        if record is None:
            return self.send_error_json(
                400, f"unregistered federation target family: {family}")
        type_ = body.get("type", "message")
        if type_ not in ("message", "reply"):
            return self.send_error_json(
                400, "federation carries only message and reply events")
        payload = body.get("payload") or {}
        if not isinstance(payload, dict) or not isinstance(payload.get("text"), str):
            return self.send_error_json(400, "federation payload requires a string 'text'")
        extra = set(payload) - {"text", "in_reply_to", "auto"}
        if extra:
            return self.send_error_json(
                400, f"federation payload does not support field(s): {', '.join(sorted(extra))}")
        in_reply_to = payload.get("in_reply_to")
        if in_reply_to is not None:
            if type_ != "reply":
                return self.send_error_json(400, "in_reply_to requires type=reply")
            if not isinstance(in_reply_to, str) or not fed_schema.UUID_RE.match(in_reply_to):
                return self.send_error_json(400, "in_reply_to must be a lowercase UUID")
        event_id = body.get("event_id") or str(uuid.uuid4())
        if not fed_schema.UUID_RE.match(event_id):
            return self.send_error_json(400, "federation event_id must be a lowercase UUID")
        source = body["source"]
        if "@" in source:
            return self.send_error_json(
                400, "federation source must be a bare local peer id")
        try:
            envelope = fed.compose_event(
                source_local=source, target=body["target"], type=type_,
                text=payload["text"], event_id=event_id, in_reply_to=in_reply_to)
        except FederationError as exc:
            return self.send_error_json(
                400, f"federation envelope rejected: {exc.category}")
        try:
            enqueued = fed.store.enqueue_outbound(
                event_id=event_id, origin=fed.identity.family,
                origin_key_id=fed.identity.key_id, source_local=source,
                source_addr=f"{source}@{fed.identity.family}", target=body["target"],
                target_family=family, type=type_,
                signed_json=canonical_bytes(
                    {k: v for k, v in envelope.items() if k != "sig"}).decode("utf-8"),
                sig=envelope["sig"], envelope_json=canonical_bytes(envelope),
                outbox_cap=fed.config.outbox_cap)
        except OutboxFull as exc:
            return self.send_error_json(429, str(exc))
        row = fed.store.get_outbound(event_id)
        # r4 F5: a repeated event_id belongs to the stored original.  Compare
        # the immutable caller intent (source/target/type/text/reply link —
        # the freshly generated timestamp is excluded for a legitimate
        # retry); a mismatch is a 409 conflict and a genuine retry is
        # answered EXCLUSIVELY from the stored original, never a mix of the
        # saved envelope and this request's payload.
        stored_event = json.loads(row["signed_json"])["event"]
        if enqueued == "existing" and (
                row["source_local"], row["target"], row["type"],
                stored_event["payload"]["text"],
                stored_event.get("in_reply_to")) != (
                source, body["target"], type_, payload["text"], in_reply_to):
            return self.send_error_json(
                409, "event_id already used for a different federation event")
        item_payload = {"text": stored_event["payload"]["text"]}
        if stored_event.get("in_reply_to") is not None:
            item_payload["in_reply_to"] = stored_event["in_reply_to"]
        item = {
            "event_id": event_id,
            "source": row["source_addr"],
            "target": row["target"],
            "type": row["type"],
            "created_at": stored_event["created_at"],
            "payload": item_payload,
            "requires_ack": True,
            "federation": {"status": row["status"], "target_family": family},
        }
        return self.send_json(item, status=201)

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length < 0:
            raise ValueError("invalid Content-Length")
        if length > self.max_body_bytes:
            raise RequestTooLarge(length)
        raw = self.rfile.read(length).decode("utf-8") if length else "{}"
        value = json.loads(raw or "{}")
        if not isinstance(value, dict):
            raise ValueError("request body must be a JSON object")
        return value

    def authorized(self, peer_id: str, scopes: set[str] | None = None) -> bool:
        auth = self.headers.get("Authorization", "")
        token = auth.removeprefix("Bearer ").strip()
        scope = self.server.store.token_scope(peer_id, token)
        return scope is not None and (scopes is None or scope in scopes)

    def send_json(self, value, status: int = 200) -> None:
        raw = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def send_error_json(self, status: int, message: str) -> None:
        self.send_json({"error": message}, status=status)

    def write_sse(self, value: dict) -> None:
        raw = f"data: {json.dumps(value, ensure_ascii=False)}\n\n".encode("utf-8")
        self.wfile.write(raw)
        self.wfile.flush()

    def log_message(self, fmt: str, *args) -> None:
        return


class AtalkHTTPServer(ThreadingHTTPServer):
    def __init__(self, address, store: AtalkStorage, wake: WakeHub, max_inbox_depth: int = 1000,
                 federation_config: FederationConfig | None = None):
        super().__init__(address, AtalkHandler)
        self.store = store
        self.wake = wake
        self.max_inbox_depth = max(1, int(max_inbox_depth))
        self.message_acl = MessageAcl()
        self._storage_health_lock = threading.Lock()
        self._storage_error: str | None = None
        self._storage_error_since: str | None = None
        # Federation is OFF unless the flag AND the peers/identity files load
        # (fail closed); self.federation stays None and every endpoint behaves
        # exactly as before.
        config = federation_config or FederationConfig.from_env()
        runtime = FederationRuntime.build(config, store)
        self.federation: FederationRuntime | None = None
        if runtime is not None:
            runtime.set_wake(wake)
            self.federation = runtime
            runtime.start()

    def server_close(self) -> None:
        if self.federation is not None:
            self.federation.stop()
            self.federation = None
        super().server_close()

    def process_request_thread(self, request, client_address) -> None:
        """Release request-thread-local storage resources when a handler exits."""
        try:
            super().process_request_thread(request, client_address)
        finally:
            close = getattr(self.store, "close_thread_connection", None)
            if close is not None:
                try:
                    close()
                except Exception:
                    self.handle_error(request, client_address)

    def mark_storage_failure(self, error: str) -> None:
        with self._storage_health_lock:
            if self._storage_error != error or self._storage_error_since is None:
                self._storage_error_since = datetime.now(timezone.utc).isoformat()
            self._storage_error = error

    def mark_storage_full(self) -> None:
        # Compatibility helper for tests and callers built against the first
        # readiness candidate.
        self.mark_storage_failure("storage_full")

    def mark_storage_success(self) -> None:
        with self._storage_health_lock:
            self._storage_error = None
            self._storage_error_since = None

    def refresh_storage_health(self) -> None:
        """Clear a write-failure latch after a durable metadata-only write."""
        with self._storage_health_lock:
            latched = self._storage_error is not None
        if not latched:
            return
        probe = getattr(self.store, "write_probe", None)
        if probe is None:
            return
        try:
            probe()
        except Exception:
            # The original classified failure remains latched.  A health request
            # must never replace it with broad exception/message heuristics.
            return
        self.mark_storage_success()

    def storage_capacity(self) -> tuple[int | None, int | None]:
        db_path = getattr(self.store, "db_path", None)
        if db_path is None:
            return None, None
        try:
            usage = shutil.disk_usage(Path(db_path).parent)
        except OSError:
            return None, None
        return usage.used, usage.total

    def storage_health(self) -> dict:
        with self._storage_health_lock:
            error = self._storage_error
            since = self._storage_error_since
        used, limit = self.storage_capacity()
        result = {
            "ok": error is None,
            "write_ready": error is None,
            "used": used,
            "limit": limit,
        }
        if error is not None:
            result.update({"error": error, "since": since})
        return result


def first(qs: dict[str, list[str]], key: str) -> str | None:
    values = qs.get(key)
    return values[0] if values else None


def _notification_views(rows) -> list[dict]:
    return [{"intent_id": r["intent_id"], "kind": r["kind"], "agent": r["agent"],
             "event_id": r["event_id"],
             "detail": json.loads(r["detail_json"] or "{}"),
             "created_at": r["created_at"]} for r in rows]


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="atalkd")
    parser.add_argument("--db", default="data/atalk.db")
    parser.add_argument("--backend", choices=("sqlite", "rqlite"), default="sqlite")
    parser.add_argument("--rqlite-endpoints", default="")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7070)
    parser.add_argument("--max-inbox-depth", type=int, default=1000)
    return parser


def main(argv: list[str] | None = None) -> int:
    argument_parser = make_parser()
    args = argument_parser.parse_args(argv)
    if args.backend == "rqlite":
        endpoints = [value.strip() for value in args.rqlite_endpoints.split(",") if value.strip()]
        if not endpoints:
            argument_parser.error("--rqlite-endpoints is required for the rqlite backend")
        store = RaftSQLStore(endpoints)
        backend = f"rqlite={','.join(endpoints)}"
    else:
        store = AtalkStore(Path(args.db))
        backend = f"sqlite={Path(args.db).resolve()}"
    server = AtalkHTTPServer((args.host, args.port), store, WakeHub(), args.max_inbox_depth)
    print(f"atalkd listening on http://{args.host}:{args.port} backend={backend}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
