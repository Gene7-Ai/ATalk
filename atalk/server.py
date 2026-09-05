from __future__ import annotations

import argparse
import json
import logging
import os
import queue
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .core import AtalkStore, EventIdConflict, event_to_dict
from .raftsql import RaftSQLStore
from .storage import AtalkStorage


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

    def notify(self, agent: str, item: dict) -> None:
        with self._lock:
            queues = list(self._queues.get(agent, set()))
        for q in queues:
            self._offer(q, item)

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
        if parsed.path == "/health":
            snapshot = self.server.store.health_snapshot()
            snapshot.update({"ok": True, "wake_streams": self.server.wake.connected(), "wake_streams_scope": "node-local"})
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
        return self.send_error_json(404, "not found")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        try:
            body = self.read_json()
            if parsed.path == "/device-tokens":
                peer = body["peer_id"]
                if self.server.store.auth_required() and not self.authorized(peer, {"full"}):
                    raise PermissionError("full peer token required")
                result = self.server.store.add_device_token(
                    peer, body["device_label"], token=body.get("token"),
                    scope=body.get("scope", "full"), actor=peer,
                )
                return self.send_json(result, status=201)
            if parsed.path == "/device-tokens/revoke":
                peer = body["peer_id"]
                if self.server.store.auth_required() and not self.authorized(peer, {"full"}):
                    raise PermissionError("full peer token required")
                rows = self.server.store.list_device_tokens(peer)
                if body["token_id"] not in {row["token_id"] for row in rows}:
                    raise PermissionError("token does not belong to authenticated peer")
                return self.send_json(
                    self.server.store.revoke_device_token(body["token_id"], actor=peer)
                )
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
                self.server.store.ack(body["event_id"], body["agent_id"], body["ack_type"], body.get("detail"))
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
    def __init__(self, address, store: AtalkStorage, wake: WakeHub, max_inbox_depth: int = 1000):
        super().__init__(address, AtalkHandler)
        self.store = store
        self.wake = wake
        self.max_inbox_depth = max(1, int(max_inbox_depth))
        self.message_acl = MessageAcl()


def first(qs: dict[str, list[str]], key: str) -> str | None:
    values = qs.get(key)
    return values[0] if values else None


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
