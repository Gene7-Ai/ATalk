from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


def _should_handle(event: dict[str, Any], agent: str) -> bool:
    """Handle genuine inbound work while preventing responder reply loops."""

    event_type = event.get("type")
    if event_type in {"message", "prompt"}:
        return True
    if event_type == "reply" and not event.get("payload", {}).get("auto"):
        return True
    print(
        f"atalk-adapter[{agent}] skip event id={event.get('id')} "
        f"event_id={event.get('event_id')} type={event_type} "
        f"auto={event.get('payload', {}).get('auto')}",
        flush=True,
    )
    return False


def http_json(
    url: str,
    payload: dict[str, Any] | None = None,
    *,
    token: str | None = None,
    timeout: float = 180,
) -> Any:
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


@dataclass
class Cursor:
    path: Path
    since_id: int = 0

    @classmethod
    def load(cls, path: str | Path) -> "Cursor":
        path = Path(path)
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            return cls(path, int(value.get("since_id", 0)))
        except FileNotFoundError:
            return cls(path, 0)

    def advance(self, event_id: int) -> None:
        self.since_id = max(self.since_id, int(event_id))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(json.dumps({"since_id": self.since_id}) + "\n", encoding="utf-8")
        temporary.replace(self.path)


@dataclass(frozen=True)
class HandlerResult:
    """Explicit handler outcome; an empty tuple means work is still pending."""

    applied_event_ids: tuple[str, ...]


class AtalkClient:
    def __init__(self, base_url: str, agent: str, token: str | None = None, timeout: float = 180):
        self.base_urls = tuple(value.strip().rstrip("/") for value in base_url.split(",") if value.strip())
        if not self.base_urls:
            raise ValueError("at least one Atalk base URL is required")
        self._preferred = 0
        self.agent = agent
        self.token = token
        self.timeout = timeout

    @property
    def base_url(self) -> str:
        return self.base_urls[self._preferred]

    def _json(self, path: str, payload: dict[str, Any] | None = None) -> Any:
        errors = []
        for offset in range(len(self.base_urls)):
            index = (self._preferred + offset) % len(self.base_urls)
            try:
                value = http_json(
                    f"{self.base_urls[index]}{path}", payload,
                    token=self.token, timeout=self.timeout,
                )
                self._preferred = index
                return value
            except (OSError, ValueError, urllib.error.HTTPError) as exc:
                errors.append(f"{self.base_urls[index]}: {exc}")
        raise RuntimeError("; ".join(errors))

    def events(self, since_id: int, limit: int = 100) -> list[dict[str, Any]]:
        query = urllib.parse.urlencode({"target": self.agent, "since_id": since_id, "limit": limit})
        return self._json(f"/events?{query}")

    def wake_events(self):
        query = urllib.parse.urlencode({"agent": self.agent})
        errors = []
        for offset in range(len(self.base_urls)):
            index = (self._preferred + offset) % len(self.base_urls)
            headers = {"Accept": "text/event-stream"}
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
            request = urllib.request.Request(f"{self.base_urls[index]}/stream?{query}", headers=headers)
            try:
                with urllib.request.urlopen(request, timeout=35) as response:
                    self._preferred = index
                    for raw in response:
                        line = raw.decode("utf-8").strip()
                        if line.startswith("data: "):
                            yield json.loads(line.removeprefix("data: "))
                return
            except (OSError, ValueError, urllib.error.HTTPError) as exc:
                errors.append(f"{self.base_urls[index]}: {exc}")
        raise RuntimeError("; ".join(errors))

    def ack(self, event_id: str, ack_type: str, detail: dict[str, Any] | None = None) -> None:
        self._json(
            "/ack",
            {"event_id": event_id, "agent_id": self.agent, "ack_type": ack_type, "detail": detail or {}},
        )

    def send(
        self,
        target: str,
        event_type: str,
        payload: dict[str, Any],
        *,
        source_ref: str | None = None,
        requires_ack: bool = True,
        event_id: str | None = None,
    ) -> dict[str, Any]:
        # Pin a stable event_id before the first attempt so that a transparent
        # retry (network error, failover to another base_url) is idempotent
        # server-side instead of creating a duplicate delivery.
        event_id = event_id or str(uuid.uuid4())
        return self._json(
            "/events",
            {
                "source": self.agent,
                "target": target,
                "type": event_type,
                "payload": payload,
                "source_ref": source_ref,
                "requires_ack": requires_ack,
                "event_id": event_id,
            },
        )


class Adapter:
    def __init__(
        self,
        client: AtalkClient,
        cursor: Cursor,
        handler: Callable[[dict[str, Any]], HandlerResult | None],
    ):
        self.client = client
        self.cursor = cursor
        self.handler = handler

    def run_once(self) -> int:
        processed = 0
        for event in self.client.events(self.cursor.since_id):
            self.client.ack(event["event_id"], "received")
            try:
                result = self.handler(event)
            except Exception as exc:
                # Do not advance: recovery polling will retry this event.
                self.client.ack(event["event_id"], "received", {"handler_error": str(exc)})
                raise
            applied_event_ids = (event["event_id"],) if result is None else result.applied_event_ids
            for event_id in applied_event_ids:
                self.client.ack(event_id, "applied")
            self.cursor.advance(event["id"])
            processed += 1
        return processed


class InboxStore:
    """Durable local-only delivery store for agents without a local model handler."""

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.pending = self.root / "pending"
        self.applied = self.root / "applied"
        for directory in (self.root, self.pending, self.applied):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            directory.chmod(0o700)

    @staticmethod
    def filename(event: dict[str, Any]) -> str:
        safe_event_id = re.sub(r"[^A-Za-z0-9_.-]", "_", str(event["event_id"]))
        return f"{int(event['id']):020d}_{safe_event_id}.json"

    def find(self, event_id: str, *, include_applied: bool = False) -> Path:
        directories = (self.pending, self.applied) if include_applied else (self.pending,)
        for directory in directories:
            for path in directory.glob("*.json"):
                try:
                    if json.loads(path.read_text(encoding="utf-8")).get("event_id") == event_id:
                        return path
                except (OSError, ValueError):
                    continue
        raise FileNotFoundError(f"event {event_id} not found")

    def deliver(self, event: dict[str, Any]) -> Path:
        filename = self.filename(event)
        destination = self.pending / filename
        applied = self.applied / filename
        if destination.exists():
            return destination
        if applied.exists():
            return applied

        temporary = self.pending / f".{filename}.{os.getpid()}.tmp"
        payload = (json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
            self._fsync_dir(self.pending)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        return destination

    def list_pending(self) -> list[dict[str, Any]]:
        items = []
        for path in sorted(self.pending.glob("*.json")):
            event = json.loads(path.read_text(encoding="utf-8"))
            items.append(event)
        return items

    def mark_applied(self, event_id: str) -> Path:
        source = self.find(event_id)
        destination = self.applied / source.name
        os.replace(source, destination)
        self._fsync_dir(self.pending)
        self._fsync_dir(self.applied)
        return destination

    @staticmethod
    def _fsync_dir(path: Path) -> None:
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


class InboxAdapter:
    """Receive to disk and ACK receipt without invoking any model or external service."""

    def __init__(self, client: AtalkClient, cursor: Cursor, inbox: InboxStore):
        self.client = client
        self.cursor = cursor
        self.inbox = inbox

    def run_once(self) -> int:
        delivered = 0
        for event in self.client.events(self.cursor.since_id):
            self.inbox.deliver(event)
            self.client.ack(event["event_id"], "received", {"delivery": "local_inbox"})
            self.cursor.advance(event["id"])
            delivered += 1
        return delivered


def chat_http_handler(client: AtalkClient, chat_url: str) -> Callable[[dict[str, Any]], None]:
    def handle(event: dict[str, Any]) -> None:
        if not _should_handle(event, client.agent):
            return HandlerResult(())  # skipped (loop-prevention); received, not applied
        text = str(event.get("payload", {}).get("text", "")).strip()
        if not text:
            raise ValueError("chat message payload requires non-empty text")
        result = http_json(chat_url, {"message": text}, timeout=client.timeout)
        reply = str(result.get("reply", "")).strip()
        if not reply:
            raise RuntimeError("chat service returned an empty reply")
        client.send(
            event["source"],
            "reply",
            {"text": reply, "in_reply_to": event["event_id"], "auto": True},
            source_ref=f"atalk:{event['event_id']}",
            event_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"atalk:{event['event_id']}:reply:{client.agent}")),
        )

    return handle


def http_agent_handler(
    client: AtalkClient, endpoint: str, request_field: str = "message", response_field: str = "reply"
) -> Callable[[dict[str, Any]], None]:
    def handle(event: dict[str, Any]) -> None:
        if not _should_handle(event, client.agent):
            return HandlerResult(())  # skipped (loop-prevention); received, not applied
        text = str(event.get("payload", {}).get("text", "")).strip()
        if not text:
            raise ValueError("HTTP agent payload requires non-empty text")
        result = http_json(endpoint, {request_field: text}, timeout=client.timeout)
        reply = str(result.get(response_field, "")).strip()
        if not reply:
            raise RuntimeError(f"HTTP agent returned empty {response_field}")
        client.send(
            event["source"], "reply", {"text": reply, "in_reply_to": event["event_id"], "auto": True},
            source_ref=f"atalk:{event['event_id']}",
            event_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"atalk:{event['event_id']}:reply:{client.agent}")),
        )

    return handle


def find_reply(value: Any) -> str:
    if isinstance(value, dict):
        for key in ("finalAssistantVisibleText", "finalAssistantRawText"):
            text = value.get(key)
            if isinstance(text, str) and text.strip():
                return text.strip()
        payloads = value.get("payloads")
        if isinstance(payloads, list):
            texts = [str(item.get("text") or item.get("content") or "").strip() for item in payloads if isinstance(item, dict)]
            if any(texts):
                return "\n".join(text for text in texts if text)
        for child in value.values():
            reply = find_reply(child)
            if reply:
                return reply
    if isinstance(value, list):
        for child in value:
            reply = find_reply(child)
            if reply:
                return reply
    return ""


class OpenClawTaskStore:
    """Durable bridge ledger linking follow-ups to one OpenClaw work thread."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def _load(self) -> dict[str, Any]:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"version": 1, "threads": {}}
        if not isinstance(value, dict) or not isinstance(value.get("threads"), dict):
            raise ValueError(f"invalid OpenClaw task state: {self.path}")
        return value

    def _save(self, value: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.path)
        self.path.chmod(0o600)

    @staticmethod
    def thread_key(event: dict[str, Any]) -> str:
        payload = event.get("payload", {})
        explicit = payload.get("thread_id") or payload.get("correlation_id")
        # Namespace the client-supplied thread id by source: two different senders that
        # happen to pick the same thread_id must NOT share a task thread, or one sender's
        # events (and completion ACKs) leak into the other's thread.
        return f"thread:{event['source']}:{explicit}" if explicit else f"source:{event['source']}"

    def append(self, event: dict[str, Any], session_id: str) -> tuple[str, ...]:
        value = self._load()
        key = self.thread_key(event)
        thread = value["threads"].setdefault(
            key,
            {"session_id": session_id, "event_ids": [], "status": "active"},
        )
        event_id = str(event["event_id"])
        if event_id not in thread["event_ids"]:
            thread["event_ids"].append(event_id)
        thread["status"] = "active"
        thread["latest_event"] = event
        thread["retry_count"] = 0
        thread.pop("next_retry_at", None)
        thread.pop("blocker_reason", None)
        thread["updated_at"] = int(time.time())
        self._save(value)
        return tuple(thread["event_ids"])

    def set_status(
        self,
        event: dict[str, Any],
        status: str,
        *,
        blocker_reason: str = "",
        retry_base: int = 60,
        retry_max: int = 1800,
    ) -> tuple[str, ...]:
        value = self._load()
        key = self.thread_key(event)
        thread = value["threads"][key]
        event_ids = tuple(str(item) for item in thread["event_ids"])
        if status == "complete":
            # Do NOT delete yet: the reply must be durably sent (and the applied ACK
            # attempted) before we forget the task, otherwise a send/ACK failure loses
            # it with no recovery. Mark complete; finalize_complete() removes it after send.
            thread["status"] = "complete"
            thread["updated_at"] = int(time.time())
            thread.pop("next_retry_at", None)
        else:
            thread["status"] = status
            thread["updated_at"] = int(time.time())
            thread["blocker_reason"] = blocker_reason[:1000]
            if status == "waiting":
                retry_count = int(thread.get("retry_count", 0)) + 1
                thread["retry_count"] = retry_count
                delay = min(retry_max, retry_base * (2 ** min(retry_count - 1, 8)))
                thread["next_retry_at"] = int(time.time()) + delay
            else:
                thread.pop("next_retry_at", None)
        self._save(value)
        return event_ids

    def finalize_complete(self, event: dict[str, Any]) -> None:
        """Remove a thread only after its completion reply has been durably sent."""
        value = self._load()
        key = self.thread_key(event)
        if key in value.get("threads", {}):
            del value["threads"][key]
            self._save(value)

    def pending(self) -> dict[str, Any]:
        return self._load()["threads"]

    def due(self, now: int | None = None) -> list[tuple[str, dict[str, Any]]]:
        now = int(time.time()) if now is None else int(now)
        return [
            (key, thread)
            for key, thread in self.pending().items()
            if thread.get("status") == "waiting"
            and int(thread.get("next_retry_at", 0)) <= now
            and isinstance(thread.get("latest_event"), dict)
        ]


_ATALK_APPLY_PATTERN = re.compile(r"(?:^|\n)ATALK_APPLY:\s*(complete|waiting|blocked)\s*$", re.I)


def parse_openclaw_outcome(reply: str) -> tuple[str, str]:
    match = _ATALK_APPLY_PATTERN.search(reply.strip())
    if not match:
        raise RuntimeError("OpenClaw reply omitted required ATALK_APPLY outcome")
    visible = reply[: match.start()].strip()
    if not visible:
        raise RuntimeError("OpenClaw returned an empty visible reply")
    return visible, match.group(1).lower()


def openclaw_handler(
    client: AtalkClient,
    openclaw_bin: str,
    openclaw_agent: str = "main",
    session_prefix: str = "atalk",
    thinking: str | None = None,
    task_store: OpenClawTaskStore | None = None,
    wait_event_driven: bool = False,
) -> Callable[[dict[str, Any]], HandlerResult | None]:
    def process(event: dict[str, Any], *, retry: bool = False) -> HandlerResult | None:
        if not _should_handle(event, client.agent):
            return HandlerResult(())  # skipped (loop-prevention); received, not applied
        text = str(event.get("payload", {}).get("text", "")).strip()
        if not text:
            raise ValueError("OpenClaw message payload requires non-empty text")
        safe_source = re.sub(r"[^A-Za-z0-9_.-]", "_", str(event["source"]))
        payload = event.get("payload", {})
        explicit_thread = payload.get("thread_id") or payload.get("correlation_id")
        safe_thread = re.sub(r"[^A-Za-z0-9_.-]", "_", str(explicit_thread or safe_source))
        session_id = f"{session_prefix}-{safe_thread}"
        pending_ids = (
            tuple(task_store.pending()[task_store.thread_key(event)]["event_ids"])
            if retry and task_store
            else task_store.append(event, session_id) if task_store
            else (str(event["event_id"]),)
        )
        prompt = (
            f"Atalk event from {event['source']} (event_id={event['event_id']}):\n{text}\n\n"
            f"This durable work thread currently contains event_ids: {', '.join(pending_ids)}.\n"
            "If this message requests actionable work within its authorization, execute that work now in this run "
            "and verify the result before replying. Do not merely acknowledge or promise future action. "
            "Use waiting only for a concrete missing file, permission, reply, authorization, or future condition; "
            "never use waiting merely to queue work that can be done with currently available local material. "
            "Before choosing waiting, re-check whether its condition is already satisfied. "
            "If completion must wait, state the exact blocker in the visible reply. "
            "Reply directly and concisely, then end with exactly one machine line: "
            "ATALK_APPLY: complete, ATALK_APPLY: waiting, or ATALK_APPLY: blocked. "
            "Use complete only when every pending event in this thread is genuinely finished. "
            "Do not contact external systems unless the event explicitly asks and authorizes it."
        )
        try:
            command = [
                openclaw_bin, "agent", "--agent", openclaw_agent,
                "--session-id", session_id,
                "--json", "--timeout", str(int(client.timeout)), "--message", prompt,
            ]
            if thinking:
                command.extend(["--thinking", thinking])
            result = subprocess.run(
                command,
                capture_output=True,
                timeout=client.timeout + 30,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"OpenClaw timed out after {exc.timeout}s") from exc
        combined = (result.stdout or b"").decode("utf-8", errors="replace") + "\n" + (result.stderr or b"").decode("utf-8", errors="replace")
        reply = ""
        for start in (index for index, char in enumerate(combined) if char == "{"):
            try:
                reply = find_reply(json.loads(combined[start:]))
            except json.JSONDecodeError:
                continue
            if reply:
                break
        if not reply:
            diagnostic = combined.strip().replace("\n", " ")[-600:]
            raise RuntimeError(
                f"OpenClaw returned no reply (exit={result.returncode}): {diagnostic}"
            )
        visible_reply, status = parse_openclaw_outcome(reply)
        if task_store:
            previous = task_store.pending()[task_store.thread_key(event)]
            attempt = int(previous.get("retry_count", 0))
            event_ids = task_store.set_status(event, status, blocker_reason=visible_reply)
        else:
            attempt = 0
            event_ids = (str(event["event_id"]),)
        # A periodic retry that remains waiting is internal bookkeeping, not a
        # reason to repeatedly message the sender. State changes and completion
        # remain visible and use distinct idempotency keys.
        if not (retry and status == "waiting"):
            client.send(
                event["source"],
                "reply",
                {
                    "text": visible_reply,
                    "in_reply_to": event["event_id"],
                    "work_status": status,
                    "auto": True,
                },
                source_ref=f"atalk:{event['event_id']}",
                event_id=str(uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    f"atalk:{event['event_id']}:reply:{client.agent}:{status}:{attempt}",
                )),
            )
        # Reply is now durably on the bus; safe to forget a completed task.
        if task_store and status == "complete":
            task_store.finalize_complete(event)
        return HandlerResult(event_ids if status == "complete" else ())

    def handle(event: dict[str, Any]) -> HandlerResult | None:
        return process(event)

    def retry_due() -> int:
        # Task status semantics stay unchanged. With the optional switch,
        # waiting remains durable but only a new event in the same thread wakes
        # inference; the legacy periodic retry remains the default.
        if not task_store or wait_event_driven:
            return 0
        completed = 0
        for _key, thread in task_store.due():
            result = process(thread["latest_event"], retry=True)
            if result and result.applied_event_ids:
                for event_id in result.applied_event_ids:
                    client.ack(event_id, "applied", {"delivery": "openclaw_retry"})
                completed += 1
        return completed

    handle.retry_due = retry_due  # type: ignore[attr-defined]

    return handle


def tmux_handler(client: AtalkClient, session: str, response_timeout: float = 180) -> Callable[[dict[str, Any]], None]:
    def run_tmux(*args: str) -> str:
        result = subprocess.run(["tmux", *args], capture_output=True, text=True, timeout=15, check=False)
        if result.returncode:
            raise RuntimeError(f"tmux {' '.join(args)} failed: {result.stderr.strip()}")
        return result.stdout

    def handle(event: dict[str, Any]) -> None:
        if not _should_handle(event, client.agent):
            return HandlerResult(())  # skipped (loop-prevention); received, not applied
        text = str(event.get("payload", {}).get("text", "")).strip()
        if not text:
            raise ValueError("tmux message payload requires non-empty text")
        marker = event["event_id"].replace("-", "")[:12]
        begin, end = f"ATALK_BEGIN_{marker}", f"ATALK_END_{marker}"
        prompt = (
            f"Atalk event from {event['source']} (id={event['event_id']}): {text}\n"
            f"Reply between markers exactly as: {begin} <your reply> {end}. "
            "Do not contact external systems unless explicitly requested and authorized."
        )
        run_tmux("send-keys", "-t", session, "-l", "--", prompt)
        run_tmux("send-keys", "-t", session, "Enter")
        deadline = time.monotonic() + response_timeout
        pattern = re.compile(rf"●\s+{re.escape(begin)}\s*(.*?)\s*{re.escape(end)}", re.S)
        reply = ""
        while time.monotonic() < deadline:
            pane = run_tmux("capture-pane", "-pt", session, "-S", "-200")
            match = pattern.search(pane)
            if match:
                reply = match.group(1).strip()
                break
            time.sleep(1)
        if not reply:
            raise RuntimeError(f"tmux agent returned no marked reply within {response_timeout}s")
        client.send(
            event["source"], "reply", {"text": reply, "in_reply_to": event["event_id"], "auto": True},
            source_ref=f"atalk:{event['event_id']}",
            event_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"atalk:{event['event_id']}:reply:{client.agent}")),
        )

    return handle


def stdout_handler(event: dict[str, Any]) -> None:
    print(json.dumps(event, ensure_ascii=False), flush=True)


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="atalk-adapter")
    parser.add_argument("--base-url", default=os.environ.get("ATALK_URL", "http://127.0.0.1:7070"))
    parser.add_argument("--agent", required=True)
    parser.add_argument("--token", default=os.environ.get("ATALK_TOKEN"))
    parser.add_argument("--state", required=True)
    parser.add_argument(
        "--mode",
        choices=["http", "inbox", "openclaw-oneshot", "openclaw", "chat-http", "stdout", "tmux"],
        required=True,
    )
    parser.add_argument("--inbox-root")
    parser.add_argument("--chat-url", default="http://127.0.0.1:8765/chat")
    parser.add_argument("--openclaw-bin", default="openclaw")
    parser.add_argument("--openclaw-agent", default="main")
    parser.add_argument("--openclaw-session-prefix", default="atalk")
    parser.add_argument("--openclaw-task-state")
    parser.add_argument(
        "--wait-event-driven",
        action="store_true",
        help="keep waiting tasks durable but retry only when the thread receives a new event",
    )
    parser.add_argument(
        "--openclaw-thinking",
        choices=["off", "minimal", "low", "medium", "high", "xhigh", "adaptive", "max"],
    )
    parser.add_argument("--tmux-session", default="atalk")
    parser.add_argument("--response-timeout", type=float, default=180)
    parser.add_argument("--http-endpoint")
    parser.add_argument("--request-field", default="message")
    parser.add_argument("--response-field", default="reply")
    parser.add_argument("--interval", type=float, default=2.0)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--poll-only", action="store_true", help="disable wake stream and use recovery polling")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    client = AtalkClient(args.base_url, args.agent, args.token)
    if args.mode == "inbox":
        if not args.inbox_root:
            raise SystemExit("--inbox-root is required for inbox mode")
        adapter = InboxAdapter(client, Cursor.load(args.state), InboxStore(args.inbox_root))
    elif args.mode == "chat-http":
        handler = chat_http_handler(client, args.chat_url)
    elif args.mode in {"openclaw-oneshot", "openclaw"}:
        task_state = args.openclaw_task_state or f"{args.state}.tasks.json"
        handler = openclaw_handler(
            client,
            args.openclaw_bin,
            args.openclaw_agent,
            args.openclaw_session_prefix,
            args.openclaw_thinking,
            OpenClawTaskStore(task_state),
            args.wait_event_driven,
        )
    elif args.mode == "tmux":
        handler = tmux_handler(client, args.tmux_session, args.response_timeout)
    elif args.mode == "http":
        if not args.http_endpoint:
            raise SystemExit("--http-endpoint is required for http mode")
        handler = http_agent_handler(client, args.http_endpoint, args.request_field, args.response_field)
    else:
        handler = stdout_handler
    if args.mode != "inbox":
        adapter = Adapter(client, Cursor.load(args.state), handler)
    while args.once or args.poll_only:
        try:
            adapter.run_once()
            retry_due = getattr(getattr(adapter, "handler", None), "retry_due", None)
            if retry_due:
                retry_due()
        except (OSError, urllib.error.URLError, ValueError, RuntimeError) as exc:
            print(f"atalk-adapter error: {exc}", flush=True)
            if args.once:
                return 1
        if args.once:
            return 0
        time.sleep(max(0.1, args.interval))

    # The stream is only a wake signal. Durable events are always recovered by
    # server-id cursor, including the subscribe race and reconnect windows.
    while True:
        try:
            adapter.run_once()
            retry_due = getattr(getattr(adapter, "handler", None), "retry_due", None)
            if retry_due:
                retry_due()
            for _wake in client.wake_events():
                adapter.run_once()
                if retry_due:
                    retry_due()
        except (OSError, urllib.error.URLError, TimeoutError, ValueError, RuntimeError) as exc:
            print(f"atalk-adapter reconnecting after: {exc}", flush=True)
            time.sleep(max(0.1, args.interval))


if __name__ == "__main__":
    raise SystemExit(main())
