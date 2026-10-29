"""Federation runtime (round 2): activation, local identity, rate limits,
outbound/receipt worker.

Activation is fail-closed on every front: ATALK_FEDERATION=1 AND the peers
file loads (raising loader, not the collapsing one) AND the local identity
file loads with mode 600 (spec 9: the private key never leaves the bus host;
a too-open file disables federation rather than half-enabling it).  The
worker is a daemon thread; TLS verification is always on and redirects are
never followed (spec 8/9).

PyNaCl is an OPTIONAL dependency (F1, r4): nothing here imports the crypto
implementation at module import time, so a zero-dependency install imports
this module (and atalk.server) fine.  The crypto backend is gated once at
activation (build) and imported at each use site; a missing backend keeps
the ordinary service running with federation off.
"""
from __future__ import annotations

import json
import logging
import os
import random
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

from ..core import AtalkStore, event_to_dict, now_iso
from . import schema
from .canonical import (
    NESTING_DEPTH_LIMIT,
    FederationError,
    canonical_bytes,
    decode_strict,
    encode,
    parse_json_text,
)
from .registry import PeerRegistry, endpoint_url_error, load_peers
from .store import FederationStore

log = logging.getLogger(__name__)

EVENT_KIND = schema.EVENT_KIND
RECEIPT_KIND = schema.RECEIPT_KIND

# HTTP codes the worker treats as permanent (spec 8): never retried.
PERMANENT_HTTP = frozenset({400, 401, 403, 409, 413, 422})


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "") or default)
    except ValueError:
        return default


@dataclass(frozen=True)
class FederationConfig:
    enabled: bool
    peers_path: str
    identity_path: str
    outbox_cap: int = 1000
    rate_conn_per_min: int = 300
    rate_family_per_min: int = 60
    worker_interval: float = 1.0
    http_timeout: float = 10.0
    backoff_base: float = 2.0
    backoff_max: float = 300.0
    # r4 F2: explicit, DEFAULT-UNAVAILABLE bypass that lets the registry and
    # the transport admit plain http to a loopback host (self-owned test
    # instances on one machine).  Never set this outside a test fixture.
    allow_insecure_loopback: bool = False

    @classmethod
    def from_env(cls) -> "FederationConfig":
        # Fail closed: the flags must be exactly "1".
        return cls(
            enabled=os.environ.get("ATALK_FEDERATION", "") == "1",
            peers_path=os.environ.get("ATALK_FEDERATION_PEERS",
                                      "/etc/atalk/federation_peers.json"),
            identity_path=os.environ.get("ATALK_FEDERATION_IDENTITY",
                                         "/etc/atalk/federation_identity.json"),
            outbox_cap=max(1, _env_int("ATALK_FED_OUTBOX_CAP", 1000)),
            rate_conn_per_min=max(1, _env_int("ATALK_FED_RATE_CONN", 300)),
            rate_family_per_min=max(1, _env_int("ATALK_FED_RATE_FAMILY", 60)),
            worker_interval=max(0.01, _env_float("ATALK_FED_WORKER_INTERVAL", 1.0)),
            http_timeout=max(0.1, _env_float("ATALK_FED_HTTP_TIMEOUT", 10.0)),
            backoff_base=max(0.01, _env_float("ATALK_FED_BACKOFF_BASE", 2.0)),
            backoff_max=max(0.02, _env_float("ATALK_FED_BACKOFF_MAX", 300.0)),
            allow_insecure_loopback=(
                os.environ.get("ATALK_FEDERATION_ALLOW_LOOPBACK_HTTP", "") == "1"),
        )


@dataclass(frozen=True)
class Identity:
    family: str
    key_id: str
    seed: bytes

    @property
    def signing_key(self):
        from . import ed25519strict  # optional crypto backend; imported lazily (F1)

        return ed25519strict.SigningKey(self.seed)


def load_identity(path: str | Path) -> Identity:
    """Load the local family identity: {"family","key_id","seed"} with seed as
    canonical base64url of the 32-byte Ed25519 seed.  The file mode must be
    EXACTLY 0600 (r4 F8 / §4.7.1: 0400, 0700, 0644, ... all disable
    federation rather than half-enable it; spec 9 keeps the private key
    owner-only on the bus host).  The JSON is parsed strictly and bounded
    (duplicate keys, numbers, over-deep nesting rejected) and every failure —
    including a leaked RecursionError — raises
    FederationError(layer="registry"), so build() collapses it cleanly to
    federation-off and the ordinary service keeps serving."""
    path = Path(path)
    try:
        mode = path.stat().st_mode & 0o777
    except OSError as exc:
        raise FederationError("registry", "file_unreadable", str(exc)) from None
    if mode != 0o600:
        # Checked BEFORE the read: a wrong mode is the precise policy
        # violation an operator needs to see (e.g. 0400 is readable-but-wrong,
        # 0000 is not even readable — both disable federation).
        raise FederationError("registry", "identity_permissions",
                              f"mode {oct(mode)} (must be exactly 0o600)")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise FederationError("registry", "file_unreadable", str(exc)) from None
    try:
        doc = parse_json_text(raw.decode("utf-8"), layer="registry")
    except FederationError as exc:
        # parse-boundary errors carry their own layers (parse, parse/schema);
        # like the peers loader, re-tag them to the registry layer.
        raise FederationError("registry", exc.category, exc.detail) from None
    except UnicodeDecodeError as exc:
        raise FederationError("registry", "invalid_json", str(exc)) from None
    except json.JSONDecodeError as exc:
        raise FederationError("registry", "invalid_json", str(exc)) from None
    except RecursionError:
        # Backstop over the bounded parse; parse_json_text already converts
        # its own, this keeps the contract airtight.
        raise FederationError("registry", "nesting_too_deep",
                              f"scanner recursion; cap is {NESTING_DEPTH_LIMIT}") from None
    if not isinstance(doc, dict):
        raise FederationError("registry", "record_format", "identity must be an object")
    family, key_id, seed = doc.get("family"), doc.get("key_id"), doc.get("seed")
    if not isinstance(family, str) or not schema.FAMILY_RE.match(family):
        raise FederationError("registry", "address_grammar", "identity.family")
    if not isinstance(key_id, str) or not schema.KEY_ID_RE.match(key_id):
        raise FederationError("registry", "key_id_grammar", "identity.key_id")
    if not isinstance(seed, str):
        raise FederationError("registry", "public_key_format", "identity.seed")
    seed_bytes = decode_strict(seed, 32, "public_key_length", layer="registry")
    return Identity(family, key_id, seed_bytes)


class TokenBucket:
    """In-process token bucket; capacity = rate per minute, continuous refill."""

    def __init__(self, rate_per_min: float):
        self.capacity = float(max(1, rate_per_min))
        self.refill_per_sec = self.capacity / 60.0
        self.tokens = self.capacity
        self.updated = time.monotonic()
        self._lock = threading.Lock()

    def allow(self) -> bool:
        with self._lock:
            now = time.monotonic()
            self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.refill_per_sec)
            self.updated = now
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            return False


@dataclass(frozen=True)
class SendOutcome:
    kind: str            # "sent" | "retry" | "permanent"
    error: str = ""
    retry_after: float | None = None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Spec 8: never follow redirects (esp. cross-origin) — the registered
    URL is the only destination.  Returning None makes urllib raise HTTPError."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _make_opener(allow_http: bool) -> urllib.request.OpenerDirector:
    """r4 F2: the outbound opener must have NO plain-HTTP handler by default
    (build_opener would silently add HTTPHandler, accepting plaintext).
    TLS verification is always the default context; redirects are never
    followed; the error processor turns non-2xx into HTTPError."""
    opener = urllib.request.OpenerDirector()
    opener.add_handler(urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    if allow_http:
        opener.add_handler(urllib.request.HTTPHandler())
    opener.add_handler(_NoRedirect())
    opener.add_handler(urllib.request.HTTPErrorProcessor())
    opener.add_handler(urllib.request.HTTPDefaultErrorHandler())
    return opener


_OPENER = _make_opener(allow_http=False)            # https only (spec 8)
_OPENER_LOOPBACK = _make_opener(allow_http=True)    # explicit loopback bypass only

_MAX_RESPONSE_BYTES = 65536


def send_envelope(url: str, body: bytes, timeout: float,
                  allow_insecure_loopback: bool = False) -> SendOutcome:
    """POST an immutable envelope original.  Only https endpoints (or, with
    the explicit default-unavailable bypass, loopback http) are sent to at
    all — anything else is a permanent configuration error with no request
    emitted (r4 F2).  A 200 counts ONLY when the response body parses as
    {"status": "stored"|"duplicate"}; blank, HTML or unknown 200 bodies are
    transient failures (spec 8)."""
    reason = endpoint_url_error(url, allow_insecure_loopback)
    if reason is not None:
        return SendOutcome("permanent", f"unsupported_endpoint_url: {reason}")
    try:
        request = urllib.request.Request(
            url, data=body, method="POST",
            headers={"Content-Type": "application/json; charset=utf-8"})
        if allow_insecure_loopback and urllib.parse.urlsplit(url).scheme == "http":
            opener = _OPENER_LOOPBACK
        else:
            opener = _OPENER
        with opener.open(request, timeout=timeout) as response:
            code = response.status
            raw = response.read(_MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        code = exc.code
        try:
            # r4 F7: the error body is unused — never read it (an unbounded
            # exc.read() let a peer that streams below the socket timeout
            # monopolize the sole sender); close the response instead.
            exc.close()
        except Exception:
            pass
        if 300 <= code < 400:
            return SendOutcome("permanent", "redirect_not_followed")
        if code == 429:
            return SendOutcome("retry", "http_429",
                               retry_after=_parse_retry_after(exc.headers.get("Retry-After")))
        if code in PERMANENT_HTTP:
            return SendOutcome("permanent", f"http_{code}")
        return SendOutcome("retry", f"http_{code}")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        # URLError wraps socket timeouts, TLS failures and unhandled URL
        # types; ValueError covers malformed URLs (both caught here so one
        # bad registry entry can never abort the whole worker cycle; the
        # pre-flight policy check above already reports them as permanent).
        return SendOutcome("retry", f"connection_error: {exc.__class__.__name__}")
    if code != 200:
        return SendOutcome("retry", f"unexpected_status_{code}")
    if len(raw) > _MAX_RESPONSE_BYTES:
        return SendOutcome("retry", "oversized_200_body")
    try:
        # r4 F3: strict bounded-depth parse; a <64KB over-deep body or an
        # oddly shaped "status" member is an expected decode failure and a
        # transient outcome — a TypeError or RecursionError must never escape
        # into the worker cycle (they used to poison the whole round).
        value = parse_json_text(raw.decode("utf-8"), layer="response")
    except (ValueError, RecursionError):
        # json/Unicode errors and FederationError (duplicate keys, nesting
        # cap, value domain) are all ValueError subclasses.
        return SendOutcome("retry", "unparseable_200_body")
    status = value.get("status") if isinstance(value, dict) else None
    if isinstance(status, str) and status in {"stored", "duplicate"}:
        return SendOutcome("sent")
    return SendOutcome("retry", "unrecognized_200_body")


def _parse_retry_after(value: str | None) -> float | None:
    """Valid Retry-After, honored IN FULL (r5 #3: the old min(3600, ...)
    shortened legitimate delays — '7200' came back as 3600 and the worker
    re-contacted the peer before it was allowed to, violating spec 8).
    Grammar-valid forms only: delta-seconds (HTTP: 1*DIGIT) or HTTP-date.
    Anything invalid is None (ordinary backoff); a huge but VALID value is
    returned whole — _backoff schedules it without ever sending early."""
    if not value:
        return None
    value = value.strip()
    if value.isascii() and value.isdigit():  # delta-seconds: exactly 1*DIGIT
        # r6 #3: the HTTP grammar's delta-seconds is ASCII 1*DIGIT.  Unicode
        # isdigit() also let '²' through (float() then raised inside the
        # worker guard) and silently accepted '١٢٣' as 123.0; neither is a
        # valid token, so both are ordinary invalid input: None (backoff).
        return float(value)
    try:
        when = parsedate_to_datetime(value)
        if when.tzinfo is None:
            # r6 #1: HTTP-date means GMT in EVERY valid form (RFC 9110
            # 5.6.7).  The obsolete asctime form (and any other tz-less
            # parse) yields a NAIVE datetime, and naive .timestamp() reads
            # the machine's LOCAL timezone — under TZ=Asia/Singapore an
            # asctime Retry-After was honored EIGHT HOURS early (reviewer r5
            # repro: parsed -> persisted -> same-DB restart -> sent early).
            # Attach UTC before converting; aware forms are untouched.
            when = when.replace(tzinfo=timezone.utc)
        delta = when.timestamp() - time.time()
        return max(0.0, delta)
    except (TypeError, ValueError, OverflowError):
        return None


class FederationRuntime:
    """Owns everything the federation flag switches on.  Construct with
    `FederationRuntime.build(config, store)`; `runtime.active` is False when
    any activation requirement failed (flag off, peers file, identity file,
    non-SQLite backend)."""

    def __init__(self, config: FederationConfig, registry: PeerRegistry,
                 identity: Identity, store: FederationStore):
        self.config = config
        self.registry = registry
        self.identity = identity
        self.store = store
        self.active = True
        self.conn_bucket = TokenBucket(config.rate_conn_per_min)
        self._family_buckets: dict[str, TokenBucket] = {}
        self._buckets_lock = threading.Lock()
        self._wake = None
        self.post_commit_hook = None       # fault-injection seam (tests); no-op when None
        self._hint_cursor: tuple[str, str] | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------ activation

    @classmethod
    def build(cls, config: FederationConfig, store) -> "FederationRuntime | None":
        if not config.enabled:
            return None
        if not isinstance(store, AtalkStore):
            log.warning("federation disabled: requires the SQLite store backend")
            return None
        try:
            # F1 (r4): PyNaCl is an optional dependency.  Gate activation on the
            # crypto backend actually being importable — enabling the flag on a
            # zero-dependency install must fail closed here (federation off,
            # ordinary service unaffected), not crash the worker later.
            from . import ed25519strict  # noqa: F401

        except ImportError as exc:
            log.warning("federation disabled: crypto backend unavailable: %s", exc)
            return None
        try:
            registry = load_peers(config.peers_path,
                                  allow_insecure_loopback=config.allow_insecure_loopback)
        except FederationError as exc:
            log.warning("federation disabled: peers file failed to load: %s", exc)
            return None
        try:
            identity = load_identity(config.identity_path)
        except FederationError as exc:
            log.warning("federation disabled: identity file failed to load: %s", exc)
            return None
        return cls(config, registry, identity, FederationStore(store))

    def set_wake(self, wake) -> None:
        self._wake = wake

    def foreign_family(self, target: str) -> str | None:
        """Family part of a grammar-valid `agent@family` POST /events target
        that is NOT ours (federation routing candidate), else None.  Grammar
        failures leave the target to the normal local path (flag-off parity)."""
        if target.count("@") != 1:
            return None
        try:
            _agent, family = schema.parse_address(target, "events.target")
        except FederationError:
            return None
        if family == self.identity.family:
            return None
        return family

    # ------------------------------------------------------------ rate limits

    def allow_conn(self) -> bool:
        return self.conn_bucket.allow()

    def allow_family(self, family: str) -> bool:
        with self._buckets_lock:
            bucket = self._family_buckets.get(family)
            if bucket is None:
                bucket = TokenBucket(self.config.rate_family_per_min)
                self._family_buckets[family] = bucket
        return bucket.allow()

    # ------------------------------------------------------------- composing

    def compose_event(self, *, source_local: str, target: str, type: str, text: str,
                      event_id: str, created_at: str | None = None,
                      in_reply_to: str | None = None) -> dict:
        """Build + sign + self-validate an outbound event; returns the envelope
        dict.  The caller persists the exact `canonical_bytes(envelope)`."""
        signed = {
            "kind": EVENT_KIND,
            "origin": self.identity.family,
            "key_id": self.identity.key_id,
            "event": {
                "event_id": event_id,
                "type": type,
                "source": f"{source_local}@{self.identity.family}",
                "target": target,
                "created_at": created_at or now_iso(),
                "payload": {"text": text},
            },
        }
        if in_reply_to is not None:
            signed["event"]["in_reply_to"] = in_reply_to
        from . import ed25519strict  # optional crypto backend; imported lazily (F1)

        sig = ed25519strict.sign(self.identity.seed, canonical_bytes(signed))
        envelope = dict(signed)
        envelope["sig"] = encode(sig)
        schema.validate_event_envelope(envelope)  # self-check; a bug must not ship bytes
        return envelope

    def compose_receipt(self, *, event_id: str, origin: str, origin_event_sig_hash: str,
                        agent: str, ack_type: str, at: str) -> dict:
        """Rebuild/materialize a receipt from FIXED fields only (spec 6.2):
        `at` must be the stored first-ack value, never the current time."""
        signed = {
            "kind": RECEIPT_KIND,
            "issuer": self.identity.family,
            "key_id": self.identity.key_id,
            "receipt": {
                "event_id": event_id,
                "origin": origin,
                "origin_event_sig_hash": origin_event_sig_hash,
                "agent": agent,
                "ack_type": ack_type,
                "at": at,
            },
        }
        from . import ed25519strict  # optional crypto backend; imported lazily (F1)

        sig = ed25519strict.sign(self.identity.seed, canonical_bytes(signed))
        envelope = dict(signed)
        envelope["sig"] = encode(sig)
        schema.validate_receipt_envelope(envelope)
        return envelope

    # ---------------------------------------------------------------- worker

    def start(self) -> None:
        if self._thread is not None:
            return
        try:
            self.recovery_scan()
        except Exception:
            # r4 F3: a poison row or a storage failure during startup recovery
            # must not abort server construction; the worker retries every
            # cycle and per-item failures are persisted with backoff.
            log.exception("federation startup recovery failed; worker will retry")
        self._thread = threading.Thread(target=self._run, name="atalk-federation-worker",
                                        daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

    def _run(self) -> None:
        while not self._stop.wait(self.config.worker_interval):
            try:
                self.process_due()
            except Exception:
                log.exception("federation worker cycle failed")

    def _backoff(self, attempts: int, retry_after: float | None) -> str:
        if retry_after is not None:
            seconds = max(0.0, retry_after)
            try:
                target = datetime.now(timezone.utc) + timedelta(seconds=seconds)
            except OverflowError:
                # A valid but unrepresentable Retry-After is honored at the
                # representable ceiling — never shortened into an EARLY send
                # (r5 #3, spec 8).
                target = datetime.max.replace(tzinfo=timezone.utc)
        else:
            steps = min(max(attempts, 1), 10)
            seconds = min(self.config.backoff_base * (2 ** (steps - 1))
                          + random.uniform(0, self.config.backoff_base),
                          self.config.backoff_max)
            target = datetime.now(timezone.utc) + timedelta(seconds=seconds)
        # r6 #2: the persisted format is whole seconds, so round the deadline
        # UP.  Truncation stored up to one second EARLY (a fixed clock at
        # 00:00:00.900 + 7200 was persisted as 02:00:00, and the due scan —
        # a string comparison at second precision — fired 0.9s before the
        # deadline it had honored).
        if target.microsecond:
            try:
                target += timedelta(seconds=1)
            except OverflowError:
                pass                    # already the datetime.max ceiling
            target = target.replace(microsecond=0)
        return target.isoformat(timespec="seconds").replace("+00:00", "Z")

    def process_due(self, now: str | None = None) -> None:
        current = now or now_iso()
        # r4 F3: every item is isolated — one poison row can no longer abort
        # the whole cycle (and with it every healthy row behind it).
        for row in self.store.due_outbound(current):
            self._guarded(self._send_outbound, row, row_kind="outbound")
        for row in self.store.due_receipts(current):
            self._guarded(self._send_receipt, row, row_kind="receipt")
        self.deliver_pending()
        self.hint_notifications()

    def _guarded(self, fn, row, *, row_kind: str) -> bool:
        """Run one worker item in isolation (r4 F3).  An unexpected failure is
        logged and, where the row has retry state, persisted as backoff — a
        poison row never hot-loops without backoff and never starves the rows
        after it.  Delivery/notification rows stay pending and are retried
        next cycle."""
        try:
            return bool(fn(row))
        except Exception as exc:
            log.exception("federation %s task failed unexpectedly (%s)", row_kind,
                          row.get("event_id") or row.get("intent_id"))
            message = f"worker_error: {exc.__class__.__name__}"
            try:
                attempts = int(row.get("attempts") or 0) + 1
                if row_kind == "outbound":
                    self.store.mark_outbound_retry(
                        row["event_id"], attempts,
                        self._backoff(attempts, None), message)
                elif row_kind == "receipt":
                    self.store.mark_receipt_retry(
                        row["event_id"], row["agent"], row["ack_type"], attempts,
                        self._backoff(attempts, None), message)
            except Exception:
                log.exception("federation %s failure backoff not persisted", row_kind)
            return False

    def _materialize_receipt(self, row: dict) -> bool:
        envelope = self.compose_receipt(
            event_id=row["event_id"], origin=row["origin"],
            origin_event_sig_hash=row["origin_event_sig_hash"],
            agent=row["agent"], ack_type=row["ack_type"], at=row["at"])
        self.store.materialize_receipt(
            row["event_id"], row["agent"], row["ack_type"],
            json.dumps(envelope, ensure_ascii=False, separators=(",", ":"),
                       sort_keys=True),
            envelope["sig"])
        return True

    def recovery_scan(self) -> None:
        """Restart path (spec 7): materialize receipts from ACK records using
        fixed fields only, resume pending deliveries and notification hints,
        and retry due sends.  Ended tasks are never reactivated: every scan
        selects status='pending' only.  Each row is isolated (r4 F3)."""
        now = now_iso()
        for row in self.store.due_receipts(now, limit=1000):
            if row["signed_json"] is None:
                self._guarded(self._materialize_receipt, row, row_kind="receipt")
        self.process_due(now)

    # ---------------------------------------------------------- send: events

    def _send_outbound(self, row: dict) -> None:
        peer = self.registry.receipts_peer(row["target_family"])
        if peer is None:
            # Deregistered mid-flight: transient (an admin may re-add the family);
            # the record stays pending with backoff, never silently dropped.
            self.store.mark_outbound_retry(
                row["event_id"], row["attempts"] + 1,
                self._backoff(row["attempts"] + 1, None), "unregistered_family")
            return
        outcome = send_envelope(peer.inbox_url, bytes(row["envelope_json"]),
                                self.config.http_timeout,
                                allow_insecure_loopback=self.config.allow_insecure_loopback)
        self._apply_outcome(
            outcome,
            sent=lambda: self.store.mark_outbound_sent(row["event_id"]),
            retry=lambda ra: self.store.mark_outbound_retry(
                row["event_id"], row["attempts"] + 1,
                self._backoff(row["attempts"] + 1, ra), outcome.error),
            permanent=lambda: self.store.fail_outbound_permanent(
                row["event_id"], outcome.error),
        )

    # -------------------------------------------------------- send: receipts

    def _send_receipt(self, row: dict) -> None:
        if row["signed_json"] is None:
            self._materialize_receipt(row)
            row = {**row, **(self.store.get_receipt_out(
                row["event_id"], row["agent"], row["ack_type"]) or {})}
        # Receipts go to the ORIGINAL sender family's receipts_url (spec 6.4).
        peer = self.registry.receipts_peer(row["origin"])
        if peer is None:
            self.store.mark_receipt_retry(
                row["event_id"], row["agent"], row["ack_type"], row["attempts"] + 1,
                self._backoff(row["attempts"] + 1, None), "unregistered_family")
            return
        body = canonical_bytes({**json.loads(row["signed_json"]), "sig": row["sig"]})
        outcome = send_envelope(peer.receipts_url, body, self.config.http_timeout,
                                allow_insecure_loopback=self.config.allow_insecure_loopback)
        self._apply_outcome(
            outcome,
            sent=lambda: self.store.mark_receipt_sent(row["event_id"], row["agent"],
                                                      row["ack_type"]),
            retry=lambda ra: self.store.mark_receipt_retry(
                row["event_id"], row["agent"], row["ack_type"], row["attempts"] + 1,
                self._backoff(row["attempts"] + 1, ra), outcome.error),
            permanent=lambda: self.store.fail_receipt_permanent(
                row["event_id"], row["agent"], row["ack_type"], outcome.error),
        )

    def _apply_outcome(self, outcome: SendOutcome, sent, retry, permanent) -> None:
        if outcome.kind == "sent":
            sent()
        elif outcome.kind == "permanent":
            permanent()
        else:
            retry(outcome.retry_after)

    # ------------------------------------------------------------- delivery

    def deliver_pending(self) -> int:
        """Push pending federation-inbound events to their recipients through
        the normal wake path (the local event row is already committed, so the
        pull path works regardless; this restores the push hint after a
        crash-between-commit-and-delivery, spec 7).  Each row is isolated
        (r4 F3)."""
        delivered = 0
        for row in self.store.pending_delivery():
            if self._guarded(self._deliver_one, row, row_kind="delivery"):
                delivered += 1
        return delivered

    def _deliver_one(self, row: dict) -> bool:
        try:
            event = self.store.inner.get_event(row["local_event_id"])
        except KeyError:
            self.store.mark_delivered(row["origin"], row["event_id"])
            return True
        self._wake_agent(event.target, {"kind": "event", "event": event_to_dict(event)})
        self.store.mark_delivered(row["origin"], row["event_id"])
        return True

    # r5 #5: the push scan walks pending agent rows via keyset pages of 100,
    # bounded by this per-cycle safety budget.  r6 #4: the keyset cursor
    # persists across cycles with wraparound, so a backlog larger than the
    # budget resumes where the previous cycle stopped (it can delay a newer
    # row by at most one full sweep instead of hiding it forever).
    HINT_SCAN_BUDGET = 5000

    def hint_notifications(self) -> int:
        # r6 #4: the keyset cursor PERSISTS across cycles (wraparound when a
        # scan reaches the end of the pending set).  It used to reset to the
        # oldest row every cycle, so a backlog larger than the budget re-read
        # only the oldest HINT_SCAN_BUDGET rows forever: 5000 offline-agent
        # rows kept every newer online hint unreachable (reviewer r5 repro: three
        # cycles, the online queue stayed empty).  The cursor is a keyset
        # POSITION, not a row reference: rows already scanned that get ACKed
        # drop out of the scan without skipping the rows behind the cursor,
        # and a sweep that runs off the end of the pending set restarts at
        # the oldest row, so every pending row is revisited at least once
        # per full sweep.  Worker-thread confined (like the rest of the
        # cycle); no lock needed for the cursor itself.
        hinted = 0
        after: tuple[str, str] | None = self._hint_cursor
        scanned = 0
        while scanned < self.HINT_SCAN_BUDGET:
            page = self.store.undelivered_notification_hints(after=after, limit=100)
            if not page:
                self._hint_cursor = None  # exhausted: wrap around next cycle
                break
            for row in page:
                if self._guarded(self._hint_one, row, row_kind="notification"):
                    hinted += 1
            scanned += len(page)
            after = (page[-1]["created_at"], page[-1]["intent_id"])
            self._hint_cursor = after
            if len(page) < 100:
                self._hint_cursor = None  # exhausted: wrap around next cycle
                break
        return hinted

    def _hint_one(self, row: dict) -> bool:
        if row["agent"] is None:
            # r4 F6: operator notifications (e.g. permanent receipt-send
            # failures) have no push target; they are surfaced through the
            # operator pull endpoint and NEVER marked from the push path.
            return False
        payload = {"kind": "federation_notification",
                   "notification": {"intent_id": row["intent_id"], "kind": row["kind"],
                                    "agent": row["agent"], "event_id": row["event_id"],
                                    "detail": json.loads(row["detail_json"])}}
        # r4 F6: a hint counts as sent ONLY when a live subscriber queue
        # accepted the item.  Offline agents, queue overflow and wake
        # exceptions leave the row pending (redelivery is absorbed by the
        # stable intent id, spec 6.6); the durable pull/ack endpoints cover
        # whatever push cannot reach.
        if not self._wake_agent(row["agent"], payload):
            return False
        self.store.mark_notification_hint_sent(row["intent_id"])
        return True

    def _wake_agent(self, agent: str | None, item: dict) -> bool:
        if self._wake is None or agent is None:
            return False
        try:
            return bool(self._wake.notify(agent, item))
        except Exception:
            log.exception("wake hint failed for %s", agent)
            return False

    def run_post_commit_hook(self) -> None:
        # Test seam: raising here simulates a crash AFTER the atomic commit but
        # BEFORE the response/wake; the sender sees a transient failure and the
        # retry is absorbed by dedup (spec 6.6/7 crash windows).
        if self.post_commit_hook is not None:
            self.post_commit_hook()
