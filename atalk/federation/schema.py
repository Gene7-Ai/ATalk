"""Federation v0 envelope schema: spec 4.2 (event), 4.3 (receipt), 4.4
(envelope + body limit). Grammar checks are exact-byte, no normalization
(spec 3). Error categories match the federation-vectors `expect` values.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

from atalk.federation.canonical import (
    FederationError,
    canonical_bytes,
    decode_strict,
    parse_strict,
)

REQUEST_BODY_LIMIT = 16384   # spec 4.4: raw received bytes, checked before parsing
COMPRESSION_ALLOWED = False  # spec 4.4: v0 rejects any Content-Encoding on requests

EVENT_KIND = "federation.event.v0"
RECEIPT_KIND = "federation.receipt.v0"
EVENT_TYPES = frozenset({"message", "reply"})
ACK_TYPES = frozenset({"received", "applied"})
TEXT_LIMIT = 8192            # spec 4.2: UTF-8 bytes of the decoded string

# Exact-byte grammars (explicit ASCII classes; Python \d would match Unicode digits).
FAMILY_RE = re.compile(r"[a-z0-9-]{1,32}\Z")
AGENT_RE = re.compile(r"[a-z0-9_-]{1,32}\Z")
KEY_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
HEX64_RE = re.compile(r"[0-9a-f]{64}\Z")
TIMESTAMP_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")

_EVENT_TOP = {"kind", "origin", "key_id", "event", "sig"}  # sig never signed (4.4)
_EVENT_FIELDS = {"event_id", "type", "source", "target", "created_at", "payload", "in_reply_to"}
_EVENT_REQUIRED = {"event_id", "type", "source", "target", "created_at", "payload"}
_RECEIPT_TOP = {"kind", "issuer", "key_id", "receipt", "sig"}
_RECEIPT_FIELDS = {"event_id", "origin", "origin_event_sig_hash", "agent", "ack_type", "at"}


@dataclass(frozen=True)
class Envelope:
    kind: str
    signed: dict    # signed object = full envelope minus sig (the signing input)
    sig_str: str
    sig: bytes

    @property
    def signed_bytes(self) -> bytes:
        return canonical_bytes(self.signed)


def check_body_size(raw: bytes) -> None:
    """4.4: raw-byte limit, applied BEFORE any parsing."""
    if len(raw) > REQUEST_BODY_LIMIT:
        raise FederationError("request", "body_too_large", f"{len(raw)} > {REQUEST_BODY_LIMIT}")


def content_encoding_rejected(encoding: str | None) -> bool:
    """4.4: v0 forbids request compression. True = the server must reject.
    Presence-based: ANY header value is rejected, including the empty
    string (an empty Content-Encoding header is still PRESENT and still
    announces an encoding); only None (header absent) passes.
    Round 2 wires this (and check_body_size) into the endpoints."""
    return not COMPRESSION_ALLOWED and encoding is not None


def _err(category: str, detail: str = "") -> FederationError:
    return FederationError("schema", category, detail)


def _fields(obj: dict, allowed: set, required: set, where: str) -> None:
    extra = sorted(set(obj) - allowed)
    if extra:
        raise _err("unknown_field", f"{where}.{extra[0]}")
    missing = sorted(required - set(obj))
    if missing:
        raise _err("missing_field", f"{where}.{missing[0]}")


def _string(obj: dict, key: str, where: str) -> str:
    value = obj.get(key)
    if value is None:
        raise _err("missing_field", f"{where}.{key}")
    if not isinstance(value, str):
        raise _err("value_domain", f"{where}.{key}")
    return value


def _regex(value: str, rx: re.Pattern, category: str, detail: str) -> None:
    if not rx.match(value):
        raise _err(category, detail)


def parse_address(addr: str, where: str):
    """agent@family; exact bytes, no normalization (spec 3). Returns (agent, family)."""
    if not isinstance(addr, str) or addr.count("@") != 1:
        raise _err("address_grammar", where)
    agent, family = addr.split("@")
    if not AGENT_RE.match(agent) or not FAMILY_RE.match(family) or len(addr) > 65:
        raise _err("address_grammar", where)  # grammar is ASCII-only: len(addr) == byte length
    return agent, family


def _timestamp(value, where: str) -> None:
    if not isinstance(value, str) or not TIMESTAMP_RE.match(value):
        raise _err("timestamp_format", where)
    try:
        datetime(int(value[:4]), int(value[5:7]), int(value[8:10]),
                 int(value[11:13]), int(value[14:16]), int(value[17:19]))
    except ValueError:
        raise _err("timestamp_format", where) from None


def _event_body(obj: dict) -> None:
    origin = _string(obj, "origin", "envelope")
    _regex(origin, FAMILY_RE, "address_grammar", "origin")
    _regex(_string(obj, "key_id", "envelope"), KEY_ID_RE, "key_id_grammar", "key_id")
    ev = obj.get("event")
    if not isinstance(ev, dict):
        raise _err("value_domain" if ev is not None else "missing_field", "event")
    _fields(ev, _EVENT_FIELDS, _EVENT_REQUIRED, "event")
    _regex(_string(ev, "event_id", "event"), UUID_RE, "event_id_format", "event.event_id")
    etype = _string(ev, "type", "event")
    if etype not in EVENT_TYPES:
        raise _err("type_whitelist", f"event.type={etype}")
    _source_agent, source_family = parse_address(_string(ev, "source", "event"), "event.source")
    if source_family != origin:
        raise _err("source_family", "event.source family != origin")
    parse_address(_string(ev, "target", "event"), "event.target")
    _timestamp(_string(ev, "created_at", "event"), "event.created_at")
    payload = ev.get("payload")
    if not isinstance(payload, dict):
        raise _err("value_domain" if payload is not None else "missing_field", "event.payload")
    if "text" not in payload:
        raise _err("missing_field", "event.payload.text")
    if set(payload) != {"text"}:
        raise _err("unknown_field", sorted(set(payload) - {"text"})[0])
    text = payload["text"]
    if not isinstance(text, str):
        raise _err("value_domain", "event.payload.text")
    size = len(text.encode("utf-8"))  # spec 4.2: decoded string, UTF-8 byte count
    if size > TEXT_LIMIT:
        raise _err("payload_too_long", f"{size} bytes")
    if "in_reply_to" in ev:
        if etype != "reply":
            raise _err("in_reply_to_disallowed", "in_reply_to outside type=reply")
        _regex(_string(ev, "in_reply_to", "event"), UUID_RE, "in_reply_to_format", "event.in_reply_to")


def _receipt_body(obj: dict) -> None:
    _regex(_string(obj, "issuer", "envelope"), FAMILY_RE, "address_grammar", "issuer")
    _regex(_string(obj, "key_id", "envelope"), KEY_ID_RE, "key_id_grammar", "key_id")
    rc = obj.get("receipt")
    if not isinstance(rc, dict):
        raise _err("value_domain" if rc is not None else "missing_field", "receipt")
    _fields(rc, _RECEIPT_FIELDS, _RECEIPT_FIELDS, "receipt")
    _regex(_string(rc, "event_id", "receipt"), UUID_RE, "event_id_format", "receipt.event_id")
    _regex(_string(rc, "origin", "receipt"), FAMILY_RE, "address_grammar", "receipt.origin")
    _regex(_string(rc, "origin_event_sig_hash", "receipt"), HEX64_RE, "hash_format",
           "receipt.origin_event_sig_hash")
    parse_address(_string(rc, "agent", "receipt"), "receipt.agent")
    ack = _string(rc, "ack_type", "receipt")
    if ack not in ACK_TYPES:
        raise _err("ack_type_whitelist", f"receipt.ack_type={ack}")
    _timestamp(_string(rc, "at", "receipt"), "receipt.at")


def _envelope(obj, kind: str, top: set, body_check) -> Envelope:
    if not isinstance(obj, dict):
        raise _err("value_domain", "envelope must be an object")
    _fields(obj, top, top, "envelope")
    if obj["kind"] != kind:
        raise _err("kind_mismatch", str(obj.get("kind")))
    body_check(obj)
    sig = obj["sig"]
    if not isinstance(sig, str):
        raise _err("value_domain", "sig")
    sig_bytes = decode_strict(sig, 64, "signature_length")
    return Envelope(kind, {k: v for k, v in obj.items() if k != "sig"}, sig, sig_bytes)


def validate_event_envelope(obj: dict) -> Envelope:
    """Domain-clean dict (see canonical.parse_strict) -> validated Envelope."""
    return _envelope(obj, EVENT_KIND, _EVENT_TOP, _event_body)


def validate_receipt_envelope(obj: dict) -> Envelope:
    return _envelope(obj, RECEIPT_KIND, _RECEIPT_TOP, _receipt_body)


def parse_event(raw: bytes) -> Envelope:
    """Raw request bytes -> Envelope (body limit, strict parse, schema, sig decode)."""
    check_body_size(raw)
    return validate_event_envelope(parse_strict(raw))


def parse_receipt(raw: bytes) -> Envelope:
    check_body_size(raw)
    return validate_receipt_envelope(parse_strict(raw))
