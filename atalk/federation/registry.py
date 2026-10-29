"""Admin-managed peer registry (spec 3): federation_peers.json, one record
per family — v0 pins exactly one key per family.

  [{"family": "org-a", "key_id": "oa-2026-10",
    "public_key": "<32-byte canonical base64url>",
    "inbox_url": "https://...", "receipts_url": "https://..."}]

Endpoint URLs are TLS-required (r4 F2): only https URLs (no userinfo, no
fragment, with a host) are accepted, at LOAD time and re-checked at the
transport boundary.  The only exception is the explicit, default-unavailable
loopback bypass (`load_peers(..., allow_insecure_loopback=True)`, fed from
ATALK_FEDERATION_ALLOW_LOOPBACK_HTTP=1) for self-owned loopback test
instances; it never accepts plain http to a non-loopback host.

Fail-closed policy: load_peers() raises on ANY problem (unreadable file,
bad JSON, bad record, wrong key length, duplicate family, plaintext or
malformed endpoint URL); servers call safe_load_peers(), which collapses
every failure to an empty registry so federation is simply disabled rather
than partially trusted.
"""
from __future__ import annotations

import json
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

from atalk.federation.canonical import (
    NESTING_DEPTH_LIMIT,
    FederationError,
    decode_strict,
    parse_json_text,
)
from atalk.federation.schema import FAMILY_RE, KEY_ID_RE

RECORD_FIELDS = frozenset({"family", "key_id", "public_key", "inbox_url", "receipts_url"})

# Hosts the explicit loopback bypass may serve plain http to (r4 F2).  The
# bypass is for self-owned test instances on one machine and is unavailable
# unless the admin/test harness turns it on.
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def endpoint_url_error(url: str, allow_insecure_loopback: bool = False) -> str | None:
    """None when `url` is acceptable as a registered peer endpoint, else a
    short stable reason string.  Spec 8: only a TLS-verified https request to
    the registered endpoint counts, so the registry (and, defensively, the
    transport) accept https only — with hostname, without userinfo or
    fragment.  allow_insecure_loopback additionally admits plain http to a
    loopback host; it is an explicit opt-in and defaults to unavailable.

    r5 F2: a malformed URL must be a POLICY result, never an exception —
    urlsplit raises ValueError for invalid IPv6 brackets, an NFKC-invalid
    netloc raises on .hostname, and an out-of-range/non-numeric port raises
    on .port.  All of them classify here as "invalid_url" (with the port
    explicitly validated), so a broken registry entry fails closed
    (unsupported_endpoint_url -> federation off) instead of crashing
    activation or the transport."""
    if not isinstance(url, str) or not url:
        return "empty"
    if any(ord(ch) < 0x20 or ch.isspace() for ch in url):
        return "control_or_whitespace"
    try:
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname  # lowercased; None when the URL has no host
        parts.port             # validated: ValueError when out of 0-65535
    except ValueError:
        return "invalid_url"
    https = parts.scheme == "https"
    loopback_http = (parts.scheme == "http" and allow_insecure_loopback
                     and (host in LOOPBACK_HOSTS
                          or (host is not None and host.endswith(".localhost"))))
    if not https and not loopback_http:
        return f"scheme_{parts.scheme or 'missing'}"
    if not parts.netloc or host is None:
        return "missing_host"
    if parts.username is not None or parts.password is not None:
        return "userinfo"
    if parts.fragment:
        return "fragment"
    return None


@dataclass(frozen=True)
class PeerRecord:
    family: str
    key_id: str
    public_key: str          # exactly as registered (canonical base64url)
    public_key_bytes: bytes  # always 32 bytes
    inbox_url: str
    receipts_url: str


class PeerRegistry:
    def __init__(self, records):
        self._records = list(records)
        self._by_family = {}
        for rec in self._records:
            if rec.family in self._by_family:
                raise FederationError("registry", "duplicate_family", rec.family)
            self._by_family[rec.family] = rec

    def lookup(self, family: str, key_id: str) -> PeerRecord | None:
        """Exact (family, key_id) match; unknown combinations are None."""
        rec = self._by_family.get(family)
        return rec if rec is not None and rec.key_id == key_id else None

    def receipts_peer(self, family: str) -> PeerRecord | None:
        """Registry record for `family` (receipts_url et al), or None."""
        return self._by_family.get(family)

    def __len__(self) -> int:
        return len(self._records)

    def families(self) -> list:
        return sorted(self._by_family)


def _record(raw, index: int, allow_insecure_loopback: bool = False) -> PeerRecord:
    where = f"peers[{index}]"
    if not isinstance(raw, dict):
        raise FederationError("registry", "record_format", where)
    extra = sorted(set(raw) - RECORD_FIELDS)
    if extra:
        raise FederationError("registry", "unknown_field", f"{where}.{extra[0]}")
    missing = sorted(RECORD_FIELDS - set(raw))
    if missing:
        raise FederationError("registry", "missing_field", f"{where}.{missing[0]}")
    family, key_id, public_key = raw["family"], raw["key_id"], raw["public_key"]
    if not isinstance(family, str) or not FAMILY_RE.match(family):
        raise FederationError("registry", "address_grammar", f"{where}.family")
    if not isinstance(key_id, str) or not KEY_ID_RE.match(key_id):
        raise FederationError("registry", "key_id_grammar", f"{where}.key_id")
    if not isinstance(public_key, str):
        raise FederationError("registry", "public_key_format", f"{where}.public_key")
    # Acceptance precondition 2: public-key length errors are caught HERE, at
    # registry load / key validation (public keys never travel in envelopes).
    pk_bytes = decode_strict(public_key, 32, "public_key_length", layer="registry")
    urls = {}
    for field in ("inbox_url", "receipts_url"):
        value = raw[field]
        if not isinstance(value, str) or not value:
            raise FederationError("registry", "record_format", f"{where}.{field}")
        # r4 F2: plaintext or malformed endpoints are a load error (spec 8:
        # only TLS-verified https counts), not something the transport
        # discovers later.  Re-checked again in the transport as defense in
        # depth against mid-flight registry edits.
        reason = endpoint_url_error(value, allow_insecure_loopback)
        if reason is not None:
            raise FederationError("registry", "unsupported_endpoint_url",
                                  f"{where}.{field}: {reason}")
        urls[field] = value
    return PeerRecord(family, key_id, public_key, pk_bytes, urls["inbox_url"], urls["receipts_url"])


def parse_peers(doc, allow_insecure_loopback: bool = False) -> PeerRegistry:
    if not isinstance(doc, list):
        raise FederationError("registry", "registry_format", "root must be an array of records")
    return PeerRegistry([_record(item, i, allow_insecure_loopback)
                         for i, item in enumerate(doc)])


def load_peers(path, allow_insecure_loopback: bool = False) -> PeerRegistry:
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise FederationError("registry", "file_unreadable", str(exc)) from None
    try:
        # Admin-controlled file, but still: strict UTF-8, duplicate-key
        # rejection, no numbers, nesting capped at canonical.NESTING_DEPTH_LIMIT
        # (same parse boundary as envelopes; parse errors re-classified below).
        doc = parse_json_text(raw.decode("utf-8"), layer="registry")
    except UnicodeDecodeError:
        raise FederationError("registry", "invalid_json", "not UTF-8") from None
    except json.JSONDecodeError as exc:
        raise FederationError("registry", "invalid_json", str(exc)) from None
    except RecursionError:
        # Unreachable while the depth cap holds; caught and classified here
        # anyway — catch-and-classify, never silently swallowed.
        raise FederationError("registry", "nesting_too_deep",
                              f"scanner recursion; cap is {NESTING_DEPTH_LIMIT}") from None
    except FederationError as exc:
        raise FederationError("registry", exc.category, exc.detail) from None
    try:
        return parse_peers(doc, allow_insecure_loopback)
    except RecursionError:
        raise FederationError("registry", "nesting_too_deep", "record walk") from None


def safe_load_peers(path, allow_insecure_loopback: bool = False) -> PeerRegistry:
    """Fail closed: any load problem -> empty registry (federation off)."""
    try:
        return load_peers(path, allow_insecure_loopback)
    except FederationError:
        return PeerRegistry([])
