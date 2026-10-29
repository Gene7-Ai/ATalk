"""Strict JSON parsing and RFC 8785 (JCS) canonical bytes for federation v0.

Spec 4.1 narrows the protocol domain to objects and strings with keys
matching [a-z_]+ only. Inside that domain Python's json.dumps with
sort_keys + compact separators + ensure_ascii=False is byte-identical to
JCS: key ordering by code point equals byte order for ASCII keys, and
string escaping (", \\, control chars via \\b \\t \\n \\f \\r or shortest
\\uXXXX) matches RFC 8785 3.2.2.2. Values outside the domain are rejected,
never coerced.

Parse boundary (design draft v0.4.2 §4.6): numbers are rejected in the
json.loads parse hooks (parse_int/parse_float/parse_constant), so an
arbitrarily long numeric literal is classified value_domain without ever
constructing the big integer (Python's int-str digit limit would otherwise
raise a bare ValueError past this module's error contract); nesting is
capped at NESTING_DEPTH_LIMIT by an iterative pre-scan, the parsed
structure is re-checked against the same cap by a second iterative walk,
and every traversal runs on an explicit stack: no step of the boundary
recurses per nesting level.  How deep the interpreter's scanner folds
before raising RecursionError is a CPython-version detail (3.12 uncoupled
C recursion from sys.getrecursionlimit()), so the cap is enforced
structurally and a leaked RecursionError is still converted to the same
stable category nesting_too_deep (layer "parse").  No global recursion or
integer limit is raised.
"""
from __future__ import annotations

import base64
import json
import re


class FederationError(ValueError):
    """Rejection with a stable layer/category pair. Categories match the
    federation-vectors `expect` values (spec 4.5)."""

    def __init__(self, layer: str, category: str, detail: str = ""):
        super().__init__(f"{layer}/{category}" + (f": {detail}" if detail else ""))
        self.layer = layer
        self.category = category
        self.detail = detail


_KEY_RE = re.compile(r"[a-z_]+\Z")


def _no_dupes(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise FederationError("parse", "duplicate_key", key)
        obj[key] = value
    return obj


# Nesting-depth cap (design draft v0.4.2 §4.6, disposition of round-1
# ambiguity 7): enforced WITHOUT touching global interpreter limits — the
# text is pre-scanned iteratively, so over-deep input is rejected
# deterministically as nesting_too_deep regardless of the recursion limit;
# RecursionError from the scanner itself is converted to the same category
# at the parse boundary (backstop).  Applies to envelope parsing AND to the
# peer-registry loader (registry.load_peers, layer "registry").
NESTING_DEPTH_LIMIT = 64


def _depth_prescan(text: str, layer: str) -> None:
    depth = 0
    in_string = escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "{[":
            depth += 1
            if depth > NESTING_DEPTH_LIMIT:
                raise FederationError(layer, "nesting_too_deep",
                                      f"depth {depth} > {NESTING_DEPTH_LIMIT}")
        elif ch in "}]":
            depth -= 1


def _short_token(token: str) -> str:
    return f"{len(token)} chars, starts {token[:32]!r}"


def _reject_number(token: str):
    # The v0 domain has no numbers. Rejecting in the hook keeps an oversized
    # integer literal from ever reaching int(): the digit limit would raise a
    # bare ValueError that escapes the FederationError contract.
    raise FederationError("parse/schema", "value_domain", f"number ({_short_token(token)})")


def _reject_constant(name: str):
    raise FederationError("parse/schema", "value_domain", f"number ({name})")


def _post_load_depth_check(obj, layer: str) -> None:
    """Second, structural enforcement of the cap: an explicit-stack walk of
    the PARSED object, so nesting beyond NESTING_DEPTH_LIMIT is rejected as
    nesting_too_deep even when the text pre-scan was bypassed or a scanner
    folds deeper than expected.  Iterative, like every walk at this
    boundary."""
    stack = [(obj, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, (dict, list)):
            # only containers consume depth, exactly like the pre-scan's
            # counting of { and [ — a leaf inside a limit-deep container is
            # not itself one level deeper
            if depth > NESTING_DEPTH_LIMIT:
                raise FederationError(layer, "nesting_too_deep",
                                      f"depth {depth} > {NESTING_DEPTH_LIMIT}")
            stack.extend((value, depth + 1) for value in
                         (node.values() if isinstance(node, dict) else node))


def parse_json_text(text: str, layer: str = "parse") -> dict:
    """json.loads with the domain hooks (duplicate-key rejection, no numbers
    of any form) plus the nesting-depth cap: the text pre-scan, then a
    structural re-check of the parsed object.  JSON syntax errors still
    surface as json.JSONDecodeError for the caller to classify;
    RecursionError is converted to nesting_too_deep (`layer`)."""
    _depth_prescan(text, layer)
    try:
        obj = json.loads(text, object_pairs_hook=_no_dupes,
                         parse_int=_reject_number, parse_float=_reject_number,
                         parse_constant=_reject_constant)
        _post_load_depth_check(obj, layer)
        return obj
    except RecursionError:
        raise FederationError(layer, "nesting_too_deep",
                              f"scanner recursion; cap is {NESTING_DEPTH_LIMIT}") from None


def _check_domain(root, path):
    """Domain walk on an explicit stack, preorder — same visit order and
    error selection as a recursive walk, but no Python frame per nesting
    level.  Recursion here would be self-inflicted: the boundary exists to
    classify over-deep input, not to die on it, and 3.12's scanner hands
    back trees deeper than the recursion limit."""
    stack = [("value", root, path)]
    while stack:
        kind, node, path = stack.pop()
        if kind == "key":
            if not _KEY_RE.match(node):
                raise FederationError("parse/schema", "value_domain",
                                      f"{path}{node} (key charset)")
        elif isinstance(node, str):
            for ch in node:
                if 0xD800 <= ord(ch) <= 0xDFFF:
                    raise FederationError("parse", "invalid_unicode", path)
        elif isinstance(node, dict):
            pending = []
            for key, value in node.items():
                pending.append(("key", key, path))
                pending.append(("value", value, f"{path}{key}."))
            stack.extend(reversed(pending))
        else:
            # numbers, booleans, null, arrays: outside the v0 protocol domain
            raise FederationError("parse/schema", "value_domain", path or "root")


def parse_strict(raw: bytes) -> dict:
    """Parse untrusted federation JSON bytes into a domain-clean object.

    Rejects invalid UTF-8 (including raw surrogate encodings), duplicate
    keys, escaped lone surrogates, numbers (rejected in the parse hooks
    before any big-integer construction), nesting deeper than
    NESTING_DEPTH_LIMIT, and any value or key outside the objects+strings /
    [a-z_]+ domain.
    """
    if not isinstance(raw, (bytes, bytearray)):
        raise FederationError("parse", "invalid_utf8", "input must be bytes")
    try:
        text = bytes(raw).decode("utf-8")
    except UnicodeDecodeError:
        raise FederationError("parse", "invalid_utf8") from None
    try:
        try:
            obj = parse_json_text(text, "parse")
        except json.JSONDecodeError:
            raise FederationError("parse", "invalid_json") from None
        if not isinstance(obj, dict):
            raise FederationError("parse/schema", "value_domain", "root must be an object")
        _check_domain(obj, "")
    except RecursionError:
        # Backstop over the whole post-decode path (loads, hooks, walks):
        # no step of the boundary may leak a bare RecursionError.
        raise FederationError("parse", "nesting_too_deep",
                              f"parser recursion; cap is {NESTING_DEPTH_LIMIT}") from None
    return obj


def canonical_bytes(obj) -> bytes:
    """JCS (RFC 8785) serialization. Only valid on the domain enforced by
    parse_strict; see module docstring for why this matches byte-for-byte."""
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


_B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_B64_VAL = {ch: i for i, ch in enumerate(_B64URL)}
_B64_RE = re.compile(r"[A-Za-z0-9_-]+\Z")


def encode(raw: bytes) -> str:
    """Canonical base64url without padding."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_strict(text: str, length: int, length_category: str = "signature_length",
                  layer: str = "schema") -> bytes:
    """Strict canonical unpadded base64url -> exactly `length` bytes.

    Check order is canonicality BEFORE length (design draft v0.4.2 §4.6):
      1. type + charset: b64url alphabet only, no padding ('=')  -> non_canonical_base64url
      2. decodable length: len(text) % 4 == 1 cannot decode      -> non_canonical_base64url
      3. decoded trailing bits must be zero (re-encoding the bytes
         would be byte-identical)                                -> non_canonical_base64url
      4. only then, decoded byte count == `length`, else raise `length_category`
         (e.g. signature_length, public_key_length).
    A string that is BOTH non-canonical AND of the wrong length is therefore
    reported as non_canonical_base64url, never as a length error; fixed
    reverse vectors for that combination live in
    federation-vectors/base64url_order_v0.json.
    """
    bad = FederationError(layer, "non_canonical_base64url")
    if not isinstance(text, str) or not _B64_RE.match(text):
        raise bad                                   # charset / padding
    if len(text) % 4 == 1:
        raise bad                                   # mod-4 length cannot decode
    acc = nbits = 0
    out = bytearray()
    for ch in text:
        acc = (acc << 6) | _B64_VAL[ch]
        nbits += 6
        if nbits >= 8:
            nbits -= 8
            out.append((acc >> nbits) & 0xFF)
    if nbits and acc & ((1 << nbits) - 1):
        raise bad  # trailing bits not zero: not the canonical encoding
    if len(out) != length:
        raise FederationError(layer, length_category)
    return bytes(out)
