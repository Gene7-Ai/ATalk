"""Ed25519 sign/verify with explicit RFC 8032 strict checks around PyNaCl.

PyNaCl/libsodium does the group math; the strict acceptance policy (spec
4.1) is enforced HERE so rejection behavior is pinned by our own code and
covered by fixed vectors (federation-vectors/strict_verify_v0.json):

  1. sig is 64 bytes; S = LE(sig[32:]) must satisfy S < L   -> non_canonical_s
  2. R = sig[:32] must decode canonically (y < p, re-encode
     round-trip, x=0 only with sign bit 0)                  -> non_canonical_r / invalid_r
  3. same for the public key A                              -> non_canonical_a / invalid_a
  4. [8]R != identity and [8]A != identity (cofactor-8
     small-order test)                                      -> small_order_r / small_order_a
  5. group equation via PyNaCl                              -> signature_invalid

Small-order detection uses the cofactor test [8]P == identity rather than a
table of known encodings. The order-8 subgroup has 8 points and exactly 8
decodable wire encodings — one canonical encoding per point. Counting
"8 points plus x-sign variants" (14) double-counts: for the six points with
x != 0, flipping the sign bit is the canonical encoding of the NEGATED
point, which is itself one of the 8 (the subgroup is closed under negation).
The only sign variants that are not decodable at all are the sign-1
encodings of the two x=0 points (identity and the order-2 point); a strict
decoder rejects those as non-canonical before the group test. A hand-built
table is easy to get subtly wrong on exactly this point; the cofactor check
needs only the extended-coordinate arithmetic below and catches every
small-order point. tests/test_federation_round1.py validates that
arithmetic via [L]A == identity on a registered key.
"""
from __future__ import annotations

import platform

import nacl
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from atalk.federation.canonical import FederationError

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, P - 2, P)) % P
_SQRT_M1 = pow(2, (P - 1) // 4, P)
_IDENTITY = (0, 1, 1, 0)

FROZEN_VERSIONS = {
    "python": platform.python_version(),
    "nacl": nacl.__version__,
    # PyNaCl 1.6.2 exposes no libsodium version symbol (nacl._sodium.lib has
    # none); freeze via the PyNaCl 1.6.2 official wheel instead of guessing.
    "libsodium": None,
    "libsodium_note": "not exposed by the PyNaCl 1.6.2 ABI; pinned by the PyNaCl 1.6.2 wheel",
    "strict_checks": [
        "signature_length", "public_key_length", "s_below_L",
        "r_canonical_roundtrip", "a_canonical_roundtrip",
        "r_not_small_order", "a_not_small_order", "nacl_group_equation",
    ],
}


def sign(key, message: bytes) -> bytes:
    """Detached Ed25519 signature. `key` is a 32-byte seed or a SigningKey."""
    sk = key if isinstance(key, SigningKey) else SigningKey(bytes(key))
    return sk.sign(bytes(message)).signature


def verify(public_key: bytes, message: bytes, sig: bytes) -> bool:
    """Strict verify; raises FederationError(layer="signature", category=...)
    on rejection, returns True only when every strict check passed."""
    if len(sig) != 64:
        raise FederationError("signature", "signature_length")
    if len(public_key) != 32:
        raise FederationError("signature", "public_key_length")
    if int.from_bytes(sig[32:], "little") >= L:
        raise FederationError("signature", "non_canonical_s")
    r = _decompress(sig[:32], "r")
    if _small_order(r):
        raise FederationError("signature", "small_order_r")
    a = _decompress(public_key, "a")
    if _small_order(a):
        raise FederationError("signature", "small_order_a")
    try:
        VerifyKey(public_key).verify(bytes(message), sig)
    except BadSignatureError:
        raise FederationError("signature", "signature_invalid") from None
    return True


def _decompress(enc: bytes, side: str):
    """Decode a 32-byte point encoding per RFC 8032 5.1.3; extended coords."""
    non_canon = FederationError("signature", f"non_canonical_{side}")
    y = int.from_bytes(enc, "little") & (2**255 - 1)
    sign_bit = enc[31] >> 7
    if y >= P:
        raise non_canon
    u = (y * y - 1) % P
    v = (_D * y * y + 1) % P
    # x = u/v = u v^3 (u v^7)^((p-5)/8), branch on v x^2 per RFC 8032 5.1.3
    x = (u * pow(v, 3, P) % P) * pow(u * pow(v, 7, P) % P, (P - 5) // 8, P) % P
    vx2 = v * x * x % P
    if vx2 == (P - u) % P:
        x = x * _SQRT_M1 % P
    elif vx2 != u:
        raise FederationError("signature", f"invalid_{side}", "not on curve")
    if x == 0 and sign_bit:
        raise non_canon  # re-encoding would flip the sign bit: no round-trip
    if x & 1 != sign_bit:
        x = P - x
    return (x, y, 1, x * y % P)


def _add(p1, p2):
    """Unified extended-coordinate addition (strongly unified, so also valid
    for doubling); twisted Edwards a=-1, RFC 8032 5.1.4."""
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * _D * t1 * t2 % P
    d = 2 * z1 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _is_identity(point) -> bool:
    x, y, z, _t = point
    return x % P == 0 and (y - z) % P == 0


def _scalar_mul(point, k: int):
    result = _IDENTITY
    for bit in bin(k)[2:]:
        result = _add(result, result)
        if bit == "1":
            result = _add(result, point)
    return result


def _small_order(point) -> bool:
    # order(P) | 8  <=>  [8]P == identity
    return _is_identity(_scalar_mul(point, 8))
