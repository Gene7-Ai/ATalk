"""Regression tests for the round-1 review fixes.

Blocking: base64url canonicality-BEFORE-length order (R1; fixed reverse
vectors in federation-vectors/base64url_order_v0.json) and the parse
exception boundary (R2: numbers rejected in json parse hooks without
constructing big integers, unified nesting-depth cap of 64, RecursionError
converted to a stable category at the boundary, same cap applied to the
registry loader).

Non-blocking: Content-Encoding PRESENCE predicate (empty header counts as
present), the small-order subgroup framing (exactly 8 canonical wire
encodings, not "8 points but 14 encodings"), and the split of version
freezing into portable behavior tests vs this file's skippable
evidence-environment consistency class (ATALK_FED_EVIDENCE_ENV=1) vs the
requirements-federation.lock artifact.
"""
import json
import os
import platform
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import nacl

from atalk.federation import canonical, ed25519strict, registry, schema
from atalk.federation.canonical import FederationError

VECTORS_DIR = Path(__file__).resolve().parent.parent / "federation-vectors"
B64_ORDER = json.loads((VECTORS_DIR / "base64url_order_v0.json").read_text(encoding="utf-8"))
LOCK_PATH = Path(__file__).resolve().parent.parent / "requirements-federation.lock"


class Base64UrlOrderVectorTest(unittest.TestCase):
    """R1: decode_strict checks canonicality (charset, mod-4 decodable
    length, re-encode byte-identical) BEFORE comparing the decoded byte
    count with the expected length, so a string that is both non-canonical
    AND of the wrong length reports non_canonical_base64url."""

    def test_order_vectors(self):
        for case in B64_ORDER["cases"]:
            with self.subTest(case["name"]):
                # the vector file means what it says: canonicality-phase
                # cases must expect non_canonical_base64url, byte-length
                # cases the length category
                if case["fires"] in ("charset", "mod4_length", "trailing_bits"):
                    self.assertEqual(case["expect"], "non_canonical_base64url")
                elif case["fires"] == "byte_length":
                    self.assertEqual(case["expect"], case["length_category"])
                if case["expect"] == "valid":
                    out = canonical.decode_strict(case["input"], case["expected_length"],
                                                  case["length_category"], case["layer"])
                    self.assertEqual(len(out), case["expected_length"])
                    self.assertEqual(canonical.encode(out), case["input"])
                else:
                    with self.assertRaises(FederationError, msg=case["name"]) as caught:
                        canonical.decode_strict(case["input"], case["expected_length"],
                                                case["length_category"], case["layer"])
                    self.assertEqual(caught.exception.category, case["expect"], case["name"])
                    self.assertEqual(caught.exception.layer, case["layer"], case["name"])


class ParseBoundaryTest(unittest.TestCase):
    """R2: nothing but FederationError escapes the parse boundary; the
    16 KiB body limit does not (and must not) shield these."""

    def test_5000_digit_number_is_value_domain_not_bare_valueerror(self):
        # exact round-1 probe; Python's int-str digit limit used to raise a
        # bare ValueError here (the parse_int hook now rejects without ever
        # constructing the big integer)
        raw = b'{"a":' + b"1" * 5000 + b"}"
        self.assertLess(len(raw), schema.REQUEST_BODY_LIMIT)
        with self.assertRaises(FederationError) as caught:
            schema.parse_event(raw)
        self.assertEqual(caught.exception.category, "value_domain")
        self.assertEqual(caught.exception.layer, "parse/schema")

    def test_4999_digit_number_rejected_by_hook_within_body_limit(self):
        raw = b'{"a":' + b"9" * 4999 + b"}"
        self.assertLess(len(raw), schema.REQUEST_BODY_LIMIT)
        with self.assertRaises(FederationError) as caught:
            schema.parse_event(raw)
        self.assertEqual(caught.exception.category, "value_domain")
        self.assertEqual(caught.exception.layer, "parse/schema")

    def test_1100_deep_nesting_is_nesting_too_deep_not_recursionerror(self):
        # exact round-1 probe
        raw = b'{"a":' * 1100 + b'"x"' + b"}" * 1100
        self.assertLess(len(raw), schema.REQUEST_BODY_LIMIT)
        with self.assertRaises(FederationError) as caught:
            schema.parse_event(raw)
        self.assertEqual(caught.exception.category, "nesting_too_deep")
        self.assertEqual(caught.exception.layer, "parse")

    def test_depth_cap_boundary_64_ok_65_rejected(self):
        self.assertEqual(canonical.NESTING_DEPTH_LIMIT, 64)
        nested = lambda d: ('{"a":' * (d - 1) + '{"a":"x"}' + '}' * (d - 1)).encode()
        self.assertIsInstance(canonical.parse_strict(nested(canonical.NESTING_DEPTH_LIMIT)), dict)
        with self.assertRaises(FederationError) as caught:
            canonical.parse_strict(nested(canonical.NESTING_DEPTH_LIMIT + 1))
        self.assertEqual(caught.exception.category, "nesting_too_deep")
        self.assertEqual(caught.exception.layer, "parse")

    def test_recursionerror_backstop_converts_when_prescan_bypassed(self):
        nested = lambda d: ('{"a":' * (d - 1) + '{"a":"x"}' + '}' * (d - 1)).encode()
        with mock.patch.object(canonical, "_depth_prescan", lambda *a, **k: None):
            with self.assertRaises(FederationError) as caught:
                canonical.parse_strict(nested(3000))
        self.assertEqual(caught.exception.category, "nesting_too_deep")
        self.assertEqual(caught.exception.layer, "parse")

    def test_deep_parsed_object_rejected_even_when_text_prescan_bypassed(self):
        # 3.12 regression pin: the C json scanner stopped counting its
        # recursion against sys.getrecursionlimit(), so loads() HANDS BACK
        # ~3000-deep trees that 3.11's scanner never finished building (it
        # raised RecursionError, which the backstop converted).  The
        # boundary therefore re-checks the parsed structure against the cap
        # with an explicit-stack walk; where the scanner gives up must not
        # decide whether over-deep input is classified.
        nested = lambda d: ('{"a":' * (d - 1) + '{"a":"x"}' + '}' * (d - 1)).encode()
        with mock.patch.object(canonical, "_depth_prescan", lambda *a, **k: None):
            with self.assertRaises(FederationError) as caught:
                canonical.parse_json_text(nested(3000).decode("utf-8"), "parse")
        self.assertEqual(caught.exception.category, "nesting_too_deep")
        self.assertEqual(caught.exception.layer, "parse")

    def test_domain_walk_is_iterative_on_deep_input(self):
        # The step that leaked on 3.12: the value-domain walk used to
        # recurse once per nesting level.  A ~3000-deep in-domain object
        # must be walked to completion without RecursionError, and a defect
        # at the BOTTOM must still be reported with its full preorder path.
        deep = current = {}
        for _ in range(2999):
            current["a"] = {}
            current = current["a"]
        current["BAD"] = "x"  # key charset defect at depth 3000
        with self.assertRaises(FederationError) as caught:
            canonical._check_domain(deep, "")
        self.assertEqual(caught.exception.category, "value_domain")
        self.assertEqual(caught.exception.layer, "parse/schema")
        self.assertEqual(caught.exception.detail, "a." * 2999 + "BAD (key charset)")
        clean = current = {}
        for _ in range(3000):
            current["a"] = {}
            current = current["a"]
        current["a"] = "x"
        self.assertIsNone(canonical._check_domain(clean, ""))

    def test_numbers_of_every_shape_rejected_at_hook(self):
        for fragment in (b"1", b"-1", b"1.5", b"1e5000", b"NaN", b"Infinity", b"-Infinity"):
            with self.subTest(fragment=fragment):
                with self.assertRaises(FederationError) as caught:
                    canonical.parse_strict(b'{"a":' + fragment + b"}")
                self.assertEqual(caught.exception.category, "value_domain")


class RegistryBoundaryTest(unittest.TestCase):
    """The depth cap and number hooks apply to the registry loader too
    (layer "registry"); failures are classified, never silently swallowed,
    and safe_load_peers still fails closed."""

    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.path = Path(d.name) / "federation_peers.json"

    def test_deep_registry_file_classified(self):
        self.path.write_text("[" * 65 + "]" * 65)
        with self.assertRaises(FederationError) as caught:
            registry.load_peers(self.path)
        self.assertEqual(caught.exception.category, "nesting_too_deep")
        self.assertEqual(caught.exception.layer, "registry")
        self.assertEqual(len(registry.safe_load_peers(self.path)), 0)

    def test_number_in_registry_file_classified(self):
        self.path.write_text("[1]")
        with self.assertRaises(FederationError) as caught:
            registry.load_peers(self.path)
        self.assertEqual(caught.exception.category, "value_domain")
        self.assertEqual(caught.exception.layer, "registry")

    def test_load_recursionerror_converted(self):
        self.path.write_text("[]")
        with mock.patch.object(registry, "parse_json_text", side_effect=RecursionError):
            with self.assertRaises(FederationError) as caught:
                registry.load_peers(self.path)
            self.assertEqual(caught.exception.category, "nesting_too_deep")
            self.assertEqual(caught.exception.layer, "registry")
        self.assertEqual(len(registry.safe_load_peers(self.path)), 0)

    def test_record_walk_recursionerror_converted(self):
        self.path.write_text("[]")
        with mock.patch.object(registry, "parse_peers", side_effect=RecursionError):
            with self.assertRaises(FederationError) as caught:
                registry.load_peers(self.path)
        self.assertEqual(caught.exception.category, "nesting_too_deep")
        self.assertEqual(caught.exception.layer, "registry")


class ContentEncodingPresenceTest(unittest.TestCase):
    """An EMPTY Content-Encoding header is PRESENT and must be rejected like
    any other value; only absence (None) passes."""

    def test_presence_not_truthiness(self):
        self.assertFalse(schema.COMPRESSION_ALLOWED)
        self.assertTrue(schema.content_encoding_rejected(""))
        self.assertTrue(schema.content_encoding_rejected("gzip"))
        self.assertTrue(schema.content_encoding_rejected("identity"))
        self.assertFalse(schema.content_encoding_rejected(None))


# Exactly 8 canonical small-order wire encodings — one per point of the
# order-8 subgroup (orders 1, 2, 4, 4, 8, 8, 8, 8), derived from the
# committed implementation's own arithmetic.  For the six points with
# x != 0 the sign-flipped string is the canonical encoding of the NEGATED
# point and is already in this set; the only non-decodable variants are the
# sign-1 encodings of the two x = 0 points.  The old "8 points but 14
# distinct wire encodings" comment double-counted those sign variants.
SMALL_ORDER_CANONICAL = [
    "0100000000000000000000000000000000000000000000000000000000000000",  # order 1 (identity)
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # order 2
    "0000000000000000000000000000000000000000000000000000000000000000",  # order 4
    "0000000000000000000000000000000000000000000000000000000000000080",  # order 4
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",  # order 8
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",  # order 8
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",  # order 8
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",  # order 8
]


class SmallOrderEncodingsTest(unittest.TestCase):
    """Non-blocking comment fix, made testable: the subgroup has exactly 8
    decodable wire encodings, and sign flips are not extra cases."""

    def test_eight_canonical_encodings_roundtrip_and_are_small_order(self):
        orders = []
        for hex_enc in SMALL_ORDER_CANONICAL:
            enc = bytes.fromhex(hex_enc)
            pt = ed25519strict._decompress(enc, "a")
            self.assertTrue(ed25519strict._small_order(pt), hex_enc)
            x, y, _z, _t = pt
            self.assertEqual((y | ((x & 1) << 255)).to_bytes(32, "little"), enc,
                             "canonical encoding must re-encode byte-identically")
            for k in (1, 2, 4, 8):
                if ed25519strict._is_identity(ed25519strict._scalar_mul(pt, k)):
                    orders.append(k)
                    break
        self.assertEqual(sorted(orders), [1, 2, 4, 4, 8, 8, 8, 8])

    def test_sign_flips_of_the_x0_points_are_not_decodable(self):
        for hex_enc in ("01" + "00" * 31, "ec" + "ff" * 30 + "7f"):
            enc = bytearray(bytes.fromhex(hex_enc))
            enc[31] ^= 0x80
            with self.assertRaises(FederationError) as caught:
                ed25519strict._decompress(bytes(enc), "a")
            self.assertEqual(caught.exception.category, "non_canonical_a")

    def test_flipped_xne0_encoding_names_the_negated_point(self):
        # subgroup closure under negation is why "8 points plus sign
        # variants" (= 14) double-counts: the flip IS another of the 8
        for hex_enc in SMALL_ORDER_CANONICAL:
            enc = bytes.fromhex(hex_enc)
            x, y, _z, _t = ed25519strict._decompress(enc, "a")
            if x == 0:
                continue
            flipped = enc[:31] + bytes([enc[31] ^ 0x80])
            x2, y2, _z2, _t2 = ed25519strict._decompress(flipped, "a")
            self.assertEqual((x2, y2), ((ed25519strict.P - x) % ed25519strict.P, y))
            self.assertTrue(ed25519strict._small_order(
                ed25519strict._decompress(flipped, "a")))


@unittest.skipUnless(
    os.environ.get("ATALK_FED_EVIDENCE_ENV") == "1",
    "evidence-environment consistency check; set ATALK_FED_EVIDENCE_ENV=1 to assert "
    "the frozen evidence versions (portable behavior tests must not)")
class EvidenceEnvironmentConsistencyTest(unittest.TestCase):
    """NOT portable: pins the exact environment the round-1 evidence pack
    was generated in.  Companion artifacts: requirements-federation.lock
    (the dependency lock, with the wheel sha256) and FROZEN_VERSIONS
    (runtime-collected context, never a lock)."""

    def test_python_version(self):
        self.assertEqual(platform.python_version(), "3.11.0rc1")

    def test_pynacl_version(self):
        self.assertEqual(nacl.__version__, "1.6.2")

    def test_frozen_versions_describe_this_runtime(self):
        fv = ed25519strict.FROZEN_VERSIONS
        self.assertEqual(fv["python"], platform.python_version())
        self.assertEqual(fv["nacl"], nacl.__version__)

    def test_lock_file_pins_pynacl_wheel(self):
        text = LOCK_PATH.read_text(encoding="utf-8")
        self.assertIn("pynacl==1.6.2", text)
        self.assertIn(
            "sha256:c8a231e36ec2cab018c4ad4358c386e36eede0319a0c41fed24f840b1dac59f6", text)
        # r5 #7: the aarch64 manylinux_2_34 wheel digest is recorded too
        # (cross-checked against PyPI metadata AND an actual pip download,
        # both matching exactly), and the file states it is an
        # evidence-environment artifact, NOT a portable dependency lock.
        self.assertIn(
            "sha256:26bfcd00dcf2cf160f122186af731ae30ab120c18e8375684ec2670dccd28130",
            text)
        self.assertIn("NOT a portable dependency lock", text)


if __name__ == "__main__":
    unittest.main()
