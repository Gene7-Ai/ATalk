"""Federation round 1: positive vectors, parse/schema unit vectors, strict
verify vectors (committed federation-vectors/strict_verify_v0.json), the
8192/8193 payload precondition, and registry public-key length precondition.
"""
import hashlib
import json
import platform
import tempfile
import unittest
from pathlib import Path

import nacl
from nacl.signing import SigningKey

from atalk.federation import canonical, ed25519strict, registry, schema
from atalk.federation.canonical import FederationError

VECTORS_DIR = Path(__file__).resolve().parent.parent / "federation-vectors"
VECTORS = json.loads((VECTORS_DIR / "vectors_v0.json").read_text(encoding="utf-8"))
STRICT = json.loads((VECTORS_DIR / "strict_verify_v0.json").read_text(encoding="utf-8"))

# Acceptance precondition: TEST ONLY keys come from public seeds.
SEEDS = {family: hashlib.sha256(b"TEST ONLY " + family.encode()).digest()
         for family in VECTORS["keys"]}
FAMILY_BY_KEY_ID = {meta["key_id"]: family for family, meta in VECTORS["keys"].items()}


def sign_object(signed: dict, family: str) -> str:
    return canonical.encode(ed25519strict.sign(SEEDS[family], canonical.canonical_bytes(signed)))


class PositiveVectorTest(unittest.TestCase):
    def test_seed_derives_registered_public_key(self):
        for family, meta in VECTORS["keys"].items():
            pub = SigningKey(SEEDS[family]).verify_key.encode()
            self.assertEqual(canonical.decode_strict(meta["public_key"], 32, "public_key_length"),
                             pub, family)

    def test_positive_vectors_recompute(self):
        cases = [VECTORS["positive"]["message"]] + VECTORS["positive"]["receipts"]
        for case in cases:
            signed = case["signed_object"]
            family = FAMILY_BY_KEY_ID[signed["key_id"]]
            jcs = canonical.canonical_bytes(signed)
            self.assertEqual(jcs.hex(), case["jcs_hex"], family)
            sig = canonical.decode_strict(case["sig"], 64)
            self.assertEqual(ed25519strict.sign(SEEDS[family], jcs), sig, family)
            self.assertTrue(ed25519strict.verify(
                SigningKey(SEEDS[family]).verify_key.encode(), jcs, sig), family)

    def test_origin_event_sig_hash_is_sha256_of_sig_bytes(self):
        sig = canonical.decode_strict(VECTORS["positive"]["message"]["sig"], 64)
        self.assertEqual(hashlib.sha256(sig).hexdigest(),
                         VECTORS["positive"]["origin_event_sig_hash"])

    def test_envelopes_validate_and_strip_sig(self):
        message = VECTORS["positive"]["message"]
        env = schema.validate_event_envelope({**message["signed_object"], "sig": message["sig"]})
        self.assertEqual(env.signed_bytes.hex(), message["jcs_hex"])
        self.assertEqual(env.sig, canonical.decode_strict(message["sig"], 64))
        for case in VECTORS["positive"]["receipts"]:
            env = schema.validate_receipt_envelope({**case["signed_object"], "sig": case["sig"]})
            self.assertEqual(env.signed_bytes.hex(), case["jcs_hex"])
            self.assertEqual(env.kind, schema.RECEIPT_KIND)


class SchemaUnitTest(unittest.TestCase):
    def test_unit_vectors(self):
        for case in VECTORS["schema_unit"]:
            raw = (bytes.fromhex(case["input_hex"]) if "input_hex" in case
                   else case["input"].encode("utf-8"))
            with self.assertRaises(FederationError, msg=case["name"]) as caught:
                schema.parse_event(raw)
            self.assertEqual(caught.exception.category, case["expect"], case["name"])
            if case["layer"] == "parse":
                self.assertEqual(caught.exception.layer, "parse", case["name"])
            else:  # "parse/schema": any of the pre-signature layers is in spec
                self.assertIn(caught.exception.layer,
                              ("parse", "parse/schema", "schema"), case["name"])


class FullInboundSchemaLayerTest(unittest.TestCase):
    def test_schema_layer_cases(self):
        for case in VECTORS["full_inbound"]:
            if case["earliest_layer"] != "schema":
                continue
            with self.assertRaises(FederationError, msg=case["name"]) as caught:
                schema.validate_event_envelope(case["envelope"])
            self.assertEqual(caught.exception.category, case["expect"], case["name"])

    def test_receipt_inbound_envelopes_are_schema_valid(self):
        for case in VECTORS["full_inbound"]:
            if case["layer"] == "receipt_inbound":
                env = schema.validate_receipt_envelope(case["envelope"])
                self.assertEqual(env.kind, schema.RECEIPT_KIND, case["name"])

    def test_tamper_no_resign_fails_signature(self):
        case = next(c for c in VECTORS["full_inbound"] if c["name"] == "tamper_no_resign")
        env = schema.validate_event_envelope(case["envelope"])  # schema-clean by design
        pub = SigningKey(SEEDS["org-a"]).verify_key.encode()
        with self.assertRaises(FederationError) as caught:
            ed25519strict.verify(pub, env.signed_bytes, env.sig)
        self.assertEqual(caught.exception.category, "signature_invalid")


class StrictVerifyVectorTest(unittest.TestCase):
    def test_strict_vectors(self):
        message = bytes.fromhex(STRICT["message_hex"])
        for case in STRICT["cases"]:
            pub, sig = bytes.fromhex(case["public_key_hex"]), bytes.fromhex(case["sig_hex"])
            if case["expect"] == "valid":
                self.assertTrue(ed25519strict.verify(pub, message, sig), case["name"])
                continue
            with self.assertRaises(FederationError, msg=case["name"]) as caught:
                ed25519strict.verify(pub, message, sig)
            self.assertEqual(caught.exception.category, case["expect"], case["name"])
            self.assertEqual(caught.exception.layer, "signature", case["name"])

    def test_identity_with_sign_bit_1_is_non_canonical_r(self):
        message = bytes.fromhex(STRICT["message_hex"])
        control = next(c for c in STRICT["cases"] if c["expect"] == "valid")
        sig = bytes([1]) + bytes(30) + bytes([0x80]) + bytes.fromhex(control["sig_hex"])[32:]
        with self.assertRaises(FederationError) as caught:
            ed25519strict.verify(bytes.fromhex(control["public_key_hex"]), message, sig)
        self.assertEqual(caught.exception.category, "non_canonical_r")

    def test_point_arithmetic_consistency(self):
        # [L]A == identity for a decompressed registered key validates the
        # reference arithmetic the cofactor-8 small-order check relies on.
        pub = SigningKey(SEEDS["org-a"]).verify_key.encode()
        point = ed25519strict._decompress(pub, "a")
        self.assertTrue(
            ed25519strict._is_identity(ed25519strict._scalar_mul(point, ed25519strict.L)))
        # and [L]identity == identity
        self.assertTrue(ed25519strict._is_identity(
            ed25519strict._scalar_mul(ed25519strict._IDENTITY, ed25519strict.L)))


class PayloadLengthTest(unittest.TestCase):
    def _envelope_with_text(self, text):
        signed = dict(VECTORS["positive"]["message"]["signed_object"])
        signed["event"] = {**signed["event"], "payload": {"text": text}}
        return {**signed, "sig": sign_object(signed, "org-a")}

    def test_8192_bytes_accepted_8193_rejected(self):
        # Acceptance precondition 4: decoded-string UTF-8 byte counts asserted
        # before execution; 8192 accepted, 8193 rejected as payload_too_long.
        ok_text = "é" * 4096
        bad_text = "é" * 4096 + "a"
        self.assertEqual(len(ok_text.encode("utf-8")), 8192)
        self.assertEqual(len(bad_text.encode("utf-8")), 8193)
        schema.validate_event_envelope(self._envelope_with_text(ok_text))
        with self.assertRaises(FederationError) as caught:
            schema.validate_event_envelope(self._envelope_with_text(bad_text))
        self.assertEqual(caught.exception.category, "payload_too_long")
        self.assertIn("8193", caught.exception.detail)


class BodyLimitTest(unittest.TestCase):
    def test_limit_is_16384_raw_bytes_before_parse(self):
        self.assertEqual(schema.REQUEST_BODY_LIMIT, 16384)
        schema.check_body_size(b"x" * 16384)
        with self.assertRaises(FederationError) as caught:
            schema.check_body_size(b"x" * 16385)
        self.assertEqual(caught.exception.category, "body_too_large")
        # applies to raw bytes even before JSON is looked at
        with self.assertRaises(FederationError) as caught:
            schema.parse_event(b"x" * 16385)
        self.assertEqual(caught.exception.category, "body_too_large")

    def test_compression_rejected_marker(self):
        self.assertFalse(schema.COMPRESSION_ALLOWED)
        self.assertTrue(schema.content_encoding_rejected("gzip"))
        self.assertFalse(schema.content_encoding_rejected(None))


class CanonicalAndBase64Test(unittest.TestCase):
    def test_jcs_escaping_and_key_order(self):
        obj = {"b": "line\n\ttab\"q\\c\r\fb\b", "a": {"z": "é", "x": "ok"}}
        self.assertEqual(
            canonical.canonical_bytes(obj),
            b'{"a":{"x":"ok","z":"\xc3\xa9"},'
            b'"b":"line\\n\\ttab\\"q\\\\c\\r\\fb\\b"}')
        self.assertEqual(canonical.canonical_bytes({"k": "\u0001\u001f"}),
                         b'{"k":"\\u0001\\u001f"}')

    def test_b64url_strict(self):
        self.assertEqual(canonical.encode(b"\x00\xff"), "AP8")
        self.assertEqual(canonical.decode_strict("AP8", 2), b"\x00\xff")
        for bad in ("AP8=", "AP9", "A+8", "A/8", ""):  # padding, bad trailing bits, charset
            with self.assertRaises(FederationError, msg=bad) as caught:
                canonical.decode_strict(bad, 2)
            self.assertEqual(caught.exception.category, "non_canonical_base64url")
        with self.assertRaises(FederationError) as caught:
            canonical.decode_strict("AAAAAAAA", 5)  # canonical 6-byte string, 5 requested
        self.assertEqual(caught.exception.category, "signature_length")


class ParseDomainTest(unittest.TestCase):
    def _assert_category(self, raw, category, layer=None):
        with self.assertRaises(FederationError) as caught:
            schema.parse_event(raw)
        self.assertEqual(caught.exception.category, category)
        if layer:
            self.assertEqual(caught.exception.layer, layer)

    def test_root_not_object(self):
        for raw in (b"[1]", b'"x"', b"1", b"null"):
            self._assert_category(raw, "value_domain")
        with self.assertRaises(FederationError) as caught:
            schema.parse_event(b"")
        self.assertEqual(caught.exception.category, "invalid_json")

    def test_non_string_values_rejected_anywhere(self):
        base = VECTORS["positive"]["message"]["signed_object"]
        for bad in (True, None, ["x"], 1.5, 1761048000):
            obj = json.loads(json.dumps(base))
            obj["event"]["type"] = bad
            self._assert_category(json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                                  "value_domain", "parse/schema")

    def test_uppercase_key_rejected(self):
        self._assert_category(b'{"Kind": "federation.event.v0"}', "value_domain", "parse/schema")

    def test_nested_duplicate_key(self):
        self._assert_category(b'{"kind": "k", "kind": "k"}', "duplicate_key", "parse")

    def test_raw_surrogate_bytes_are_invalid_utf8(self):
        self._assert_category(b'{"k": "\xed\xa0\x80"}', "invalid_utf8", "parse")

    def test_escaped_surrogate_rejected(self):
        self._assert_category('{"kind": "\\ud800"}'.encode(), "invalid_unicode", "parse")

    def test_escaped_surrogate_pair_combined_then_canonicalized(self):
        # A VALID surrogate pair is not a lone surrogate: the JSON decoder
        # combines it to the scalar, and JCS re-emits raw UTF-8 bytes.
        obj = canonical.parse_strict('{"kind": "\\ud83d\\ude00"}'.encode("utf-8"))
        self.assertEqual(canonical.canonical_bytes(obj),
                         b'{"kind":"\xf0\x9f\x98\x80"}')


class RegistryTest(unittest.TestCase):
    def _write(self, doc):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        path = Path(d.name) / "federation_peers.json"
        path.write_text(json.dumps(doc), encoding="utf-8")
        return path

    def _good_doc(self):
        def rec(family, kid):
            return {"family": family, "key_id": kid,
                    "public_key": VECTORS["keys"][family]["public_key"],
                    "inbox_url": f"https://{family}.example/inbox",
                    "receipts_url": f"https://{family}.example/receipts"}
        return [rec("org-a", "oa-2026-10"), rec("org-b", "ob-2026-10")]

    def test_lookup_exact_pair_only(self):
        reg = registry.load_peers(self._write(self._good_doc()))
        rec = reg.lookup("org-a", "oa-2026-10")
        self.assertEqual(rec.public_key_bytes, canonical.decode_strict(
            VECTORS["keys"]["org-a"]["public_key"], 32, "public_key_length"))
        self.assertIsNone(reg.lookup("org-a", "other-key"))
        self.assertIsNone(reg.lookup("org-unknown", "oa-2026-10"))
        self.assertEqual(reg.receipts_peer("org-b").receipts_url,
                         "https://org-b.example/receipts")
        self.assertIsNone(reg.receipts_peer("org-unknown"))

    def test_public_key_length_error_is_load_error(self):
        # Acceptance precondition 2: wrong-length public key fails registry load.
        doc = self._good_doc()
        doc[0]["public_key"] = canonical.encode(b"\x01" * 31)  # valid b64url, 31 bytes
        with self.assertRaises(FederationError) as caught:
            registry.load_peers(self._write(doc))
        self.assertEqual(caught.exception.category, "public_key_length")
        self.assertEqual(caught.exception.layer, "registry")

    def test_load_failures_fail_closed(self):
        missing = Path(tempfile.gettempdir()) / "no-such-federation-peers.json"
        with self.assertRaises(FederationError) as caught:
            registry.load_peers(missing)
        self.assertEqual(caught.exception.category, "file_unreadable")
        reg = registry.safe_load_peers(missing)
        self.assertEqual(len(reg), 0)
        self.assertIsNone(reg.lookup("org-a", "oa-2026-10"))

    def test_duplicate_family_rejected(self):
        doc = self._good_doc()
        doc.append(dict(doc[0]))
        with self.assertRaises(FederationError) as caught:
            registry.load_peers(self._write(doc))
        self.assertEqual(caught.exception.category, "duplicate_family")

    def test_bad_family_grammar_rejected(self):
        doc = self._good_doc()
        doc[0]["family"] = "Org-A"
        with self.assertRaises(FederationError) as caught:
            registry.load_peers(self._write(doc))
        self.assertEqual(caught.exception.category, "address_grammar")


class FrozenVersionsTest(unittest.TestCase):
    def test_frozen_versions_match_runtime(self):
        # PORTABLE self-consistency only (no pinned-version assertions): this
        # must pass on any Python >= 3.11 / PyNaCl >= 1.5. The exact
        # evidence-environment versions (python==3.11.0rc1, nacl==1.6.2) are
        # asserted separately behind ATALK_FED_EVIDENCE_ENV=1 in
        # tests/test_federation_review_fixes.py and pinned by
        # requirements-federation.lock.
        fv = ed25519strict.FROZEN_VERSIONS
        self.assertEqual(fv["python"], platform.python_version())
        self.assertEqual(fv["nacl"], nacl.__version__)
        self.assertIsNone(fv["libsodium"])
        for check in ("s_below_L", "r_not_small_order", "a_not_small_order",
                      "r_canonical_roundtrip", "a_canonical_roundtrip"):
            self.assertIn(check, fv["strict_checks"])


if __name__ == "__main__":
    unittest.main()
