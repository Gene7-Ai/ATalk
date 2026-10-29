"""Federation round 2: endpoints, outbound delivery, receipts, dedup,
recovery and the six spec-11 self-tests, plus flag-off byte equivalence.

Fixture decisions (acceptance precondition 3, spec 4.5): every full-inbound
vector case gets a FRESH server+DB (the vectors reuse one event_id, so state
must not leak between cases); the receiving fixture for event vectors is
org-b with allowed members bob/carol and registry keys for org-a +
org-test; the receiving fixture for receipt vectors is org-a (the sender
whose federation_outbound holds the original message) with registry keys for
org-b + org-test.  Vector keys/seeds come from the committed vectors file
(TEST ONLY, public seeds).  Each vector case asserts the expected earliest
layer/category, the mapped HTTP status, and zero business side effects.

In-process loopback honesty note (spec preamble / section 11): everything
here runs against TWO OR MORE self-owned instances inside one process on
loopback HTTP; this is not a cross-host
acceptance run.
"""
import hashlib
import json
import os
import re
import shutil
import socket
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import _r4_support as support

from nacl.signing import SigningKey

from atalk.core import AtalkStore
from atalk.federation import canonical, ed25519strict, schema
from atalk.federation.canonical import FederationError
from atalk.federation.runtime import FederationConfig
from atalk.server import AtalkHTTPServer, MessageAcl, WakeHub

REPO_ROOT = Path(__file__).resolve().parent.parent

VECTORS_DIR = Path(__file__).resolve().parent.parent / "federation-vectors"
VECTORS = json.loads((VECTORS_DIR / "vectors_v0.json").read_text(encoding="utf-8"))
SEEDS = {family: hashlib.sha256(b"TEST ONLY " + family.encode()).digest()
         for family in VECTORS["keys"]}
PUB = {family: SigningKey(seed).verify_key.encode() for family, seed in SEEDS.items()}
PUB_STR = {family: VECTORS["keys"][family]["public_key"] for family in SEEDS}
KID = {family: meta["key_id"] for family, meta in VECTORS["keys"].items()}

MSG = VECTORS["positive"]["message"]
EID = MSG["signed_object"]["event"]["event_id"]
MSG_HASH = VECTORS["positive"]["origin_event_sig_hash"]
RCPT_BASE = VECTORS["positive"]["receipts"][0]["signed_object"]  # received, bob@org-b


def sign_envelope(signed: dict, family: str) -> dict:
    sig = ed25519strict.sign(SEEDS[family], canonical.canonical_bytes(signed))
    return {**signed, "sig": canonical.encode(sig)}


def raw_of(envelope: dict) -> bytes:
    return canonical.canonical_bytes(envelope)


def craft_event(*, family: str = "org-a", event_id: str = EID, etype: str = "message",
                source: str = "alice@org-a", target: str = "bob@org-b",
                created_at: str = "2026-10-21T12:00:00Z", text: str | None = None,
                in_reply_to: str | None = None) -> dict:
    event = {"event_id": event_id, "type": etype, "source": source, "target": target,
             "created_at": created_at,
             "payload": {"text": MSG["signed_object"]["event"]["payload"]["text"]
                         if text is None else text}}
    if in_reply_to is not None:
        event["in_reply_to"] = in_reply_to
    return sign_envelope({"kind": schema.EVENT_KIND, "origin": family,
                          "key_id": KID[family], "event": event}, family)


def craft_receipt(*, issuer: str = "org-b", ack_type: str = "received",
                  at: str = "2026-10-21T12:00:05Z", event_id: str = EID,
                  origin: str = "org-a", agent: str = "bob@org-b",
                  sig_hash: str = MSG_HASH) -> dict:
    return sign_envelope({"kind": schema.RECEIPT_KIND, "issuer": issuer,
                          "key_id": KID[issuer],
                          "receipt": {"event_id": event_id, "origin": origin,
                                      "origin_event_sig_hash": sig_hash, "agent": agent,
                                      "ack_type": ack_type, "at": at}}, issuer)


def reserve_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def wait_until(fn, timeout: float = 8.0, what: str = "condition") -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if fn():
            return
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {what}")


def event_row(store, event_id):
    """get_event raises KeyError for a missing event; poll-friendly wrapper."""
    try:
        return store.get_event(event_id)
    except KeyError:
        return None


class RecorderHandler(BaseHTTPRequestHandler):
    """Programmable peer: pops one behavior per request, records bodies."""

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self.server.requests.append((self.path, body))
        behavior = self.server.behaviors.pop(0) if self.server.behaviors else "stored"
        if behavior == "503":
            self._reply(503, b"nope")
        elif behavior == "blank200":
            self._reply(200, b"")
        elif behavior == "html200":
            self._reply(200, b"<html>ok</html>")
        elif behavior == "unknown200":
            self._reply(200, b'{"status": "weird"}')
        elif behavior == "redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/elsewhere")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif behavior == "duplicate":
            self._reply(200, b'{"status": "duplicate"}')
        elif behavior == "slow":
            time.sleep(4.0)
            self._reply(200, b'{"status": "stored"}')
        else:
            self._reply(200, b'{"status": "stored"}')

    def _reply(self, code: int, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


class Recorder:
    def __init__(self, behaviors=None, port=None):
        self.port = port or reserve_port()
        self.server = ThreadingHTTPServer(("127.0.0.1", self.port), RecorderHandler)
        self.server.behaviors = list(behaviors or [])
        self.server.requests = []
        self.requests = self.server.requests
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


class FedEnv:
    """One self-owned federation instance on loopback."""

    def __init__(self, root: str, family: str, members, peers, port=None, **cfg):
        self.family = family
        self.dir = Path(root) / family
        self.dir.mkdir(parents=True, exist_ok=True)
        self.store = AtalkStore(self.dir / "atalk.db")
        self.tokens = {m: self.store.add_peer(m, role="agent") for m in members}
        ident = self.dir / "federation_identity.json"
        ident.write_text(json.dumps({"family": family, "key_id": KID[family],
                                     "seed": canonical.encode(SEEDS[family])}))
        os.chmod(ident, 0o600)
        peers_path = self.dir / "federation_peers.json"
        peers_path.write_text(json.dumps(peers))
        options = dict(outbox_cap=100, rate_conn_per_min=10 ** 6,
                       rate_family_per_min=10 ** 6, worker_interval=0.05,
                       http_timeout=2.0, backoff_base=0.05, backoff_max=0.5,
                       # r4 F2: loopback HTTP peer URLs in this in-process
                       # fixture need the explicit, default-unavailable bypass.
                       allow_insecure_loopback=True)
        options.update(cfg)
        self.config = FederationConfig(enabled=True, peers_path=str(peers_path),
                                       identity_path=str(ident), **options)
        self.server = AtalkHTTPServer(("127.0.0.1", port or reserve_port()), self.store,
                                      WakeHub(), federation_config=self.config)
        self.server.message_acl = MessageAcl(path=str(self.dir / "missing-acl.json"))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.fed = self.server.federation

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

    def call(self, method, path, raw=None, token=None, headers=None, timeout=5.0):
        req = urllib.request.Request(self.base + path, data=raw, method=method)
        req.add_header("Content-Type", "application/json")
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return response.status, response.headers.get("Content-Type"), response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.headers.get("Content-Type"), exc.read()

    def call_json(self, method, path, obj=None, token=None, headers=None, timeout=5.0):
        raw = None if obj is None else json.dumps(obj).encode("utf-8")
        status, ctype, body = self.call(method, path, raw, token, headers, timeout)
        return status, json.loads(body)

    def post_envelope(self, envelope: dict, path="/federation/inbox"):
        status, _ctype, body = self.call("POST", path, raw_of(envelope))
        return status, json.loads(body)

    def business_counts(self) -> dict:
        conn = self.store.conn
        return {table: conn.execute(f"SELECT count(*) n FROM {table}").fetchone()["n"]
                for table in ("events", "acks", "federation_inbound",
                              "federation_receipt_out", "federation_receipt_in",
                              "federation_receipt_in_originals", "federation_notifications")}

    def seed_outbound(self, envelope: dict = None, source_local="alice",
                      target="bob@org-b", target_family="org-b", etype="message"):
        """Pre-existing outbound record (receipt-vector fixture)."""
        envelope = envelope or sign_envelope(MSG["signed_object"], "org-a")
        signed = {k: v for k, v in envelope.items() if k != "sig"}
        self.fed.store.enqueue_outbound(
            event_id=MSG["signed_object"]["event"]["event_id"], origin="org-a",
            origin_key_id=KID["org-a"], source_local=source_local,
            source_addr=f"{source_local}@org-a", target=target,
            target_family=target_family, type=etype,
            signed_json=canonical.canonical_bytes(signed).decode("utf-8"),
            sig=envelope["sig"], envelope_json=raw_of(envelope),
            outbox_cap=self.config.outbox_cap)
        self.fed.store.mark_outbound_sent(envelope["event"]["event_id"])


def peer_record(family: str, inbox: str, receipts: str) -> dict:
    return {"family": family, "key_id": KID[family], "public_key": PUB_STR[family],
            "inbox_url": inbox, "receipts_url": receipts}


class EnvTestCase(unittest.TestCase):
    def make_env(self, root, family, members, peers, **cfg) -> FedEnv:
        env = FedEnv(root, family, members, peers, **cfg)
        self.addCleanup(env.stop)
        return env

    def make_pair(self, root):
        port_local, port_cloud = reserve_port(), reserve_port()
        env_a = self.make_env(
            root, "org-b", ["bob", "carol"],
            [peer_record("org-a", f"http://127.0.0.1:{port_cloud}/federation/inbox",
                         f"http://127.0.0.1:{port_cloud}/federation/receipts")],
            port=port_local)
        env_b = self.make_env(
            root, "org-a", ["alice"],
            [peer_record("org-b", f"http://127.0.0.1:{port_local}/federation/inbox",
                         f"http://127.0.0.1:{port_local}/federation/receipts")],
            port=port_cloud)
        return env_a, env_b


# ---------------------------------------------------------------------------
# Flag-off equivalence (deliverable 3, r4 P1): a TRUE base-vs-candidate
# comparison.  The r3 test only replayed candidate responses against values
# pinned at d121af4+round1 — exactly the blind spot through which F1 slipped
# (flag-off could not even import without PyNaCl; no pinned candidate value
# could see that).  Now base ed9973d is checked out into a temp git worktree
# (the working tree is never touched) and base and candidate serve on the
# SAME port in identical driver subprocesses: status, Content-Type and raw
# response bodies must match byte-for-byte on every probe — with exactly
# ONE explicitly bounded exception, the oversize probe (r5 #6; see the
# comment where it is compared) — including the 404/500 paths and the
# federation routes as unknown paths.  Only the
# documented-volatile fields (fresh-store id/seq, wall-clock timestamps,
# filesystem usage numbers) are masked, identically on both sides.  The
# no-PyNaCl startup legs of the same equivalence contract live in
# tests/test_federation_r4_fixes.py (NoNaclStartupTest).
# ---------------------------------------------------------------------------

PINNED_NOT_FOUND = {"error": "not found"}
PINNED_404_CTYPE = "application/json; charset=utf-8"

FLAGOFF_EVENT = {"source": "alice", "target": "bob", "type": "message",
                 "event_id": "flagoff-0001", "created_at": "2026-10-24T00:00:00Z",
                 "payload": {"text": "hi"}}


def _mask_volatile(raw: bytes) -> bytes:
    """Mask ONLY the fields that legitimately differ between two fresh stores
    seconds apart; the masking is identical on both sides of the compare."""
    raw = re.sub(rb'"(stored_at|created_at)": "[^"]*"', rb'"\1": "<ts>"', raw)
    raw = re.sub(rb'"(used|limit|storage_used|storage_limit|id|seq)": [-0-9.]+',
                 rb'"\1": <n>', raw)
    return raw


class FlagOffEquivalenceTest(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        if not support.have_base_commit():
            raise unittest.SkipTest(
                f"base commit {support.BASE_COMMIT} not available")
        cls.tmp = tempfile.mkdtemp(prefix="atalk-flagoff-equiv-")
        added = support.git("worktree", "add", "--detach",
                            str(Path(cls.tmp) / "base"), support.BASE_COMMIT)
        if added.returncode != 0:
            shutil.rmtree(cls.tmp, ignore_errors=True)
            raise unittest.SkipTest(
                f"git worktree add failed: {added.stderr[-300:]}")
        cls.base_root = Path(cls.tmp) / "base"

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "base_root"):
            support.git("worktree", "remove", "--force", str(cls.base_root))
            support.git("worktree", "prune")
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _one(self, base, method, path, raw=None, headers=None):
        status, ctype, body = support.http_raw(method, base + path, raw, headers)
        return status, ctype, _mask_volatile(body if isinstance(body, bytes) else b"")

    def _collect(self, base):
        return {
            "health": self._one(base, "GET", "/health"),
            "readiness": self._one(base, "GET", "/readiness"),
            "unknown_path": self._one(base, "GET", "/definitely-not-a-path"),
            "fed_inbox_404": self._one(base, "POST", "/federation/inbox",
                                       b'{"x": "1"}'),
            "fed_inbox_404_gzip": self._one(base, "POST", "/federation/inbox",
                                            b'{"x": "1"}',
                                            {"Content-Encoding": "gzip"}),
            "fed_bad_json_400": self._one(base, "POST", "/federation/inbox",
                                          b"{oops"),
            "fed_array_400": self._one(base, "POST", "/federation/inbox", b"[1]"),
            "fed_notifications_404": self._one(base, "GET",
                                               "/federation/notifications"),
            "fed_ack_404": self._one(base, "POST", "/federation/notifications/ack",
                                     b'{"x": "1"}'),
            "events_201": self._one(base, "POST", "/events",
                                    json.dumps(FLAGOFF_EVENT).encode()),
            "events_list": self._one(base, "GET", "/events?target=bob&state=all"),
            "ack_500": self._one(base, "POST", "/ack", json.dumps(
                {"event_id": "no-such", "agent_id": "alice",
                 "ack_type": "received"}).encode()),
            "oversize_413": self._one(base, "POST", "/federation/inbox",
                                      b"x" * ((1 << 20) + 1)),
        }

    def test_base_and_candidate_flagoff_match_byte_for_byte(self):
        port = support.reserve_port()
        with support.serve(self.base_root, port=port) as base_url:
            base_results = self._collect(base_url)
        with support.serve(REPO_ROOT, port=port) as candidate_url:
            candidate_results = self._collect(candidate_url)
        self.assertEqual(sorted(base_results), sorted(candidate_results))
        for key, base_result in base_results.items():
            candidate_result = candidate_results[key]
            if key == "oversize_413":
                # BOUNDED LEGACY EXCEPTION (r5 #6) — the ONLY probe where
                # byte equality is not demanded; every other probe keeps the
                # true base-vs-candidate byte-for-byte comparison, and this
                # exception does NOT widen the equivalence claim for any
                # other route or payload.  The pre-existing no-drain
                # early-reject (base trait, same as the astra_http_boundary
                # #14 exclusion) can surface either as the pinned 413 or as
                # a mid-upload broken pipe.  Why a given run lands on one or
                # the other is UNDETERMINED: the two observed asymmetric
                # flakes' logs were not saved, so the earlier "load-
                # sensitive" explanation is unproven and is no longer
                # asserted.  Each side is therefore checked against the
                # 413/broken-pipe union independently; byte-compare only
                # when both got the pinned reply.  (r3 observed broken-pipe
                # on BOTH sides of a single run — an observation of that
                # run, NOT an accepted alias-equivalence ruling.)
                for side, result in (("base", base_result),
                                     ("candidate", candidate_result)):
                    self.assertIn(result[0], (413, "broken-pipe"),
                                  f"{key} ({side}): {result[0]!r}")
                if base_result[0] == 413 and candidate_result[0] == 413:
                    self.assertEqual(base_result, candidate_result, key)
            else:
                self.assertEqual(base_result, candidate_result, key)


class FlagOffInProcessTest(EnvTestCase):
    """Direct in-process checks of the same contract for the live candidate
    object: no worker thread, federation routes behave as unknown paths,
    @-targets stay plain local strings."""

    def setUp(self):
        env_patch = mock.patch.dict(os.environ)
        env_patch.start()
        self.addCleanup(env_patch.stop)
        os.environ.pop("ATALK_FEDERATION", None)
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        store = AtalkStore(Path(self.tmp) / "atalk.db")
        self.alice_token = store.add_peer("alice", role="agent")
        self.server = AtalkHTTPServer(("127.0.0.1", 0), store, WakeHub())
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.server.message_acl = MessageAcl(path=os.path.join(self.tmp, "missing-acl.json"))
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.assertIsNone(self.server.federation)

    def call(self, method, path, raw=None, headers=None, token=None):
        req = urllib.request.Request(self.base + path, data=raw, method=method)
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                return (response.status, response.headers.get("Content-Type"),
                        json.loads(response.read()))
        except urllib.error.HTTPError as exc:
            return exc.code, exc.headers.get("Content-Type"), json.loads(exc.read())

    def test_no_worker_thread_when_disabled(self):
        names = [t.name for t in threading.enumerate()]
        self.assertNotIn("atalk-federation-worker", names)

    def test_federation_paths_behave_as_unknown_paths(self):
        cases = [
            ("GET", "/federation/inbox", None, None),
            ("GET", "/federation/receipts", None, None),
            ("POST", "/federation/inbox", b'{"x": "1"}', None),
            ("POST", "/federation/receipts", b'{"x": "1"}', None),
            ("POST", "/federation/inbox", b'{"x": "1"}', {"Content-Encoding": "gzip"}),
            ("POST", "/federation/inbox", b"", None),
            ("POST", "/federation/inbox", '{"x": "é"}'.encode("utf-8"), None),
        ]
        for method, path, raw, headers in cases:
            status, ctype, body = self.call(method, path, raw, headers)
            self.assertEqual((status, ctype, body),
                             (404, PINNED_404_CTYPE, PINNED_NOT_FOUND), (method, path))
        status, ctype, body = self.call("POST", "/federation/inbox", b"{oops")
        self.assertEqual((status, ctype, body),
                         (400, PINNED_404_CTYPE,
                          {"error": "Expecting property name enclosed in double quotes: "
                                    "line 1 column 2 (char 1)"}))
        status, ctype, body = self.call("POST", "/federation/inbox", b"[1]")
        self.assertEqual((status, ctype, body),
                         (400, PINNED_404_CTYPE,
                          {"error": "request body must be a JSON object"}))

    def test_events_and_ack_unchanged_with_at_targets(self):
        status, _ctype, body = self.call(
            "POST", "/events",
            json.dumps({"source": "alice", "target": "x@org-other", "type": "message",
                        "event_id": "probe-1", "payload": {"text": "hi"}}).encode(),
            token=self.alice_token)
        self.assertEqual(status, 201)
        for key, value in (("event_id", "probe-1"), ("source", "alice"),
                           ("target", "x@org-other"), ("type", "message"),
                           ("payload", {"text": "hi"}), ("requires_ack", True),
                           ("source_ref", None), ("auth_actor", None)):
            self.assertEqual(body[key], value)
        # a target that is a grammar-valid address of OUR OWN family stays local
        status, _ctype, body = self.call(
            "POST", "/events",
            json.dumps({"source": "alice", "target": "bob@org-b", "type": "message",
                        "event_id": "probe-2", "payload": {"text": "hi2"}}).encode(),
            token=self.alice_token)
        self.assertEqual(status, 201)
        self.assertEqual(body["target"], "bob@org-b")
        status, _ctype, body = self.call(
            "GET", "/events?target=x%40org-other&state=all", token=self.alice_token)
        self.assertEqual((status, body), (403, {"error": "target token rejected"}))
        status, _ctype, body = self.call(
            "POST", "/ack",
            json.dumps({"event_id": "no-such", "agent_id": "alice",
                        "ack_type": "received"}).encode(), token=self.alice_token)
        self.assertEqual((status, body), (500, {"error": "internal server error"}))


# ---------------------------------------------------------------------------
# Deliverable C.1: all full_inbound vectors through the REAL HTTP endpoint.
# ---------------------------------------------------------------------------

EVENT_VECTOR_CASES = [
    ("source_family_mismatch", 400, "source_family"),
    ("target_other_family", 422, "target_family"),
    ("target_unknown_member", 422, "target_member"),
    ("type_command", 400, "type_whitelist"),
    ("type_grant", 400, "type_whitelist"),
    ("target_broadcast", 400, "address_grammar"),
    ("tamper_no_resign", 403, "signature_invalid"),
    ("unknown_key_id", 403, "unregistered_key"),
]

RECEIPT_VECTOR_CASES = [
    ("receipt_wrong_issuer_org_test", 403, "issuer_not_target_family"),
    ("receipt_wrong_agent", 403, "agent_mismatch"),
    ("receipt_wrong_hash", 403, "hash_mismatch"),
    ("receipt_unknown_event", 403, "unknown_event"),
]


class FullInboundVectorTest(EnvTestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))

    def event_env(self) -> FedEnv:
        return self.make_env(
            self.tmp, "org-b", ["bob", "carol"],
            [peer_record("org-a", "http://127.0.0.1:9/inbox",
                         "http://127.0.0.1:9/receipts"),
             peer_record("org-test", "http://127.0.0.1:9/inbox",
                         "http://127.0.0.1:9/receipts")])

    def receipt_env(self) -> FedEnv:
        env = self.make_env(
            self.tmp, "org-a", ["alice"],
            [peer_record("org-b", "http://127.0.0.1:9/inbox",
                         "http://127.0.0.1:9/receipts"),
             peer_record("org-test", "http://127.0.0.1:9/inbox",
                         "http://127.0.0.1:9/receipts")])
        env.seed_outbound()
        return env

    def assert_no_side_effects(self, env: FedEnv):
        counts = env.business_counts()
        for table, count in counts.items():
            self.assertEqual(count, 0, table)

    def test_event_vectors_rejected_at_expected_layer(self):
        for name, want_status, want_reason in EVENT_VECTOR_CASES:
            with self.subTest(case=name):
                env = self.event_env()
                case = next(c for c in VECTORS["full_inbound"] if c["name"] == name)
                status, body = env.post_envelope(case["envelope"])
                self.assertEqual(status, want_status, body)
                self.assertEqual(body, {"status": "rejected", "reason": want_reason}, name)
                self.assert_no_side_effects(env)

    def test_receipt_vectors_rejected_at_binding(self):
        for name, want_status, want_reason in RECEIPT_VECTOR_CASES:
            with self.subTest(case=name):
                env = self.receipt_env()
                case = next(c for c in VECTORS["full_inbound"] if c["name"] == name)
                status, body = env.post_envelope(case["envelope"],
                                                 path="/federation/receipts")
                self.assertEqual(status, want_status, body)
                self.assertEqual(body, {"status": "rejected", "reason": want_reason}, name)
                counts = env.business_counts()
                self.assertEqual(counts["federation_receipt_in"], 0)
                self.assertEqual(counts["federation_receipt_in_originals"], 0)
                self.assertEqual(counts["federation_notifications"], 0)

    def test_receipt_fixture_signatures_are_valid(self):
        # Spec 4.5: the fixture separately confirms the rejected receipts are
        # signature-valid for their (registered) issuer keys — the binding
        # check is what rejects them, not the signature.
        for name, _status, _reason in RECEIPT_VECTOR_CASES:
            case = next(c for c in VECTORS["full_inbound"] if c["name"] == name)
            env_obj = schema.validate_receipt_envelope(case["envelope"])
            family = {"ot-2026-10": "org-test", "ob-2026-10": "org-b"}[case["envelope"]["key_id"]]
            self.assertTrue(ed25519strict.verify(PUB[family], env_obj.signed_bytes,
                                                 env_obj.sig), name)

    def test_postverify_event_vector_signatures_are_valid(self):
        for name in ("target_other_family", "target_unknown_member"):
            case = next(c for c in VECTORS["full_inbound"] if c["name"] == name)
            env_obj = schema.validate_event_envelope(case["envelope"])
            self.assertTrue(ed25519strict.verify(PUB["org-a"], env_obj.signed_bytes,
                                                 env_obj.sig), name)

    def test_oversized_body_and_content_encoding(self):
        env = self.event_env()
        status, body = env.call_json("POST", "/federation/inbox", {"x": "1"},
                                     headers={"Content-Length": "20000"})
        # send a genuinely oversized raw body
        status, _ctype, raw = env.call("POST", "/federation/inbox", b"x" * 16385)
        self.assertEqual(status, 413)
        self.assertEqual(json.loads(raw), {"status": "rejected", "reason": "body_too_large"})
        status, _ctype, raw = env.call("POST", "/federation/inbox", raw_of(craft_event()),
                                       headers={"Content-Encoding": "gzip"})
        self.assertEqual((status, json.loads(raw)),
                         (400, {"status": "rejected", "reason": "content_encoding_rejected"}))
        self.assert_no_side_effects(env)

    def test_payload_8192_accepted_8193_rejected_at_endpoint(self):
        ok_text = "é" * 4096
        bad_text = "é" * 4096 + "a"
        self.assertEqual(len(ok_text.encode("utf-8")), 8192)
        self.assertEqual(len(bad_text.encode("utf-8")), 8193)
        env = self.event_env()
        status, body = env.post_envelope(craft_event(text=ok_text, event_id=EID))
        self.assertEqual((status, body), (200, {"status": "stored"}))
        status, body = env.post_envelope(craft_event(text=bad_text, event_id=EID))
        self.assertEqual((status, body), (400, {"status": "rejected",
                                                "reason": "payload_too_long"}))
        # exactly one local logical event from the accepted case
        self.assertEqual(env.business_counts()["events"], 1)


# ---------------------------------------------------------------------------
# Spec 11 Test 1: normal round trip between two full instances.
# ---------------------------------------------------------------------------

class RoundTripTest(EnvTestCase):
    def test_two_instances_two_directions_receipts_and_offline_verify(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        env_a, env_b = self.make_pair(tmp)

        # A -> B message from bob to alice@org-a
        eid = "5240aa70-1111-4000-8000-00000000fa11"
        status, body = env_a.call_json(
            "POST", "/events",
            {"source": "bob", "target": "alice@org-a", "type": "message",
             "event_id": eid, "payload": {"text": "hello cloud"}}, token=env_a.tokens["bob"])
        self.assertEqual(status, 201, body)
        self.assertEqual(body["federation"], {"status": "pending", "target_family": "org-a"})
        wait_until(lambda: event_row(env_b.store, eid) is not None, what="B inbound event")
        ev = env_b.store.get_event(eid)
        self.assertEqual((ev.source, ev.target, ev.type),
                         ("bob@org-b", "alice", "message"))
        row = env_b.fed.store.get_inbound(origin="org-b", event_id=eid)
        self.assertIsNotNone(row)
        self.assertEqual(row["reg_family"], "org-b")

        # HTTP 200 from B is NOT the agent receipt: nothing on A's receipt side yet
        self.assertEqual(env_a.business_counts()["federation_receipt_in"], 0)

        # reply B -> A BEFORE acking: reply referencing the original, and one
        # referencing a MISSING parent — both must deliver (conversational only)
        status, body = env_b.call_json(
            "POST", "/events",
            {"source": "alice", "target": "bob@org-b", "type": "reply",
             "event_id": "5240aa70-2222-4000-8000-00000000fa22",
             "payload": {"text": "hi back", "in_reply_to": eid}}, token=env_b.tokens["alice"])
        self.assertEqual(status, 201, body)
        missing_parent = "5240aa70-dddd-4000-8000-00000000fad0"
        status, body = env_b.call_json(
            "POST", "/events",
            {"source": "alice", "target": "bob@org-b", "type": "reply",
             "event_id": "5240aa70-eeee-4000-8000-00000000fae0",
             "payload": {"text": "orphan reply", "in_reply_to": missing_parent}},
            token=env_b.tokens["alice"])
        self.assertEqual(status, 201, body)
        wait_until(lambda: event_row(
            env_a.store, "5240aa70-eeee-4000-8000-00000000fae0") is not None,
            what="orphan reply delivered")
        reply = env_a.store.get_event("5240aa70-2222-4000-8000-00000000fa22")
        self.assertEqual(reply.source, "alice@org-a")
        self.assertEqual(reply.payload.get("in_reply_to"), eid)

        # alice ACKs both ways; receipts arrive at A only after /ack
        for ack_type in ("received", "applied"):
            status, body = env_b.call_json(
                "POST", "/ack",
                {"event_id": eid, "agent_id": "alice", "ack_type": ack_type},
                token=env_b.tokens["alice"])
            self.assertEqual(status, 200, body)
        # the original's receipt names the ORIGINAL FULL TARGET as its agent
        wait_until(lambda: env_a.fed.store.receipt_stage(eid, "alice@org-a") == "applied",
                   what="receipts on A")
        original_sig = canonical.decode_strict(env_a.fed.store.get_outbound(eid)["sig"], 64)
        receipt_row = env_a.fed.store.receipt_originals(
            eid, agent="alice@org-a", ack_type="received")[0]
        self.assertEqual(
            hashlib.sha256(original_sig).hexdigest(),
            json.loads(receipt_row["signed_json"])["receipt"]["origin_event_sig_hash"])

        # bob ACKs the reply; org-a receives a receipt naming the FULL target
        status, body = env_a.call_json(
            "POST", "/ack",
            {"event_id": "5240aa70-2222-4000-8000-00000000fa22", "agent_id": "bob",
             "ack_type": "received"}, token=env_a.tokens["bob"])
        self.assertEqual(status, 200, body)
        wait_until(lambda: env_b.fed.store.receipt_originals(
            "5240aa70-2222-4000-8000-00000000fa22") != [], what="receipt on B")
        received = env_b.fed.store.receipt_originals(
            "5240aa70-2222-4000-8000-00000000fa22")[0]
        self.assertEqual(received["agent"], "bob@org-b")
        self.assertEqual(received["issuer"], "org-b")

        # offline re-verification from stored originals with PINNED keys (§10)
        for env, origin_family in ((env_a, "org-b"), (env_b, "org-a")):
            rows = env.store.conn.execute(
                "SELECT origin, event_id, signed_json, sig FROM federation_inbound").fetchall()
            self.assertTrue(rows)
            for row in rows:
                env_obj = schema.validate_event_envelope(
                    {**json.loads(row["signed_json"]), "sig": row["sig"]})
                self.assertTrue(ed25519strict.verify(PUB[row["origin"]],
                                                     env_obj.signed_bytes, env_obj.sig))
                self.assertEqual(env_obj.signed["event"]["source"].split("@")[1],
                                 row["origin"])


# ---------------------------------------------------------------------------
# Spec 11 Test 2: duplicates and conflicts.
# ---------------------------------------------------------------------------

class DuplicateConflictTest(EnvTestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.env = self.make_env(
            self.tmp, "org-b", ["bob", "carol"],
            [peer_record("org-a", "http://127.0.0.1:9/inbox",
                         "http://127.0.0.1:9/receipts")])

    def test_lost_response_retry_is_duplicate_no_new_local_event(self):
        envelope = craft_event()
        self.assertEqual(self.env.post_envelope(envelope), (200, {"status": "stored"}))
        status, body = self.env.post_envelope(envelope)
        self.assertEqual((status, body), (200, {"status": "duplicate"}))
        self.assertEqual(self.env.business_counts()["events"], 1)
        self.assertEqual(self.env.business_counts()["federation_inbound"], 1)

    def test_same_id_changed_content_conflicts_and_audits(self):
        original = craft_event()
        self.assertEqual(self.env.post_envelope(original), (200, {"status": "stored"}))
        attacker = craft_event(text="entirely different text")
        self.assertNotEqual(attacker["sig"], original["sig"])
        status, body = self.env.post_envelope(attacker)
        self.assertEqual((status, body), (409, {"status": "conflict"}))
        stored = self.env.fed.store.get_inbound(origin="org-a", event_id=EID)
        self.assertEqual(stored["sig"], original["sig"])  # original untouched
        conflicts = self.env.fed.store.conflicts_for("org-a", EID)
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0]["reason"], "same_id_different_content")
        self.assertEqual(self.env.business_counts()["events"], 1)

    def test_local_event_id_collision_conflicts(self):
        self.env.store.insert_event("bob", "carol", "message", {"text": "local"},
                                    event_id=EID)
        status, body = self.env.post_envelope(craft_event())
        self.assertEqual((status, body), (409, {"status": "conflict"}))
        conflicts = self.env.fed.store.conflicts_for("org-a", EID)
        self.assertEqual(conflicts[0]["reason"], "local_event_id_collision")
        # the pre-existing local event is untouched
        self.assertEqual(self.env.store.get_event(EID).target, "carol")

    def test_concurrent_same_key_inserts(self):
        base = craft_event()
        variant = craft_event(text="concurrent variant")
        results = {"base": [], "variant": []}
        barrier = threading.Barrier(8)

        def fire(key, env_obj):
            barrier.wait()
            results[key].append(self.env.post_envelope(env_obj))

        threads = [threading.Thread(target=fire, args=(key, obj))
                   for key, obj in ([(k, base) for k in ("base",) * 4]
                                    + [(k, variant) for k in ("variant",) * 4])]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(30)
        base_statuses = {status for status, _body in results["base"]}
        variant_statuses = {status for status, _body in results["variant"]}
        # whichever content wins the unique-constraint race is stored; its
        # same-content threads get duplicate (200) and the OTHER content's
        # threads all get 409.  Exactly one business row exists either way.
        self.assertTrue(base_statuses <= {200, 409})
        self.assertTrue(variant_statuses <= {200, 409})
        self.assertTrue((base_statuses == {200} and variant_statuses == {409})
                        or (base_statuses == {409} and variant_statuses == {200}),
                        (base_statuses, variant_statuses))
        counts = self.env.business_counts()
        self.assertEqual(counts["events"], 1)
        self.assertEqual(counts["federation_inbound"], 1)
        self.assertEqual(len(self.env.fed.store.conflicts_for("org-a", EID)), 4)

    def test_repeat_ack_identical_receipt_original(self):
        envelope = craft_event()
        self.assertEqual(self.env.post_envelope(envelope), (200, {"status": "stored"}))
        for _ in range(2):
            status, body = self.env.call_json(
                "POST", "/ack", {"event_id": EID, "agent_id": "bob",
                                 "ack_type": "received"}, token=self.env.tokens["bob"])
            self.assertEqual(status, 200, body)
        row = self.env.fed.store.get_receipt_out(EID, "bob@org-b", "received")
        wait_until(lambda: (self.env.fed.store.get_receipt_out(
            EID, "bob@org-b", "received") or {}).get("sig"), what="receipt materialized")
        after = self.env.fed.store.get_receipt_out(EID, "bob@org-b", "received")
        self.assertEqual(after["at"], row["at"])
        # the second ACK generated no new receipt task or original
        rows = self.env.store.conn.execute(
            "SELECT count(*) n FROM federation_receipt_out WHERE event_id=?", (EID,)).fetchone()
        self.assertEqual(rows["n"], 1)


class OutboundEventIdCollisionTest(EnvTestCase):
    """r4 F5: a repeated federation event_id belongs to the stored original.
    Cross-actor or changed-intent retries are 409; a genuine retry is echoed
    EXCLUSIVELY from the stored original (never saved headers mixed with the
    new request's payload), including while the outbox is at cap."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.env = self.make_env(
            self.tmp, "org-b", ["bob", "carol"],
            [peer_record("org-a", "http://127.0.0.1:9/inbox",
                         "http://127.0.0.1:9/receipts")])
        self.eid = "cccc0000-0000-4000-8000-00000000f501"

    def _send(self, env, source, token, event_id=None, target="alice@org-a",
              text="hello", type_="message", in_reply_to=None, expect=201):
        payload = {"text": text}
        if in_reply_to is not None:
            payload["in_reply_to"] = in_reply_to
        status, body = env.call_json(
            "POST", "/events",
            {"source": source, "target": target, "type": type_,
             "event_id": event_id or self.eid, "payload": payload},
            token=token)
        self.assertEqual(status, expect, body)
        return body

    def test_cross_actor_same_id_conflicts(self):
        first = self._send(self.env, "bob", self.env.tokens["bob"])
        self.assertEqual(first["source"], "bob@org-b")
        self._send(self.env, "carol", self.env.tokens["carol"], expect=409)
        row = self.env.fed.store.get_outbound(self.eid)
        self.assertEqual(row["source_local"], "bob")  # original untouched

    def test_changed_intent_conflicts(self):
        self._send(self.env, "bob", self.env.tokens["bob"])
        self._send(self.env, "bob", self.env.tokens["bob"], text="replacement",
                   expect=409)
        self._send(self.env, "bob", self.env.tokens["bob"],
                   target="other@org-a", expect=409)
        # the reply link is part of the immutable intent too
        self._send(self.env, "bob", self.env.tokens["bob"], type_="reply",
                   in_reply_to="cccc0000-0000-4000-8000-000000000d0d", expect=409)
        row = self.env.fed.store.get_outbound(self.eid)
        self.assertEqual(json.loads(row["signed_json"])["event"]["payload"]["text"],
                         "hello")

    def test_exact_retry_echoes_stored_original_only(self):
        first = self._send(self.env, "bob", self.env.tokens["bob"])
        retry = self._send(self.env, "bob", self.env.tokens["bob"])
        # created_at/payload/source are the STORED original's, not the
        # freshly composed (re-timestamped) request's
        self.assertEqual(retry["created_at"], first["created_at"])
        self.assertEqual(retry["payload"], first["payload"])
        self.assertEqual(retry["source"], "bob@org-b")
        rows = self.env.store.conn.execute(
            "SELECT count(*) n FROM federation_outbound WHERE event_id=?",
            (self.eid,)).fetchone()
        self.assertEqual(rows["n"], 1)

    def test_exact_retry_at_cap_is_idempotent_changed_intent_conflicts(self):
        env = self.make_env(
            self.tmp, "org-b", ["bob", "carol"],
            [peer_record("org-a",
                         f"http://127.0.0.1:{reserve_port()}/federation/inbox",
                         f"http://127.0.0.1:{reserve_port()}/federation/receipts")],
            outbox_cap=1)
        first = self._send(env, "bob", env.tokens["bob"])  # consumes the cap
        status, body = env.call_json(
            "POST", "/events",
            {"source": "bob", "target": "alice@org-a", "type": "message",
             "event_id": "cccc0000-0000-4000-8000-00000000f502",
             "payload": {"text": "fills the cap"}}, token=env.tokens["bob"])
        self.assertEqual(status, 429)  # a NEW event is rejected at the cap
        # an exact retry bypasses the cap and echoes the stored original
        retry = self._send(env, "bob", env.tokens["bob"], expect=201)
        self.assertEqual(retry["created_at"], first["created_at"])
        self.assertEqual(retry["payload"], first["payload"])
        rows = env.store.conn.execute(
            "SELECT count(*) n FROM federation_outbound WHERE event_id=?",
            (self.eid,)).fetchone()
        self.assertEqual(rows["n"], 1)
        # a changed intent on the same id is a conflict, not a silent accept
        self._send(env, "bob", env.tokens["bob"], text="changed", expect=409)


class ReceiptInboundDedupTest(EnvTestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.env = self.make_env(
            self.tmp, "org-a", ["alice"],
            [peer_record("org-b", "http://127.0.0.1:9/inbox",
                         "http://127.0.0.1:9/receipts")])
        self.env.seed_outbound()
        self.path = "/federation/receipts"

    def test_applied_then_received_never_downgrades_and_synthesizes_nothing(self):
        applied = craft_receipt(ack_type="applied")
        self.assertEqual(self.env.post_envelope(applied, path=self.path),
                         (200, {"status": "stored"}))
        self.assertEqual(self.env.fed.store.receipt_stage(EID, "bob@org-b"), "applied")
        # no synthesized received
        self.assertEqual(self.env.fed.store.receipt_originals(EID, ack_type="received"), [])
        received = craft_receipt(ack_type="received")
        self.assertEqual(self.env.post_envelope(received, path=self.path),
                         (200, {"status": "stored"}))
        self.assertEqual(self.env.fed.store.receipt_stage(EID, "bob@org-b"), "applied")

    def test_same_key_different_at_both_kept_and_flagged(self):
        first = craft_receipt(ack_type="received", at="2026-10-21T12:00:05Z")
        second = craft_receipt(ack_type="received", at="2026-10-22T08:00:00Z")
        self.assertNotEqual(first["sig"], second["sig"])
        self.assertEqual(self.env.post_envelope(first, path=self.path),
                         (200, {"status": "stored"}))
        self.assertEqual(self.env.post_envelope(second, path=self.path),
                         (200, {"status": "stored"}))
        originals = self.env.fed.store.receipt_originals(EID, agent="bob@org-b",
                                                         ack_type="received")
        self.assertEqual(len(originals), 2)
        self.assertEqual(sorted(o["is_variant"] for o in originals), [0, 1])
        self.assertEqual({o["sig"] for o in originals}, {first["sig"], second["sig"]})
        # exactly one logical notification despite two originals
        self.assertEqual(self.env.business_counts()["federation_notifications"], 1)

    def test_identical_receipt_redelivery_is_duplicate(self):
        receipt = craft_receipt()
        self.assertEqual(self.env.post_envelope(receipt, path=self.path),
                         (200, {"status": "stored"}))
        self.assertEqual(self.env.post_envelope(receipt, path=self.path),
                         (200, {"status": "duplicate"}))
        self.assertEqual(len(self.env.fed.store.receipt_originals(EID)), 1)
        self.assertEqual(self.env.business_counts()["federation_notifications"], 1)

    def test_notification_crash_window_exactly_once(self):
        # Fault injection: the commit hook raises AFTER the atomic commit but
        # BEFORE the response — the sender sees a transient failure and retries;
        # the local logical notification must exist exactly once.
        env = self.env
        hook_errors = []
        def boom():
            hook_errors.append(1)
            raise RuntimeError("simulated crash after commit")
        env.fed.post_commit_hook = boom
        receipt = craft_receipt()
        status, body = env.post_envelope(receipt, path=self.path)
        self.assertEqual(status, 500)
        self.assertEqual(hook_errors, [1])
        # the commit stands: original + merged state + notification recorded
        self.assertEqual(len(env.fed.store.receipt_originals(EID)), 1)
        self.assertEqual(env.business_counts()["federation_notifications"], 1)
        env.fed.post_commit_hook = None
        status, body = env.post_envelope(receipt, path=self.path)
        self.assertEqual((status, body), (200, {"status": "duplicate"}))
        self.assertEqual(env.business_counts()["federation_notifications"], 1)


# ---------------------------------------------------------------------------
# Spec 11 Test 3: disconnection and crash recovery.
# ---------------------------------------------------------------------------

class RecoveryTest(EnvTestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.recorder = Recorder()
        self.addCleanup(self.recorder.stop)
        peers = [peer_record("org-a",
                             f"http://127.0.0.1:{self.recorder.port}/federation/inbox",
                             f"http://127.0.0.1:{self.recorder.port}/federation/receipts")]
        self.env = self.make_env(self.tmp, "org-b", ["bob"], peers)

    def federated_send(self, event_id, text="hello"):
        status, body = self.env.call_json(
            "POST", "/events",
            {"source": "bob", "target": "alice@org-a", "type": "message",
             "event_id": event_id, "payload": {"text": text}}, token=self.env.tokens["bob"])
        self.assertEqual(status, 201, body)
        return self.env.fed.store.get_outbound(event_id)

    def outbound_row(self, event_id):
        return self.env.fed.store.get_outbound(event_id)

    def test_transient_then_success_resends_identical_bytes(self):
        self.recorder.server.behaviors = ["503", "stored"]
        row = self.federated_send("6f3c1e00-0000-4000-8000-00000000fca1")
        wait_until(lambda: len(self.recorder.requests) >= 1, what="first attempt")
        wait_until(lambda: self.outbound_row(row["event_id"])["status"] == "sent",
                   what="sent")
        wait_until(lambda: len(self.recorder.requests) >= 2, what="second attempt")
        first, second = self.recorder.requests[0][1], self.recorder.requests[1][1]
        self.assertEqual(first, second)
        self.assertEqual(first, bytes(row["envelope_json"]))
        self.assertEqual(self.outbound_row(row["event_id"])["status"], "sent")

    def test_blank_html_unknown_200_are_transient(self):
        self.recorder.server.behaviors = ["blank200", "html200", "unknown200", "stored"]
        row = self.federated_send("6f3c1e00-0000-4000-8000-00000000fca2")
        wait_until(lambda: self.outbound_row(row["event_id"])["status"] == "sent",
                   what="eventually sent")
        self.assertEqual(len(self.recorder.requests), 4)
        self.assertTrue(all(body == bytes(row["envelope_json"])
                            for _path, body in self.recorder.requests))

    def test_redirect_is_permanent_and_never_followed(self):
        self.recorder.server.behaviors = ["redirect"]
        row = self.federated_send("6f3c1e00-0000-4000-8000-00000000fca3")
        wait_until(lambda: self.outbound_row(row["event_id"])["status"] == "failed_permanent",
                   what="permanent failure")
        self.assertEqual(len(self.recorder.requests), 1)
        self.assertIn("redirect_not_followed", self.outbound_row(row["event_id"])["last_error"])
        counts = self.env.business_counts()
        self.assertEqual(counts["federation_notifications"], 1)

    def test_ended_tasks_not_reactivated_by_recovery(self):
        self.recorder.server.behaviors = ["stored"]
        row = self.federated_send("6f3c1e00-0000-4000-8000-00000000fca4")
        wait_until(lambda: self.outbound_row(row["event_id"])["status"] == "sent",
                   what="sent")
        self.recorder.requests.clear()
        for _ in range(3):
            self.env.fed.process_due()
        # simulated restart with a fresh runtime on the same DB
        self.env.server.shutdown()
        self.env.server.server_close()
        store = AtalkStore(self.env.dir / "atalk.db")
        peers_path = self.env.config.peers_path
        ident_path = self.env.config.identity_path
        restarted = AtalkHTTPServer(
            ("127.0.0.1", 0), store, WakeHub(),
            federation_config=FederationConfig(
                enabled=True, peers_path=peers_path, identity_path=ident_path,
                outbox_cap=100, rate_conn_per_min=10 ** 6, rate_family_per_min=10 ** 6,
                worker_interval=0.05, http_timeout=2.0, backoff_base=0.05,
                backoff_max=0.5, allow_insecure_loopback=True))
        self.addCleanup(restarted.server_close)  # never served: no shutdown() event
        self.assertEqual(self.recorder.requests, [])

    def test_receipt_send_failing_then_rebuilt_same_at_after_restart(self):
        # Receipts endpoint of the peer is DOWN (closed port) at first.
        dead_port = reserve_port()
        peers = [peer_record("org-a", f"http://127.0.0.1:9/inbox",
                             f"http://127.0.0.1:{dead_port}/federation/receipts")]
        env = self.make_env(self.tmp, "org-a", ["alice", "bob"], peers)
        # a message org-a genuinely receives (target family == self)
        envelope = craft_event(target="alice@org-a")
        status, body = env.post_envelope(envelope)
        self.assertEqual((status, body), (200, {"status": "stored"}))
        hook_error = []
        env.fed.post_commit_hook = lambda: (hook_error.append(1), (_ for _ in ()).throw(
            RuntimeError("crash after ack commit")))
        status, body = env.call_json("POST", "/ack",
                                     {"event_id": EID, "agent_id": "alice",
                                      "ack_type": "received"}, token=env.tokens["alice"])
        env.fed.post_commit_hook = None
        self.assertEqual(status, 500)  # response failed; the COMMIT stands
        row = env.fed.store.get_receipt_out(EID, "alice@org-a", "received")
        self.assertIsNotNone(row)
        fixed_at = row["at"]
        # ACK-recorded but receipt unsent: simulate the crash window with a restart
        env.stop()
        self.recorder.server.behaviors = ["stored"]
        peers[0]["receipts_url"] = f"http://127.0.0.1:{self.recorder.port}/federation/receipts"
        (Path(env.config.peers_path)).write_text(json.dumps(peers))
        store = AtalkStore(env.dir / "atalk.db")
        restarted = AtalkHTTPServer(
            ("127.0.0.1", 0), store, WakeHub(),
            federation_config=FederationConfig(
                enabled=True, peers_path=env.config.peers_path,
                identity_path=env.config.identity_path,
                outbox_cap=100, rate_conn_per_min=10 ** 6, rate_family_per_min=10 ** 6,
                worker_interval=0.05, http_timeout=2.0, backoff_base=0.05,
                backoff_max=0.5, allow_insecure_loopback=True))
        self.addCleanup(restarted.server_close)  # never served: no shutdown() event
        wait_until(lambda: len(self.recorder.requests) >= 1, what="rebuilt receipt sent")
        sent = json.loads(self.recorder.requests[0][1])
        self.assertEqual(sent["receipt"]["at"], fixed_at)
        self.assertIsNone(row["sig"])  # rebuilt from the ACK record, not pre-signed
        env_obj = schema.validate_receipt_envelope(sent)
        self.assertTrue(ed25519strict.verify(PUB["org-a"], env_obj.signed_bytes,
                                             env_obj.sig))
        # second rebuild attempt (another restart) resends the SAME original
        self.recorder.requests.clear()
        self.recorder.server.behaviors = ["stored"]
        restarted2 = AtalkHTTPServer(
            ("127.0.0.1", 0), AtalkStore(env.dir / "atalk.db"), WakeHub(),
            federation_config=FederationConfig(
                enabled=True, peers_path=env.config.peers_path,
                identity_path=env.config.identity_path,
                outbox_cap=100, rate_conn_per_min=10 ** 6, rate_family_per_min=10 ** 6,
                worker_interval=0.05, http_timeout=2.0, backoff_base=0.05,
                backoff_max=0.5, allow_insecure_loopback=True))
        self.addCleanup(restarted2.server_close)  # never served: no shutdown() event
        time.sleep(0.4)
        self.assertEqual(self.recorder.requests, [])  # ended task not reactivated

    def test_receipt_committed_response_lost_then_redelivered_identical(self):
        # "A committed but the response was lost": the peer sleeps past our
        # client timeout, we retry, the peer sees byte-identical originals.
        slow = Recorder(behaviors=["slow", "stored"])
        self.addCleanup(slow.stop)
        peers = [peer_record("org-a", f"http://127.0.0.1:9/inbox",
                             f"http://127.0.0.1:{slow.port}/federation/receipts")]
        env = self.make_env(self.tmp, "org-a", ["alice"], peers)
        status, body = env.post_envelope(craft_event(target="alice@org-a"))
        self.assertEqual((status, body), (200, {"status": "stored"}))
        status, body = env.call_json("POST", "/ack",
                                     {"event_id": EID, "agent_id": "alice",
                                      "ack_type": "received"}, token=env.tokens["alice"])
        self.assertEqual(status, 200, body)
        wait_until(lambda: len(slow.requests) >= 2, what="retry after response loss")
        self.assertEqual(slow.requests[0][1], slow.requests[1][1])
        wait_until(lambda: env.fed.store.get_receipt_out(
            EID, "alice@org-a", "received")["status"] == "sent", what="receipt sent")

    def test_crash_after_commit_before_delivery_recovered_by_scan(self):
        env = self.make_env(
            self.tmp, "org-b", ["bob", "carol"],
            [peer_record("org-a", "http://127.0.0.1:9/inbox",
                         "http://127.0.0.1:9/receipts")])
        def boom():
            raise RuntimeError("crash between commit and delivery")
        env.fed.post_commit_hook = boom
        status, body = env.post_envelope(craft_event())
        self.assertEqual(status, 500)
        env.fed.post_commit_hook = None
        row = env.fed.store.get_inbound(origin="org-a", event_id=EID)
        self.assertIsNotNone(row)
        self.assertEqual(row["delivery_state"], "pending")
        # the pull path already sees the committed event
        self.assertIsNotNone(env.store.get_event(EID))
        # recovery delivers: state advances through the scan
        env.fed.deliver_pending()
        row = env.fed.store.get_inbound(origin="org-a", event_id=EID)
        self.assertEqual(row["delivery_state"], "delivered")

    def test_ack_survives_receipt_worker_failure(self):
        # ACK always commits even while the receipt sender keeps failing;
        # the receipt is rebuilt later from the fixed ACK record.
        env = self.make_env(
            self.tmp, "org-b", ["bob"],
            [peer_record("org-a", "http://127.0.0.1:9/inbox",
                         f"http://127.0.0.1:{reserve_port()}/federation/receipts")])
        self.assertEqual(env.post_envelope(craft_event()), (200, {"status": "stored"}))
        status, body = env.call_json("POST", "/ack",
                                     {"event_id": EID, "agent_id": "bob",
                                      "ack_type": "received"}, token=env.tokens["bob"])
        self.assertEqual(status, 200, body)  # ACK committed although sends fail
        row = env.fed.store.get_receipt_out(EID, "bob@org-b", "received")
        self.assertEqual(row["status"], "pending")
        self.assertIsNotNone(row["at"])


# ---------------------------------------------------------------------------
# Spec 11 Test 5: impersonation.
# ---------------------------------------------------------------------------

class ImpersonationTest(EnvTestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.env = self.make_env(
            self.tmp, "org-b", ["bob", "carol"],
            [peer_record("org-a", "http://127.0.0.1:9/inbox",
                         "http://127.0.0.1:9/receipts")])
        self.assertEqual(self.env.post_envelope(craft_event()), (200, {"status": "stored"}))

    def test_local_non_recipient_cannot_ack(self):
        status, body = self.env.call_json(
            "POST", "/ack", {"event_id": EID, "agent_id": "carol",
                             "ack_type": "received"}, token=self.env.tokens["carol"])
        self.assertEqual(status, 403)
        self.assertEqual(body, {"error": "only the recipient of a federation event may ack it"})
        self.assertIsNone(self.env.fed.store.get_receipt_out(EID, "carol@org-b",
                                                             "received"))
        # the actual recipient ACKs with their own peer id and token
        status, body = self.env.call_json(
            "POST", "/ack", {"event_id": EID, "agent_id": "bob",
                             "ack_type": "received"}, token=self.env.tokens["bob"])
        self.assertEqual(status, 200, body)
        row = self.env.fed.store.get_receipt_out(EID, "bob@org-b", "received")
        self.assertIsNotNone(row)

    def test_validly_signed_receipt_with_wrong_agent_rejected_at_binding(self):
        cloud_env = self.make_env(
            self.tmp, "org-a", ["alice"],
            [peer_record("org-b", "http://127.0.0.1:9/inbox",
                         "http://127.0.0.1:9/receipts")])
        cloud_env.seed_outbound()
        # same-name agent, wrong family: valid org-b signature, wrong agent
        wrong = craft_receipt(agent="bob@org-other")
        status, body = cloud_env.post_envelope(wrong, path="/federation/receipts")
        self.assertEqual((status, body), (403, {"status": "rejected",
                                                "reason": "agent_mismatch"}))


# ---------------------------------------------------------------------------
# Spec 11 Test 6: privilege and limits.
# ---------------------------------------------------------------------------

class PrivilegeLimitsTest(EnvTestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))

    def rejected_envelope_env(self):
        env = self.make_env(
            self.tmp, "org-b", ["bob", "carol"],
            [peer_record("org-a", "http://127.0.0.1:9/inbox",
                         "http://127.0.0.1:9/receipts"),
             peer_record("org-test", "http://127.0.0.1:9/inbox",
                         "http://127.0.0.1:9/receipts")])
        # a local grant that would authorize this op if commands crossed families
        env.store.add_grant("bob", "bob", "op1")
        return env

    def test_registered_valid_command_grant_unknown_broadcast_rejected(self):
        cases = [
            (craft_event(etype="command"), 400, "type_whitelist"),
            (craft_event(etype="grant"), 400, "type_whitelist"),
            (craft_event(etype="status_query"), 400, "type_whitelist"),
            (craft_event(target="*@org-b"), 400, "address_grammar"),
        ]
        for envelope, want_status, want_reason in cases:
            with self.subTest(etype=envelope["event"]["type"],
                              target=envelope["event"]["target"]):
                env = self.rejected_envelope_env()
                grants_before = env.store.conn.execute(
                    "SELECT count(*) n FROM peer_grants").fetchone()["n"]
                status, body = env.post_envelope(envelope)
                self.assertEqual(status, want_status, body)
                self.assertEqual(body, {"status": "rejected", "reason": want_reason})
                counts = env.business_counts()
                for table in ("events", "acks", "federation_inbound",
                              "federation_notifications"):
                    self.assertEqual(counts[table], 0, table)
                grants_after = env.store.conn.execute(
                    "SELECT count(*) n FROM peer_grants").fetchone()["n"]
                self.assertEqual(grants_before, grants_after)

    def test_outbox_cap_rejects_sender_receipts_uncapped(self):
        env = self.make_env(
            self.tmp, "org-b", ["bob"],
            [peer_record("org-a", f"http://127.0.0.1:{reserve_port()}/federation/inbox",
                         f"http://127.0.0.1:{reserve_port()}/federation/receipts")],
            outbox_cap=1)
        status, body = env.call_json(
            "POST", "/events",
            {"source": "bob", "target": "alice@org-a", "type": "message",
             "event_id": "aaaa0000-0000-4000-8000-00000000ca01",
             "payload": {"text": "one"}}, token=env.tokens["bob"])
        self.assertEqual(status, 201, body)
        status, body = env.call_json(
            "POST", "/events",
            {"source": "bob", "target": "alice@org-a", "type": "message",
             "event_id": "aaaa0000-0000-4000-8000-00000000ca02",
             "payload": {"text": "two"}}, token=env.tokens["bob"])
        self.assertEqual(status, 429)
        self.assertIn("outbox is full", body["error"])
        # receipts are never capped: inbound + two ACKs commit regardless
        self.assertEqual(env.post_envelope(craft_event()), (200, {"status": "stored"}))
        for ack_type in ("received", "applied"):
            status, body = env.call_json(
                "POST", "/ack", {"event_id": EID, "agent_id": "bob",
                                 "ack_type": ack_type}, token=env.tokens["bob"])
            self.assertEqual(status, 200, body)
        self.assertEqual(
            env.store.conn.execute("SELECT count(*) n FROM federation_receipt_out")
            .fetchone()["n"], 2)

    def test_retry_of_capped_outbox_event_is_idempotent(self):
        env = self.make_env(
            self.tmp, "org-b", ["bob"],
            [peer_record("org-a", f"http://127.0.0.1:{reserve_port()}/federation/inbox",
                         f"http://127.0.0.1:{reserve_port()}/federation/receipts")],
            outbox_cap=1)
        payload = {"source": "bob", "target": "alice@org-a", "type": "message",
                   "event_id": "aaaa0000-0000-4000-8000-00000000ca03",
                   "payload": {"text": "idempotent"}}
        self.assertEqual(env.call_json("POST", "/events", payload,
                                       token=env.tokens["bob"])[0], 201)
        env.call_json("POST", "/events",
                      {"source": "bob", "target": "alice@org-a", "type": "message",
                       "event_id": "aaaa0000-0000-4000-8000-00000000ca04",
                       "payload": {"text": "fills the cap"}}, token=env.tokens["bob"])
        # wait until the cap is genuinely consumed
        wait_until(lambda: env.store.conn.execute(
            "SELECT count(*) n FROM federation_outbound WHERE status='pending'"
        ).fetchone()["n"] >= 1, what="pending rows")
        status, body = env.call_json("POST", "/events", payload, token=env.tokens["bob"])
        self.assertEqual(status, 201)  # retry bypasses the cap, no new row
        rows = env.store.conn.execute(
            "SELECT count(*) n FROM federation_outbound WHERE event_id=?",
            ("aaaa0000-0000-4000-8000-00000000ca03",)).fetchone()
        self.assertEqual(rows["n"], 1)

    def test_local_traffic_still_flows_when_federation_on(self):
        env = self.make_env(
            self.tmp, "org-b", ["bob", "carol"],
            [peer_record("org-a", "http://127.0.0.1:9/inbox",
                         "http://127.0.0.1:9/receipts")])
        status, body = env.call_json(
            "POST", "/events",
            {"source": "bob", "target": "carol", "type": "message",
             "event_id": "bbbb0000-0000-4000-8000-000000001ca1",
             "payload": {"text": "local hi"}}, token=env.tokens["bob"])
        self.assertEqual(status, 201, body)
        self.assertNotIn("federation", body)
        status, body = env.call_json(
            "POST", "/ack", {"event_id": "bbbb0000-0000-4000-8000-000000001ca1",
                             "agent_id": "carol", "ack_type": "received"},
            token=env.tokens["carol"])
        self.assertEqual(status, 200, body)
        self.assertEqual(env.fed.store.get_receipt_out(
            "bbbb0000-0000-4000-8000-000000001ca1", "carol", "received"), None)


if __name__ == "__main__":
    unittest.main()
