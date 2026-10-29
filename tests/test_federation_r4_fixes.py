"""Federation r4 fixes (round-3 review F1-F8, plus P1/P2 process items).

Every fix ships with the regression tests that pin it.  Environment notes:
- "no nacl" means `-S` (no site module -> no site-packages) on the current
  interpreter with only the tree under test on PYTHONPATH; a precondition
  test asserts PyNaCl is genuinely hidden that way.
- loopback HTTP peers in these tests use the EXPLICIT test-only bypass
  (ATALK_FEDERATION_ALLOW_LOOPBACK_HTTP / allow_insecure_loopback), which is
  unavailable by default (r4 F2).
"""
import base64
import email.message
import email.utils
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import _r4_support as support
from atalk.core import AtalkStore
from atalk.federation import canonical, registry, runtime
from atalk.federation.canonical import FederationError
from atalk.federation.runtime import FederationConfig, FederationRuntime
from atalk.federation.store import FederationStore
from atalk.server import AtalkHTTPServer, WakeHub

REPO_ROOT = support.REPO_ROOT


class NoNaclStartupTest(unittest.TestCase):
    """F1: flag-off must import and start in a zero-dependency environment;
    flag-on without the crypto backend fails closed (federation off, ordinary
    service unaffected)."""

    def test_minus_s_really_hides_pynacl(self):
        proc = support.run_nonacl(["-c", "import nacl"])
        self.assertNotEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("nacl", proc.stderr)

    def test_candidate_flagoff_imports_without_nacl(self):
        proc = support.run_nonacl(
            ["-c", "import atalk.server, atalk.federation.runtime, atalk.federation.canonical"])
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_candidate_crypto_is_optional_at_import_without_nacl(self):
        proc = support.run_nonacl(["-c", "import atalk.federation.ed25519strict"])
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("nacl", proc.stderr)

    def test_base_flagoff_imports_without_nacl(self):
        if not support.have_base_commit():
            self.skipTest(f"base commit {support.BASE_COMMIT} not available")
        with support.base_worktree(REPO_ROOT) as base_root:
            proc = support.run_nonacl(["-c", "import atalk.server"], source_root=base_root)
            self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_candidate_flagoff_server_serves_without_nacl(self):
        with support.serve(REPO_ROOT) as url:
            status, _ctype, _raw = support.http_raw("GET", f"{url}/health")
            self.assertEqual(status, 200)
            status, _ctype, body = support.http_raw("GET", f"{url}/definitely-not-a-path")
            self.assertEqual((status, json.loads(body)), (404, {"error": "not found"}))

    def test_base_flagoff_server_serves_without_nacl(self):
        if not support.have_base_commit():
            self.skipTest(f"base commit {support.BASE_COMMIT} not available")
        with support.base_worktree(REPO_ROOT) as base_root:
            with support.serve(base_root) as url:
                status, _ctype, _raw = support.http_raw("GET", f"{url}/health")
                self.assertEqual(status, 200)

    def test_flag_on_without_crypto_fails_closed_and_server_serves(self):
        state = Path(tempfile.mkdtemp(prefix="atalk-fed-nonacl-"))
        self.addCleanup(lambda: shutil.rmtree(state, ignore_errors=True))
        peers = state / "federation_peers.json"
        peers.write_text("[]")
        ident = state / "federation_identity.json"
        seed = base64.urlsafe_b64encode(b"\x01" * 32).rstrip(b"=").decode()
        ident.write_text(json.dumps({"family": "org-b", "key_id": "ob-2026-10",
                                     "seed": seed}))
        os.chmod(ident, 0o600)
        env = {"ATALK_FEDERATION": "1",
               "ATALK_FEDERATION_PEERS": str(peers),
               "ATALK_FEDERATION_IDENTITY": str(ident)}
        with support.serve(REPO_ROOT, env_extra=env) as url:
            status, _ctype, _raw = support.http_raw("GET", f"{url}/health")
            self.assertEqual(status, 200)
            status, _ctype, body = support.http_raw(
                "POST", f"{url}/federation/inbox", raw=b'{"x": "1"}')
            self.assertEqual((status, json.loads(body)), (404, {"error": "not found"}))


class BuiltWheelTest(unittest.TestCase):
    """F1 acceptance gate (r5 #4).  The built wheel must ship the federation
    subpackage, install into a CLEAN target, and that installed tree must
    import under `-S` OUTSIDE the source tree with no PyNaCl present, expose
    the schema.sql resource, and start the ordinary server.

    r4 turned every build error, timeout or missing artifact into SkipTest,
    which is exactly how a broken build toolchain (no bdist_wheel) got
    reported as "6 skipped, exit 0" — the required packaging evidence never
    existed and the failure was invisible.  The declared build dependencies
    (pyproject build-system: setuptools>=61, wheel) are a PREREQUISITE of
    this gate: missing tooling, a build failure, a timeout or a missing
    artifact is a FAIL with the reason, never a skip."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="atalk-wheel-"))
        try:
            error = cls._provisioning_error()
            if error:
                raise AssertionError(
                    "wheel acceptance gate prerequisite not met "
                    "(build deps must be provisioned): " + error)
            cls.build_dir = cls.tmp / "build"
            cls.target = cls.tmp / "target"
            cls.run_dir = cls.tmp / "run"
            for d in (cls.build_dir, cls.target, cls.run_dir):
                d.mkdir()
            proc = subprocess_wheel_build(str(cls.build_dir))
            if isinstance(proc, subprocess.TimeoutExpired):
                raise AssertionError("wheel build timed out (300s)")
            if proc.returncode != 0:
                raise AssertionError(
                    f"wheel build failed (rc={proc.returncode}):\n"
                    + (proc.stderr or proc.stdout or "")[-2000:])
            wheels = sorted(cls.build_dir.glob("atalk-*.whl"))
            if not wheels:
                raise AssertionError("pip produced no atalk wheel artifact")
            cls.wheel = wheels[0]
            install = subprocess.run(
                [sys.executable, "-m", "pip", "install", "--no-deps",
                 "--no-index", "--target", str(cls.target), str(cls.wheel)],
                capture_output=True, text=True, timeout=300)
            if install.returncode != 0:
                raise AssertionError(
                    "installing the wheel into a clean target failed:\n"
                    + (install.stderr or install.stdout or "")[-2000:])
        except Exception:
            shutil.rmtree(cls.tmp, ignore_errors=True)
            raise

    @staticmethod
    def _provisioning_error() -> str | None:
        try:
            import setuptools  # noqa: F401
        except ImportError:
            return "setuptools is not importable"
        try:
            import pip  # noqa: F401
        except ImportError:
            return "pip is not importable"
        try:
            import wheel  # noqa: F401
        except ImportError:
            try:
                from setuptools.command.bdist_wheel import bdist_wheel  # noqa: F401,F403
            except ImportError:
                return ("neither the 'wheel' distribution nor setuptools' "
                        "vendored bdist_wheel is importable")
        return None

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_wheel_ships_federation_subpackage(self):
        with zipfile.ZipFile(self.wheel) as zf:
            names = set(zf.namelist())
        for member in ("atalk/server.py", "atalk/schema.sql",
                       "atalk/federation/__init__.py",
                       "atalk/federation/canonical.py",
                       "atalk/federation/runtime.py",
                       "atalk/federation/ed25519strict.py"):
            self.assertIn(member, names, member)

    def test_installed_tree_imports_from_target_only_minus_s_without_nacl(self):
        script = (
            "import sys\n"
            "target = sys.argv[1]\n"
            "import atalk, atalk.server\n"                      # noqa: E401
            "import atalk.federation.canonical, atalk.federation.runtime\n"
            "assert atalk.__file__ and atalk.__file__.startswith(target), atalk.__file__\n"
            "print('ATALK_FILE:', atalk.__file__)\n"
            "try:\n"
            "    import nacl\n"
            "except ImportError:\n"
            "    print('NACL-ABSENT')\n"
            "else:\n"
            "    print('nacl unexpectedly importable:', nacl.__file__)\n"
            "    sys.exit(3)\n"
        )
        proc = support.run_nonacl(["-c", script, str(self.target)],
                                  source_root=self.target, cwd=self.run_dir)
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        self.assertIn("ATALK_FILE:", proc.stdout)
        self.assertIn("NACL-ABSENT", proc.stdout)

    def test_schema_resource_available_in_installed_tree(self):
        script = (
            "from pathlib import Path\n"
            "import atalk\n"
            "raw = (Path(atalk.__file__).parent / 'schema.sql').read_bytes()\n"
            "assert b'CREATE TABLE' in raw and len(raw) > 1000, len(raw)\n"
            "print('SCHEMA-OK', len(raw))\n"
        )
        proc = support.run_nonacl(["-c", script],
                                  source_root=self.target, cwd=self.run_dir)
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        self.assertIn("SCHEMA-OK", proc.stdout)

    def test_installed_tree_starts_and_serves(self):
        with support.serve(str(self.target),
                           state_dir=str(self.tmp / "state"),
                           cwd=self.run_dir) as url:
            status, _ctype, _raw = support.http_raw("GET", f"{url}/health")
            self.assertEqual(status, 200)
            status, _ctype, raw = support.http_raw("GET", f"{url}/no-such-path")
            self.assertEqual((status, json.loads(raw)),
                             (404, {"error": "not found"}))


def subprocess_wheel_build(out_dir: str):
    return subprocess.run(
        [sys.executable, "-m", "pip", "wheel", "--no-deps", "--no-build-isolation",
         "--wheel-dir", out_dir, str(REPO_ROOT)],
        capture_output=True, text=True, timeout=300)


# ---------------------------------------------------------------------------
# F2: https-only endpoints at LOAD and at the TRANSPORT; the loopback http
# bypass exists, is explicit, and is unavailable by default.
# ---------------------------------------------------------------------------

class EndpointUrlPolicyTest(unittest.TestCase):
    def test_accepts_and_rejects(self):
        cases = [
            ("https://fam.example/inbox", False, None),
            ("HTTPS://fam.example/inbox", False, None),  # normalized scheme, still TLS
            ("https://fam.example:8443/x?a=b", False, None),
            ("http://127.0.0.1:9/inbox", True, None),    # explicit bypass only
            ("http://localhost:9/inbox", True, None),
            ("http://[::1]:9/inbox", True, None),
            ("http://bus.localhost/inbox", True, None),
            ("http://127.0.0.1:9/inbox", False, "scheme_http"),  # default: unavailable
            ("https://u:p@host.example/x", False, "userinfo"),
            ("https://u:p@127.0.0.1/x", True, "userinfo"),       # bypass != anything-goes
            ("https://host.example/x#frag", False, "fragment"),
            ("https:///path", False, "missing_host"),
            ("ftp://host.example/x", False, "scheme_ftp"),
            ("not-a-url", False, "scheme_missing"),
            ("", False, "empty"),
            ("https://hos t.example/x", False, "control_or_whitespace"),
            ("http://registry.example/x", True, "scheme_http"),  # bypass never leaves loopback
            # r5 F2: malformed URLs are policy results, never exceptions
            ("https://[broken/inbox", False, "invalid_url"),      # bad IPv6 brackets
            ("https://host℀/x", False, "invalid_url"),            # NFKC-invalid netloc
            ("https://host.example:99999/x", False, "invalid_url"),  # port out of range
            ("https://host.example:-1/x", False, "invalid_url"),     # negative port
        ]
        for url, bypass, want in cases:
            with self.subTest(url=url, bypass=bypass):
                self.assertEqual(registry.endpoint_url_error(url, bypass), want)


def _test_public_key() -> str:
    return canonical.encode(b"\x02" * 32)


class RegistryHttpsLoadTest(unittest.TestCase):
    def _write(self, tmp, inbox_url):
        doc = [{"family": "org-a", "key_id": "oa-2026-10",
                "public_key": _test_public_key(),
                "inbox_url": inbox_url, "receipts_url": inbox_url}]
        path = Path(tmp) / "federation_peers.json"
        path.write_text(json.dumps(doc))
        return path

    def test_plaintext_endpoint_is_load_error_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, "http://127.0.0.1:9/federation/inbox")
            with self.assertRaises(FederationError) as caught:
                registry.load_peers(path)
            self.assertEqual(caught.exception.category, "unsupported_endpoint_url")
            self.assertEqual(caught.exception.layer, "registry")
            self.assertEqual(len(registry.safe_load_peers(path)), 0)

    def test_loopback_bypass_admits_loopback_http_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg = registry.load_peers(
                self._write(tmp, "http://127.0.0.1:9/federation/inbox"),
                allow_insecure_loopback=True)
            self.assertEqual(len(reg), 1)
            with self.assertRaises(FederationError) as caught:
                registry.load_peers(
                    self._write(tmp, "http://registry.example/federation/inbox"),
                    allow_insecure_loopback=True)
            self.assertEqual(caught.exception.category, "unsupported_endpoint_url")


class MalformedUrlFailClosedTest(unittest.TestCase):
    """r5 F2: a registered endpoint URL that makes urlsplit (or the
    hostname/port accessors) raise ValueError must be a stable
    unsupported_endpoint_url POLICY result — federation collapses to off,
    the ordinary service keeps serving, and the transport classifies without
    ever throwing."""

    MALFORMED = [
        ("ipv6_bracket", "https://[broken/inbox"),
        ("nfkc_netloc", "https://host℀/x"),
        ("port_out_of_range", "https://host.example:99999/x"),
        ("port_negative", "https://host.example:-1/x"),
    ]

    def _write(self, tmp, inbox_url):
        doc = [{"family": "org-a", "key_id": "oa-2026-10",
                "public_key": _test_public_key(),
                "inbox_url": inbox_url, "receipts_url": inbox_url}]
        path = Path(tmp) / "federation_peers.json"
        path.write_text(json.dumps(doc))
        return path

    def test_load_peers_classifies_unsupported_endpoint_url(self):
        for name, url in self.MALFORMED:
            with self.subTest(case=name), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(FederationError) as caught:
                    registry.load_peers(self._write(tmp, url))
                self.assertEqual(caught.exception.category,
                                 "unsupported_endpoint_url")
                self.assertEqual(caught.exception.layer, "registry")
                self.assertIn("invalid_url", caught.exception.detail)

    def test_safe_load_peers_fails_closed(self):
        for name, url in self.MALFORMED:
            with self.subTest(case=name), tempfile.TemporaryDirectory() as tmp:
                self.assertEqual(len(registry.safe_load_peers(self._write(tmp, url))), 0)

    def test_build_collapses_to_off_and_ordinary_service_serves(self):
        for name, url in self.MALFORMED:
            with self.subTest(case=name), tempfile.TemporaryDirectory() as tmp:
                peers = self._write(tmp, url)
                ident = Path(tmp) / "federation_identity.json"
                seed = base64.urlsafe_b64encode(b"\x01" * 32).rstrip(b"=").decode()
                ident.write_text(json.dumps({"family": "org-b",
                                             "key_id": "ob-2026-10", "seed": seed}))
                os.chmod(ident, 0o600)
                store = AtalkStore(Path(tmp) / "atalk.db")
                config = FederationConfig(enabled=True, peers_path=str(peers),
                                          identity_path=str(ident))
                # pre-fix this raised ValueError (Invalid IPv6 URL) out of build
                self.assertIsNone(FederationRuntime.build(config, store), name)
                server = AtalkHTTPServer(("127.0.0.1", 0), store, WakeHub(),
                                         federation_config=config)
                self.addCleanup(server.server_close)
                self.addCleanup(server.shutdown)
                self.assertIsNone(server.federation, name)
                threading.Thread(target=server.serve_forever, daemon=True).start()
                status, _ctype, _raw = support.http_raw(
                    "GET", f"http://127.0.0.1:{server.server_address[1]}/health")
                self.assertEqual(status, 200, name)

    def test_transport_classifies_without_throwing(self):
        for name, url in self.MALFORMED:
            with self.subTest(case=name):
                outcome = runtime.send_envelope(url, b"{}", 5.0)
                self.assertEqual(outcome.kind, "permanent", name)
                self.assertIn("unsupported_endpoint_url: invalid_url",
                              outcome.error, name)


class LoopbackBypassConfigTest(unittest.TestCase):
    def test_env_flag_exact_match(self):
        with mock.patch.dict(os.environ,
                             {"ATALK_FEDERATION_ALLOW_LOOPBACK_HTTP": "1"}):
            self.assertTrue(FederationConfig.from_env().allow_insecure_loopback)
        with mock.patch.dict(os.environ,
                             {"ATALK_FEDERATION_ALLOW_LOOPBACK_HTTP": "true"}):
            self.assertFalse(FederationConfig.from_env().allow_insecure_loopback)

    def test_flag_on_with_plaintext_peers_file_stays_off_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            peers = Path(tmp) / "federation_peers.json"
            peers.write_text(json.dumps([{
                "family": "org-a", "key_id": "oa-2026-10",
                "public_key": _test_public_key(),
                "inbox_url": "http://127.0.0.1:9/federation/inbox",
                "receipts_url": "http://127.0.0.1:9/federation/receipts"}]))
            ident = Path(tmp) / "federation_identity.json"
            seed = base64.urlsafe_b64encode(b"\x01" * 32).rstrip(b"=").decode()
            ident.write_text(json.dumps({"family": "org-b", "key_id": "ob-2026-10",
                                         "seed": seed}))
            os.chmod(ident, 0o600)
            config = FederationConfig(enabled=True, peers_path=str(peers),
                                      identity_path=str(ident))
            self.assertFalse(config.allow_insecure_loopback)
            store = AtalkStore(Path(tmp) / "atalk.db")
            self.assertIsNone(FederationRuntime.build(config, store))


class _QuietServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass  # expected: strict-client TLS handshake failures, dropped uploads


class _StubPeerHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self.server.requests.append((self.path, body))
        behavior = self.server.behaviors.pop(0) if self.server.behaviors else "stored"
        if behavior == "redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/elsewhere")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if behavior.startswith("retryafter:"):
            # r5 #3: a 429 whose valid Retry-After the client must honor IN
            # FULL ("7200" = delta-seconds form; "@7200" = HTTP-date 7200s
            # ahead of now).
            spec = behavior.split(":", 1)[1]
            if spec.startswith("@"):
                value = email.utils.formatdate(time.time() + int(spec[1:]),
                                               usegmt=True)
            else:
                value = spec
            self.send_response(429)
            self.send_header("Retry-After", value)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if behavior == "statuslist":      # F3: {"status": []} poisoned the worker
            raw = b'{"status": []}'
            status_code = 200
        elif behavior == "statusdict":    # F3: {"status": {}}
            raw = b'{"status": {}}'
            status_code = 200
        elif behavior == "deep200":       # F3: <64KB but over the depth cap
            raw = (b'{"status": "stored", "a":' + b'{"a":' * 3000
                   + b'"x"' + b'}' * 3000)
            status_code = 200
        elif behavior.startswith("big") and behavior[3:].isdigit():
            # F7: a large error body the client never reads
            raw = b"x" * (1 << 20)
            status_code = int(behavior[3:])
        elif behavior.isdigit() and len(behavior) == 3:   # F4: any 2xx/other code
            raw = b'{"status": "stored"}'
            status_code = int(behavior)
        else:
            raw = json.dumps({"status": behavior}).encode()
            status_code = 200
        try:
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, fmt, *args):
        return


class StubPeer:
    """Programmable loopback peer; plain http (needs the explicit bypass) or,
    with tls_cert/tls_key, server-side TLS with a self-signed TEST cert."""

    def __init__(self, behaviors=None, tls_cert=None, tls_key=None):
        self.server = _QuietServer(("127.0.0.1", 0), _StubPeerHandler)
        self.server.behaviors = list(behaviors or [])
        self.server.requests = []
        self._tls = tls_cert is not None
        if self._tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(str(tls_cert), str(tls_key))
            self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def url(self):
        scheme = "https" if self._tls else "http"
        return f"{scheme}://127.0.0.1:{self.port}/federation/inbox"

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


def _self_signed_cert(tmp):
    cert = Path(tmp) / "cert.pem"
    key = Path(tmp) / "key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(key),
         "-out", str(cert), "-days", "2", "-nodes", "-subj", "/CN=127.0.0.1",
         "-addext", "subjectAltName=IP:127.0.0.1"],
        check=True, capture_output=True, timeout=60)
    return cert, key


class TransportHttpsOnlyTest(unittest.TestCase):
    def test_default_transport_never_sends_plaintext(self):
        peer = StubPeer()
        self.addCleanup(peer.stop)
        outcome = runtime.send_envelope(peer.url, b"{}", 5.0)
        self.assertEqual(outcome.kind, "permanent")
        self.assertIn("unsupported_endpoint_url", outcome.error)
        self.assertEqual(peer.server.requests, [])

    def test_explicit_bypass_is_the_only_plaintext_path(self):
        peer = StubPeer()
        self.addCleanup(peer.stop)
        outcome = runtime.send_envelope(peer.url, b"{}", 5.0,
                                        allow_insecure_loopback=True)
        self.assertEqual(outcome.kind, "sent")
        self.assertEqual(len(peer.server.requests), 1)

    def test_bypass_redirect_still_never_followed(self):
        peer = StubPeer(behaviors=["redirect"])
        self.addCleanup(peer.stop)
        outcome = runtime.send_envelope(peer.url, b"{}", 5.0,
                                        allow_insecure_loopback=True)
        self.assertEqual((outcome.kind, outcome.error),
                         ("permanent", "redirect_not_followed"))
        self.assertEqual(len(peer.server.requests), 1)

    def test_certificate_mismatch_fails_closed_before_sending_useful_data(self):
        if not shutil.which("openssl"):
            self.skipTest("openssl not available for a self-signed test peer")
        with tempfile.TemporaryDirectory() as tmp:
            cert, key = _self_signed_cert(tmp)
            peer = StubPeer(tls_cert=cert, tls_key=key)
            self.addCleanup(peer.stop)
            outcome = runtime.send_envelope(f"{peer.url}/x", b"{}", 5.0)
            # default context: strict verification stays ON; mismatch is a
            # transient connection error, classified without hanging.
            self.assertEqual(outcome.kind, "retry")
            self.assertIn("connection_error", outcome.error)
            self.assertEqual(peer.server.requests, [])

    def test_https_positive_leg_end_to_end(self):
        # The mismatch test above proves the default context still verifies;
        # this proves the https plumbing end-to-end by trusting the TEST
        # peer's cert in a TEST-only opener (product code untouched).
        if not shutil.which("openssl"):
            self.skipTest("openssl not available for a self-signed test peer")
        with tempfile.TemporaryDirectory() as tmp:
            cert, key = _self_signed_cert(tmp)
            peer = StubPeer(tls_cert=cert, tls_key=key)
            self.addCleanup(peer.stop)
            trusting = ssl.create_default_context(cafile=str(cert))
            opener = urllib.request.OpenerDirector()
            opener.add_handler(urllib.request.HTTPSHandler(context=trusting))
            opener.add_handler(runtime._NoRedirect())
            opener.add_handler(urllib.request.HTTPErrorProcessor())
            opener.add_handler(urllib.request.HTTPDefaultErrorHandler())
            with mock.patch.object(runtime, "_OPENER", opener):
                outcome = runtime.send_envelope(peer.url, b"{}", 5.0)
            self.assertEqual(outcome.kind, "sent")
            self.assertEqual(len(peer.server.requests), 1)


# ---------------------------------------------------------------------------
# F3: malformed 200s are transient outcomes, worker items are isolated with
# persisted backoff, and startup recovery survives a poison peer.
# ---------------------------------------------------------------------------

def wait_until(fn, timeout: float = 8.0, what: str = "condition") -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if fn():
            return
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {what}")


class Malformed200Test(unittest.TestCase):
    def test_expected_shapes_are_transient_outcomes_never_crashes(self):
        for behavior, want_error in (("statuslist", "unrecognized_200_body"),
                                     ("statusdict", "unrecognized_200_body"),
                                     ("deep200", "unparseable_200_body")):
            with self.subTest(behavior=behavior):
                peer = StubPeer(behaviors=[behavior])
                self.addCleanup(peer.stop)
                outcome = runtime.send_envelope(peer.url, b"{}", 5.0,
                                                allow_insecure_loopback=True)
                self.assertEqual(outcome.kind, "retry")
                self.assertEqual(outcome.error, want_error)


class WorkerHarness:
    """Minimal federation runtime (no HTTP server) over a real AtalkStore,
    with per-family loopback StubPeers behind the explicit bypass."""

    def __init__(self, tmp, peers_by_family):
        self.peers = peers_by_family
        self.store = AtalkStore(Path(tmp) / "atalk.db")
        doc = [{"family": family, "key_id": f"{family}-kid",
                "public_key": _test_public_key(),
                "inbox_url": peer.url, "receipts_url": peer.url}
               for family, peer in peers_by_family.items()]
        peers_path = Path(tmp) / "federation_peers.json"
        peers_path.write_text(json.dumps(doc))
        config = FederationConfig(
            enabled=True, peers_path=str(peers_path),
            identity_path=str(Path(tmp) / "unused-identity.json"),
            worker_interval=0.05, http_timeout=2.0, backoff_base=0.05,
            backoff_max=0.5, allow_insecure_loopback=True)
        identity = runtime.Identity("org-b", "ob-2026-10", b"\x01" * 32)
        self.rt = runtime.FederationRuntime(
            config, registry.load_peers(peers_path, allow_insecure_loopback=True),
            identity, FederationStore(self.store))
        self.wake = WakeHub()
        self.rt.set_wake(self.wake)

    def enqueue(self, event_id, family, target):
        self.rt.store.enqueue_outbound(
            event_id=event_id, origin="org-b", origin_key_id="ob-2026-10",
            source_local="bob", source_addr="bob@org-b", target=target,
            target_family=family, type="message",
            signed_json='{"kind": "federation.event.v0"}', sig="not-a-real-sig",
            envelope_json=b'{"kind": "federation.event.v0"}', outbox_cap=100)

    def stop(self):
        self.rt.stop()


class WorkerPoisonIsolationTest(unittest.TestCase):
    def test_poison_outbound_row_does_not_starve_healthy_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            poisoned = StubPeer(behaviors=["statuslist"])
            healthy = StubPeer()
            harness = WorkerHarness(tmp, {"org-a": poisoned, "org-test": healthy})
            self.addCleanup(harness.stop)
            harness.enqueue("cccc0000-0000-4000-8000-00000000f301", "org-a",
                            "alice@org-a")
            harness.enqueue("cccc0000-0000-4000-8000-00000000f302", "org-test",
                            "nori@org-test")
            harness.rt.process_due()  # must not raise
            bad = harness.rt.store.get_outbound("cccc0000-0000-4000-8000-00000000f301")
            good = harness.rt.store.get_outbound("cccc0000-0000-4000-8000-00000000f302")
            self.assertEqual(good["status"], "sent")
            self.assertEqual(bad["status"], "pending")
            self.assertEqual(bad["attempts"], 1)
            self.assertIsNotNone(bad["next_retry_at"])  # backoff persisted
            self.assertEqual(bad["last_error"], "unrecognized_200_body")

    def test_poison_receipt_row_isolated_with_backoff(self):
        with tempfile.TemporaryDirectory() as tmp:
            harness = WorkerHarness(tmp, {"org-a": StubPeer()})
            self.addCleanup(harness.stop)
            event_id = "cccc0000-0000-4000-8000-00000000f303"
            harness.store.insert_event("bob", "carol", "message", {"text": "x"},
                                       event_id=event_id)
            harness.rt.store.ack_with_receipt_intent(
                event_id=event_id, agent_id="carol", ack_type="received",
                detail=None, receipt_agent="carol@org-b", origin="org-a",
                origin_event_sig_hash="a" * 64, issuer="org-b",
                issuer_key_id="ob-2026-10")
            # corrupt the signed original so the send path raises unexpectedly
            harness.store.conn.execute(
                "UPDATE federation_receipt_out SET signed_json='not-json' "
                "WHERE event_id=?", (event_id,))
            harness.rt.process_due()  # must not raise
            row = harness.rt.store.get_receipt_out(event_id, "carol@org-b",
                                                   "received")
            self.assertEqual(row["status"], "pending")
            self.assertEqual(row["attempts"], 1)
            self.assertIsNotNone(row["next_retry_at"])
            self.assertIn("worker_error", row["last_error"])

    def test_startup_recovery_survives_malformed_peer_and_then_progresses(self):
        with tempfile.TemporaryDirectory() as tmp:
            peer = StubPeer(behaviors=["statuslist"])
            harness = WorkerHarness(tmp, {"org-a": peer})
            self.addCleanup(harness.stop)
            event_id = "cccc0000-0000-4000-8000-00000000f304"
            harness.enqueue(event_id, "org-a", "alice@org-a")
            harness.rt.start()  # worker with the malformed peer
            wait_until(lambda: harness.rt.store.get_outbound(event_id)["attempts"] >= 1,
                       what="first poisoned attempt")
            harness.rt.stop()
            # simulated restart against the same DB while the peer is STILL
            # returning malformed 200s (pre-fix this raised out of
            # recovery_scan -> start() -> server construction failed)
            peer.behaviors = ["statuslist", "statuslist"]
            restarted = WorkerHarness(tmp, {"org-a": peer})
            self.addCleanup(restarted.stop)
            restarted.rt.start()  # must not raise
            peer.behaviors = ["stored"]
            wait_until(lambda: restarted.rt.store.get_outbound(event_id)["status"]
                       == "sent", what="sent after restart")
            restarted.rt.stop()


# ---------------------------------------------------------------------------
# F4: ONLY 200 satisfies spec 8; other 2xx are transient failures for both
# outbound events and receipts.  (The code==200 gate itself landed with the
# F2/F3 send_envelope restructure; these are the regressions the reviewer asked for.)
# ---------------------------------------------------------------------------

class Non200SuccessTest(unittest.TestCase):
    # process_due(now=...) with a far-future timestamp drives the retry cycle
    # deterministically past second-resolution backoff (no wall-clock races).
    FAR_FUTURE = "9999-12-31T23:59:59Z"

    def test_event_task_rejects_non_200_2xx_and_stays_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            peer = StubPeer(behaviors=["201", "202", "206", "stored"])
            harness = WorkerHarness(tmp, {"org-a": peer})
            self.addCleanup(harness.stop)
            event_id = "cccc0000-0000-4000-8000-00000000f401"
            harness.enqueue(event_id, "org-a", "alice@org-a")
            harness.rt.process_due()
            row = harness.rt.store.get_outbound(event_id)
            self.assertEqual(row["status"], "pending")
            self.assertEqual(row["attempts"], 1)
            self.assertEqual(row["last_error"], "unexpected_status_201")
            for _ in range(3):
                harness.rt.process_due(now=self.FAR_FUTURE)
            row = harness.rt.store.get_outbound(event_id)
            self.assertEqual(row["status"], "sent")
            self.assertEqual(len(peer.server.requests), 4)

    def test_receipt_task_rejects_non_200_2xx_and_stays_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            peer = StubPeer(behaviors=["202", "stored"])
            harness = WorkerHarness(tmp, {"org-a": peer})
            self.addCleanup(harness.stop)
            event_id = "cccc0000-0000-4000-8000-00000000f402"
            harness.store.insert_event("bob", "carol", "message", {"text": "x"},
                                       event_id=event_id)
            harness.rt.store.ack_with_receipt_intent(
                event_id=event_id, agent_id="carol", ack_type="received",
                detail=None, receipt_agent="carol@org-b", origin="org-a",
                origin_event_sig_hash="a" * 64, issuer="org-b",
                issuer_key_id="ob-2026-10")
            harness.rt.process_due()
            row = harness.rt.store.get_receipt_out(event_id, "carol@org-b",
                                                   "received")
            self.assertEqual(row["status"], "pending")
            self.assertEqual(row["attempts"], 1)
            self.assertEqual(row["last_error"], "unexpected_status_202")
            harness.rt.process_due(now=self.FAR_FUTURE)
            row = harness.rt.store.get_receipt_out(event_id, "carol@org-b",
                                                   "received")
            self.assertEqual(row["status"], "sent")
            self.assertEqual(len(peer.server.requests), 2)

    def test_200_control_still_sends(self):
        with tempfile.TemporaryDirectory() as tmp:
            peer = StubPeer()
            harness = WorkerHarness(tmp, {"org-a": peer})
            self.addCleanup(harness.stop)
            event_id = "cccc0000-0000-4000-8000-00000000f403"
            harness.enqueue(event_id, "org-a", "alice@org-a")
            harness.rt.process_due()
            self.assertEqual(harness.rt.store.get_outbound(event_id)["status"],
                             "sent")
            self.assertEqual(len(peer.server.requests), 1)


# ---------------------------------------------------------------------------
# F6: notification delivery is real.  Push hints mark sent only on a
# confirmed enqueue; the durable pull/ack path covers offline agents;
# operator rows (agent IS NULL) are never push-marked; a crash between push
# and mark redelivers (at-least-once) while the logical row stays unique.
# ---------------------------------------------------------------------------

class NotificationDeliveryTest(unittest.TestCase):
    def _harness(self, tmp):
        harness = WorkerHarness(tmp, {"org-a": StubPeer()})
        self.addCleanup(harness.stop)
        return harness

    def _receipt_notification(self, harness, event_id, agent="alice"):
        """Mint a stable notification intent directly (the receipts-endpoint
        flow that creates these is covered by the round-2 suite)."""
        harness.store.insert_event("bob", agent, "message", {"text": "x"},
                                   event_id=event_id)
        status, notification = harness.rt.store.record_receipt_in(
            event_id=event_id, agent=f"{agent}@org-b", ack_type="received",
            issuer="org-a", issuer_key_id="org-a-kid",
            signed_json='{"kind": "federation.receipt.v0"}', sig="b" * 64,
            notify_agent=agent,
            notify_detail={"origin": "org-a", "target": f"{agent}@org-b",
                           "origin_event_sig_hash": "c" * 64})
        self.assertEqual(status, "stored")
        return notification

    def test_offline_agent_stays_pending_pull_then_ack_delivers(self):
        with tempfile.TemporaryDirectory() as tmp:
            harness = self._harness(tmp)
            notification = self._receipt_notification(
                harness, "cccc0000-0000-4000-8000-00000000f601")
            intent = notification["intent_id"]
            harness.rt.process_due()  # nobody subscribed: the push is a no-op
            pending = harness.rt.store.notification_hints_for("alice")
            self.assertEqual([r["intent_id"] for r in pending], [intent])
            self.assertEqual(pending[0]["hint_sent"], 0)  # pull does not mutate
            self.assertEqual(
                harness.rt.store.ack_notification_hints([intent], "alice"), 1)
            self.assertEqual(harness.rt.store.notification_hints_for("alice"), [])
            self.assertEqual(harness.rt.store.conn.execute(
                "SELECT count(*) n FROM federation_notifications").fetchone()["n"], 1)

    def test_live_push_marks_hint_but_pull_still_lists_until_ack(self):
        # r5 F6: a marked hint is NOT a delivery — the row stays pullable
        # (unacked) until an authenticated consumer ACK completes it.
        with tempfile.TemporaryDirectory() as tmp:
            harness = self._harness(tmp)
            notification = self._receipt_notification(
                harness, "cccc0000-0000-4000-8000-00000000f602")
            intent = notification["intent_id"]
            q = harness.wake.subscribe("alice")
            harness.rt.process_due()
            self.assertEqual(q.qsize(), 1)
            self.assertEqual(harness.rt.store.conn.execute(
                "SELECT hint_sent FROM federation_notifications WHERE intent_id=?",
                (intent,)).fetchone()["hint_sent"], 1)
            self.assertEqual([r["intent_id"] for r in
                              harness.rt.store.notification_hints_for("alice")],
                             [intent])
            self.assertEqual(
                harness.rt.store.ack_notification_hints([intent], "alice"), 1)
            self.assertEqual(harness.rt.store.notification_hints_for("alice"), [])

    def test_reconnect_before_consume_still_recoverable_via_pull(self):
        # r5 F6 hole fixed: subscribe -> hint pushed AND marked -> the agent
        # reconnects (the stale SSE lane is replaced by an empty queue) ->
        # before the fix the queued-but-unconsumed notification was gone.
        with tempfile.TemporaryDirectory() as tmp:
            harness = self._harness(tmp)
            notification = self._receipt_notification(
                harness, "cccc0000-0000-4000-8000-00000000f611")
            intent = notification["intent_id"]
            first = harness.wake.subscribe("alice")
            harness.rt.process_due()
            self.assertEqual(first.qsize(), 1)
            harness.wake.unsubscribe("alice", first)
            second = harness.wake.subscribe("alice")  # reconnect: new queue
            harness.rt.process_due()  # no re-hint (marked), nothing lost
            self.assertEqual(second.qsize(), 0)
            pending = harness.rt.store.notification_hints_for("alice")
            self.assertEqual([r["intent_id"] for r in pending], [intent])
            self.assertEqual(
                harness.rt.store.ack_notification_hints([intent], "alice"), 1)
            self.assertEqual(harness.rt.store.notification_hints_for("alice"), [])
            self.assertEqual(harness.rt.store.conn.execute(
                "SELECT count(*) n FROM federation_notifications").fetchone()["n"], 1)

    def test_restart_after_enqueue_and_mark_row_still_pullable(self):
        # r5 F6 hole fixed: process death after the push+mark left the
        # notification unreachable; now the durable row survives the restart
        # and pull lists it until the consumer ACKs.
        with tempfile.TemporaryDirectory() as tmp:
            harness = self._harness(tmp)
            notification = self._receipt_notification(
                harness, "cccc0000-0000-4000-8000-00000000f612")
            intent = notification["intent_id"]
            q = harness.wake.subscribe("alice")
            harness.rt.process_due()
            self.assertEqual(q.qsize(), 1)
            restarted = WorkerHarness(tmp, {"org-a": StubPeer()})
            self.addCleanup(restarted.stop)
            # simulated restart: fresh runtime/store on the SAME database,
            # no subscriber connected yet
            pending = restarted.rt.store.notification_hints_for("alice")
            self.assertEqual([r["intent_id"] for r in pending], [intent])
            self.assertEqual(
                restarted.rt.store.ack_notification_hints([intent], "alice"), 1)
            self.assertEqual(
                restarted.rt.store.notification_hints_for("alice"), [])

    def test_crash_after_mark_window_recovers_and_stays_unique(self):
        # The existing crash test covers BEFORE mark; this covers the window
        # AFTER mark: the push succeeded and the hint was marked, but the
        # consumer never saw it (queue replaced) — redelivery through pull
        # must still be possible and the logical row must stay unique.
        with tempfile.TemporaryDirectory() as tmp:
            harness = self._harness(tmp)
            notification = self._receipt_notification(
                harness, "cccc0000-0000-4000-8000-00000000f613")
            intent = notification["intent_id"]
            q = harness.wake.subscribe("alice")
            harness.rt.process_due()  # pushed and marked
            self.assertEqual(q.qsize(), 1)
            self.assertEqual(dict(harness.rt.store.conn.execute(
                "SELECT hint_sent, acked FROM federation_notifications "
                "WHERE intent_id=?", (intent,)).fetchone()),
                {"hint_sent": 1, "acked": 0})
            harness.wake.unsubscribe("alice", q)  # consumer never consumed
            # both delivery paths are checked after the crash window
            self.assertEqual([r["intent_id"] for r in
                              harness.rt.store.notification_hints_for("alice")],
                             [intent])
            second = harness.wake.subscribe("alice")
            harness.rt.process_due()  # marked: no duplicate push...
            self.assertEqual(second.qsize(), 0)
            # ...but an unmarked retry path (hint state lost, e.g. pre-mark
            # crash) redelivers under the SAME stable intent id, no new row
            harness.rt.store.conn.execute(
                "UPDATE federation_notifications SET hint_sent=0 WHERE intent_id=?",
                (intent,))
            harness.rt.process_due()
            self.assertEqual(second.qsize(), 1)
            self.assertEqual(harness.rt.store.conn.execute(
                "SELECT count(*) n FROM federation_notifications").fetchone()["n"], 1)

    def test_operator_backlog_does_not_starve_agent_push_hints(self):
        # r5 #5: 100+ never-pushable operator rows used to fill the push
        # scan's global LIMIT window and starve every agent hint behind
        # them (the reviewer's repro).  Operator rows are excluded from the push
        # scan; the keyset walk reaches the agent row within one cycle.
        with tempfile.TemporaryDirectory() as tmp:
            harness = self._harness(tmp)
            conn = harness.rt.store.conn
            for i in range(150):
                conn.execute(
                    "INSERT OR IGNORE INTO federation_notifications "
                    "(intent_id, kind, agent, event_id, detail_json, "
                    " hint_sent, acked, created_at) "
                    "VALUES (?,?,?,?,?,0,0,?)",
                    (f"00000000-0000-4000-8000-{i:012d}", "receipt_send_failed",
                     None, None, "{}",
                     f"2026-10-24T00:{i // 60:02d}:{i % 60:02d}Z"))
            notification = self._receipt_notification(
                harness, "cccc0000-0000-4000-8000-00000000f615")
            intent = notification["intent_id"]  # created NOW: behind all 150
            # the push scan itself carries no operator rows: only the agent
            # row is scannable despite the 150 older operator rows
            scan_ids = [r["intent_id"] for r in
                        harness.rt.store.undelivered_notification_hints()]
            self.assertEqual(scan_ids, [intent])
            q = harness.wake.subscribe("alice")
            self.assertEqual(harness.rt.hint_notifications(), 1)
            self.assertEqual(q.qsize(), 1)   # reached within one cycle
            # agent row marked (still pullable until ack, r5 F6); the 150
            # operator rows are untouched and stay pull-listed
            self.assertEqual(harness.rt.store.conn.execute(
                "SELECT hint_sent, acked FROM federation_notifications "
                "WHERE intent_id=?", (intent,)).fetchone()["hint_sent"], 1)
            self.assertEqual(len(harness.rt.store.operator_notification_hints(limit=200)),
                             150)

    def test_repeat_ack_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            harness = self._harness(tmp)
            notification = self._receipt_notification(
                harness, "cccc0000-0000-4000-8000-00000000f614")
            intent = notification["intent_id"]
            self.assertEqual(
                harness.rt.store.ack_notification_hints([intent], "alice"), 1)
            self.assertEqual(
                harness.rt.store.ack_notification_hints([intent], "alice"), 0)
            self.assertEqual(
                harness.rt.store.ack_notification_hints([intent], "alice"), 0)
            self.assertEqual(harness.rt.store.notification_hints_for("alice"), [])
            # the row still exists exactly once, durably acked
            self.assertEqual(dict(harness.rt.store.conn.execute(
                "SELECT count(*) n, max(acked) a FROM federation_notifications"
            ).fetchone()), {"n": 1, "a": 1})
            # an acked row is never re-hinted by the push scan
            harness.rt.process_due()
            self.assertEqual(harness.rt.store.conn.execute(
                "SELECT hint_sent FROM federation_notifications WHERE intent_id=?",
                (intent,)).fetchone()["hint_sent"], 0)

    def test_queue_overflow_is_never_a_delivery(self):
        with tempfile.TemporaryDirectory() as tmp:
            harness = self._harness(tmp)
            notification = self._receipt_notification(
                harness, "cccc0000-0000-4000-8000-00000000f603")
            intent = notification["intent_id"]
            q = harness.wake.subscribe("alice")
            for i in range(1024):
                q.put_nowait({"kind": "filler", "i": i})
            harness.rt.process_due()
            self.assertEqual(harness.rt.store.notification_hints_for("alice")[0]
                             ["intent_id"], intent)
            self.assertEqual(q.qsize(), 1024)  # hint dropped, not counted sent

    def test_wake_exception_is_isolated_and_recovery_delivers(self):
        with tempfile.TemporaryDirectory() as tmp:
            harness = self._harness(tmp)
            notification = self._receipt_notification(
                harness, "cccc0000-0000-4000-8000-00000000f604")
            intent = notification["intent_id"]

            class Boom:
                def notify(self, agent, item):
                    raise RuntimeError("wake down")

            harness.rt._wake = Boom()
            harness.rt.process_due()  # guarded: no raise, row stays pending
            self.assertEqual(harness.rt.store.notification_hints_for("alice")[0]
                             ["intent_id"], intent)
            q = harness.wake.subscribe("alice")
            harness.rt._wake = harness.wake
            harness.rt.process_due()
            # r5 F6: the recovered push marks the hint; the row stays
            # pullable until the consumer ACKs
            self.assertEqual(harness.rt.store.conn.execute(
                "SELECT hint_sent FROM federation_notifications WHERE intent_id=?",
                (intent,)).fetchone()["hint_sent"], 1)
            self.assertEqual([r["intent_id"] for r in
                              harness.rt.store.notification_hints_for("alice")],
                             [intent])
            self.assertEqual(
                harness.rt.store.ack_notification_hints([intent], "alice"), 1)
            self.assertEqual(harness.rt.store.notification_hints_for("alice"), [])
            self.assertEqual(q.qsize(), 1)

    def test_operator_rows_never_push_marked_and_ack_is_scoped(self):
        with tempfile.TemporaryDirectory() as tmp:
            harness = self._harness(tmp)
            # an operator failure notification arises from a REAL permanent
            # receipt-send failure: create the pending task first
            event_id = "cccc0000-0000-4000-8000-00000000f605"
            harness.store.insert_event("bob", "alice", "message", {"text": "x"},
                                       event_id=event_id)
            harness.rt.store.ack_with_receipt_intent(
                event_id=event_id, agent_id="alice", ack_type="received",
                detail=None, receipt_agent="alice@org-b", origin="org-a",
                origin_event_sig_hash="d" * 64, issuer="org-b",
                issuer_key_id="ob-2026-10")
            notification = harness.rt.store.fail_receipt_permanent(
                event_id, "alice@org-b", "received", "http_403")
            self.assertIsNotNone(notification)
            self.assertIsNone(notification["agent"])
            intent = notification["intent_id"]
            q = harness.wake.subscribe("alice")
            for _ in range(3):
                harness.rt.process_due()
            operator = harness.rt.store.operator_notification_hints()
            self.assertEqual([r["intent_id"] for r in operator], [intent])
            self.assertEqual(q.qsize(), 0)
            # an agent ack cannot touch operator rows
            self.assertEqual(
                harness.rt.store.ack_notification_hints([intent], "alice"), 0)
            self.assertEqual(
                harness.rt.store.ack_notification_hints([intent], None), 1)
            self.assertEqual(harness.rt.store.operator_notification_hints(), [])

    def test_crash_between_push_and_mark_redelivers_with_unique_row(self):
        with tempfile.TemporaryDirectory() as tmp:
            harness = self._harness(tmp)
            notification = self._receipt_notification(
                harness, "cccc0000-0000-4000-8000-00000000f606")
            intent = notification["intent_id"]
            q = harness.wake.subscribe("alice")
            original = harness.rt.store.mark_notification_hint_sent
            calls = []

            def flaky(intent_id):
                calls.append(intent_id)
                if len(calls) == 1:
                    raise RuntimeError("crash after send before mark")
                original(intent_id)

            harness.rt.store.mark_notification_hint_sent = flaky
            harness.rt.process_due()  # push OK, mark crashed -> still pending
            self.assertEqual(harness.rt.store.notification_hints_for("alice")[0]
                             ["intent_id"], intent)
            harness.rt.process_due()  # at-least-once redelivery, then marked
            # r5 F6: marked hint, still pullable until the consumer ACKs
            self.assertEqual(harness.rt.store.conn.execute(
                "SELECT hint_sent FROM federation_notifications WHERE intent_id=?",
                (intent,)).fetchone()["hint_sent"], 1)
            self.assertEqual([r["intent_id"] for r in
                              harness.rt.store.notification_hints_for("alice")],
                             [intent])
            self.assertEqual(
                harness.rt.store.ack_notification_hints([intent], "alice"), 1)
            self.assertEqual(harness.rt.store.notification_hints_for("alice"), [])
            self.assertEqual(calls, [intent, intent])
            self.assertEqual(q.qsize(), 2)  # consumer dedupes by intent_id
            self.assertEqual(harness.rt.store.conn.execute(
                "SELECT count(*) n FROM federation_notifications").fetchone()["n"], 1)


class NotificationEndpointTest(unittest.TestCase):
    """F6: the durable pull/ack endpoints authenticate and scope correctly."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        peers = [{"family": "org-a", "key_id": "org-a-kid",
                  "public_key": _test_public_key(),
                  "inbox_url": "http://127.0.0.1:9/federation/inbox",
                  "receipts_url": "http://127.0.0.1:9/federation/receipts"}]
        peers_path = Path(self.tmp) / "federation_peers.json"
        peers_path.write_text(json.dumps(peers))
        ident = Path(self.tmp) / "federation_identity.json"
        seed = base64.urlsafe_b64encode(b"\x01" * 32).rstrip(b"=").decode()
        ident.write_text(json.dumps({"family": "org-b", "key_id": "ob-2026-10",
                                     "seed": seed}))
        os.chmod(ident, 0o600)
        self.store = AtalkStore(Path(self.tmp) / "atalk.db")
        self.alice_token = self.store.add_peer("alice", role="agent")
        self.oper_token = self.store.add_peer("oper", role="operator")
        config = FederationConfig(enabled=True, peers_path=str(peers_path),
                                  identity_path=str(ident),
                                  rate_conn_per_min=10 ** 6,
                                  rate_family_per_min=10 ** 6,
                                  worker_interval=0.05, http_timeout=2.0,
                                  backoff_base=0.05, backoff_max=0.5,
                                  allow_insecure_loopback=True)
        self.server = AtalkHTTPServer(("127.0.0.1", 0), self.store, WakeHub(),
                                      federation_config=config)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        fed_store = self.server.federation.store
        eid = "cccc0000-0000-4000-8000-00000000f607"
        self.store.insert_event("alice", "alice", "message", {"text": "x"},
                                event_id=eid)
        _status, self.agent_notification = fed_store.record_receipt_in(
            event_id=eid, agent="alice@org-b", ack_type="received",
            issuer="org-a", issuer_key_id="org-a-kid",
            signed_json='{"kind": "federation.receipt.v0"}', sig="b" * 64,
            notify_agent="alice",
            notify_detail={"origin": "org-a", "target": "alice@org-b",
                           "origin_event_sig_hash": "c" * 64})
        # an operator failure notification arises from a REAL permanent
        # receipt-send failure: create the pending task first
        eid_op = "cccc0000-0000-4000-8000-00000000f608"
        self.store.insert_event("alice", "alice", "message", {"text": "x"},
                                event_id=eid_op)
        fed_store.ack_with_receipt_intent(
            event_id=eid_op, agent_id="alice", ack_type="received", detail=None,
            receipt_agent="alice@org-b", origin="org-a",
            origin_event_sig_hash="d" * 64, issuer="org-b",
            issuer_key_id="ob-2026-10")
        self.operator_notification = fed_store.fail_receipt_permanent(
            eid_op, "alice@org-b", "received", "http_403")
        self.assertIsNotNone(self.operator_notification)

    def _call(self, method, path, obj=None, token=None):
        raw = None if obj is None else json.dumps(obj).encode()
        req = urllib.request.Request(self.base + path, data=raw, method=method)
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_agent_pull_lists_only_own_pending_rows(self):
        status, body = self._call("GET", "/federation/notifications?agent=alice",
                                  token=self.alice_token)
        self.assertEqual(status, 200)
        self.assertEqual([r["intent_id"] for r in body],
                         [self.agent_notification["intent_id"]])
        self.assertEqual(body[0]["kind"], "receipt_received")
        # the operator listing needs a full-scope peer and shows operator rows
        status, body = self._call("GET", "/federation/notifications?peer=oper",
                                  token=self.oper_token)
        self.assertEqual(status, 200)
        self.assertEqual([r["intent_id"] for r in body],
                         [self.operator_notification["intent_id"]])
        # the operator listing requires a FULL-scope token: alice's primary
        # token is full-scope (every primary token is), but a notify-scope
        # device token is rejected
        limited = self.store.add_device_token("alice", "limited", scope="notify",
                                              actor="alice")["token"]
        status, body = self._call("GET", "/federation/notifications?peer=alice",
                                  token=limited)
        self.assertEqual((status, body), (403, {"error": "full peer token required"}))
        status, body = self._call("GET", "/federation/notifications",
                                  token=self.alice_token)
        self.assertEqual(status, 400)

    def test_agent_pull_requires_own_token(self):
        status, body = self._call("GET", "/federation/notifications?agent=alice",
                                  token=self.oper_token)
        self.assertEqual((status, body), (403, {"error": "agent token rejected"}))

    def test_full_scope_peer_is_the_documented_operator_boundary(self):
        # r5 #5: DOCUMENTED trust boundary — ANY full-scope peer token lists
        # and ACKs operator notifications.  This is the full-scope token's
        # established capability (every primary peer token is full-scope),
        # NOT an operator-role authorization; see atalk/federation/README.md
        # ("Operator-notification trust boundary").  Pinned so a change
        # cannot happen silently.
        fed_store = self.server.federation.store
        eid_op2 = "cccc0000-0000-4000-8000-00000000f609"
        self.store.insert_event("alice", "alice", "message", {"text": "x"},
                                event_id=eid_op2)
        fed_store.ack_with_receipt_intent(
            event_id=eid_op2, agent_id="alice", ack_type="received", detail=None,
            receipt_agent="alice@org-b", origin="org-a",
            origin_event_sig_hash="e" * 64, issuer="org-b",
            issuer_key_id="ob-2026-10")
        notification = fed_store.fail_receipt_permanent(
            eid_op2, "alice@org-b", "received", "http_403")
        self.assertIsNotNone(notification)
        status, body = self._call("GET", "/federation/notifications?peer=alice",
                                  token=self.alice_token)
        self.assertEqual(status, 200)
        self.assertIn(notification["intent_id"], [r["intent_id"] for r in body])
        status, body = self._call(
            "POST", "/federation/notifications/ack",
            {"peer": "alice", "intent_ids": [notification["intent_id"]]},
            token=self.alice_token)
        self.assertEqual((status, body), (200, {"acked": 1}))
        self.assertNotIn(notification["intent_id"],
                         [r["intent_id"] for r in
                          fed_store.operator_notification_hints()])

    def test_ack_scoping_over_http(self):
        status, body = self._call(
            "POST", "/federation/notifications/ack",
            {"agent": "alice", "intent_ids": [self.agent_notification["intent_id"]]},
            token=self.alice_token)
        self.assertEqual((status, body), (200, {"acked": 1}))
        # alice's ack cannot mark the operator row
        status, body = self._call(
            "POST", "/federation/notifications/ack",
            {"agent": "alice", "intent_ids": [self.operator_notification["intent_id"]]},
            token=self.alice_token)
        self.assertEqual((status, body), (200, {"acked": 0}))
        # operator ack via a full-scope peer touches only operator rows
        status, body = self._call(
            "POST", "/federation/notifications/ack",
            {"peer": "oper", "intent_ids": [self.operator_notification["intent_id"]]},
            token=self.oper_token)
        self.assertEqual((status, body), (200, {"acked": 1}))
        # malformed body -> 400; unauthenticated -> 403
        status, _body = self._call(
            "POST", "/federation/notifications/ack",
            {"agent": "alice", "intent_ids": "not-a-list"}, token=self.alice_token)
        self.assertEqual(status, 400)
        status, body = self._call(
            "POST", "/federation/notifications/ack",
            {"agent": "alice", "intent_ids": ["x"]})
        self.assertEqual((status, body), (403, {"error": "agent token rejected"}))


# ---------------------------------------------------------------------------
# F7: HTTP error responses are classified WITHOUT reading the (possibly
# unbounded) body; the response object is closed and the worker moves on.
# ---------------------------------------------------------------------------

class _RecordingFP:
    def __init__(self):
        self.read_calls = []
        self.closed = False

    def read(self, *args):
        self.read_calls.append(args)
        raise AssertionError("error body must not be read (r4 F7)")

    def close(self):
        self.closed = True


class ErrorBodyBoundedTest(unittest.TestCase):
    def _fake_error(self, code, fp=None, headers=None):
        return urllib.error.HTTPError(
            url="https://peer.example/federation/inbox", code=code, msg="nope",
            hdrs=headers if headers is not None else email.message.Message(),
            fp=fp)

    @staticmethod
    def _opener_raising(error):
        opener = mock.Mock()
        opener.open.side_effect = error
        return opener

    def test_error_body_never_read_and_response_closed(self):
        for code, want_kind, want_error in (
                (403, "permanent", "http_403"),
                (429, "retry", "http_429"),
                (503, "retry", "http_503"),
                (302, "permanent", "redirect_not_followed")):
            with self.subTest(code=code):
                fp = _RecordingFP()
                with mock.patch.object(runtime, "_OPENER",
                                       self._opener_raising(
                                           self._fake_error(code, fp=fp))):
                    outcome = runtime.send_envelope(
                        "https://peer.example/federation/inbox", b"{}", 5.0)
                self.assertEqual(outcome.kind, want_kind)
                self.assertEqual(outcome.error, want_error)
                self.assertEqual(fp.read_calls, [])
                self.assertTrue(fp.closed)

    def test_429_retry_after_still_honored_without_reading_body(self):
        headers = email.message.Message()
        headers["Retry-After"] = "7"
        fp = _RecordingFP()
        with mock.patch.object(runtime, "_OPENER", self._opener_raising(
                self._fake_error(429, fp=fp, headers=headers))):
            outcome = runtime.send_envelope(
                "https://peer.example/federation/inbox", b"{}", 5.0)
        self.assertEqual(outcome.kind, "retry")
        self.assertEqual(outcome.retry_after, 7.0)
        self.assertEqual(fp.read_calls, [])
        self.assertTrue(fp.closed)

    def test_big_error_responses_classified_and_next_tasks_proceed(self):
        with tempfile.TemporaryDirectory() as tmp:
            peer = StubPeer(behaviors=["big403", "big503", "stored"])
            harness = WorkerHarness(tmp, {"org-a": peer})
            self.addCleanup(harness.stop)
            first = "cccc0000-0000-4000-8000-00000000f701"
            second = "cccc0000-0000-4000-8000-00000000f702"
            harness.enqueue(first, "org-a", "alice@org-a")
            harness.enqueue(second, "org-a", "alice@org-a")
            harness.rt.process_due()  # first: big403 permanent; second: big503 retry
            self.assertEqual(harness.rt.store.get_outbound(first)["status"],
                             "failed_permanent")
            self.assertEqual(harness.rt.store.get_outbound(second)["status"],
                             "pending")
            harness.rt.process_due(now="9999-12-31T23:59:59Z")  # second: stored
            self.assertEqual(harness.rt.store.get_outbound(second)["status"],
                             "sent")
            self.assertEqual(len(peer.server.requests), 3)


# ---------------------------------------------------------------------------
# r5 #3: a VALID Retry-After is honored IN FULL (spec 8).  The old
# min(3600, ...) shortened '7200' to 3600 and re-contacted the peer before
# it was allowed to; the schedule is persisted and survives a restart, and
# an unrepresentable value is honored at the representable ceiling, never
# sent early.
# ---------------------------------------------------------------------------

class RetryAfterHonorTest(unittest.TestCase):
    def test_parse_seconds_honored_in_full(self):
        self.assertEqual(runtime._parse_retry_after("7200"), 7200.0)
        self.assertEqual(runtime._parse_retry_after("7"), 7.0)
        self.assertEqual(runtime._parse_retry_after("0"), 0.0)

    def test_parse_future_http_date_honored_in_full(self):
        value = email.utils.formatdate(time.time() + 7200, usegmt=True)
        parsed = runtime._parse_retry_after(value)
        self.assertIsNotNone(parsed)
        self.assertGreater(parsed, 7100.0)
        self.assertLessEqual(parsed, 7200.0)

    def test_parse_invalid_is_none(self):
        # invalid per the HTTP grammar (delta-seconds = 1*DIGIT): ordinary
        # backoff, never a fabricated short delay
        for bad in ("", None, "abc", "+5", "1e5", "nan", "inf", "-5"):
            self.assertIsNone(runtime._parse_retry_after(bad), bad)
        self.assertEqual(runtime._parse_retry_after(
            email.utils.formatdate(time.time() - 100, usegmt=True)), 0.0)

    def test_backoff_keeps_full_value_and_ceils_unrepresentable(self):
        rt = runtime.FederationRuntime.__new__(runtime.FederationRuntime)
        target = rt._backoff(1, 7200.0)
        delta = (datetime.fromisoformat(target.replace("Z", "+00:00"))
                 - datetime.now(timezone.utc)).total_seconds()
        self.assertGreaterEqual(delta, 7199)      # NOT shortened to 3600
        # r6 #2: deadlines now CEIL to the persisted whole second, which can
        # add up to one second (never subtract — a deadline is never early)
        self.assertLessEqual(delta, 7201)
        ceiling = datetime.fromisoformat(
            rt._backoff(1, 1e30).replace("Z", "+00:00"))
        self.assertGreater(ceiling,
                           datetime.now(timezone.utc) + timedelta(days=365 * 100))


class RetryAfterScheduleTest(unittest.TestCase):
    def _iso_at(self, epoch: float) -> str:
        return datetime.fromtimestamp(epoch, timezone.utc).isoformat(
            timespec="seconds").replace("+00:00", "Z")

    def _scheduled_epoch(self, text: str) -> float:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()

    def test_7200_delta_persisted_not_sent_early_survives_restart(self):
        event_id = "cccc0000-0000-4000-8000-00000000a301"
        with tempfile.TemporaryDirectory() as tmp:
            peer = StubPeer(behaviors=["retryafter:7200", "stored"])
            harness = WorkerHarness(tmp, {"org-a": peer})
            self.addCleanup(harness.stop)
            harness.enqueue(event_id, "org-a", "alice@org-a")
            before = time.time()
            harness.rt.process_due()
            row = harness.rt.store.get_outbound(event_id)
            self.assertEqual(row["status"], "pending")
            self.assertEqual(row["last_error"], "http_429")
            scheduled = self._scheduled_epoch(row["next_retry_at"]) - before
            self.assertGreaterEqual(scheduled, 7100)   # honored IN FULL
            # r6 #2: ceil-to-second can add up to one second, never subtract
            self.assertLessEqual(scheduled, 7201)
            # not due yet: nothing sent, even after a restart against the
            # same database (the schedule lives in the store)
            restarted = WorkerHarness(tmp, {"org-a": peer})
            self.addCleanup(restarted.stop)
            restarted.rt.process_due(now=self._iso_at(before + 3600))
            self.assertEqual(len(peer.server.requests), 1)
            # at/after the honored schedule the retry goes out and succeeds
            restarted.rt.process_due(now="9999-12-31T23:59:59Z")
            self.assertEqual(
                restarted.rt.store.get_outbound(event_id)["status"], "sent")
            self.assertEqual(len(peer.server.requests), 2)

    def test_future_http_date_persisted_and_honored(self):
        event_id = "cccc0000-0000-4000-8000-00000000a302"
        with tempfile.TemporaryDirectory() as tmp:
            peer = StubPeer(behaviors=["retryafter:@7200", "stored"])
            harness = WorkerHarness(tmp, {"org-a": peer})
            self.addCleanup(harness.stop)
            harness.enqueue(event_id, "org-a", "alice@org-a")
            before = time.time()
            harness.rt.process_due()
            row = harness.rt.store.get_outbound(event_id)
            self.assertEqual(row["status"], "pending")
            scheduled = self._scheduled_epoch(row["next_retry_at"]) - before
            self.assertGreaterEqual(scheduled, 7100)
            # r6 #2: ceil-to-second can add up to one second, never subtract
            self.assertLessEqual(scheduled, 7201)
            harness.rt.process_due(now=self._iso_at(before + 3600))
            self.assertEqual(len(peer.server.requests), 1)   # not early
            harness.rt.process_due(now="9999-12-31T23:59:59Z")
            self.assertEqual(harness.rt.store.get_outbound(event_id)["status"],
                             "sent")


# ---------------------------------------------------------------------------
# F8: identity activation follows §4.7.1 exactly — mode must be 0600, the
# identity JSON is parsed strictly and bounded, and every malformed admin
# file collapses to federation-off with the ordinary service still serving.
# ---------------------------------------------------------------------------

def _identity_doc(seed=b"\x01" * 32, family="org-b", key_id="ob-2026-10"):
    return {"family": family, "key_id": key_id,
            "seed": base64.urlsafe_b64encode(seed).rstrip(b"=").decode()}


class IdentityActivationTest(unittest.TestCase):
    def _write(self, tmp, text, mode):
        path = Path(tmp) / "federation_identity.json"
        if path.exists():
            os.chmod(path, 0o600)  # the previous mode may forbid overwriting
        path.write_text(text)
        os.chmod(path, mode)
        return path

    def test_exact_mode_required(self):
        doc = json.dumps(_identity_doc())
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(
                runtime.load_identity(self._write(tmp, doc, 0o600)).family,
                "org-b")
            for mode in (0o700, 0o400, 0o644, 0o666, 0o000):
                with self.subTest(mode=oct(mode)):
                    with self.assertRaises(FederationError) as caught:
                        runtime.load_identity(self._write(tmp, doc, mode))
                    self.assertEqual(caught.exception.category,
                                     "identity_permissions")
                    self.assertEqual(caught.exception.layer, "registry")

    def test_identity_parse_failures_classified(self):
        good_seed = base64.urlsafe_b64encode(b"\x01" * 32).rstrip(b"=").decode()
        cases = {
            "deep": '{"seed": ' + '{"a":' * 3000 + '"y"' + '}' * 3000 + '}',
            "duplicate": '{"family": "a", "family": "b"}',
            "number": '{"seed": 5}',
        }
        for name, text in cases.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(FederationError) as caught:
                    runtime.load_identity(self._write(tmp, text, 0o600))
                self.assertEqual(caught.exception.layer, "registry")
                self.assertIn(caught.exception.category,
                              ("nesting_too_deep", "duplicate_key", "value_domain"))

    def _server_with_identity(self, tmp, identity_text, mode=0o600):
        peers = Path(tmp) / "federation_peers.json"
        peers.write_text("[]")
        ident = Path(tmp) / "federation_identity.json"
        ident.write_text(identity_text)
        os.chmod(ident, mode)
        store = AtalkStore(Path(tmp) / "atalk.db")
        config = FederationConfig(enabled=True, peers_path=str(peers),
                                  identity_path=str(ident))
        return AtalkHTTPServer(("127.0.0.1", 0), store, WakeHub(),
                               federation_config=config)

    def test_bad_identity_leaves_ordinary_service_available(self):
        good_seed = base64.urlsafe_b64encode(b"\x01" * 32).rstrip(b"=").decode()
        cases = {
            "mode0700": (json.dumps(_identity_doc()), 0o700),
            "deep_doc": ('{"family": "org-b", "key_id": "ob-2026-10", '
                         '"seed": "' + good_seed + '", "x":' + '{"a":' * 3000
                         + '"y"' + '}' * 3000 + '}', 0o600),
            "duplicate_keys": ('{"family": "org-b", "family": "org-b", '
                               '"key_id": "ob-2026-10", "seed": "'
                               + good_seed + '"}', 0o600),
            "number_value": ('{"family": "org-b", "key_id": "ob-2026-10", '
                             '"seed": 5}', 0o600),
        }
        for name, (text, mode) in cases.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory() as tmp:
                server = self._server_with_identity(tmp, text, mode)
                self.addCleanup(server.server_close)
                self.addCleanup(server.shutdown)
                # malformed admin file: federation off, ordinary service up
                self.assertIsNone(server.federation, name)
                threading.Thread(target=server.serve_forever, daemon=True).start()
                base = f"http://127.0.0.1:{server.server_address[1]}"
                status, _ctype, _raw = support.http_raw("GET", f"{base}/health")
                self.assertEqual(status, 200, name)
                status, _ctype, raw = support.http_raw("POST",
                                                       f"{base}/federation/inbox",
                                                       raw=b'{"x": "1"}')
                self.assertEqual(json.loads(raw), {"error": "not found"}, name)


if __name__ == "__main__":
    unittest.main()
