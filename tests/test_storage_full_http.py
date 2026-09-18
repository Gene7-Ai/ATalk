import errno
import json
import os
import sqlite3
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from unittest import mock

from atalk.core import AtalkStore
from atalk.server import AtalkHTTPServer, MessageAcl, WakeHub


class ToggleFullStore:
    def __init__(self, inner):
        self.inner = inner
        self.failure = None

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def insert_event(self, *args, **kwargs):
        if self.failure == "full":
            exc = sqlite3.OperationalError("database or disk is full")
            exc.sqlite_errorcode = sqlite3.SQLITE_FULL
            raise exc
        if self.failure == "ioerr":
            exc = sqlite3.OperationalError("disk I/O error")
            exc.sqlite_errorcode = sqlite3.SQLITE_IOERR_WRITE
            raise exc
        return self.inner.insert_event(*args, **kwargs)


class StorageFullHttpTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        inner = AtalkStore(os.path.join(self.tmp.name, "atalk.db"))
        self.alice_token = inner.add_peer("alice", role="agent")
        inner.add_peer("bob", role="agent")
        self.store = ToggleFullStore(inner)
        self.server = AtalkHTTPServer(("127.0.0.1", 0), self.store, WakeHub())
        self.server.message_acl = MessageAcl(path=os.path.join(self.tmp.name, "missing-acl.json"))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def call(self, method, path, body=None, token=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def post_event(self, event_id):
        return self.call(
            "POST",
            "/events",
            {
                "source": "alice",
                "target": "bob",
                "type": "message",
                "event_id": event_id,
                "payload": {"text": "hello"},
            },
            self.alice_token,
        )

    def test_storage_full_returns_507_and_recovers_after_real_write(self):
        self.store.failure = "full"
        status, body = self.post_event("full-1")
        self.assertEqual(status, 507)
        self.assertEqual(body["error"], "storage_full")
        self.assertTrue(body["retryable"])
        self.assertEqual(self.store.inner.list_events(target="bob", state="all"), [])
        counter = self.store.inner.conn.execute(
            "SELECT last_seq FROM source_counters WHERE source='alice'"
        ).fetchone()
        self.assertIsNone(counter)

        status, health = self.call("GET", "/health")
        self.assertEqual(status, 200)
        self.assertFalse(health["ok"])
        self.assertEqual(health["status"], "degraded")
        self.assertEqual(health["storage"]["error"], "storage_full")

        status, readiness = self.call("GET", "/readiness")
        self.assertEqual(status, 503)
        self.assertFalse(readiness["ready"])
        self.assertEqual(readiness["storage"]["error"], "storage_full")

        self.store.failure = None
        status, event = self.post_event("recovered-1")
        self.assertEqual(status, 201)
        self.assertEqual(event["seq"], 1)

        status, readiness = self.call("GET", "/readiness")
        self.assertEqual(status, 200)
        self.assertTrue(readiness["ready"])
        self.assertTrue(readiness["storage"]["ok"])

    def test_idempotent_retry_does_not_clear_storage_full(self):
        status, _ = self.post_event("existing-1")
        self.assertEqual(status, 201)
        self.server.mark_storage_full()

        status, _ = self.post_event("existing-1")
        self.assertEqual(status, 201)
        status, readiness = self.call("GET", "/readiness")
        self.assertEqual(status, 503)
        self.assertFalse(readiness["ready"])

    def test_quota_ioerr_with_edquot_probe_maps_to_storage_full(self):
        self.store.failure = "ioerr"
        with mock.patch("atalk.server.probe_storage_errno", return_value=errno.EDQUOT):
            status, body = self.post_event("quota-1")
        self.assertEqual(status, 507)
        self.assertEqual(body["error"], "storage_full")
        status, readiness = self.call("GET", "/readiness")
        self.assertEqual(status, 503)
        self.assertEqual(readiness["storage"]["error"], "storage_full")

    def test_genuine_ioerr_is_not_misreported_as_capacity(self):
        self.store.failure = "ioerr"
        with mock.patch("atalk.server.probe_storage_errno", return_value=errno.EIO):
            status, body = self.post_event("ioerr-1")
        self.assertEqual(status, 503)
        self.assertEqual(body["error"], "storage_io_error")
        status, readiness = self.call("GET", "/readiness")
        self.assertEqual(status, 503)
        self.assertEqual(readiness["storage"]["error"], "storage_io_error")


if __name__ == "__main__":
    unittest.main()
