import json
import sqlite3
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from atalk.core import AtalkStore, legacy_token_id, now_iso, token_hash
from atalk.server import AtalkHTTPServer, WakeHub


class DeviceTokenTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "atalk.db"

    def tearDown(self):
        self.tmp.cleanup()

    def legacy_store(self):
        conn = sqlite3.connect(self.db)
        conn.executescript("""
        CREATE TABLE peers (peer_id TEXT PRIMARY KEY, token_hash TEXT, role TEXT,
          platform TEXT, endpoint TEXT, delivery_class TEXT NOT NULL DEFAULT 'normal',
          ack_timeout_sec INTEGER NOT NULL DEFAULT 180, created_at TEXT NOT NULL,
          revoked_at TEXT);
        CREATE TABLE peer_tokens (id INTEGER PRIMARY KEY AUTOINCREMENT,
          peer_id TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
          created_at TEXT NOT NULL, grace_until TEXT, revoked_at TEXT);
        """)
        conn.execute("INSERT INTO peers(peer_id,token_hash,created_at) VALUES(?,?,?)",
                     ("alice", token_hash("legacy"), now_iso()))
        conn.execute("INSERT INTO peer_tokens(peer_id,token_hash,created_at) VALUES(?,?,?)",
                     ("alice", token_hash("legacy"), now_iso()))
        conn.commit()
        conn.close()
        return AtalkStore(self.db)

    def test_legacy_migration_is_idempotent(self):
        store = self.legacy_store()
        expected = legacy_token_id("alice", token_hash("legacy"))
        self.assertTrue(store.validate_token("alice", "legacy"))
        self.assertEqual(expected, store.list_device_tokens("alice")[0]["token_id"])
        store._ensure_token_schema()
        self.assertEqual(1, len(store.list_device_tokens("alice")))
        self.assertTrue(store.validate_token("alice", "legacy"))

    def test_add_list_revoke_isolated_and_audited(self):
        store = AtalkStore(self.db)
        store.add_peer("alice", "primary-token")
        first = store.add_device_token("alice", "iphone", token="iphone-token")
        second = store.add_device_token("alice", "ipad", token="ipad-token", scope="notify")
        listed = {row["token_id"]: row for row in store.list_device_tokens("alice")}
        self.assertIn(first["token_id"], listed)
        self.assertNotIn("token", listed[first["token_id"]])
        self.assertEqual("notify", store.token_scope("alice", "ipad-token"))
        self.assertEqual("accepted", store.revoke_device_token(first["token_id"])["result"])
        self.assertFalse(store.validate_token("alice", "iphone-token"))
        self.assertTrue(store.validate_token("alice", "primary-token"))
        self.assertEqual("notify", store.token_scope("alice", "ipad-token"))
        self.assertEqual("already_revoked", store.revoke_device_token(first["token_id"])["result"])
        actions = [row[0] for row in store.conn.execute(
            "SELECT action FROM audit_log WHERE action LIKE 'device_token_%' ORDER BY id")]
        self.assertEqual(["device_token_add", "device_token_add",
                          "device_token_revoke", "device_token_revoke"], actions)

    def test_rotate_and_peer_add_do_not_revoke_device_tokens(self):
        store = AtalkStore(self.db)
        store.add_peer("alice", "primary-one")
        device = store.add_device_token("alice", "iphone", token="iphone-token")
        store.rotate_peer_token("alice", "primary-two", grace_seconds=0)
        self.assertTrue(store.validate_token("alice", "iphone-token"))
        self.assertIsNone(next(row for row in store.list_device_tokens("alice")
                               if row["token_id"] == device["token_id"])["grace_until"])
        store.add_peer("alice", "primary-three")
        self.assertTrue(store.validate_token("alice", "iphone-token"))

    def test_reserved_device_labels_rejected(self):
        store = AtalkStore(self.db)
        store.add_peer("alice", "primary-token")
        for label in ("legacy", "primary", "rotation"):
            with self.assertRaisesRegex(ValueError, "reserved"):
                store.add_device_token("alice", label)


class DeviceTokenHTTPTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = AtalkStore(Path(self.tmp.name) / "atalk.db")
        self.store.add_peer("alice", "alice-full")
        self.store.add_peer("bob", "bob-full")
        self.notify = self.store.add_device_token(
            "alice", "notify-sidecar", token="alice-notify", scope="notify")
        self.server = AtalkHTTPServer(("127.0.0.1", 0), self.store, WakeHub())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=2)
        self.server.server_close()
        self.tmp.cleanup()

    def request(self, path, token, body=None, method=None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(
            self.base + path, data=data,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            method=method or ("POST" if body is not None else "GET"))
        return urllib.request.urlopen(req, timeout=3)

    def assert_forbidden(self, path, token, body=None, method=None):
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.request(path, token, body, method)
        self.assertEqual(403, caught.exception.code)

    def test_notify_scope_and_cross_peer_guards(self):
        self.store.insert_event("bob", "alice", "message", {"text": "visible"})
        with self.request("/events?target=alice&state=all", "alice-notify") as response:
            self.assertEqual(200, response.status)
        self.assert_forbidden("/events?target=bob", "alice-notify")
        self.assert_forbidden("/stream?agent=bob", "alice-notify")
        self.assert_forbidden("/events", "alice-notify", {
            "source": "alice", "target": "bob", "payload": {"text": "no"}})
        self.assert_forbidden("/ack", "alice-notify", {
            "event_id": "none", "agent_id": "alice", "ack_type": "received"})
        self.assert_forbidden("/acks?event_id=none&agent=alice", "alice-notify")
        self.assert_forbidden("/device-tokens", "alice-notify", {
            "peer_id": "alice", "device_label": "no"})
        self.assert_forbidden("/device-tokens/revoke", "bob-full", {
            "peer_id": "alice", "token_id": self.notify["token_id"]})
        self.assertEqual("notify", self.store.token_scope("alice", "alice-notify"))


if __name__ == "__main__":
    unittest.main()
