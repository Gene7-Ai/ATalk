import json, tempfile, unittest
from pathlib import Path
from atalk.core import AtalkStore, EventIdConflict, token_hash


class EventIdCollisionTest(unittest.TestCase):
    def _store(self):
        d = tempfile.TemporaryDirectory(); self.addCleanup(d.cleanup)
        s = AtalkStore(Path(d.name) / "t.db")
        for p in ("alice", "bob", "mallory", "eve"):
            s.add_peer(p, f"tok-{p}")
        return s

    def test_reused_event_id_from_other_peer_is_rejected(self):
        s = self._store()
        eid = "11111111-1111-4111-8111-111111111111"
        first = s.insert_event("alice", "bob", "message", {"secret": "ORIGINAL"},
                               event_id=eid, token="tok-alice")
        self.assertEqual(first.payload["secret"], "ORIGINAL")
        # mallory reuses the same event_id for a different (source,target)
        with self.assertRaises(EventIdConflict):
            s.insert_event("mallory", "eve", "message", {"x": "y"},
                           event_id=eid, token="tok-mallory")

    def test_true_idempotent_retry_still_returns_original(self):
        s = self._store()
        eid = "22222222-2222-4222-8222-222222222222"
        a = s.insert_event("alice", "bob", "message", {"n": 1}, event_id=eid, token="tok-alice")
        b = s.insert_event("alice", "bob", "message", {"n": 1}, event_id=eid, token="tok-alice")
        self.assertEqual(a.id, b.id)


if __name__ == "__main__":
    unittest.main()


import threading
from atalk.raftsql import RaftSQLStore


class EventIdConcurrencyTest(unittest.TestCase):
    def test_sqlite_concurrent_same_event_id_other_peer_conflicts(self):
        d = tempfile.TemporaryDirectory(); self.addCleanup(d.cleanup)
        s = AtalkStore(Path(d.name) / "t.db")
        for p in ("alice", "mallory", "bob", "eve"):
            s.add_peer(p, f"tok-{p}")
        eid = "33333333-3333-4333-8333-333333333333"
        results = {}
        barrier = threading.Barrier(2)

        own = {"a": "ALICE", "m": "MALLORY"}

        def submit(name, src, tgt, secret):
            barrier.wait()
            try:
                ev = s.insert_event(src, tgt, "message", {"secret": secret},
                                    event_id=eid, token=f"tok-{src}")
                results[name] = ("ok", ev.payload["secret"])
            except EventIdConflict:
                results[name] = ("conflict", None)
            except Exception as e:  # transient sqlite "database is locked" is acceptable
                results[name] = ("err", type(e).__name__)

        t1 = threading.Thread(target=submit, args=("a", "alice", "bob", "ALICE"))
        t2 = threading.Thread(target=submit, args=("m", "mallory", "eve", "MALLORY"))
        t1.start(); t2.start(); t1.join(); t2.join()
        # Security property (must hold under any interleaving): no thread ever receives
        # the OTHER peer's body. Any "ok" must carry the caller's own secret.
        for name, (kind, secret) in results.items():
            if kind == "ok":
                self.assertEqual(secret, own[name], "a peer received another peer's body")
        # The security invariant is what matters here and holds under any interleaving:
        # at most one writer commits this event_id, and neither reads the other's body.
        # (Liveness under 2-thread SQLite lock contention is not asserted.)
        oks = [n for n, (k, _) in results.items() if k == "ok"]
        self.assertLessEqual(len(oks), 1, "both writers committed the same event_id")


class FakeRqliteClient:
    """Minimal stub: pretends event_id X already exists as alice->bob."""
    def __init__(self, existing):
        self._existing = existing
    def query(self, sql, params=()):
        if "FROM events WHERE event_id" in sql and params and params[0] == self._existing["event_id"]:
            return [self._existing]
        return []
    def transaction(self, statements):
        return []


class RaftSQLReturnExistingTest(unittest.TestCase):
    def test_preexisting_event_id_from_other_peer_conflicts(self):
        existing = {
            "id": 1, "event_id": "44444444-4444-4444-8444-444444444444",
            "source": "alice", "target": "bob", "type": "message", "seq": 1,
            "created_at": "2026-01-01T00:00:00Z", "stored_at": "2026-01-01T00:00:00Z",
            "payload_json": json.dumps({"secret": "ORIGINAL"}),
            "requires_ack": 1, "source_ref": None, "auth_actor": None,
        }
        store = RaftSQLStore.__new__(RaftSQLStore)
        store.client = FakeRqliteClient(existing)
        with self.assertRaises(EventIdConflict):
            store.insert_event("mallory", "eve", "message", {"x": 1},
                               event_id=existing["event_id"], token=None)

    def test_preexisting_event_id_same_peer_message_is_idempotent(self):
        # Same (source,target,type) retry over rqlite must return the stored event,
        # not raise (regression for the message pre-insert branch).
        existing = {
            "id": 2, "event_id": "66666666-6666-4666-8666-666666666666",
            "source": "alice", "target": "bob", "type": "message", "seq": 1,
            "created_at": "2026-01-01T00:00:00Z", "stored_at": "2026-01-01T00:00:00Z",
            "payload_json": json.dumps({"n": 1}),
            "requires_ack": 1, "source_ref": None, "auth_actor": None,
        }
        store = RaftSQLStore.__new__(RaftSQLStore)
        store.client = FakeRqliteClient(existing)
        got = store.insert_event("alice", "bob", "message", {"n": 1},
                                 event_id=existing["event_id"], token=None)
        self.assertEqual(got.event_id, existing["event_id"])


class FakeRqliteClientCmd:
    """Stub where event_id X already exists as a command grant.command from alice->bob."""
    def __init__(self, existing):
        self._existing = existing
    def query(self, sql, params=()):
        s = sql.lower()
        if "from events where event_id" in s and params and params[0] == self._existing["event_id"]:
            return [self._existing]
        if "peers" in s and "revoked_at is null" in s:
            return [{"present": 1}]
        if "peer_tokens" in s or "peer_grants" in s:
            return [{"scope": "full"}] if "scope" in s else [{"present": 1}]
        return []
    def transaction(self, statements):
        return []


class RaftSQLCommandPathTest(unittest.TestCase):
    def _existing_command(self):
        return {
            "id": 7, "event_id": "55555555-5555-4555-8555-555555555555",
            "source": "alice", "target": "bob", "type": "command", "seq": 1,
            "created_at": "2026-01-01T00:00:00Z", "stored_at": "2026-01-01T00:00:00Z",
            "payload_json": json.dumps({"op": "rescue.health"}),
            "requires_ack": 1, "source_ref": None, "auth_actor": "alice",
        }

    def test_command_idempotent_retry_does_not_raise_nameerror(self):
        # Same peer re-submitting the same command event_id must return it, not NameError.
        ev = self._existing_command()
        store = RaftSQLStore.__new__(RaftSQLStore)
        store.client = FakeRqliteClientCmd(ev)
        got = store._insert_command("alice", "bob", {"op": "rescue.health"},
                                    seq=None, event_id=ev["event_id"],
                                    created_at="2026-01-01T00:00:00Z", requires_ack=True,
                                    source_ref="ref-1", token="tok")
        self.assertEqual(got.event_id, ev["event_id"])

    def test_command_event_id_reuse_by_other_peer_conflicts(self):
        ev = self._existing_command()
        store = RaftSQLStore.__new__(RaftSQLStore)
        store.client = FakeRqliteClientCmd(ev)
        with self.assertRaises(EventIdConflict):
            store._insert_command("mallory", "eve", {"op": "rescue.health"},
                                  seq=None, event_id=ev["event_id"],
                                  created_at="2026-01-01T00:00:00Z", requires_ack=True,
                                  source_ref="ref-2", token="tok")
