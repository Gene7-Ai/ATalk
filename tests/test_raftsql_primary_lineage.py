import unittest

from atalk.raftsql import RaftSQLStore


class _RecordingClient:
    def __init__(self):
        self.statements = []

    def transaction(self, statements):
        self.statements = statements
        return [{"rows_affected": 1} for _ in statements]


class RaftSQLPrimaryLineageTest(unittest.TestCase):
    def setUp(self):
        self.store = object.__new__(RaftSQLStore)
        self.store.client = _RecordingClient()

    def test_rotate_only_graces_primary_lineage(self):
        self.store.rotate_peer_token("alice", "next", grace_seconds=1)
        sql = self.store.client.statements[0][0]
        self.assertIn("device_label IS NULL", sql)
        self.assertIn("'legacy','primary','rotation'", sql)

    def test_add_peer_only_revokes_primary_lineage(self):
        self.store.add_peer("alice", "next")
        sql = self.store.client.statements[2][0]
        self.assertIn("device_label IS NULL", sql)
        self.assertIn("'legacy','primary','rotation'", sql)


if __name__ == "__main__":
    unittest.main()

