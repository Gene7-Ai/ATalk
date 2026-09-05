import sqlite3, tempfile, unittest
from pathlib import Path
from atalk import migration


class MigrationTableSetTest(unittest.TestCase):
    def test_acl_tables_are_configured(self):
        for name in ("peer_target_acl", "peer_target_acl_targets"):
            self.assertIn(name, migration.TABLES)
            self.assertIn(name, migration.ORDER_BY)
            self.assertIn(name, migration.PRIMARY_KEY)

    def test_every_table_reads_with_real_columns(self):
        # Build a schema-accurate SQLite DB with ACL rows and read every migrated
        # table the way the migrator does. A wrong ORDER_BY/column (e.g. a
        # non-existent `id`) raises OperationalError here.
        schema = (Path(__file__).resolve().parent.parent / "atalk" / "schema.sql").read_text()
        d = tempfile.TemporaryDirectory(); self.addCleanup(d.cleanup)
        db = Path(d.name) / "t.db"
        conn = sqlite3.connect(db)
        conn.executescript(schema)
        now = "2026-01-01T00:00:00Z"
        conn.execute("INSERT INTO peers(peer_id,token_hash,role,platform,delivery_class,ack_timeout_sec,created_at) VALUES(?,?,?,?,?,?,?)",
                     ("guest", "h", "agent", "demo", "normal", 180, now))
        conn.execute("INSERT INTO peers(peer_id,token_hash,role,platform,delivery_class,ack_timeout_sec,created_at) VALUES(?,?,?,?,?,?,?)",
                     ("alice", "h2", "agent", "demo", "normal", 180, now))
        conn.execute("INSERT INTO peers(peer_id,token_hash,role,platform,delivery_class,ack_timeout_sec,created_at) VALUES(?,?,?,?,?,?,?)",
                     ("bob", "h3", "agent", "demo", "normal", 180, now))
        conn.execute("INSERT INTO peer_target_acl(peer_id,created_at,updated_at) VALUES(?,?,?)", ("guest", now, now))
        conn.execute("INSERT INTO peer_target_acl_targets(peer_id,target_peer,created_at) VALUES(?,?,?)", ("guest", "alice", now))
        conn.execute("INSERT INTO peer_target_acl_targets(peer_id,target_peer,created_at) VALUES(?,?,?)", ("guest", "bob", now))
        conn.commit()
        for table in migration.TABLES:
            cols = migration._columns(conn, table)
            rows = migration._sqlite_rows(conn, table, cols)  # raises if ORDER_BY column is wrong
            if table == "peer_target_acl_targets":
                self.assertEqual(len(rows), 2)
                self.assertEqual({r["target_peer"] for r in rows}, {"alice", "bob"})
        conn.close()


if __name__ == "__main__":
    unittest.main()
