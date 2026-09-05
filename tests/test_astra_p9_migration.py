import sys,os,tempfile,sqlite3
sys.path.insert(0,os.path.expanduser("~/atalk-release-prep/public"))
from atalk import raftsql, migration
from atalk.core import AtalkStore
class FakeRqlite:
    def __init__(self):
        self.conn=sqlite3.connect(":memory:"); self.conn.row_factory=sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=OFF")
        for stmt in raftsql.SCHEMA_STATEMENTS: self.conn.execute(stmt)
    def query(self, sql, parameters=()):
        return [dict(r) for r in self.conn.execute(sql, tuple(parameters)).fetchall()]
    def transaction(self, statements):
        out=[]
        for st in statements:
            cur=self.conn.execute(st[0], tuple(st[1:])); out.append({"last_insert_id":cur.lastrowid})
        self.conn.commit(); return out
fails=[]
d=tempfile.mkdtemp(); src=os.path.join(d,"src.db")
s=AtalkStore(src); s.add_peer("alice",token="T"); s.add_peer("bob",token="U")
for i in range(5): s.insert_event("alice","bob","message",{"text":str(i)},token="T")
s.conn.execute("DELETE FROM events WHERE id<5")
maxid=s.conn.execute("SELECT max(id) m FROM events").fetchone()["m"]
snap=os.path.join(d,"snap.db"); migration.snapshot_sqlite(src,snap)
# happy path: import + verification passes
fake=FakeRqlite(); mig=migration.ShadowMigrator(fake); counts=mig.import_snapshot(snap)
print("import verified, events:",counts["events"])
# high-water advances: next autoincrement id > maxid
newid=fake.conn.execute("INSERT INTO events(event_id,source,target,type,seq,created_at,stored_at,payload_json,requires_ack) VALUES('n','alice','bob','message',9,'t','t','{}',1)").lastrowid
print("next id:",newid,">",maxid)
if newid<=maxid: fails.append("#9 high-water not advanced")
# partial-import detection: shadow missing a row must be caught by verify_counts
fake2=FakeRqlite()
fake2.conn.execute("INSERT INTO peers(peer_id,created_at) VALUES('x','t')")  # 1 row
try:
    migration.ShadowMigrator(fake2).verify_counts({"peers":2})
    fails.append("#9 partial import NOT detected")
except RuntimeError as e:
    print("partial import detected:",str(e)[:70])
if fails: print("FAILURES:",*fails,sep="\n  "); sys.exit(1)
print("ALL PASS #9: high-water advances; partial import now detected (was silent)")
