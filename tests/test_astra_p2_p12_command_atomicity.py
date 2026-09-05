import sys,os,tempfile
sys.path.insert(0,os.path.expanduser("~/atalk-release-prep/public"))
from atalk.core import AtalkStore
fails=[]
d=tempfile.mkdtemp(); s=AtalkStore(os.path.join(d,"a.db"))
# target grants source the right to run op1
s.add_peer("worker", token="W")    # source (grantee) — sends the command
s.add_peer("boss", token="B")      # target (grantor) — grants the command
gid=s.add_grant("boss","worker","op1")

def event_count(): return s.conn.execute("SELECT count(*) n FROM events").fetchone()["n"]
def seq_now():
    r=s.conn.execute("SELECT last_seq FROM source_counters WHERE source='worker'").fetchone()
    return r["last_seq"] if r else 0

# 1) valid command with grant -> stored
ev=s.insert_event("worker","boss","command",{"op":"op1","arg":1},source_ref="ref1",event_id="c1",token="W")
print("valid command stored:",ev.type=="command", "auth_actor=",ev.auth_actor)
if ev.auth_actor!="worker": fails.append("valid command missing auth_actor")
seq_after_ok=seq_now(); ec_after_ok=event_count()

# 2) revoke the grant, then a NEW command -> rejected, and NO partial state left
s.revoke_grant(gid)
try:
    s.insert_event("worker","boss","command",{"op":"op1","arg":2},source_ref="ref2",event_id="c2",token="W")
    fails.append("#12 command with revoked grant was accepted")
except PermissionError as e:
    print("revoked-grant command rejected:",e)
# atomicity: rejected command must leave no event row and must not burn a seq
if event_count()!=ec_after_ok: fails.append("#2 rejected command left an event row (no rollback)")
if seq_now()!=seq_after_ok: fails.append("#2 rejected command burned a seq (no rollback)")
# audit must record the reject
rej=s.conn.execute("SELECT count(*) n FROM audit_log WHERE event_id='c2' AND result='grant_denied'").fetchone()["n"]
if rej<1: fails.append("#2 reject not audited")
else: print("reject audited, no event/seq leaked: OK")

# 3) invalid token -> rejected too
try:
    s.insert_event("worker","boss","command",{"op":"op1"},source_ref="ref3",event_id="c3",token="WRONG")
    fails.append("#12 command with bad token accepted")
except PermissionError as e:
    print("bad-token command rejected:",e)

if fails: print("FAILURES:",*fails,sep="\n  "); sys.exit(1)
print("ALL PASS #2/#12: command authorization atomic; rejects roll back cleanly")
