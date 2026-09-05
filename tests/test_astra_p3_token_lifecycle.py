import sys,os,tempfile,threading,json,time,urllib.request,urllib.error
sys.path.insert(0,os.path.expanduser("~/atalk-release-prep/public"))
from atalk.core import AtalkStore, now_iso
from atalk.server import AtalkHTTPServer, WakeHub, MessageAcl
fails=[]
d=tempfile.mkdtemp(); store=AtalkStore(os.path.join(d,"a.db"))

# ---- #3-A: revoking the last peer must NOT turn auth off ----
store.add_peer("solo", token="S0")
assert store.auth_required() is True
store.conn.execute("UPDATE peers SET revoked_at=? WHERE peer_id=?", (now_iso(),"solo"))
if store.auth_required() is not True:
    fails.append("#3-A revoking last peer flipped auth OFF (fail-open)")
else:
    print("#3-A last-peer-revoke keeps auth required: OK")

# ---- #3-B: rotate must not revive an already-grace-expired token ----
store.add_peer("alice", token="T0")
store.rotate_peer_token("alice", token="T1", grace_seconds=300)   # T0 -> grace
# simulate T0's grace already expired
store.conn.execute("UPDATE peer_tokens SET grace_until='2000-01-01T00:00:00Z' "
                   "WHERE peer_id='alice' AND device_label='primary'")
assert store.token_scope("alice","T0") is None, "precondition: T0 should be expired"
store.rotate_peer_token("alice", token="T2", grace_seconds=300)   # must NOT revive T0
if store.token_scope("alice","T0") is not None:
    fails.append("#3-B rotate revived an expired token (T0 valid again)")
else:
    print("#3-B expired token stays dead after subsequent rotate: OK")

# ---- #3-C: revoking a token cuts an active SSE stream ----
tok=store.add_peer("carol", token="C0")   # returns token 'C0'
srv=AtalkHTTPServer(("127.0.0.1",0),store,WakeHub())
srv.message_acl=MessageAcl(path=os.path.join(d,"noacl.json"))
port=srv.server_address[1]; threading.Thread(target=srv.serve_forever,daemon=True).start()
base=f"http://127.0.0.1:{port}"
lines=[]
def read_stream():
    req=urllib.request.Request(base+"/stream?agent=carol",headers={"Authorization":"Bearer C0","Accept":"text/event-stream"})
    try:
        with urllib.request.urlopen(req,timeout=8) as r:
            for raw in r:
                s=raw.decode().strip()
                if s.startswith("data: "): lines.append(json.loads(s[6:]))
                if any(l.get("kind")=="revoked" for l in lines): break
    except Exception as e: lines.append({"kind":"conn_error","e":str(e)})
th=threading.Thread(target=read_stream,daemon=True); th.start()
time.sleep(0.6)  # let it connect & get 'ready'
# revoke carol's primary token
row=store.conn.execute("SELECT token_id FROM peer_tokens WHERE peer_id='carol'").fetchone()
store.revoke_device_token(row["token_id"])
# push an event so the stream loop wakes and re-checks auth
srv.wake.notify("carol", {"kind":"event","event":{"hi":1}})
th.join(timeout=6)
kinds=[l.get("kind") for l in lines]
print("#3-C stream kinds:",kinds)
if "revoked" not in kinds:
    fails.append("#3-C revoked token stream did not close (kinds=%s)"%kinds)
elif "event" in kinds:
    fails.append("#3-C stream delivered event after revocation")
else:
    print("#3-C SSE stream closed on revocation, event withheld: OK")
srv.shutdown()

if fails: print("FAILURES:",*fails,sep="\n  "); sys.exit(1)
print("ALL PASS #3: token lifecycle (rotate/auth_required/SSE revocation)")
