import sys,os,tempfile,threading,json,urllib.request,urllib.error
sys.path.insert(0,os.path.expanduser("~/atalk-release-prep/public"))
from atalk.core import AtalkStore
from atalk.server import AtalkHTTPServer, WakeHub, MessageAcl
from atalk.adapter import AtalkClient

fails=[]
# ---- 11a client-side: send pins a stable non-None event_id ----
c=AtalkClient("http://x,http://y","alice")
captured={}
def fake_json(path,payload=None):
    captured["body"]=payload; return {"ok":True}
c._json=fake_json
c.send("bob","message",{"text":"hi"})
eid=captured["body"]["event_id"]
print("11a client event_id:",eid)
if not eid: fails.append("11a client send left event_id=None (dup risk on retry)")

# ---- 11b server-side: backlog-full still accepts idempotent retry ----
d=tempfile.mkdtemp(); store=AtalkStore(os.path.join(d,"a.db"))
ta=store.add_peer("alice"); tb=store.add_peer("bob")
srv=AtalkHTTPServer(("127.0.0.1",0),store,WakeHub(),max_inbox_depth=1)
srv.message_acl=MessageAcl(path=os.path.join(d,"noacl.json"))
port=srv.server_address[1]; threading.Thread(target=srv.serve_forever,daemon=True).start()
base=f"http://127.0.0.1:{port}"
def post(body):
    req=urllib.request.Request(base+"/events",data=json.dumps(body).encode(),method="POST")
    req.add_header("Authorization",f"Bearer {ta}")
    try:
        r=urllib.request.urlopen(req,timeout=5); return r.status,json.loads(r.read())
    except urllib.error.HTTPError as e: return e.code, e.read().decode()
# fill backlog to depth 1 for target bob
st,ev=post({"source":"alice","target":"bob","payload":{"text":"1"},"event_id":"ev-A"})
print("first event:",st)
# retry SAME event_id while backlog full -> must be idempotent, not 429
st,ev=post({"source":"alice","target":"bob","payload":{"text":"1"},"event_id":"ev-A"})
print("idempotent retry while full ->",st)
if st==429: fails.append("11b idempotent retry rejected by backlog (429)")
# a genuinely NEW event while full -> 429
st,ev=post({"source":"alice","target":"bob","payload":{"text":"2"},"event_id":"ev-B"})
print("new event while full ->",st)
if st!=429: fails.append("11b new event not backlog-limited (got %s)"%st)
srv.shutdown()

if fails: print("FAILURES:",*fails,sep="\n  "); sys.exit(1)
print("ALL PASS #11: stable client event_id + idempotent retry bypasses backlog, new event still limited")
