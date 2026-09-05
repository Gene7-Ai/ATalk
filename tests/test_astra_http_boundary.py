import sys,os,tempfile,threading,json,urllib.request,urllib.error,time
sys.path.insert(0,os.path.expanduser("~/atalk-release-prep/public"))
from atalk.core import AtalkStore
from atalk.server import AtalkHTTPServer, WakeHub, MessageAcl

d=tempfile.mkdtemp(); db=os.path.join(d,"a.db")
store=AtalkStore(db)
ta=store.add_peer("alice",role="agent"); tb=store.add_peer("bob",role="agent"); tc=store.add_peer("carol",role="agent")
# neutral ACL (no restrictions)
srv=AtalkHTTPServer(("127.0.0.1",0),store,WakeHub())
srv.message_acl=MessageAcl(path=os.path.join(d,"noacl.json"))
port=srv.server_address[1]
threading.Thread(target=srv.serve_forever,daemon=True).start()
base=f"http://127.0.0.1:{port}"
def call(method,path,body=None,token=None,raw=None,headers=None):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req=urllib.request.Request(base+path,data=data,method=method)
    if token: req.add_header("Authorization",f"Bearer {token}")
    for k,v in (headers or {}).items(): req.add_header(k,v)
    try:
        r=urllib.request.urlopen(req,timeout=5); return r.status, r.read().decode()
    except urllib.error.HTTPError as e: return e.code, e.read().decode()

fails=[]
# ---- #7: non-object payload rejected ----
st,bd=call("POST","/events",{"source":"alice","target":"bob","payload":"i am a string"},token=ta)
print("#7 string payload ->",st,bd)
if st!=400: fails.append("#7 non-object payload not rejected (got %s)"%st)
# valid dict payload still works
st,bd=call("POST","/events",{"source":"alice","target":"bob","payload":{"text":"hi"}},token=ta)
print("#7 valid payload ->",st)
if st!=201: fails.append("#7 valid payload broke (got %s)"%st); 
ev=json.loads(bd); eid=ev["event_id"]
# ---- #10: non-party cannot read acks ----
# bob acks it (bob is target -> party)
call("POST","/ack",{"event_id":eid,"agent_id":"bob","ack_type":"received","detail":{"secret":"diag"}},token=tb)
st,bd=call("GET",f"/acks?event_id={eid}&agent=bob",token=tb)
print("#10 party(bob) reads acks ->",st)
if st!=200: fails.append("#10 party denied (got %s)"%st)
st,bd=call("GET",f"/acks?event_id={eid}&agent=carol",token=tc)
print("#10 non-party(carol) reads acks ->",st,bd)
if st!=403: fails.append("#10 non-party could read acks (got %s): %s"%(st,bd))
# ---- #14: oversized body -> 413 ----
big=b'{"source":"alice","target":"bob","payload":{"text":"'+b'x'*(1<<21)+b'"}}'
st,bd=call("POST","/events",raw=big,token=ta,headers={"Content-Type":"application/json"})
print("#14 oversized body ->",st,bd[:60])
if st!=413: fails.append("#14 oversized body not rejected (got %s)"%st)

srv.shutdown()
if fails:
    print("FAILURES:",*fails,sep="\n  "); sys.exit(1)
print("ALL PASS: #7 #10 #14(body)")
