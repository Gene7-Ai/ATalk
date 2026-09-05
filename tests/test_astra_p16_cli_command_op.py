import sys,os,tempfile,json,io,contextlib
sys.path.insert(0,os.path.expanduser("~/atalk-release-prep/public"))
from atalk import cli
from atalk.core import AtalkStore
d=tempfile.mkdtemp(); db=os.path.join(d,"a.db")
# init + peers + grant via the store directly
s=AtalkStore(db); s.add_peer("worker",token="W"); s.add_peer("boss",token="B")
s.add_grant("boss","worker","restart")
def run(argv):
    buf=io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc=cli.main(["--db",db,*argv])
    return rc, buf.getvalue().strip()
fails=[]
# 1) command WITHOUT --op must be refused (previously impossible to express op at all)
try:
    run(["send","--from","worker","--to","boss","--type","command","--source-ref","r0","--token","W","hello"])
    fails.append("#16 command without op was accepted")
except SystemExit as e:
    print("no-op command refused:",e)
# 2) command WITH --op is now expressible and stored
rc,out=run(["send","--from","worker","--to","boss","--type","command","--op","restart",
            "--source-ref","r1","--event-id","c1","--token","W"])
ev=json.loads(out)
print("command stored:",ev["type"],ev["payload"])
if ev["type"]!="command" or ev["payload"].get("op")!="restart":
    fails.append("#16 command op not stored: %s"%ev)
# 3) --payload-json path
rc,out=run(["send","--from","worker","--to","boss","--type","command",
            "--payload-json",json.dumps({"op":"restart","service":"x"}),
            "--source-ref","r2","--event-id","c2","--token","W"])
ev=json.loads(out)
if ev["payload"].get("service")!="x": fails.append("#16 payload-json fields dropped")
else: print("payload-json merged:",ev["payload"])
if fails: print("FAILURES:",*fails,sep="\n  "); sys.exit(1)
print("ALL PASS #16: CLI can express command op")
