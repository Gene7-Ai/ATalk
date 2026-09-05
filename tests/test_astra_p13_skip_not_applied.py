import sys,os,tempfile; sys.path.insert(0,os.path.expanduser("~/atalk-release-prep/public"))
from atalk.adapter import openclaw_handler, Adapter, Cursor, HandlerResult

class FakeClient:
    agent="acme"
    def __init__(self): self.acks=[]; self.sent=[]; self._events=[]
    def events(self, since_id, limit=100): return list(self._events)
    def ack(self, event_id, ack_type, detail=None): self.acks.append((event_id, ack_type))
    def send(self, *a, **k): self.sent.append((a,k))

d=tempfile.mkdtemp()
fc=FakeClient()
# an AUTO reply event -> _should_handle returns False -> skipped
fc._events=[{"id":1,"event_id":"skip-1","source":"dave","target":"acme",
             "type":"reply","payload":{"text":"ok","auto":True}}]
handler=openclaw_handler(fc,"/nonexistent/openclaw")  # bin never invoked for skipped event
from pathlib import Path
cur=Cursor(Path(d)/"cursor.json")
adapter=Adapter(fc,cur,handler)
adapter.run_once()
applied=[e for e,t in fc.acks if t=="applied"]
print("acks:",fc.acks)
print("applied acks (must be empty for a skipped event):",applied)
assert applied==[], "FAIL #13: skipped event was recorded applied"
assert ("skip-1","received") in fc.acks, "should still ack received"
assert cur.since_id==1, "cursor must advance past skipped event"
print("PASS #13: skipped event acked received only, not applied; cursor advanced")
