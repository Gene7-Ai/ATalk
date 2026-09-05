import sys,os,tempfile; sys.path.insert(0,os.path.expanduser("~/atalk-release-prep/public"))
from atalk.adapter import OpenClawTaskStore
d=tempfile.mkdtemp(); ts=OpenClawTaskStore(os.path.join(d,"t.json"))
# two DIFFERENT senders, SAME client-chosen thread_id
a={"event_id":"a1","source":"alice","target":"acme","type":"message","payload":{"text":"x","thread_id":"job-7"}}
b={"event_id":"b1","source":"bob","target":"acme","type":"message","payload":{"text":"y","thread_id":"job-7"}}
ka=ts.thread_key(a); kb=ts.thread_key(b)
print("alice key:",ka,"| bob key:",kb)
assert ka!=kb, "FAIL: distinct senders collide into one thread"
ts.append(a,"s1"); ts.append(b,"s2")
th=ts.pending()
# each thread must contain only its own sender's event
assert th[ka]["event_ids"]==["a1"], th[ka]["event_ids"]
assert th[kb]["event_ids"]==["b1"], th[kb]["event_ids"]
print("PASS #4: same thread_id from different senders stays isolated")
