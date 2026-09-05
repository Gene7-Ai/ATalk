import sys,os,tempfile,time; sys.path.insert(0,os.path.expanduser("~/atalk-release-prep/public"))
from atalk.adapter import OpenClawTaskStore
d=tempfile.mkdtemp(); ts=OpenClawTaskStore(os.path.join(d,"tasks.json"))
ev={"event_id":"e1","source":"alice","target":"acme","type":"message","payload":{"text":"do X"}}
ts.append(ev,"sess1")
k=ts.thread_key(ev)
# complete: thread must SURVIVE (not deleted) so a send failure is recoverable
eids=ts.set_status(ev,"complete",blocker_reason="done")
present_after_complete = k in ts.pending()
print("event_ids:",eids,"| thread present after complete (must be True):",present_after_complete)
# finalize only after successful send
ts.finalize_complete(ev)
present_after_finalize = k in ts.pending()
print("thread present after finalize (must be False):",present_after_finalize)
assert present_after_complete and not present_after_finalize, "FAIL"
print("PASS #5: task survives complete until finalize")
