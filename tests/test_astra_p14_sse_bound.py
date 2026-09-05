import sys,os,queue; sys.path.insert(0,os.path.expanduser("~/atalk-release-prep/public"))
from atalk.server import WakeHub
h=WakeHub(); q=h.subscribe("alice")
# subscriber never drains; notifier must not block/grow unbounded
for i in range(5000):
    h.notify("alice",{"n":i})
print("queue size after 5000 notifies (bounded at 1024):",q.qsize())
assert q.qsize()<=1024, "FAIL: unbounded"
print("PASS #14: SSE wake queue bounded, notifier never blocks")
