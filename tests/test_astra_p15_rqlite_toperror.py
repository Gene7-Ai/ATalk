import sys,os; sys.path.insert(0,os.path.expanduser("~/atalk-release-prep/public"))
import atalk.raftsql as R
cls=[getattr(R,n) for n in dir(R) if isinstance(getattr(R,n),type) and hasattr(getattr(R,n),"_raise_sql_errors")][0]
f=cls._raise_sql_errors; fails=[]
try: f({"error":"authorization required"}); fails.append("top-level error ignored")
except RuntimeError as e: print("top-level error -> raised:",e)
try: f({"results":[{"error":"UNIQUE constraint failed"}]}); fails.append("stmt error ignored")
except RuntimeError as e: print("stmt error -> raised:",e)
f({"results":[{"last_insert_id":5}]}); print("clean -> no raise")
if fails: print("FAIL:",fails); sys.exit(1)
print("PASS #15: rqlite top-level error no longer ignored")
