"""Integration tests: real ATalk server (temp SQLite) + atalk_mcp.py over real stdio JSON-RPC.
usage: PYTHONPATH=<atalk src> python integration_check.py <python-for-mcp-server>"""
import atexit, json, os, subprocess, sys, tempfile, threading, time, uuid, httpx
SRC = os.environ["PYTHONPATH"]; PY = sys.argv[1]; HERE = os.path.dirname(os.path.abspath(__file__))
def stop_process(p):
    if p.poll() is None: p.terminate()
    try: p.wait(timeout=5)
    except subprocess.TimeoutExpired: p.kill(); p.wait(timeout=5)
def tracked_popen(*a, **kw):
    p = subprocess.Popen(*a, **kw)
    atexit.register(stop_process, p)
    return p
PORT = 7181; URL = f"http://127.0.0.1:{PORT}"
d = tempfile.mkdtemp(); db = os.path.join(d, "t.db")
run = lambda *a: subprocess.run([sys.executable, "-m", "atalk.cli", "--db", db, *a], check=True, capture_output=True)
run("init"); run("peer-add", "me", "--token", "tok-me", "--role", "agent", "--platform", "mcp"); run("peer-add", "peer", "--token", "tok-p", "--role", "agent", "--platform", "t")
srv = tracked_popen([sys.executable, "-m", "atalk.server", "--db", db, "--host", "127.0.0.1", "--port", str(PORT), "--max-inbox-depth", "10000"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(1.5)
P = {"Authorization": "Bearer tok-p", "Content-Type": "application/json"}
def peer_send(text):
    e = str(uuid.uuid4()); httpx.post(f"{URL}/events", headers=P, json={"source": "peer", "target": "me", "type": "task", "event_id": e, "payload": {"text": text}}).raise_for_status(); return e
env = dict(os.environ, ATALK_URL=URL, ATALK_AGENT="me", ATALK_TOKEN="tok-me")
mc = tracked_popen([PY, os.path.join(HERE, "atalk_mcp.py")], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True)
n = 0
def rpc(method, params=None, notify=False):
    global n
    m = {"jsonrpc": "2.0", "method": method, **({"params": params} if params is not None else {})}
    if not notify: n += 1; m["id"] = n
    mc.stdin.write(json.dumps(m) + "\n"); mc.stdin.flush()
    if notify: return
    while True:
        line = mc.stdout.readline()
        if not line: raise SystemExit("server died: " + mc.stderr.read()[-1500:])
        msg = json.loads(line)   # any non-JSON line on stdout = log pollution -> test fails here
        if msg.get("id") == n: return msg
def call(name, args):
    r = rpc("tools/call", {"name": name, "arguments": args})
    if "error" in r: return {"__error__": r["error"]}
    res = r["result"]
    if res.get("isError"): return {"__error__": res["content"][0]["text"]}
    return res.get("structuredContent") or json.loads(res["content"][0]["text"])
ok = [];
def check(name, cond, info=""): ok.append(cond); print(("PASS " if cond else "FAIL ") + name, info)
info = rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}})
rpc("notifications/initialized", {}, notify=True)
tools = sorted(t["name"] for t in rpc("tools/list", {})["result"]["tools"])
check("tools/list", tools == sorted(["atalk_send", "atalk_inbox", "atalk_history", "atalk_ack", "atalk_receipts", "atalk_wait"]), tools)
# 1 out-of-order applied must not hide older pending
e1, e2 = peer_send("one"), peer_send("two")
call("atalk_ack", {"event_id": e2, "ack_type": "applied"})
ib = call("atalk_inbox", {})
check("1 out-of-order applied keeps older pending", [x["event_id"] for x in ib["events"]] == [e1], ib["pending_total"])
call("atalk_ack", {"event_id": e1, "ack_type": "applied"})
# 2 more than one page (250 pending) all visible; ack the 250th works
ids = [peer_send(f"bulk {i}") for i in range(250)]
ib = call("atalk_inbox", {"limit": 5})
check("2 pagination: pending_total=250", ib["pending_total"] == 250, ib["pending_total"])
call("atalk_ack", {"event_id": ids[-1], "ack_type": "applied"})
check("2 ack beyond first page", call("atalk_inbox", {})["pending_total"] == 249)
for e in ids[:-1]: httpx.post(f"{URL}/ack", headers={"Authorization": "Bearer tok-me", "Content-Type": "application/json"}, json={"agent_id": "me", "event_id": e, "ack_type": "applied"})
# 3 progress and final replies are distinct; identical retry is idempotent
t = peer_send("do x")
a = call("atalk_send", {"target": "peer", "text": "working on it", "in_reply_to": t})
b = call("atalk_send", {"target": "peer", "text": "done: 42", "in_reply_to": t})
b2 = call("atalk_send", {"target": "peer", "text": "done: 42", "in_reply_to": t})
got = [e["payload"]["text"] for e in httpx.get(f"{URL}/events", headers=P, params={"target": "peer", "since_id": 0, "limit": 50, "state": "all"}).json()]
check("3 progress+final both stored", got.count("working on it") == 1 and got.count("done: 42") == 1, got)
check("3 identical retry same event_id", b["event_id"] == b2["event_id"] and a["event_id"] != b["event_id"])
k1 = call("atalk_send", {"target": "peer", "text": "A", "idempotency_key": "k1"})
k2 = call("atalk_send", {"target": "peer", "text": "B", "idempotency_key": "k1"})
check("3 reused key with different content -> error, not silent", "__error__" in k2, str(k2)[:120])
call("atalk_ack", {"event_id": t, "ack_type": "applied", "detail": "sha256:abc"})
rc = call("atalk_receipts", {"event_id": t})
check("receipts carry detail", any(r["detail"] for r in rc["receipts"]), rc)
# 4 wait returns immediately when work already pending
p = peer_send("already waiting"); t0 = time.monotonic(); w = call("atalk_wait", {"timeout_s": 20})
check("4 wait returns at once with existing pending", time.monotonic() - t0 < 3 and w["pending_total"] == 1, round(time.monotonic() - t0, 2))
call("atalk_ack", {"event_id": p, "ack_type": "applied"})
# 4b wait wakes on new event; 4c honors total deadline
threading.Timer(2, lambda: peer_send("late")).start(); t0 = time.monotonic(); w = call("atalk_wait", {"timeout_s": 20})
check("4b wait wakes on new event", 1.5 < time.monotonic() - t0 < 6 and w["pending_total"] == 1, round(time.monotonic() - t0, 2))
for e in w["events"]: call("atalk_ack", {"event_id": e["event_id"], "ack_type": "applied"})
t0 = time.monotonic(); w = call("atalk_wait", {"timeout_s": 3})
check("4c wait total deadline", 2.5 < time.monotonic() - t0 < 6 and w["timed_out"], round(time.monotonic() - t0, 2))

# 5 no silent cap: 5001 pending all counted, continuation via after_id
import sqlite3
big = [str(uuid.uuid4()) for _ in range(5001)]
with httpx.Client() as c:
    for i, e in enumerate(big):
        c.post(f"{URL}/events", headers=P, json={"source": "peer", "target": "me", "type": "task", "event_id": e, "payload": {"text": f"b{i}"}}).raise_for_status()
ib = call("atalk_inbox", {"limit": 3})
check("5 pending_total counts all 5001", ib["pending_total"] == 5001 and ib["more"], ib["pending_total"])
ib2 = call("atalk_inbox", {"limit": 3, "after_id": ib["next_after_id"]})
check("5 continuation after_id", [e["event_id"] for e in ib2["events"]] == big[3:6] and ib2["pending_total"] == 4998 and ib2["complete"])
h1 = call("atalk_history", {"limit": 200})
h2 = call("atalk_history", {"since_id": h1["next_since_id"], "limit": 200})
check("history continuation beyond first page", len(h1["events"]) == 200 and len(h2["events"]) == 200 and h2["events"][0]["id"] > h1["next_since_id"])
stop_process(mc)
mc = tracked_popen([PY, os.path.join(HERE, "atalk_mcp.py")], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True); n = 0
rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}); rpc("notifications/initialized", {}, notify=True)
recovered = call("atalk_inbox", {"limit": 3})
check("restart recovers earliest pending", recovered["pending_total"] == 5001 and [e["event_id"] for e in recovered["events"]] == big[:3])
stop_process(mc); stop_process(srv)
# 6/7 adversarial fake servers: deadline must be absolute; partial work must survive
import http.server, socketserver
def ev(i): return {"id": i, "event_id": str(uuid.UUID(int=i)), "source": "peer", "target": "me", "type": "task", "payload": {"text": f"f{i}"}, "created_at": "x"}
class Fake(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _json(self, obj, code=200):
        b = json.dumps(obj).encode(); self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        mode = self.server.mode
        if mode in ("auth401", "auth403"): return self._json({"error": "denied"}, int(mode[-3:]))
        if mode in ("stream401", "stream403") and not self.path.startswith("/events"):
            return self._json({"error": "denied"}, int(mode[-3:]))
        if self.path.startswith("/events"):
            since = int(self.path.split("since_id=")[1].split("&")[0])
            if mode == "ready_race":
                self.server.reads = getattr(self.server, "reads", 0) + 1
                return self._json([] if self.server.reads == 1 else [ev(1)])
            if mode == "slowjson":                       # dribble a valid empty list very slowly
                self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", "2"); self.end_headers()
                try:
                    for ch in b"[]": time.sleep(4); self.wfile.write(bytes([ch])); self.wfile.flush()
                except Exception: pass
                return
            if mode in ("page2hang", "page2err") and since > 0:
                if mode == "page2err": return self._json({"error": "boom"}, 500)
                time.sleep(30); return
            if mode in ("page2hang", "page2err") and since == 0: return self._json([ev(i) for i in range(1, 201)])
            return self._json([])
        self.send_response(200); self.send_header("Content-Type", "text/event-stream"); self.end_headers()
        try:
            if mode == "ready_race":
                self.wfile.write(b'data: {"kind": "ready"}\n\n'); self.wfile.flush(); time.sleep(1)
            elif mode == "heartbeat":
                self.wfile.write(b'data: {"kind": "ready"}\n\n'); self.wfile.flush()
                for _ in range(200): self.wfile.write(b": ping\n\n"); self.wfile.flush(); time.sleep(0.1)
            elif mode == "nonewline":
                for _ in range(400): self.wfile.write(b"x"); self.wfile.flush(); time.sleep(0.05)
        except Exception: pass
class TS(socketserver.ThreadingMixIn, http.server.HTTPServer): daemon_threads = True
def with_fake(mode, port, fn):
    global mc, n
    fs = TS(("127.0.0.1", port), Fake); fs.mode = mode; threading.Thread(target=fs.serve_forever, daemon=True).start()
    mc = tracked_popen([PY, os.path.join(HERE, "atalk_mcp.py")], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=dict(env, ATALK_URL=f"http://127.0.0.1:{port}"), text=True); n = 0
    rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}); rpc("notifications/initialized", {}, notify=True)
    try: fn()
    finally: stop_process(mc); fs.shutdown(); fs.server_close()
def timed(args):
    t0 = time.monotonic(); r = call("atalk_wait", args); return r, time.monotonic() - t0
def t_hb():
    for to in (1, 3):
        r, dt = timed({"timeout_s": to}); check(f"6 heartbeat wait({to}) bounded", dt < to + 0.6 and r.get("timed_out"), round(dt, 2))
def t_slow():
    r, dt = timed({"timeout_s": 1}); check("6 slow JSON body: wait(1) bounded", dt < 1.6 and r.get("timed_out"), round(dt, 2))
def t_nonl():
    r, dt = timed({"timeout_s": 1}); check("6 SSE bytes without newline: wait(1) bounded", dt < 1.6, round(dt, 2))
def t_p2hang():
    r, dt = timed({"timeout_s": 2})
    check("7 page2 hangs: wait keeps page-1 work", dt < 2.6 and r["pending_total"] == 200 and len(r["events"]) == 50 and r["complete"] is False and not r["timed_out"], (round(dt, 2), r["pending_total"], r["complete"]))
def t_p2err():
    r = call("atalk_inbox", {"limit": 5})
    check("7 page2 error: inbox returns page-1 work, complete=false", r.get("pending_total") == 200 and r.get("complete") is False and len(r.get("events", [])) == 5, {k: r.get(k) for k in ("pending_total", "complete", "error")})
with_fake("heartbeat", 7182, t_hb); with_fake("slowjson", 7183, t_slow); with_fake("nonewline", 7184, t_nonl)
with_fake("page2hang", 7185, t_p2hang); with_fake("page2err", 7186, t_p2err)
def t_auth(label):
    r, dt = timed({"timeout_s": 3})
    check(label + " produces an immediate tool error", "__error__" in r and dt < 1.5, round(dt, 2))
for i, mode in enumerate(("auth401", "auth403", "stream401", "stream403")):
    with_fake(mode, 7186 + i, lambda mode=mode: t_auth(mode))
def t_ready_race():
    r, dt = timed({"timeout_s": 3})
    check("ready recheck recovers subscription-window task", r.get("pending_total") == 1 and not r.get("timed_out") and dt < 1.5)
with_fake("ready_race", 7190, t_ready_race)
print(f"{sum(ok)}/{len(ok)} passed"); sys.exit(0 if all(ok) else 1)
