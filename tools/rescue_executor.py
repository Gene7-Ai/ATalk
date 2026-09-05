#!/usr/bin/env python3
"""ATalk rescue-executor: a whitelist-driven sidecar that runs recovery actions on
behalf of a peer whose own agent is down. Only whitelisted services, logs and
endpoints may be touched (see examples/rescue-whitelist.example.json).

It consumes type='command' events addressed to this agent with op=rescue.*, runs them subject to a whitelist, replies with the result plus rollback info, and sends an applied ACK.
Three gates: server-side grant (source authority) -> this executor's whitelist (target control) -> full auditing (server audit log + local log + reply trail).
Read-only by default; state-changing ops (restart/switch) only run the mapped command from the whitelist. Recovery runs on behalf of a peer whose agent is down; see README and examples/.

Usage: python3 rescue_executor.py --agent <me> --token <tok> --api http://HOST:PORT \
        --whitelist /etc/atalk/rescue-whitelist.json [--once] [--interval 10]
"""
import argparse
import json
import os
import subprocess
import time
import urllib.parse
import urllib.request
import uuid

RESCUE_OPS = {"rescue.health", "rescue.logs", "rescue.switch_endpoint",
              "rescue.restart_service", "rescue.takeover", "rescue.report"}


def api(base, path, token, payload=None, timeout=8):
    url = base.rstrip("/") + path
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, headers={
        "Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=timeout))


def sh(cmd, timeout=20):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).strip()[:2000]


def handle(op, p, wl):
    """Return (ok, result_dict). State-changing ops include rollback info."""
    if op == "rescue.health":
        _, up = sh("uptime")
        _, disk = sh("df -h / | tail -1")
        return True, {"uptime": up, "disk_root": disk}
    if op == "rescue.logs":
        path = p.get("path")
        if path not in (wl.get("logs") or []):
            return False, {"refused": f"log path not whitelisted: {path}", "whitelisted": wl.get("logs")}
        n = min(int(p.get("lines") or 50), 500)
        _, out = sh(f"tail -n {n} '{path}'")
        return True, {"path": path, "tail": out}
    if op == "rescue.switch_endpoint":
        kind, to = p.get("kind"), p.get("to")
        allowed = (wl.get("endpoints") or {}).get(kind) or []
        if to not in allowed:
            return False, {"refused": f"endpoint not whitelisted: {kind}->{to}", "whitelisted": allowed}
        state_file = wl["endpoint_state"]
        try:
            old = json.load(open(state_file)).get(kind)
        except Exception:
            old = None
        state = {}
        try:
            state = json.load(open(state_file))
        except Exception:
            pass
        state[kind] = to
        json.dump(state, open(state_file, "w"))
        return True, {"kind": kind, "old": old, "new": to, "rollback": f"switch back to {old}"}
    if op == "rescue.restart_service":
        svc = p.get("service")
        cmd = (wl.get("services") or {}).get(svc)
        if not cmd:
            return False, {"refused": f"service not whitelisted: {svc}", "whitelisted": list((wl.get("services") or {}).keys())}
        rc, out = sh(cmd)
        return rc == 0, {"service": svc, "rc": rc, "out": out, "rollback": "service was restarted; stop it to revert"}
    if op == "rescue.takeover":
        # Takeover request reuses the task convention: create a handoff task for the
        # target agent rather than seizing control directly.
        return True, {"takeover_task": {
            "task_id": str(uuid.uuid4()), "op": "create",
            "title": f"takeover request: {p.get('what') or 'unspecified'}",
            "assignee": p.get("to"), "context": p.get("why")}}
    if op == "rescue.report":
        return True, {"report_target": wl.get("report_to") or "owner", "summary": p.get("summary") or "(empty)"}
    return False, {"refused": f"unknown rescue op {op}"}


def drain(args, wl, localog):
    events = api(args.api, f"/events?target={urllib.parse.quote(args.agent)}&state=pending&limit=200", args.token)
    done = 0
    for ev in events:
        p = ev.get("payload") or {}
        if ev.get("type") != "command" or not str(p.get("op", "")).startswith("rescue."):
            continue
        eid, op = ev["event_id"], p["op"]
        ok, result = (False, {"refused": f"op not in executor allowlist: {op}"}) if op not in RESCUE_OPS \
            else handle(op, p, wl)
        # Persist side-effecting results: takeover emits a task event, report emits a message.
        if ok and op == "rescue.takeover" and result.get("takeover_task", {}).get("assignee"):
            t = result["takeover_task"]
            api(args.api, "/events", args.token, {
                "source": args.agent, "target": t["assignee"], "type": "task",
                "payload": {"task_id": t["task_id"], "op": "create", "title": t["title"],
                            "assignee": t["assignee"], "context": t.get("context")}})
        if ok and op == "rescue.report":
            api(args.api, "/events", args.token, {
                "source": args.agent, "target": result["report_target"], "type": "message",
                "payload": {"text": f"[rescue.report] {result['summary']}"}})
        reply_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"rescue-reply:{eid}:{args.agent}"))
        api(args.api, "/events", args.token, {
            "source": args.agent, "target": ev["source"], "type": "reply", "event_id": reply_id,
            "payload": {"in_reply_to": eid, "text": json.dumps(
                {"op": op, "ok": ok, "result": result}, ensure_ascii=False)}})
        api(args.api, "/ack", args.token, {"agent_id": args.agent, "event_id": eid, "ack_type": "applied"})
        line = json.dumps({"ts": time.strftime("%FT%T"), "event_id": eid, "op": op, "ok": ok}, ensure_ascii=False)
        with open(localog, "a") as f:
            f.write(line + "\n")
        done += 1
    return done


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent", required=True)
    ap.add_argument("--token", default=os.environ.get("ATALK_TOKEN"),
                    help="defaults to env ATALK_TOKEN (recommended: argv is visible in the process list)")
    ap.add_argument("--api", required=True)
    ap.add_argument("--whitelist", required=True)
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--interval", type=int, default=10)
    args = ap.parse_args()
    if not args.token:
        ap.error("no token: pass --token or set ATALK_TOKEN")
    wl = json.load(open(args.whitelist))
    localog = wl.get("audit_log") or "/tmp/rescue-executor-audit.jsonl"
    if args.once:
        print(f"processed={drain(args, wl, localog)}")
        return
    while True:
        try:
            drain(args, wl, localog)
        except Exception as exc:
            print(f"drain error: {exc}", flush=True)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
