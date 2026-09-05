#!/usr/bin/env python3
"""ATalk tasklib: folds a task event-log into current task state
(create -> accept -> start <-> block -> handoff -> complete). The ledger is the
source of truth and completion must be verifiable.

State is a pure function of the ledger: current task state = a fold over the type='task' event stream in ledger order.
There is no separate task database; anyone can recompute and reconcile state with this library. The ledger is the source of truth; see README.
Usage:
  python3 tasklib.py --rqlite http://HOST:PORT [--task TASK_ID] [--json]
  (or import fold to process a list of event dicts from any source)
"""
import argparse
import json
import sys
import urllib.parse
import urllib.request

PENDING, ACCEPTED, IN_PROGRESS, WAITING = "pending", "accepted", "in_progress", "waiting"
COMPLETED, FAILED, CANCELLED = "completed", "failed", "cancelled"
TERMINAL = {COMPLETED, FAILED, CANCELLED}
OPS = {"create", "accept", "start", "update", "block", "handoff",
       "deliver", "verify", "complete", "fail", "cancel"}


def _anom(task, ev, why):
    task.setdefault("anomalies", []).append(
        {"event_id": ev.get("event_id"), "ledger_id": ev.get("id"), "op": (ev.get("payload") or {}).get("op"), "why": why})


def _hist(task, ev, note=None):
    p = ev.get("payload") or {}
    task["history"].append({
        "ledger_id": ev.get("id"), "event_id": ev.get("event_id"), "actor": ev.get("source"),
        "op": p.get("op"), "at": ev.get("created_at"), "note": note or p.get("note")})
    task["updated_at"] = ev.get("created_at")


def fold(events):
    """events: a list of dicts (each with id, event_id, source, created_at, payload). Returns {task_id: state_dict}."""
    tasks = {}
    for ev in sorted(events, key=lambda e: e["id"]):
        p = ev.get("payload") or {}
        tid, op = p.get("task_id"), p.get("op")
        if not tid or op not in OPS:
            continue
        t = tasks.get(tid)
        if op == "create":
            if t is not None:
                _anom(t, ev, "duplicate create ignored")
                continue
            if not p.get("title") or not p.get("assignee"):
                tasks[tid] = t = {"task_id": tid, "status": None, "history": [], "anomalies": []}
                _anom(t, ev, "create missing title/assignee — task not opened")
                continue
            tasks[tid] = t = {
                "task_id": tid, "title": p["title"], "context": p.get("context"),
                "initiator": ev.get("source"), "assignee": p["assignee"],
                "participants": p.get("participants") or [ev.get("source"), p["assignee"]],
                "status": PENDING, "priority": p.get("priority"), "deadline": p.get("deadline"),
                "deps": p.get("deps") or [], "blocked_reason": None, "next_action": p.get("next_action"),
                "deliverable": None, "verification": None,
                "history": [], "anomalies": [], "created_at": ev.get("created_at"), "updated_at": None}
            _hist(t, ev)
            continue
        if t is None or t.get("status") is None:
            if t is None:
                tasks[tid] = t = {"task_id": tid, "status": None, "history": [], "anomalies": []}
            _anom(t, ev, f"op {op} before valid create")
            continue
        st = t["status"]
        if st in TERMINAL:
            _anom(t, ev, f"op {op} after terminal state {st}")
            continue
        src = ev.get("source")
        if op == "accept":
            if src != t["assignee"]:
                _anom(t, ev, f"accept by {src}, assignee is {t['assignee']}")
            elif st != PENDING:
                _anom(t, ev, f"accept from {st}")
            else:
                t["status"] = ACCEPTED
                _hist(t, ev)
        elif op == "start":
            if st in (ACCEPTED, WAITING):
                t["status"] = IN_PROGRESS
                t["blocked_reason"] = None
                _hist(t, ev)
            else:
                _anom(t, ev, f"start from {st}")
        elif op == "block":
            if st in (ACCEPTED, IN_PROGRESS):
                t["status"] = WAITING
                t["blocked_reason"] = p.get("reason") or "unspecified"
                _hist(t, ev)
            else:
                _anom(t, ev, f"block from {st}")
        elif op == "update":
            for k in ("next_action", "priority", "deadline", "context"):
                if p.get(k) is not None:
                    t[k] = p[k]
            _hist(t, ev)
        elif op == "deliver":
            if not p.get("deliverable"):
                _anom(t, ev, "deliver without deliverable")
            else:
                t["deliverable"] = p["deliverable"]
                _hist(t, ev)
        elif op == "verify":
            if not p.get("verification"):
                _anom(t, ev, "verify without verification")
            else:
                t["verification"] = p["verification"]
                _hist(t, ev)
        elif op == "handoff":
            to = p.get("to")
            if not to:
                _anom(t, ev, "handoff without to")
            else:
                _hist(t, ev, note=f"handoff {t['assignee']} -> {to}: {p.get('note') or ''}")
                t["assignee"] = to
                t["status"] = PENDING
                if to not in t["participants"]:
                    t["participants"].append(to)
        elif op == "complete":
            deliverable = p.get("deliverable") or t.get("deliverable")
            verification = p.get("verification") or t.get("verification")
            if st != IN_PROGRESS:
                _anom(t, ev, f"complete from {st}")
            elif not deliverable or not verification:
                _anom(t, ev, "complete without deliverable+verification — status NOT advanced")
            else:
                t["deliverable"], t["verification"] = deliverable, verification
                t["status"] = COMPLETED
                _hist(t, ev)
        elif op == "fail":
            if not p.get("reason"):
                _anom(t, ev, "fail without reason")
            else:
                t["status"] = FAILED
                t["blocked_reason"] = p["reason"]
                _hist(t, ev)
        elif op == "cancel":
            t["status"] = CANCELLED
            _hist(t, ev, note=p.get("reason"))
    return tasks


def fetch_rqlite(base, timeout=6):
    """Query all task events directly from rqlite (for ops/reconciliation; agents can feed the atalk API event stream to fold instead)."""
    sql = "SELECT id,event_id,source,target,created_at,payload_json FROM events WHERE type='task' ORDER BY id"
    url = base.rstrip("/") + "/db/query?level=strong&q=" + urllib.parse.quote(sql)
    rows = json.load(urllib.request.urlopen(url, timeout=timeout))["results"][0].get("values", [])
    return [{"id": r[0], "event_id": r[1], "source": r[2], "target": r[3],
             "created_at": r[4], "payload": json.loads(r[5] or "{}")} for r in rows]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rqlite", required=True, help="rqlite base URL, e.g. http://127.0.0.1:24001")
    ap.add_argument("--task", help="show only this task_id")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    tasks = fold(fetch_rqlite(args.rqlite))
    if args.task:
        tasks = {k: v for k, v in tasks.items() if k == args.task}
    if args.json:
        print(json.dumps(tasks, ensure_ascii=False, indent=2))
        return
    for t in tasks.values():
        print(f"[{t.get('status')}] {t['task_id']} {t.get('title','?')} assignee={t.get('assignee')} "
              f"deliverable={'yes' if t.get('deliverable') else 'no'} anomalies={len(t.get('anomalies') or [])}")


if __name__ == "__main__":
    main()
