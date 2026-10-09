"""ATalk MCP server — join an ATalk bus from an MCP client as a normal peer.

Env: ATALK_URL (e.g. http://127.0.0.1:7070), ATALK_AGENT (peer id), ATALK_TOKEN (peer bearer token).

Design notes (reviewed v4, with integration fixes):
- No local cursor. "What do I still owe?" is answered by the server's per-target pending state
  (events without your `applied` ack), paged to the end. Out-of-order `applied` therefore can't hide older work.
- Replies are idempotent per content: event_id = uuid5(agent, target, in_reply_to, text) unless you pass
  `idempotency_key`. Retrying the same reply never duplicates; a progress note and a final answer are distinct events.
  After every send the stored payload is compared with what was sent; a mismatch is reported as an error.
- atalk_wait checks pending first, re-checks after the stream is ready, and enforces a total deadline.
- `applied` is the receiver's own report of completion, not a quality check; receipts return any `detail` evidence.
"""
import asyncio, json, os, time, uuid
import httpx
try:  # mcp >= 2
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server

URL = os.environ.get("ATALK_URL", "http://127.0.0.1:7070").rstrip("/")
AGENT = os.environ.get("ATALK_AGENT", "")
TOKEN = os.environ.get("ATALK_TOKEN", "")
H = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}
PAGE = 200

mcp = _Server("atalk", instructions=(
    "ATalk is a message bus between agents. atalk_inbox lists work addressed to you that you have not marked applied. "
    "Ack 'received' before working, reply with atalk_send(target, text, in_reply_to=event_id), then ack 'applied'. "
    "atalk_receipts shows whether a peer received/applied what you sent."))

def _get(path: str, params: dict) -> list | dict:
    return _get_t(path, params, None)

def _brief(ev: dict) -> dict:
    return {"id": ev["id"], "event_id": ev["event_id"], "from": ev["source"], "type": ev["type"],
            "payload": ev.get("payload", {}), "created_at": ev.get("created_at")}

def _get_t(path: str, params: dict, deadline: float | None) -> list | dict:
    t = 15.0 if deadline is None else max(0.2, min(15.0, deadline - time.monotonic()))
    r = httpx.get(f"{URL}{path}", headers=H, params=params, timeout=t); r.raise_for_status(); return r.json()

@mcp.tool()
def atalk_send(target: str, text: str, type: str = "message", in_reply_to: str | None = None,
               idempotency_key: str | None = None) -> dict:
    """Send a message/task (target='*' broadcasts). Replies (in_reply_to set) are idempotent per content;
    pass idempotency_key to make any send safely retryable. Returns the stored event_id."""
    payload = {"text": text}
    if in_reply_to: payload["in_reply_to"] = in_reply_to
    if idempotency_key:
        eid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"atalk-mcp:{AGENT}:key:{idempotency_key}"))
    elif in_reply_to:
        eid = str(uuid.uuid5(uuid.NAMESPACE_URL, json.dumps(["atalk-mcp-reply", AGENT, target, in_reply_to, text])))
    else:
        eid = str(uuid.uuid4())
    r = httpx.post(f"{URL}/events", headers=H, json={"source": AGENT, "target": target,
                   "type": "reply" if in_reply_to else type, "event_id": eid, "payload": payload}, timeout=15)
    if r.status_code == 409:
        raise ValueError(f"event_id {eid} already holds different content (idempotency key reused for a different message)")
    r.raise_for_status(); ev = r.json()
    if ev.get("payload") != payload or ev.get("target") != target:
        raise ValueError(f"stored event {ev.get('event_id')} does not match what was sent")
    return {"event_id": ev["event_id"], "id": ev["id"]}

@mcp.tool()
def atalk_inbox(limit: int = 50, after_id: int = 0) -> dict:
    """Work addressed to you that you have not marked applied, oldest first. pending_total counts pending events after after_id across all pages;
    when complete=false it is only the count observed so far.
    Returns up to `limit` events after `after_id`; continue with after_id=next_after_id.
    If a later page fails, what was already read is returned with complete=false and the error."""
    total, kept, since, err = 0, [], after_id, None
    keep = max(1, limit)
    try:
        while True:
            page = _get_t("/events", {"target": AGENT, "since_id": since, "limit": PAGE, "state": "pending"}, None)
            if not page: break
            total += len(page)
            if len(kept) < keep: kept += page[: keep - len(kept)]
            since = page[-1]["id"]
            if len(page) < PAGE: break
    except (httpx.HTTPError, ValueError) as e:
        if not kept: raise
        err = f"{type(e).__name__}: {e}"
    out = {"pending_total": total, "events": [_brief(e) for e in kept], "next_after_id": kept[-1]["id"] if kept else after_id,
           "more": total > len(kept) or err is not None, "complete": err is None}
    if err: out["error"] = err
    return out

@mcp.tool()
def atalk_history(since_id: int = 0, limit: int = 50) -> dict:
    """Your full history (including applied), one page at a time. Use next_since_id to continue."""
    page = _get("/events", {"target": AGENT, "since_id": since_id, "limit": max(1, min(limit, PAGE)), "state": "all"})
    return {"events": [_brief(e) for e in page], "next_since_id": page[-1]["id"] if page else since_id}

@mcp.tool()
def atalk_ack(event_id: str, ack_type: str, detail: str | None = None) -> dict:
    """'received' = stored, not done yet; 'applied' = you finished it (it leaves your inbox).
    `detail` can carry evidence, e.g. a result hash or a link."""
    if ack_type not in ("received", "applied"):
        raise ValueError("ack_type must be 'received' or 'applied'")
    body = {"agent_id": AGENT, "event_id": event_id, "ack_type": ack_type}
    if detail: body["detail"] = {"note": detail}
    r = httpx.post(f"{URL}/ack", headers=H, json=body, timeout=15); r.raise_for_status()
    return {"ok": True}

@mcp.tool()
def atalk_receipts(event_id: str) -> dict:
    """Receipts for an event you sent or received: who acked received/applied, when, and any detail."""
    rows = _get("/acks", {"event_id": event_id, "agent": AGENT})
    out = []
    for a in rows:
        d = a.get("detail_json")
        try: d = json.loads(d) if isinstance(d, str) else d
        except ValueError: pass
        out.append({"by": a["agent_id"], "ack": a["ack_type"], "at": a["ack_at"], "detail": d or None})
    return {"receipts": out}

@mcp.tool()
async def atalk_wait(timeout_s: int = 60) -> dict:
    """Scan existing pending work without waiting for a new wake signal, or wait until the deadline (max 600s).
    The deadline is absolute: the whole wait (paging, connecting, reading the stream) runs under one cancellable
    timer, so slow bodies or heartbeats can't extend it. Work found before the deadline is returned even if the
    scan didn't finish (complete=false)."""
    budget = max(1, min(timeout_s, 600))
    found: dict = {"total": 0, "events": [], "complete": True}

    async def scan(client) -> bool:
        found.update(total=0, events=[], complete=False)
        since = 0
        while True:
            r = await client.get(f"{URL}/events", headers=H, params={"target": AGENT, "since_id": since, "limit": PAGE, "state": "pending"})
            r.raise_for_status(); page = r.json()
            if not page: break
            found["total"] += len(page)
            if len(found["events"]) < 50: found["events"] += page[: 50 - len(found["events"])]
            since = page[-1]["id"]
            if len(page) < PAGE: break
        found["complete"] = True
        return found["total"] > 0

    async def body():
        async with httpx.AsyncClient(timeout=None) as client:
            while True:
                try:
                    if await scan(client): return
                    async with client.stream("GET", f"{URL}/stream", headers=H, params={"agent": AGENT}) as st:
                        st.raise_for_status()
                        async for line in st.aiter_lines():
                            if not line.startswith("data:"): continue
                            kind = json.loads(line[5:]).get("kind")
                            if kind == "event": break
                            if kind == "ready" and await scan(client): return   # close the subscribe race
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code in (401, 403):
                        # Permanent authorization failures must not masquerade as an empty timed-out wait.
                        raise ValueError(f"ATalk authorization failed (HTTP {exc.response.status_code}); check peer/token and permissions") from exc
                    if found["events"]: return
                    await asyncio.sleep(0.5)
                except httpx.HTTPError:
                    if found["events"]: return                                    # keep what we already found
                    await asyncio.sleep(0.5)

    try:
        await asyncio.wait_for(body(), timeout=budget)
        timed_out = False
    except asyncio.TimeoutError:
        timed_out = True
    has = bool(found["events"])
    return {"pending_total": found["total"], "events": [_brief(e) for e in found["events"]],
            "complete": found["complete"], "timed_out": timed_out and not has}

def main() -> None:
    if not AGENT or not TOKEN:
        raise SystemExit("set ATALK_AGENT and ATALK_TOKEN (and ATALK_URL)")
    mcp.run("stdio")

if __name__ == "__main__":
    main()
