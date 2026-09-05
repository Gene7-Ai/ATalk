from __future__ import annotations

import argparse
import json
import os
import uuid
from pathlib import Path

from .adapter import AtalkClient, InboxStore


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="atalk-inbox")
    parser.add_argument("--base-url", default=os.environ.get("ATALK_URL", "http://127.0.0.1:7070"))
    parser.add_argument("--agent", default=os.environ.get("ATALK_AGENT"), required=os.environ.get("ATALK_AGENT") is None)
    parser.add_argument("--token", default=os.environ.get("ATALK_TOKEN"))
    parser.add_argument("--root", required=True)
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list")
    show = sub.add_parser("show")
    show.add_argument("event_id")
    apply = sub.add_parser("apply")
    apply.add_argument("event_id")
    reply = sub.add_parser("reply")
    reply.add_argument("event_id")
    reply.add_argument("text")
    return parser


def summary(event: dict) -> dict:
    payload = event.get("payload") or {}
    return {
        "id": event.get("id"),
        "event_id": event.get("event_id"),
        "source": event.get("source"),
        "type": event.get("type"),
        "created_at": event.get("created_at"),
        "text_preview": str(payload.get("text", ""))[:120],
    }


def main(argv: list[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    store = InboxStore(args.root)

    if args.cmd == "list":
        print(json.dumps([summary(item) for item in store.list_pending()], ensure_ascii=False, indent=2))
        return 0

    path = store.find(args.event_id, include_applied=args.cmd == "show")
    event = json.loads(path.read_text(encoding="utf-8"))
    if args.cmd == "show":
        print(json.dumps(event, ensure_ascii=False, indent=2))
        return 0

    if not args.token:
        raise SystemExit("ATALK_TOKEN or --token is required")
    client = AtalkClient(args.base_url, args.agent, args.token)
    if args.cmd == "reply":
        reply_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"atalk:{event['event_id']}:reply:{args.agent}"))
        client.send(
            event["source"],
            "reply",
            {"text": args.text, "in_reply_to": event["event_id"]},
            source_ref=f"atalk:{event['event_id']}",
            event_id=reply_id,
        )
    client.ack(event["event_id"], "applied", {"delivery": "local_inbox"})
    store.mark_applied(event["event_id"])
    print(json.dumps({"ok": True, "event_id": event["event_id"], "action": args.cmd}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
