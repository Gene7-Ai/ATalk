from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .core import AtalkStore, event_to_dict
from .raftsql import RaftSQLStore


def default_db() -> Path:
    return Path(os.environ.get("ATALK_DB", "data/atalk.db"))


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="atalk")
    parser.add_argument("--db", default=str(default_db()))
    parser.add_argument("--backend", choices=("sqlite", "rqlite"), default="sqlite")
    parser.add_argument("--rqlite-endpoints", default=os.environ.get("ATALK_RQLITE_ENDPOINTS", ""))
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init")

    peer = sub.add_parser("peer-add")
    peer.add_argument("peer_id")
    peer.add_argument("--token")
    peer.add_argument("--role")
    peer.add_argument("--platform")
    peer.add_argument("--endpoint")
    peer.add_argument("--delivery-class", choices=["fast", "normal", "slow"], default="normal")
    peer.add_argument("--ack-timeout-sec", type=int, default=180)

    rotate = sub.add_parser("peer-rotate")
    rotate.add_argument("peer_id")
    rotate.add_argument("--token")
    rotate.add_argument("--grace-seconds", type=int, default=300)

    device = sub.add_parser("device-token")
    device_sub = device.add_subparsers(dest="device_cmd", required=True)
    device_add = device_sub.add_parser("add")
    device_add.add_argument("peer_id")
    device_add.add_argument("--label", required=True)
    device_add.add_argument("--scope", choices=("full", "notify"), default="full")
    device_add.add_argument("--token")
    device_add.add_argument("--actor", default=os.environ.get("ATALK_OPERATOR", "cli-operator"))
    device_list = device_sub.add_parser("list")
    device_list.add_argument("peer_id")
    device_revoke = device_sub.add_parser("revoke")
    device_revoke.add_argument("token_id")
    device_revoke.add_argument("--actor", default=os.environ.get("ATALK_OPERATOR", "cli-operator"))

    grant = sub.add_parser("grant-add")
    grant.add_argument("--grantor", required=True, help="target peer authorizing the command")
    grant.add_argument("--grantee", required=True, help="source peer receiving authority")
    grant.add_argument("--command", required=True)
    grant.add_argument("--scope-json", default="{}")
    grant.add_argument("--valid-until")

    revoke = sub.add_parser("grant-revoke")
    revoke.add_argument("grant_id", type=int)

    acl_set = sub.add_parser("acl-set")
    acl_set.add_argument("--peer", required=True)
    acl_set.add_argument("--allow", action="append", default=[])
    acl_list = sub.add_parser("acl-list")
    acl_list.add_argument("--peer")
    acl_clear = sub.add_parser("acl-clear")
    acl_clear.add_argument("--peer", required=True)

    send = sub.add_parser("send")
    send.add_argument("--from", dest="source", required=True)
    send.add_argument("--to", dest="target", required=True)
    send.add_argument("--type", default="message")
    send.add_argument("--op", help="command operation (payload.op); required for --type command")
    send.add_argument("--payload-json", dest="payload_json",
                      help="full payload as a JSON object; merged under --op/--text")
    send.add_argument("--seq", type=int)
    send.add_argument("--event-id")
    send.add_argument("--source-ref")
    send.add_argument("--token")
    send.add_argument("text", nargs="?")

    inbox = sub.add_parser("inbox")
    inbox.add_argument("--agent", required=True)
    inbox.add_argument("--since-id", type=int, default=0)
    inbox.add_argument("--limit", type=int, default=50)

    ack = sub.add_parser("ack")
    ack.add_argument("--event", required=True)
    ack.add_argument("--agent", required=True)
    ack.add_argument("--type", choices=["received", "applied"], required=True)

    acks = sub.add_parser("acks")
    acks.add_argument("--event", required=True)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    if args.backend == "rqlite":
        endpoints = [e.strip() for e in (args.rqlite_endpoints or "").split(",") if e.strip()]
        if not endpoints:
            print(json.dumps({"error": "--rqlite-endpoints (or ATALK_RQLITE_ENDPOINTS) required for rqlite backend"}))
            return 2
        if args.cmd == "init":
            print(json.dumps({"error": "init not supported on rqlite backend (schema managed by server deployment)"}))
            return 2
        store = RaftSQLStore(endpoints, initialize=False)
    else:
        store = AtalkStore(args.db)

    if args.cmd == "init":
        print(json.dumps({"ok": True, "db": str(Path(args.db).resolve())}, ensure_ascii=False))
        return 0

    if args.cmd == "peer-add":
        token = store.add_peer(
            args.peer_id, args.token, args.role, args.platform, args.endpoint,
            args.delivery_class, args.ack_timeout_sec,
        )
        print(json.dumps({"peer_id": args.peer_id, "token": token}, ensure_ascii=False))
        return 0

    if args.cmd == "peer-rotate":
        token = store.rotate_peer_token(args.peer_id, args.token, args.grace_seconds)
        print(json.dumps({"peer_id": args.peer_id, "token": token, "grace_seconds": args.grace_seconds}, ensure_ascii=False))
        return 0

    if args.cmd == "device-token":
        if args.device_cmd == "add":
            result = store.add_device_token(
                args.peer_id, args.label, token=args.token, scope=args.scope, actor=args.actor
            )
            print(json.dumps(result, ensure_ascii=False))
            return 0
        if args.device_cmd == "list":
            print(json.dumps(store.list_device_tokens(args.peer_id), ensure_ascii=False))
            return 0
        if args.device_cmd == "revoke":
            print(json.dumps(store.revoke_device_token(args.token_id, actor=args.actor), ensure_ascii=False))
            return 0

    if args.cmd == "grant-add":
        grant_id = store.add_grant(
            args.grantor, args.grantee, args.command, json.loads(args.scope_json), args.valid_until
        )
        print(json.dumps({"grant_id": grant_id, "ok": True}, ensure_ascii=False))
        return 0

    if args.cmd == "grant-revoke":
        store.revoke_grant(args.grant_id)
        print(json.dumps({"grant_id": args.grant_id, "revoked": True}, ensure_ascii=False))
        return 0

    if args.cmd == "acl-set":
        store.set_target_acl(args.peer, args.allow)
        print(json.dumps(store.list_target_acls(args.peer)[0], ensure_ascii=False))
        return 0
    if args.cmd == "acl-list":
        print(json.dumps(store.list_target_acls(args.peer), ensure_ascii=False))
        return 0
    if args.cmd == "acl-clear":
        store.clear_target_acl(args.peer)
        print(json.dumps({"peer_id": args.peer, "mode": "unrestricted", "allowed_targets": []}, ensure_ascii=False))
        return 0

    if args.cmd == "send":
        payload: dict = {}
        if args.payload_json:
            payload = json.loads(args.payload_json)
            if not isinstance(payload, dict):
                raise SystemExit("--payload-json must be a JSON object")
        if args.op:
            payload["op"] = args.op
        if args.text is not None:
            payload["text"] = args.text
        if not payload:
            payload = {"text": ""}
        if args.type == "command" and not str(payload.get("op", "")).strip():
            raise SystemExit("--type command requires --op (or an 'op' field in --payload-json)")
        event = store.insert_event(
            args.source,
            args.target,
            args.type,
            payload,
            seq=args.seq,
            event_id=args.event_id,
            source_ref=args.source_ref,
            token=args.token,
        )
        print(json.dumps(event_to_dict(event), ensure_ascii=False))
        return 0

    if args.cmd == "inbox":
        events = store.list_events(args.agent, args.since_id, args.limit)
        print(json.dumps([event_to_dict(e) for e in events], ensure_ascii=False))
        return 0

    if args.cmd == "ack":
        store.ack(args.event, args.agent, args.type)
        print(json.dumps({"ok": True, "event_id": args.event, "agent_id": args.agent, "ack_type": args.type}, ensure_ascii=False))
        return 0

    if args.cmd == "acks":
        print(json.dumps(store.acks_for(args.event), ensure_ascii=False))
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
