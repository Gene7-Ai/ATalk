import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from atalk.adapter import (
    Adapter,
    AtalkClient,
    Cursor,
    InboxAdapter,
    InboxStore,
    OpenClawTaskStore,
    find_reply,
    openclaw_handler,
    chat_http_handler,
    parse_openclaw_outcome,
)
from atalk.core import AtalkStore
from atalk.server import AtalkHTTPServer, WakeHub


class FakeChatHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length))
        raw = json.dumps({"reply": f"chat heard: {body['message']}"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, fmt, *args):
        return


class AdapterRoundtripTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = AtalkStore(Path(self.tmp.name) / "atalk.db")
        self.atalk = AtalkHTTPServer(("127.0.0.1", 0), self.store, WakeHub())
        self.atalk_thread = threading.Thread(target=self.atalk.serve_forever, daemon=True)
        self.atalk_thread.start()
        self.base = f"http://127.0.0.1:{self.atalk.server_address[1]}"
        self.chat_srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeChatHandler)
        self.chat_thread = threading.Thread(target=self.chat_srv.serve_forever, daemon=True)
        self.chat_thread.start()
        self.chat_url = f"http://127.0.0.1:{self.chat_srv.server_address[1]}/chat"

    def tearDown(self):
        self.atalk.shutdown()
        self.chat_srv.shutdown()
        self.atalk_thread.join(timeout=2)
        self.chat_thread.join(timeout=2)
        self.atalk.server_close()
        self.chat_srv.server_close()
        self.tmp.cleanup()

    def test_alice_bob_alice_roundtrip_and_cursor(self):
        alice = AtalkClient(self.base, "alice")
        sent = alice.send("bob", "message", {"text": "hello"})
        cursor_path = Path(self.tmp.name) / "bob-state.json"
        bob = AtalkClient(self.base, "bob")
        adapter = Adapter(bob, Cursor.load(cursor_path), chat_http_handler(bob, self.chat_url))
        self.assertEqual(adapter.run_once(), 1)
        self.assertEqual(adapter.run_once(), 0)

        replies = alice.events(0)
        self.assertEqual(len(replies), 1)
        self.assertEqual(replies[0]["payload"]["text"], "chat heard: hello")
        self.assertEqual(replies[0]["payload"]["in_reply_to"], sent["event_id"])
        self.assertEqual({ack["ack_type"] for ack in self.store.acks_for(sent["event_id"])}, {"received", "applied"})
        self.assertEqual(json.loads(cursor_path.read_text())["since_id"], sent["id"])

    def test_retry_does_not_duplicate_correlated_reply(self):
        alice = AtalkClient(self.base, "alice")
        sent = alice.send("bob", "message", {"text": "again"})
        bob = AtalkClient(self.base, "bob")
        handler = chat_http_handler(bob, self.chat_url)
        event = bob.events(0)[0]
        handler(event)
        handler(event)
        replies = alice.events(0)
        self.assertEqual(len(replies), 1)
        self.assertEqual(replies[0]["payload"]["in_reply_to"], sent["event_id"])

    def test_openclaw_reply_parser(self):
        value = {"result": {"payloads": [{"text": "CHAT_OK"}]}}
        self.assertEqual(find_reply(value), "CHAT_OK")

    def test_openclaw_outcome_is_required_and_removed_from_visible_reply(self):
        self.assertEqual(
            parse_openclaw_outcome("review queued\nATALK_APPLY: waiting"),
            ("review queued", "waiting"),
        )
        with self.assertRaisesRegex(RuntimeError, "omitted required"):
            parse_openclaw_outcome("I will do it later")

    @patch("atalk.adapter.subprocess.run")
    def test_openclaw_waiting_is_durable_and_not_applied(self, run):
        run.return_value.returncode = 0
        run.return_value.stdout = json.dumps(
            {"result": {"payloads": [{"text": "waiting for revision\nATALK_APPLY: waiting"}]}}
        ).encode()
        run.return_value.stderr = b""
        sender = AtalkClient(self.base, "carol")
        sent = sender.send("alice", "message", {"text": "review this patch"})
        client = AtalkClient(self.base, "alice")
        store = OpenClawTaskStore(Path(self.tmp.name) / "tasks.json")
        adapter = Adapter(
            client,
            Cursor.load(Path(self.tmp.name) / "alice-state.json"),
            openclaw_handler(client, "/usr/bin/openclaw", task_store=store),
        )

        self.assertEqual(adapter.run_once(), 1)
        self.assertEqual(
            {ack["ack_type"] for ack in self.store.acks_for(sent["event_id"])},
            {"received"},
        )
        self.assertEqual(next(iter(store.pending().values()))["status"], "waiting")
        command = run.call_args.args[0]
        self.assertEqual(command[command.index("--session-id") + 1], "atalk-carol")

    @patch("atalk.adapter.subprocess.run")
    def test_openclaw_followup_reuses_session_and_completes_pending_events(self, run):
        responses = iter(
            [
                "revision requested\nATALK_APPLY: waiting",
                "re-review passed\nATALK_APPLY: complete",
            ]
        )

        def fake_run(*_args, **_kwargs):
            result = type("Result", (), {})()
            result.returncode = 0
            result.stdout = json.dumps(
                {"result": {"payloads": [{"text": next(responses)}]}}
            ).encode()
            result.stderr = b""
            return result

        run.side_effect = fake_run
        sender = AtalkClient(self.base, "carol")
        first = sender.send("alice", "message", {"text": "review v1"})
        client = AtalkClient(self.base, "alice")
        store = OpenClawTaskStore(Path(self.tmp.name) / "tasks.json")
        adapter = Adapter(
            client,
            Cursor.load(Path(self.tmp.name) / "alice-state.json"),
            openclaw_handler(client, "/usr/bin/openclaw", task_store=store),
        )
        adapter.run_once()
        second = sender.send("alice", "message", {"text": "revision v2 delivered"})
        adapter.run_once()

        for sent in (first, second):
            self.assertEqual(
                {ack["ack_type"] for ack in self.store.acks_for(sent["event_id"])},
                {"received", "applied"},
            )
        self.assertEqual(store.pending(), {})
        session_ids = [
            call.args[0][call.args[0].index("--session-id") + 1]
            for call in run.call_args_list
        ]
        self.assertEqual(session_ids, ["atalk-carol", "atalk-carol"])

    @patch("atalk.adapter.subprocess.run")
    def test_openclaw_waiting_is_periodically_retried_and_applied(self, run):
        responses = iter(
            [
                "missing file /tmp/revision.diff\nATALK_APPLY: waiting",
                "file arrived; review passed\nATALK_APPLY: complete",
            ]
        )

        def fake_run(*_args, **_kwargs):
            result = type("Result", (), {})()
            result.returncode = 0
            result.stdout = json.dumps(
                {"result": {"payloads": [{"text": next(responses)}]}}
            ).encode()
            result.stderr = b""
            return result

        run.side_effect = fake_run
        sender = AtalkClient(self.base, "carol")
        sent = sender.send("alice", "message", {"text": "review when file arrives"})
        client = AtalkClient(self.base, "alice")
        path = Path(self.tmp.name) / "tasks.json"
        store = OpenClawTaskStore(path)
        handler = openclaw_handler(client, "/usr/bin/openclaw", task_store=store)
        adapter = Adapter(client, Cursor.load(Path(self.tmp.name) / "alice-state.json"), handler)

        adapter.run_once()
        state = json.loads(path.read_text())
        state["threads"]["source:carol"]["next_retry_at"] = 0
        path.write_text(json.dumps(state))
        self.assertEqual(handler.retry_due(), 1)

        self.assertEqual(store.pending(), {})
        self.assertEqual(
            {ack["ack_type"] for ack in self.store.acks_for(sent["event_id"])},
            {"received", "applied"},
        )
        replies = sender.events(0)
        self.assertEqual([item["payload"]["work_status"] for item in replies], ["waiting", "complete"])
        self.assertEqual(run.call_count, 2)

    @patch("atalk.adapter.subprocess.run")
    def test_openclaw_event_driven_wait_does_not_periodically_retry(self, run):
        run.return_value.returncode = 0
        run.return_value.stdout = json.dumps(
            {"result": {"payloads": [{"text": "waiting for revision\nATALK_APPLY: waiting"}]}}
        ).encode()
        run.return_value.stderr = b""
        sender = AtalkClient(self.base, "carol")
        sender.send("alice", "message", {"text": "review when ready"})
        client = AtalkClient(self.base, "alice")
        store = OpenClawTaskStore(Path(self.tmp.name) / "tasks.json")
        handler = openclaw_handler(
            client, "/usr/bin/openclaw", task_store=store, wait_event_driven=True
        )
        adapter = Adapter(client, Cursor.load(Path(self.tmp.name) / "state.json"), handler)

        adapter.run_once()
        self.assertEqual(handler.retry_due(), 0)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(next(iter(store.pending().values()))["status"], "waiting")

    @patch("atalk.adapter.subprocess.run")
    def test_openclaw_event_driven_followup_wakes_once_and_clears_thread(self, run):
        replies = iter([
            "waiting for revision\nATALK_APPLY: waiting",
            "revision accepted\nATALK_APPLY: complete",
        ])
        def fake_run(*_args, **_kwargs):
            result = type("Result", (), {})()
            result.returncode = 0
            result.stdout = json.dumps(
                {"result": {"payloads": [{"text": next(replies)}]}}
            ).encode()
            result.stderr = b""
            return result
        run.side_effect = fake_run
        sender = AtalkClient(self.base, "carol")
        first = sender.send("alice", "message", {"text": "review v1"})
        client = AtalkClient(self.base, "alice")
        store = OpenClawTaskStore(Path(self.tmp.name) / "tasks.json")
        handler = openclaw_handler(
            client, "/usr/bin/openclaw", task_store=store, wait_event_driven=True
        )
        adapter = Adapter(client, Cursor.load(Path(self.tmp.name) / "state.json"), handler)
        adapter.run_once()
        self.assertEqual(handler.retry_due(), 0)
        second = sender.send("alice", "message", {"text": "revision v2"})
        adapter.run_once()

        self.assertEqual(run.call_count, 2)
        self.assertEqual(store.pending(), {})
        for event in (first, second):
            self.assertEqual(
                {ack["ack_type"] for ack in self.store.acks_for(event["event_id"])},
                {"received", "applied"},
            )

    def test_inbox_adapter_durably_receives_without_applying(self):
        sender = AtalkClient(self.base, "alice")
        sent = sender.send("carol", "message", {"text": "internal only"})
        root = Path(self.tmp.name) / "carol-inbox"
        cursor_path = Path(self.tmp.name) / "carol-delivery.json"
        inbox = InboxStore(root)
        adapter = InboxAdapter(AtalkClient(self.base, "carol"), Cursor.load(cursor_path), inbox)

        self.assertEqual(adapter.run_once(), 1)
        self.assertEqual(adapter.run_once(), 0)
        pending = inbox.list_pending()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["event_id"], sent["event_id"])
        self.assertEqual(pending[0]["payload"]["text"], "internal only")
        self.assertEqual(json.loads(cursor_path.read_text())["since_id"], sent["id"])
        self.assertEqual(root.stat().st_mode & 0o777, 0o700)
        self.assertEqual(next((root / "pending").glob("*.json")).stat().st_mode & 0o777, 0o600)

        ack_types = {ack["ack_type"] for ack in self.store.acks_for(sent["event_id"])}
        self.assertEqual(ack_types, {"received"})

    def test_inbox_store_moves_event_only_when_applied(self):
        sender = AtalkClient(self.base, "alice")
        sent = sender.send("dave", "message", {"text": "apply later"})
        inbox = InboxStore(Path(self.tmp.name) / "dave-inbox")
        adapter = InboxAdapter(
            AtalkClient(self.base, "dave"),
            Cursor.load(Path(self.tmp.name) / "dave-delivery.json"),
            inbox,
        )
        adapter.run_once()
        AtalkClient(self.base, "dave").ack(sent["event_id"], "applied", {"delivery": "local_inbox"})
        destination = inbox.mark_applied(sent["event_id"])

        self.assertTrue(destination.exists())
        self.assertEqual(inbox.list_pending(), [])
        ack_types = {ack["ack_type"] for ack in self.store.acks_for(sent["event_id"])}
        self.assertEqual(ack_types, {"received", "applied"})


if __name__ == "__main__":
    unittest.main()
