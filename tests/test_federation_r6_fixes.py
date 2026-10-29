"""Federation r6 fixes (round-5 review residual items 1-5).

1. (MEDIUM) A valid HTTP-date Retry-After means GMT in EVERY accepted form:
   the obsolete asctime form parses as a NAIVE datetime and used to be read
   in the machine's local timezone (TZ=Asia/Singapore honored it 8h early).
2. Persisted retry deadlines CEIL to the persisted whole-second format;
   rounding down could fire the due scan up to one second early.
3. Retry-After delta-seconds is ASCII 1*DIGIT; Unicode isdigit() lookalikes
   ('²', '١٢٣') are ordinary invalid input (backoff), not a crash or a
   silently accepted value.
4. The notification push-scan keyset cursor persists across cycles with
   wraparound: a backlog larger than the per-cycle budget delays a newer
   row's hint by at most one full sweep instead of hiding it forever, and
   ACKing already-scanned rows does not skip the rows behind the cursor.
5. Schema column migration (PRAGMA check + ALTER) runs under BEGIN
   IMMEDIATE: two processes initializing one SQLite file serialize; the
   loser re-checks instead of dying with "duplicate column name".

The timezone-dependent tests pin the process-local zone with time.tzset()
(the same harness the round-5 boundary evidence used) and skip on platforms
without it.  Loopback peers use the explicit test-only http bypass via the
r4 WorkerHarness; no external host is contacted.
"""
import contextlib
import os
import sqlite3
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from atalk.core import AtalkStore
from atalk.federation import runtime

from test_federation_r4_fixes import StubPeer, WorkerHarness

HAS_TZSET = hasattr(time, "tzset")


@contextlib.contextmanager
def _local_timezone(name: str):
    """Pin the process-local timezone for the guarded block (restored
    afterwards); this is the exact axis the r6 #1 defect lived on."""
    if not HAS_TZSET:
        raise unittest.SkipTest("time.tzset unavailable on this platform")
    previous = os.environ.get("TZ")
    os.environ["TZ"] = name
    time.tzset()
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = previous
        time.tzset()


# ---------------------------------------------------------------------------
# r6 #1: HTTP-date Retry-After is GMT, whatever form it arrived in.
# ---------------------------------------------------------------------------

GMT_CASES = {
    # label: (Retry-After value, the GMT instant it MUST mean)
    "imf-fixdate": ("Sun, 06 Nov 2095 08:49:37 GMT",
                    datetime(2095, 11, 6, 8, 49, 37, tzinfo=timezone.utc)),
    "rfc850": ("Sunday, 06-Nov-49 08:49:37 GMT",
               datetime(2049, 11, 6, 8, 49, 37, tzinfo=timezone.utc)),
    "asctime": ("Sun Nov  6 08:49:37 2095",
                datetime(2095, 11, 6, 8, 49, 37, tzinfo=timezone.utc)),
}
FIXED_NOW = 2_000_000_000.0        # deterministic "now" (UTC 2033-05-18),
# chosen BEFORE every GMT target below so no max(0.0, ...) clamp masks the
# value the contract pins


class RetryAfterHttpDateIsGmtTest(unittest.TestCase):
    """The parse is TZ-invariant and always the GMT reading.  Before the fix
    the naive asctime form read the LOCAL zone: under Asia/Singapore the same
    header came back 28800 seconds short (the reviewer's real early-send repro)."""

    def _parse(self, value: str) -> float:
        with mock.patch.object(runtime.time, "time", lambda: FIXED_NOW):
            return runtime._parse_retry_after(value)

    def test_asctime_actually_parses_naive(self):
        # the defect is real for exactly this shape: parsedate_to_datetime
        # hands back a tz-less datetime for the obsolete asctime form
        self.assertIsNone(parsedate_to_datetime(GMT_CASES["asctime"][0]).tzinfo)
        self.assertIsNotNone(parsedate_to_datetime(GMT_CASES["imf-fixdate"][0]).tzinfo)
        self.assertIsNotNone(parsedate_to_datetime(GMT_CASES["rfc850"][0]).tzinfo)

    @unittest.skipUnless(HAS_TZSET, "time.tzset unavailable")
    def test_all_three_forms_read_gmt_under_any_local_zone(self):
        for zone in ("UTC", "Asia/Singapore", "America/New_York"):
            with self.subTest(zone=zone), _local_timezone(zone):
                for label, (value, gmt) in GMT_CASES.items():
                    with self.subTest(format=label):
                        self.assertEqual(self._parse(value),
                                         gmt.timestamp() - FIXED_NOW)


class _RawRetryAfterHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        self.server.requests.append(self.path)
        value, self.server.retry_after = self.server.retry_after, None
        if value is not None:
            self.send_response(429)
            self.send_header("Retry-After", value)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        raw = b'{"status": "stored"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, fmt, *args):
        return


class _QuietServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass  # expected: aborted test requests


class RawRetryAfterPeer:
    """Loopback peer whose first answer carries a VERBATIM Retry-After value
    (the r4 StubPeer can only produce now-relative dates)."""

    def __init__(self, retry_after=None):
        self.server = _QuietServer(("127.0.0.1", 0), _RawRetryAfterHandler)
        self.server.requests = []
        self.server.retry_after = retry_after
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}/federation/inbox"

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


class RetryAfterHttpDatePersistenceTest(unittest.TestCase):
    """The reviewer's repro end to end, under the offending local zone: the naive
    asctime header must persist a deadline that is never EARLIER than the
    GMT instant it names, including after a restart on the same database."""

    EVENT_ID = "cccc0000-0000-4000-8000-00000000c601"
    TARGET = datetime(2095, 11, 6, 8, 49, 37, tzinfo=timezone.utc)

    @unittest.skipUnless(HAS_TZSET, "time.tzset unavailable")
    def test_persisted_deadline_never_precedes_gmt_across_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            peer = RawRetryAfterPeer("Sun Nov  6 08:49:37 2095")
            self.addCleanup(peer.stop)
            harness = WorkerHarness(tmp, {"org-a": peer})
            self.addCleanup(harness.stop)
            harness.enqueue(self.EVENT_ID, "org-a", "alice@org-a")
            with _local_timezone("Asia/Singapore"):
                harness.rt.process_due()
            row = harness.rt.store.get_outbound(self.EVENT_ID)
            self.assertEqual(row["status"], "pending")
            self.assertEqual(row["last_error"], "http_429")
            stored = datetime.fromisoformat(row["next_retry_at"].replace("Z", "+00:00"))
            # before the fix this was 2095-11-06T01:49:37Z — eight hours EARLY
            self.assertGreaterEqual(stored, self.TARGET)
            self.assertLessEqual(stored, self.TARGET + timedelta(seconds=2))
            # a fresh runtime on the SAME database may not send before the
            # GMT deadline either
            restarted = WorkerHarness(tmp, {"org-a": peer})
            self.addCleanup(restarted.stop)
            restarted.rt.process_due(now="2095-11-06T08:49:36Z")
            self.assertEqual(len(peer.server.requests), 1)   # not early
            restarted.rt.process_due(now="2095-11-06T08:49:39Z")
            self.assertEqual(len(peer.server.requests), 2)
            self.assertEqual(
                restarted.rt.store.get_outbound(self.EVENT_ID)["status"], "sent")


# ---------------------------------------------------------------------------
# r6 #2: persisted deadlines are CEILed to the whole second (never early).
# ---------------------------------------------------------------------------

class RetryDeadlineCeilTest(unittest.TestCase):
    def test_fixed_clock_fraction_is_ceil_not_floor(self):
        # the reviewer's exact repro: a fixed clock at 00:00:00.900 + 7200 persisted
        # 02:00:00 (0.9s EARLY); it must persist 02:00:01.
        rt = runtime.FederationRuntime.__new__(runtime.FederationRuntime)

        class FixedDatetime(datetime):
            @classmethod
            def now(cls, tz=None):
                return datetime(2026, 11, 6, 0, 0, 0, 900000, tzinfo=timezone.utc)

        with mock.patch.object(runtime, "datetime", FixedDatetime):
            stored = rt._backoff(1, 7200.0)
        self.assertEqual(stored, "2026-11-06T02:00:01Z")

    def test_unrepresentable_ceiling_stays_storable(self):
        # datetime.max + 1s overflows; the ceiling is kept, still formatted
        rt = runtime.FederationRuntime.__new__(runtime.FederationRuntime)
        self.assertEqual(rt._backoff(1, 1e30), "9999-12-31T23:59:59Z")

    def test_fractional_deadline_never_earlier_than_true_deadline(self):
        rt = runtime.FederationRuntime.__new__(runtime.FederationRuntime)
        for seconds in (0.9, 7199.1, 0.001):
            with self.subTest(seconds=seconds):
                before = time.time()
                stored = rt._backoff(1, seconds)
                epoch = datetime.fromisoformat(
                    stored.replace("Z", "+00:00")).timestamp()
                self.assertGreaterEqual(epoch, before + seconds)  # NEVER early
                self.assertLessEqual(epoch, time.time() + seconds + 1.0)
                self.assertRegex(stored, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

    def test_fractional_retry_after_row_not_due_before_its_ceiling(self):
        # end to end: the due scan (string comparison at whole-second
        # precision) must not fire before the honored deadline
        with tempfile.TemporaryDirectory() as tmp:
            peer = StubPeer()
            self.addCleanup(peer.stop)
            harness = WorkerHarness(tmp, {"org-a": peer})
            self.addCleanup(harness.stop)
            event_id = "cccc0000-0000-4000-8000-00000000c602"
            harness.enqueue(event_id, "org-a", "alice@org-a")
            before = time.time()
            with mock.patch.object(runtime, "send_envelope",
                                   lambda *a, **k: runtime.SendOutcome(
                                       "retry", "http_429", 7199.1)):
                harness.rt.process_due()
            row = harness.rt.store.get_outbound(event_id)
            self.assertEqual(row["status"], "pending")
            stored = datetime.fromisoformat(row["next_retry_at"].replace("Z", "+00:00"))
            self.assertGreaterEqual(stored.timestamp(), before + 7199.1)
            frac = (before + 7199.1) % 1.0
            if not 0.01 < frac < 0.99:
                self.skipTest("degenerate clock alignment for the ceil probe")
            # the whole second BELOW the true deadline is not due (the first
            # attempt was mocked and made no HTTP request at all)
            floored = datetime.fromtimestamp(before + 7199.1, timezone.utc)
            floored = floored.replace(microsecond=0)
            harness.rt.process_due(
                now=floored.strftime("%Y-%m-%dT%H:%M:%SZ"))
            self.assertEqual(len(peer.server.requests), 0)
            # at the persisted ceiling the row is due and sends
            harness.rt.process_due(now=row["next_retry_at"])
            self.assertEqual(
                harness.rt.store.get_outbound(event_id)["status"], "sent")
            self.assertEqual(len(peer.server.requests), 1)


# ---------------------------------------------------------------------------
# r6 #3: delta-seconds is ASCII 1*DIGIT, not Unicode isdigit().
# ---------------------------------------------------------------------------

class RetryAfterAsciiDigitsTest(unittest.TestCase):
    def test_non_ascii_digit_lookalikes_are_ordinary_invalid(self):
        for value in ("²", "¹²³", "١٢٣", "1²", "٣"):
            with self.subTest(value=value):
                # these DID pass the old isdigit() gate...
                self.assertTrue(value.isdigit())
                self.assertFalse(value.isascii())
                # ...'²' then crashed float() inside the worker guard and
                # '١٢٣' was silently ACCEPTED as 123.0; both are invalid
                self.assertIsNone(runtime._parse_retry_after(value), value)

    def test_ascii_digits_and_invalid_shapes_unchanged(self):
        self.assertEqual(runtime._parse_retry_after("45"), 45.0)
        self.assertEqual(runtime._parse_retry_after("  45  "), 45.0)
        for bad in ("-5", "4.5", "+5", "", None, "1e5", "inf"):
            self.assertIsNone(runtime._parse_retry_after(bad), bad)


# ---------------------------------------------------------------------------
# r6 #4: the push-scan keyset cursor persists across cycles (wraparound).
# ---------------------------------------------------------------------------

def _insert_hint_row(store, intent_id, agent, created_at):
    store.conn.execute(
        "INSERT OR IGNORE INTO federation_notifications "
        "(intent_id, kind, agent, event_id, detail_json, hint_sent, acked, created_at) "
        "VALUES (?,?,?,?,?,0,0,?)",
        (intent_id, "receipt_received", agent, None, "{}", created_at))


class HintScanCursorTest(unittest.TestCase):
    def _harness(self, tmp):
        peer = StubPeer()
        self.addCleanup(peer.stop)
        harness = WorkerHarness(tmp, {"org-a": peer})
        self.addCleanup(harness.stop)
        return harness

    @staticmethod
    def _backlog(harness, count, start_second=0, agent="ghost"):
        """Insert `count` pending notification rows for an offline agent at
        one-second created_at spacing starting at 2026-10-24T00:00:00Z."""
        created0 = datetime(2026, 10, 24, 0, 0, 0, tzinfo=timezone.utc)
        conn = harness.rt.store.conn
        conn.execute("BEGIN IMMEDIATE")
        for i in range(count):
            when = (created0 + timedelta(seconds=start_second + i)) \
                .isoformat().replace("+00:00", "Z")
            _insert_hint_row(
                harness.rt.store,
                f"00000000-0000-4000-8000-{i + start_second:012d}",
                agent, when)
        conn.execute("COMMIT")

    def test_backlog_over_budget_cannot_starve_a_newer_online_hint(self):
        # reviewer r5 repro, exact numbers: 5000 offline rows (agent "ghost",
        # nobody subscribed) + one newer online row.  The old per-cycle
        # cursor reset kept the scan pinned to the 5000 oldest rows: the
        # online queue stayed empty after three cycles.  Now cycle 1 spends
        # the budget on the backlog and cycle 2 CONTINUES from the cursor.
        with tempfile.TemporaryDirectory() as tmp:
            harness = self._harness(tmp)
            self._backlog(harness, 5000)
            online = "20000000-0000-4000-8000-000000000001"
            _insert_hint_row(harness.rt.store, online, "alice",
                             "2026-10-24T01:56:00Z")    # behind ALL 5000 rows
            q = harness.wake.subscribe("alice")
            self.assertEqual(harness.rt.hint_notifications(), 0)
            self.assertEqual(q.qsize(), 0)   # budget spent on the backlog
            self.assertEqual(harness.rt.hint_notifications(), 1)
            self.assertEqual(q.qsize(), 1)   # reached on the very next cycle
            self.assertEqual(harness.rt.store.conn.execute(
                "SELECT hint_sent FROM federation_notifications "
                "WHERE intent_id=?", (online,)).fetchone()["hint_sent"], 1)
            # marked once, not re-hinted; the backlog itself is untouched
            self.assertEqual(harness.rt.hint_notifications(), 0)
            self.assertEqual(q.qsize(), 1)
            self.assertEqual(harness.rt.store.conn.execute(
                "SELECT count(*) n FROM federation_notifications "
                "WHERE hint_sent=0 AND acked=0").fetchone()["n"], 5000)

    def test_acking_scanned_rows_does_not_skip_rows_behind_cursor(self):
        # The cursor is a keyset POSITION: rows scanned in an earlier cycle
        # that are since ACKed vanish from the scan, and the rows behind the
        # cursor must still be reached (never a rewind-past-remaining skip).
        with tempfile.TemporaryDirectory() as tmp:
            harness = self._harness(tmp)
            harness.rt.HINT_SCAN_BUDGET = 100   # exactly one page per cycle
            self._backlog(harness, 100)
            ids = [f"00000000-0000-4000-8000-{i:012d}" for i in range(100)]
            self.assertEqual(harness.rt.hint_notifications(), 0)  # budget spent
            self.assertEqual(
                harness.rt.store.ack_notification_hints(ids, "ghost"), 100)
            live = "20000000-0000-4000-8000-000000000002"
            _insert_hint_row(harness.rt.store, live, "alice",
                             "2026-10-24T00:02:00Z")   # strictly behind cursor
            q = harness.wake.subscribe("alice")
            self.assertEqual(harness.rt.hint_notifications(), 1)
            self.assertEqual(q.qsize(), 1)

    def test_cursor_wraps_after_exhausting_the_pending_set(self):
        # A sweep that runs off the end of the pending set restarts at the
        # oldest row, so even a row that sorts BEFORE the current cursor is
        # revisited (once per full sweep at worst).
        with tempfile.TemporaryDirectory() as tmp:
            harness = self._harness(tmp)
            harness.rt.HINT_SCAN_BUDGET = 100
            self._backlog(harness, 100, start_second=60)   # created 00:01:xx
            ids = [f"00000000-0000-4000-8000-{i + 60:012d}" for i in range(100)]
            self.assertEqual(harness.rt.hint_notifications(), 0)
            self.assertEqual(
                harness.rt.store.ack_notification_hints(ids, "ghost"), 100)
            backdated = "20000000-0000-4000-8000-000000000003"
            _insert_hint_row(harness.rt.store, backdated, "alice",
                             "2026-10-24T00:00:30Z")   # OLDER than the cursor
            # this cycle scans past the cursor, finds nothing, wraps
            self.assertEqual(harness.rt.hint_notifications(), 0)
            q = harness.wake.subscribe("alice")
            self.assertEqual(harness.rt.hint_notifications(), 1)  # wrapped
            self.assertEqual(q.qsize(), 1)


# ---------------------------------------------------------------------------
# r6 #5: column migration is transactional; concurrent initializers of one
# SQLite file serialize and both succeed.
# ---------------------------------------------------------------------------

class ConcurrentInitTest(unittest.TestCase):
    def test_two_instances_initializing_one_file_both_succeed(self):
        # Two threads run the FULL init path together (barrier inside
        # __init__) on a database whose schema is MISSING a migrated column:
        # with the fix ANY interleaving succeeds, because the check+ALTER is
        # one BEGIN IMMEDIATE transaction — whoever loses the write lock
        # re-checks a complete schema instead of dying with "duplicate
        # column name".  (The database is pre-created so the boot
        # journal-mode switch on a never-before-existing FILE — a separate,
        # narrower race outside r6 #5 — is not what is under test.)
        for attempt in range(3):
            with self.subTest(attempt=attempt):
                with tempfile.TemporaryDirectory() as tmp:
                    path = Path(tmp) / "atalk.db"
                    AtalkStore(path).close_thread_connection()
                    raw = sqlite3.connect(path, timeout=10)
                    raw.execute(
                        "ALTER TABLE peers DROP COLUMN delivery_class")
                    raw.commit()
                    raw.close()
                    barrier = threading.Barrier(2, timeout=30)
                    failures = []

                    def build():
                        try:
                            barrier.wait()
                            store = AtalkStore(path)
                            store.close_thread_connection()
                        except Exception as exc:
                            failures.append(repr(exc))

                    threads = [threading.Thread(target=build, name=f"init{i}")
                               for i in range(2)]
                    for thread in threads:
                        thread.start()
                    for thread in threads:
                        thread.join(timeout=30)
                    self.assertEqual(failures, [])
                    verify = sqlite3.connect(path)
                    try:
                        for table, column in (
                                ("federation_notifications", "acked"),
                                ("peers", "delivery_class"),
                                ("peers", "ack_timeout_sec"),
                                ("peer_tokens", "scope")):
                            names = {r[1] for r in verify.execute(
                                f"PRAGMA table_info({table})")}
                            self.assertIn(column, names, (table, column))
                    finally:
                        verify.close()

    def test_blocked_initializer_rechecks_after_the_winner_commits(self):
        # Deterministic serialization repro (reviewer r5 #5): a second writer
        # holds the SQLite write lock and adds the column MID-initialization.
        # The initializing process must WAIT, then re-check and succeed —
        # the old check-then-alter issued its PRAGMA against the pre-add
        # snapshot and died with "duplicate column name" once the lock
        # freed.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "atalk.db"
            first = AtalkStore(path)
            first.close_thread_connection()
            raw = sqlite3.connect(path, timeout=10)
            # recreate the schema an older build would have shipped
            raw.execute("ALTER TABLE peers DROP COLUMN delivery_class")
            raw.commit()
            raw.execute("BEGIN IMMEDIATE")       # hold the write lock
            try:
                result = []

                def build():
                    try:
                        result.append(AtalkStore(path))
                    except Exception as exc:
                        result.append(exc)

                thread = threading.Thread(target=build)
                thread.start()
                time.sleep(0.5)   # the builder is now blocked on the lock
                raw.execute(
                    "ALTER TABLE peers ADD COLUMN delivery_class "
                    "TEXT NOT NULL DEFAULT 'normal'")
                raw.commit()     # the "other process" wins the migration
                thread.join(timeout=30)
                self.assertFalse(thread.is_alive())
                self.assertIsInstance(result[0], AtalkStore, repr(result))
            finally:
                raw.close()
            names = {r[1] for r in sqlite3.connect(path).execute(
                "PRAGMA table_info(peers)")}
            self.assertIn("delivery_class", names)

    def test_winner_between_check_and_alter_cannot_duplicate(self):
        # Deterministic reviewer repro, scheduler injected at the production seam
        # WITHOUT touching product code: the builder's PRAGMA view is doctored
        # stale exactly while a "winner" tries to add the column in that same
        # gap.  If production holds the write lock ACROSS check+ALTER (the
        # fix), the winner cannot commit, starves out, and yields — the
        # builder then adds the column itself and both schemas agree.  If
        # check and ALTER are separate statements (pre-r6), the builder acts
        # on the stale answer and MUST die with "duplicate column name".
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "atalk.db"
            AtalkStore(path).close_thread_connection()
            raw = sqlite3.connect(path, timeout=0.2)   # short: starves fast
            raw.execute(
                "ALTER TABLE peers DROP COLUMN delivery_class")
            raw.commit()

            injected = []

            class _RacedConn:
                def __init__(self, inner):
                    self._inner = inner

                def execute(self, sql, *args):
                    if sql.startswith("PRAGMA table_info(peers)"):
                        rows = self._inner.execute(sql, *args).fetchall()
                        try:
                            raw.execute(
                                "ALTER TABLE peers ADD COLUMN delivery_class "
                                "TEXT NOT NULL DEFAULT 'normal'")
                            raw.commit()
                            injected.append("winner_committed")
                            # stale view: hide what the winner just added
                            return [r for r in rows
                                    if r["name"] != "delivery_class"]
                        except sqlite3.OperationalError:
                            # the fix holds the write lock: the winner is
                            # starved and the view stays fresh
                            injected.append("winner_starved")
                            return rows
                    return self._inner.execute(sql, *args)

                def __getattr__(self, name):
                    return getattr(self._inner, name)

            class _RacedStore(AtalkStore):
                def _new_conn(self):
                    inner = super()._new_conn()
                    proxy = _RacedConn(inner)
                    self._local.conn = proxy
                    return proxy

            store = _RacedStore(path)
            self.assertEqual(injected, ["winner_starved"])
            store.close_thread_connection()
            raw.close()
            names = {r[1] for r in sqlite3.connect(path).execute(
                "PRAGMA table_info(peers)")}
            self.assertIn("delivery_class", names)
            # a plain initializer on the migrated file still succeeds
            AtalkStore(path).close_thread_connection()

    def test_duplicate_column_error_tolerated_only_after_recheck(self):
        # Simulate the (cross-process-only) outcome the catch guards: the
        # ALTER reports "duplicate column name" while the target schema is
        # still INCOMPLETE — that is a real defect and must raise (and leave
        # the connection free of transaction debris).
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "atalk.db"
            store = AtalkStore(path)
            raw = sqlite3.connect(path, timeout=10)
            raw.execute(
                "ALTER TABLE federation_notifications DROP COLUMN acked")
            raw.commit()

            class _Hooked:
                def __init__(self, inner):
                    self._inner = inner

                def execute(self, sql, *args):
                    if "ADD COLUMN" in sql and "acked" in sql:
                        raise sqlite3.OperationalError(
                            "duplicate column name: acked")
                    return self._inner.execute(sql, *args)

                def __getattr__(self, name):
                    return getattr(self._inner, name)

            original = store._local.conn
            store._local.conn = _Hooked(original)
            try:
                with self.assertRaises(sqlite3.OperationalError):
                    store._ensure_notification_ack_column()
            finally:
                store._local.conn = original
            # the failed migration left no transaction debris: the helper
            # runs again cleanly and completes the schema for real
            store._ensure_notification_ack_column()
            names = {r["name"] for r in store.conn.execute(
                "PRAGMA table_info(federation_notifications)")}
            self.assertIn("acked", names)


if __name__ == "__main__":
    unittest.main()
