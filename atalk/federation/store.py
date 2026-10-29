"""Federation persistence (round 2): all federation tables, written in single
immediate transactions on the existing SQLite store.

This layer is deliberately SQLite-specific (design draft v0.4.1 has no rqlite
story for federation); the runtime refuses to activate on other backends.
Every public mutating method owns ONE transaction: the dedup arbiter is the
DB unique constraint (federation_inbound UNIQUE(origin, event_id)), never a
check-then-insert.  All times are the store's `now_iso()` (RFC 3339 UTC, the
exact format the v0 schema requires for receipt `at`).
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from typing import Any

from ..core import AtalkStore, now_iso


def stable_intent_id(*parts: str) -> str:
    """Deterministic notification-intent id: retries and rebuilds reuse it, so
    the local logical notification is created exactly once (spec 6.6)."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "atalk-fed-notify:" + ":".join(parts)))


class OutboxFull(Exception):
    """Raised inside the enqueue transaction when the pending outbox is at cap."""


class FederationStore:
    def __init__(self, inner: AtalkStore):
        self.inner = inner

    @property
    def conn(self):
        return self.inner.conn

    # ------------------------------------------------------------- outbound

    def enqueue_outbound(
        self, *, event_id: str, origin: str, origin_key_id: str, source_local: str,
        source_addr: str, target: str, target_family: str, type: str,
        signed_json: str, sig: str, envelope_json: bytes, outbox_cap: int,
    ) -> str:
        """One persistent commit writing the outbound record + pending state
        (spec 5.2).  Cap is checked inside the same immediate transaction.
        Returns "queued" or "existing" (idempotent retry of the same event_id)."""
        now = now_iso()
        notify_id = stable_intent_id("send_failed", event_id)
        with self.inner.lock:
            conn = self.conn
            conn.execute("BEGIN IMMEDIATE")
            in_txn = True
            try:
                existing = conn.execute(
                    "SELECT event_id, status FROM federation_outbound WHERE event_id=?",
                    (event_id,)).fetchone()
                if existing:
                    conn.execute("COMMIT")
                    in_txn = False
                    return "existing"
                row = conn.execute(
                    "SELECT count(*) AS n FROM federation_outbound WHERE status='pending'"
                ).fetchone()
                if int(row["n"]) >= outbox_cap:
                    conn.execute("ROLLBACK")
                    in_txn = False
                    raise OutboxFull(f"federation outbox is full (cap {outbox_cap})")
                conn.execute(
                    """
                    INSERT INTO federation_outbound
                      (event_id, origin, origin_key_id, source_local, source_addr, target,
                       target_family, type, signed_json, sig, envelope_json, notify_intent_id,
                       status, attempts, next_retry_at, last_error, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,'pending',0,NULL,NULL,?,?)
                    """,
                    (event_id, origin, origin_key_id, source_local, source_addr, target,
                     target_family, type, signed_json, sig, bytes(envelope_json), notify_id,
                     now, now),
                )
                conn.execute("COMMIT")
                in_txn = False
                return "queued"
            finally:
                if in_txn:
                    try:
                        conn.execute("ROLLBACK")
                    except Exception:
                        pass

    def get_outbound(self, event_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM federation_outbound WHERE event_id=?", (event_id,)).fetchone()
        return dict(row) if row else None

    def due_outbound(self, now: str, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM federation_outbound WHERE status='pending' "
            "AND (next_retry_at IS NULL OR next_retry_at <= ?) ORDER BY id LIMIT ?",
            (now, limit)).fetchall()
        return [dict(r) for r in rows]

    def mark_outbound_sent(self, event_id: str) -> None:
        # Only pending -> sent; ended tasks are never reactivated by recovery.
        with self.inner.lock, self.conn:
            self.conn.execute(
                "UPDATE federation_outbound SET status='sent', attempts=attempts+1, "
                "last_error=NULL, updated_at=? WHERE event_id=? AND status='pending'",
                (now_iso(), event_id))

    def mark_outbound_retry(self, event_id: str, attempts: int, next_retry_at: str,
                            last_error: str) -> None:
        with self.inner.lock, self.conn:
            self.conn.execute(
                "UPDATE federation_outbound SET attempts=?, next_retry_at=?, last_error=?, "
                "updated_at=? WHERE event_id=? AND status='pending'",
                (attempts, next_retry_at, last_error, now_iso(), event_id))

    def fail_outbound_permanent(self, event_id: str, error: str) -> dict | None:
        """pending -> failed_permanent + exactly-once notification (spec 8:
        keep the failed state, notify, never silently drop)."""
        now = now_iso()
        notification = None
        with self.inner.lock:
            conn = self.conn
            conn.execute("BEGIN IMMEDIATE")
            in_txn = True
            try:
                row = conn.execute(
                    "SELECT * FROM federation_outbound WHERE event_id=? AND status='pending'",
                    (event_id,)).fetchone()
                if row:
                    conn.execute(
                        "UPDATE federation_outbound SET status='failed_permanent', "
                        "attempts=attempts+1, last_error=?, updated_at=? WHERE id=?",
                        (error, now, row["id"]))
                    notification = self._insert_notification(
                        conn, row["notify_intent_id"], "send_failed",
                        row["source_local"], event_id,
                        {"target": row["target"], "target_family": row["target_family"],
                         "error": error})
                conn.execute("COMMIT")
                in_txn = False
                return notification
            finally:
                if in_txn:
                    try:
                        conn.execute("ROLLBACK")
                    except Exception:
                        pass

    # -------------------------------------------------------------- inbound

    def receive_event(
        self, *, origin: str, event_id: str, event_jcs: bytes, signed_json: str,
        sig: str, reg_family: str, reg_key_id: str, reg_public_key: str,
        source_addr: str, target_addr: str, target_local: str, type: str,
        payload: dict[str, Any], created_at: str,
    ) -> tuple[str, dict[str, Any] | None]:
        """The section 5.5 atomic commit.  Writes the dedup key (DB unique
        constraint), the envelope original, the registry snapshot used, the
        local logical event and the delivery-pending state in ONE transaction.

        `target_addr` is the full signed address (kept for receipt binding);
        `target_local` is the bare agent id the local bus delivers to.

        Returns ("stored", row) | ("duplicate", existing_row) |
        ("conflict", {"reason": ...}).  On conflict the original is untouched
        and a conflict-audit row is committed (spec 7)."""
        now = now_iso()
        with self.inner.lock:
            conn = self.conn
            conn.execute("BEGIN IMMEDIATE")
            in_txn = True
            try:
                cur = conn.execute(
                    """
                    INSERT INTO federation_inbound
                      (origin, event_id, target, event_jcs, signed_json, sig, reg_family,
                       reg_key_id, reg_public_key, local_event_id, delivery_state, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?, ?, 'pending', ?)
                    """,
                    (origin, event_id, target_addr, bytes(event_jcs), signed_json, sig,
                     reg_family, reg_key_id, reg_public_key, event_id, now),
                )
                payload_local = dict(payload)
                signed = json.loads(signed_json)
                if signed.get("event", {}).get("in_reply_to"):
                    # Local reply convention (adapter/inbox put in_reply_to in the
                    # payload); conversational only, never a permission link.
                    payload_local["in_reply_to"] = signed["event"]["in_reply_to"]
                seq = self.inner.next_seq(source_addr)
                conn.execute(
                    """
                    INSERT INTO events
                      (event_id, source, target, type, seq, created_at, stored_at,
                       payload_json, requires_ack, source_ref, auth_actor)
                    VALUES (?,?,?,?,?,?,?, ?, 1, NULL, NULL)
                    """,
                    (event_id, source_addr, target_local, type, seq, created_at, now,
                     json.dumps(payload_local, ensure_ascii=False, separators=(",", ":"),
                                sort_keys=True)),
                )
                row = dict(conn.execute(
                    "SELECT * FROM federation_inbound WHERE id=?", (cur.lastrowid,)).fetchone())
                conn.execute("COMMIT")
                in_txn = False
                return "stored", row
            except sqlite3.IntegrityError:
                conn.execute("ROLLBACK")
                in_txn = False
            finally:
                if in_txn:
                    try:
                        conn.execute("ROLLBACK")
                    except Exception:
                        pass
            # The unique constraint rejected us: classify without re-inserting.
            existing = conn.execute(
                "SELECT * FROM federation_inbound WHERE origin=? AND event_id=?",
                (origin, event_id)).fetchone()
            if existing is not None and bytes(existing["event_jcs"]) == bytes(event_jcs):
                return "duplicate", dict(existing)
            reason = ("local_event_id_collision" if existing is None
                      else "same_id_different_content")
            with self.inner.lock, conn:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    conn.execute(
                        """
                        INSERT INTO federation_inbound_conflicts
                          (origin, event_id, event_jcs, signed_json, sig, reason, seen_at)
                        VALUES (?,?,?,?,?,?,?)
                        """,
                        (origin, event_id, bytes(event_jcs), signed_json, sig, reason, now),
                    )
                    conn.execute("COMMIT")
                except Exception:
                    conn.execute("ROLLBACK")
                    raise
            return "conflict", {"reason": reason}

    def get_inbound(self, origin: str | None = None, event_id: str | None = None) -> dict | None:
        if origin is not None:
            row = self.conn.execute(
                "SELECT * FROM federation_inbound WHERE origin=? AND event_id=?",
                (origin, event_id)).fetchone()
        else:
            row = self.conn.execute(
                "SELECT * FROM federation_inbound WHERE event_id=?", (event_id,)).fetchone()
        return dict(row) if row else None

    def is_local_member(self, agent: str) -> bool:
        """Spec 5.3.6: the target agent must be an accepted local member."""
        row = self.conn.execute(
            "SELECT 1 FROM peers WHERE peer_id=? AND revoked_at IS NULL", (agent,)).fetchone()
        return row is not None

    def pending_delivery(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM federation_inbound WHERE delivery_state='pending' "
            "ORDER BY id LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def mark_delivered(self, origin: str, event_id: str) -> None:
        with self.inner.lock, self.conn:
            self.conn.execute(
                "UPDATE federation_inbound SET delivery_state='delivered' "
                "WHERE origin=? AND event_id=?", (origin, event_id))

    def conflicts_for(self, origin: str, event_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM federation_inbound_conflicts WHERE origin=? AND event_id=? ORDER BY id",
            (origin, event_id)).fetchall()
        return [dict(r) for r in rows]

    # ----------------------------------------------------------------- acks

    def ack_with_receipt_intent(
        self, *, event_id: str, agent_id: str, ack_type: str, detail: dict | None,
        receipt_agent: str, origin: str, origin_event_sig_hash: str,
        issuer: str, issuer_key_id: str,
    ) -> None:
        """Section 6.2: the local ACK and the durable receipt-send intent in the
        SAME transaction.  Declaration fields (including `at`) are fixed at the
        first ack; repeat acks never update them.  If this commit fails, the
        caller's ACK must fail."""
        now = now_iso()
        with self.inner.lock:
            conn = self.conn
            conn.execute("BEGIN IMMEDIATE")
            in_txn = True
            try:
                # Same SQL/upsert semantics as AtalkStore.ack (local behavior
                # preserved, including ack_at refresh on repeat acks).
                conn.execute(
                    """
                    INSERT INTO acks (event_id, agent_id, ack_type, ack_at, detail_json)
                    VALUES (?,?,?,?,?)
                    ON CONFLICT(event_id, agent_id, ack_type) DO UPDATE SET
                      ack_at=excluded.ack_at, detail_json=excluded.detail_json
                    """,
                    (event_id, agent_id, ack_type, now, json.dumps(detail or {}, sort_keys=True)),
                )
                conn.execute(
                    """
                    INSERT INTO federation_receipt_out
                      (event_id, agent, ack_type, at, origin, origin_event_sig_hash,
                       issuer, issuer_key_id, signed_json, sig, status, attempts,
                       next_retry_at, last_error, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?, NULL, NULL, 'pending', 0, NULL, NULL, ?, ?)
                    ON CONFLICT(event_id, agent, ack_type) DO NOTHING
                    """,
                    (event_id, receipt_agent, ack_type, now, origin, origin_event_sig_hash,
                     issuer, issuer_key_id, now, now),
                )
                conn.execute("COMMIT")
                in_txn = False
            finally:
                if in_txn:
                    try:
                        conn.execute("ROLLBACK")
                    except Exception:
                        pass

    def get_receipt_out(self, event_id: str, agent: str, ack_type: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM federation_receipt_out WHERE event_id=? AND agent=? AND ack_type=?",
            (event_id, agent, ack_type)).fetchone()
        return dict(row) if row else None

    def due_receipts(self, now: str, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM federation_receipt_out WHERE status='pending' "
            "AND (next_retry_at IS NULL OR next_retry_at <= ?) ORDER BY id LIMIT ?",
            (now, limit)).fetchall()
        return [dict(r) for r in rows]

    def materialize_receipt(self, event_id: str, agent: str, ack_type: str,
                            signed_json: str, sig: str) -> bool:
        """Persist the signed original if not yet generated.  Rebuild paths pass
        fixed fields only (never a fresh timestamp), so the original is stable."""
        with self.inner.lock, self.conn:
            cur = self.conn.execute(
                "UPDATE federation_receipt_out SET signed_json=?, sig=?, updated_at=? "
                "WHERE event_id=? AND agent=? AND ack_type=? AND signed_json IS NULL "
                "AND status='pending'",
                (signed_json, sig, now_iso(), event_id, agent, ack_type))
            return cur.rowcount > 0

    def mark_receipt_sent(self, event_id: str, agent: str, ack_type: str) -> None:
        with self.inner.lock, self.conn:
            self.conn.execute(
                "UPDATE federation_receipt_out SET status='sent', attempts=attempts+1, "
                "last_error=NULL, updated_at=? WHERE event_id=? AND agent=? AND ack_type=? "
                "AND status='pending'",
                (now_iso(), event_id, agent, ack_type))

    def mark_receipt_retry(self, event_id: str, agent: str, ack_type: str,
                           attempts: int, next_retry_at: str, last_error: str) -> None:
        with self.inner.lock, self.conn:
            self.conn.execute(
                "UPDATE federation_receipt_out SET attempts=?, next_retry_at=?, last_error=?, "
                "updated_at=? WHERE event_id=? AND agent=? AND ack_type=? AND status='pending'",
                (attempts, next_retry_at, last_error, now_iso(), event_id, agent, ack_type))

    def fail_receipt_permanent(self, event_id: str, agent: str, ack_type: str,
                               error: str) -> dict | None:
        now = now_iso()
        notification = None
        with self.inner.lock:
            conn = self.conn
            conn.execute("BEGIN IMMEDIATE")
            in_txn = True
            try:
                row = conn.execute(
                    "SELECT * FROM federation_receipt_out WHERE event_id=? AND agent=? "
                    "AND ack_type=? AND status='pending'",
                    (event_id, agent, ack_type)).fetchone()
                if row:
                    conn.execute(
                        "UPDATE federation_receipt_out SET status='failed_permanent', "
                        "attempts=attempts+1, last_error=?, updated_at=? WHERE id=?",
                        (error, now, row["id"]))
                    notification = self._insert_notification(
                        conn, stable_intent_id("receipt_send_failed", event_id, agent, ack_type),
                        "receipt_send_failed", None, event_id,
                        {"agent": agent, "ack_type": ack_type, "error": error})
                conn.execute("COMMIT")
                in_txn = False
                return notification
            finally:
                if in_txn:
                    try:
                        conn.execute("ROLLBACK")
                    except Exception:
                        pass

    # ------------------------------------------------------ receipts inbound

    def record_receipt_in(
        self, *, event_id: str, agent: str, ack_type: str, issuer: str,
        issuer_key_id: str, signed_json: str, sig: str,
        notify_agent: str | None, notify_detail: dict[str, Any],
    ) -> tuple[str, dict | None]:
        """Section 6.6 atomic commit: receipt original(s), merged state and the
        notification intent in ONE transaction.  Returns ("stored"|"duplicate",
        notification-or-None); "duplicate" means this exact signed original was
        already stored (the network redelivered it)."""
        now = now_iso()
        notification = None
        with self.inner.lock:
            conn = self.conn
            conn.execute("BEGIN IMMEDIATE")
            in_txn = True
            try:
                first = conn.execute(
                    "SELECT id FROM federation_receipt_in_originals WHERE event_id=? "
                    "AND agent=? AND ack_type=? ORDER BY id LIMIT 1",
                    (event_id, agent, ack_type)).fetchone()
                is_variant = first is not None
                cur = conn.execute(
                    """
                    INSERT OR IGNORE INTO federation_receipt_in_originals
                      (event_id, agent, ack_type, issuer, issuer_key_id, signed_json, sig,
                       is_variant, first_seen_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (event_id, agent, ack_type, issuer, issuer_key_id, signed_json, sig,
                     1 if is_variant else 0, now),
                )
                inserted = cur.rowcount > 0
                original_id = conn.execute(
                    "SELECT id FROM federation_receipt_in_originals WHERE event_id=? "
                    "AND agent=? AND ack_type=? AND sig=?",
                    (event_id, agent, ack_type, sig)).fetchone()["id"]
                conn.execute(
                    """
                    INSERT INTO federation_receipt_in
                      (event_id, agent, ack_type, issuer, original_id, updated_at)
                    VALUES (?,?,?,?,?,?)
                    ON CONFLICT(event_id, agent, ack_type) DO NOTHING
                    """,
                    (event_id, agent, ack_type, issuer, original_id, now),
                )
                if inserted:
                    # Exactly-once local logical notification by stable intent id.
                    notification = self._insert_notification(
                        conn, stable_intent_id("receipt", event_id, agent, ack_type),
                        "receipt_received", notify_agent, event_id,
                        dict(notify_detail, agent=agent, ack_type=ack_type, issuer=issuer))
                conn.execute("COMMIT")
                in_txn = False
                return ("stored" if inserted else "duplicate"), notification
            finally:
                if in_txn:
                    try:
                        conn.execute("ROLLBACK")
                    except Exception:
                        pass

    def receipt_stage(self, event_id: str, agent: str) -> str | None:
        """Merged stage for (event_id, agent): applied > received, never downgraded
        (spec 7).  None = nothing valid received."""
        rows = self.conn.execute(
            "SELECT ack_type FROM federation_receipt_in WHERE event_id=? AND agent=?",
            (event_id, agent)).fetchall()
        types = {r["ack_type"] for r in rows}
        if "applied" in types:
            return "applied"
        if "received" in types:
            return "received"
        return None

    def receipt_originals(self, event_id: str, agent: str | None = None,
                          ack_type: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM federation_receipt_in_originals WHERE event_id=?"
        params: list[Any] = [event_id]
        if agent is not None:
            sql += " AND agent=?"
            params.append(agent)
        if ack_type is not None:
            sql += " AND ack_type=?"
            params.append(ack_type)
        rows = self.conn.execute(sql + " ORDER BY id", params).fetchall()
        return [dict(r) for r in rows]

    # --------------------------------------------------------- notifications

    @staticmethod
    def _insert_notification(conn, intent_id: str, kind: str, agent: str | None,
                             event_id: str | None, detail: dict[str, Any]) -> dict | None:
        cur = conn.execute(
            """
            INSERT OR IGNORE INTO federation_notifications
              (intent_id, kind, agent, event_id, detail_json, hint_sent, created_at)
            VALUES (?,?,?,?,?, 0, ?)
            """,
            (intent_id, kind, agent, event_id,
             json.dumps(detail, ensure_ascii=False, sort_keys=True), now_iso()),
        )
        if cur.rowcount == 0:
            return None  # intent already recorded: logical notification exists
        return {"intent_id": intent_id, "kind": kind, "agent": agent,
                "event_id": event_id, "detail": detail}

    def undelivered_notification_hints(self, after: tuple[str, str] | None = None,
                                       limit: int = 100) -> list[dict[str, Any]]:
        """Push-scan page (r4 F6 / r5 #5).  Rows that have never had a live
        subscriber queue accept a hint AND are not durably acknowledged.

        Operator rows (agent IS NULL) are NEVER in this scan: they have no
        push target and are never marked, so a plain LIMIT window filled
        with them starved every agent hint behind it (reviewer repro: 100
        operator rows -> agent push hints never scanned).  They are
        pull-only (operator_notification_hints).

        Keyset pagination on (created_at, intent_id): the caller walks ALL
        pending agent rows per cycle instead of re-reading only the oldest
        LIMIT window, so a large offline backlog cannot hide newer rows.
        Re-pushing is safe (stable intent id); this is only the optimization
        that avoids re-hinting every cycle."""
        sql = ("SELECT * FROM federation_notifications "
               "WHERE hint_sent=0 AND acked=0 AND agent IS NOT NULL")
        params: list[Any] = []
        if after is not None:
            sql += " AND (created_at > ? OR (created_at = ? AND intent_id > ?))"
            params += [after[0], after[0], after[1]]
        sql += " ORDER BY created_at, intent_id LIMIT ?"
        params.append(limit)
        rows = self.conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def mark_notification_hint_sent(self, intent_id: str) -> None:
        with self.inner.lock, self.conn:
            self.conn.execute(
                "UPDATE federation_notifications SET hint_sent=1 WHERE intent_id=?",
                (intent_id,))

    # r4 F6 / r5 F6: durable pull/ack delivery.  hint_sent (a live queue once
    # accepted a push hint) and acked (an authenticated consumer ACKed the
    # notification) are DIFFERENT states: a reconnect replaces the SSE queue,
    # a restart empties every queue, so a hinted row is NOT delivered until a
    # consumer ACKed it.  The pull queries therefore list every un-ACKed row
    # REGARDLESS of hint_sent; only ack_notification_hints() completes
    # delivery durably.

    def notification_hints_for(self, agent: str, limit: int = 100) -> list[dict[str, Any]]:
        """Unacknowledged notifications for one agent — including rows that
        were already push-hinted (r5 F6: only an authenticated ACK completes
        delivery; pulling never mutates)."""
        rows = self.conn.execute(
            "SELECT * FROM federation_notifications WHERE acked=0 AND agent=? "
            "ORDER BY created_at, intent_id LIMIT ?", (agent, limit)).fetchall()
        return [dict(r) for r in rows]

    def operator_notification_hints(self, limit: int = 100) -> list[dict[str, Any]]:
        """Unacknowledged operator notifications (agent IS NULL), e.g.
        permanent receipt-send failures that no local agent can receive."""
        rows = self.conn.execute(
            "SELECT * FROM federation_notifications WHERE acked=0 AND agent IS NULL "
            "ORDER BY created_at, intent_id LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def ack_notification_hints(self, intent_ids: list[str], agent: str | None) -> int:
        """Durable completion (r5 F6): set acked=1.  An agent ack touches only
        that agent's rows; an operator ack (agent=None) touches only operator
        rows (agent IS NULL).  Idempotent: already-acked rows are not counted
        again.  Returns the number of rows newly marked."""
        if not intent_ids:
            return 0
        marks = ",".join("?" for _ in intent_ids)
        sql = (f"UPDATE federation_notifications SET acked=1 "
               f"WHERE acked=0 AND intent_id IN ({marks})")
        params: list[Any] = list(intent_ids)
        if agent is None:
            sql += " AND agent IS NULL"
        else:
            sql += " AND agent=?"
            params.append(agent)
        with self.inner.lock, self.conn:
            cur = self.conn.execute(sql, params)
            return cur.rowcount
