from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .raftsql import RaftSQLStore, RqliteClient


TABLES = (
    "peers",
    "peer_tokens",
    "peer_grants",
    "peer_target_acl",
    "peer_target_acl_targets",
    "source_counters",
    "events",
    "acks",
    "audit_log",
    "settings",
)

ORDER_BY = {
    "peers": "peer_id",
    "peer_tokens": "id",
    "peer_grants": "id",
    "peer_target_acl": "peer_id",
    "peer_target_acl_targets": "peer_id, target_peer",
    "source_counters": "source",
    "events": "id",
    "acks": "id",
    "audit_log": "id",
    "settings": "key",
}

PRIMARY_KEY = {
    "peers": ("peer_id",),
    "peer_tokens": ("id",),
    "peer_grants": ("id",),
    "peer_target_acl": ("peer_id",),
    "peer_target_acl_targets": ("peer_id", "target_peer"),
    "source_counters": ("source",),
    "events": ("id",),
    "acks": ("id",),
    "audit_log": ("id",),
    "settings": ("key",),
}


@dataclass(frozen=True)
class TableDigest:
    rows: int
    sha256: str


def snapshot_sqlite(source: str | Path, destination: str | Path) -> Path:
    """Take a consistent online backup without writing to the source DB."""
    source = Path(source).resolve()
    destination = Path(destination).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    reader = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    writer = sqlite3.connect(destination)
    try:
        reader.backup(writer)
    finally:
        writer.close()
        reader.close()
    return destination


def _columns(connection: sqlite3.Connection, table: str) -> list[str]:
    return [str(row[1]) for row in connection.execute(f'PRAGMA table_info("{table}")')]


def _sqlite_rows(connection: sqlite3.Connection, table: str, columns: list[str]) -> list[dict[str, Any]]:
    connection.row_factory = sqlite3.Row
    selected = ",".join(f'"{column}"' for column in columns)
    rows = connection.execute(f'SELECT {selected} FROM "{table}" ORDER BY {ORDER_BY[table]}').fetchall()
    return [dict(row) for row in rows]


def _canonical_digest(rows: list[dict[str, Any]], columns: list[str]) -> TableDigest:
    digest = hashlib.sha256()
    for row in rows:
        values = [row.get(column) for column in columns]
        digest.update(json.dumps(values, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        digest.update(b"\n")
    return TableDigest(len(rows), digest.hexdigest())


class ShadowMigrator:
    def __init__(self, client: RqliteClient):
        self.client = client

    def _target_count(self, table: str) -> int:
        rows = self.client.query(f'SELECT count(*) AS n FROM "{table}"')
        return int(rows[0]["n"])

    def assert_empty_shadow(self) -> None:
        occupied = {table: self._target_count(table) for table in TABLES if table != "settings"}
        occupied = {table: count for table, count in occupied.items() if count}
        if occupied:
            raise RuntimeError(f"shadow ledger is not empty: {occupied}")

    def import_snapshot(self, snapshot: str | Path, *, batch_size: int = 100) -> dict[str, int]:
        """Import into an empty initialized shadow ledger.

        The target is never cleared implicitly. This method refuses a non-empty
        ledger, so it cannot be used as an accidental production overwrite.
        """
        self.assert_empty_shadow()
        connection = sqlite3.connect(Path(snapshot))
        counts: dict[str, int] = {}
        try:
            self.client.transaction([["DELETE FROM settings"]])
            for table in TABLES:
                columns = _columns(connection, table)
                if not columns:
                    raise RuntimeError(f"source table missing: {table}")
                rows = _sqlite_rows(connection, table, columns)
                placeholders = ",".join("?" for _ in columns)
                names = ",".join(f'"{column}"' for column in columns)
                sql = f'INSERT INTO "{table}"({names}) VALUES({placeholders})'
                for offset in range(0, len(rows), max(1, int(batch_size))):
                    statements = [[sql, *(row[column] for column in columns)] for row in rows[offset:offset + batch_size]]
                    if statements:
                        self.client.transaction(statements)
                counts[table] = len(rows)
        finally:
            connection.close()
        # Verify every source row landed in the shadow. Without this a partial
        # import (an older/mismatched source schema, a dropped batch, an ignored
        # row) passed silently and only surfaced later as data loss.
        self.verify_counts(counts)
        return counts

    def verify_counts(self, expected: dict[str, int]) -> None:
        """Raise if any shadow table row count differs from the expected count."""
        mismatches = {}
        for table, want in expected.items():
            got = self._target_count(table)
            if got != want:
                mismatches[table] = {"expected": want, "actual": got}
        if mismatches:
            raise RuntimeError(f"import verification failed (row-count mismatch): {mismatches}")

    def compare(self, snapshot: str | Path) -> dict[str, dict[str, Any]]:
        connection = sqlite3.connect(Path(snapshot))
        report: dict[str, dict[str, Any]] = {}
        try:
            for table in TABLES:
                columns = _columns(connection, table)
                source_rows = _sqlite_rows(connection, table, columns)
                selected = ",".join(f'"{column}"' for column in columns)
                target_rows = self.client.query(f'SELECT {selected} FROM "{table}" ORDER BY {ORDER_BY[table]}')
                source_digest = _canonical_digest(source_rows, columns)
                target_digest = _canonical_digest(target_rows, columns)
                report[table] = {
                    "source_rows": source_digest.rows,
                    "target_rows": target_digest.rows,
                    "source_sha256": source_digest.sha256,
                    "target_sha256": target_digest.sha256,
                    "match": source_digest == target_digest,
                }
        finally:
            connection.close()
        return report

    def sync_snapshot(self, snapshot: str | Path, *, batch_size: int = 100) -> dict[str, int]:
        """Upsert a consistent source snapshot into an existing shadow ledger.

        This intentionally performs no deletes. A target-only row remains a
        detectable comparison mismatch and requires an explicit shadow rebuild.
        """
        connection = sqlite3.connect(Path(snapshot))
        counts: dict[str, int] = {}
        try:
            for table in TABLES:
                columns = _columns(connection, table)
                rows = _sqlite_rows(connection, table, columns)
                keys = PRIMARY_KEY[table]
                updates = [column for column in columns if column not in keys]
                names = ",".join(f'"{column}"' for column in columns)
                placeholders = ",".join("?" for _ in columns)
                conflict = ",".join(f'"{column}"' for column in keys)
                if updates:
                    action = "DO UPDATE SET " + ",".join(
                        f'"{column}"=excluded."{column}"' for column in updates
                    )
                else:
                    action = "DO NOTHING"
                sql = f'INSERT INTO "{table}"({names}) VALUES({placeholders}) ON CONFLICT({conflict}) {action}'
                for offset in range(0, len(rows), max(1, int(batch_size))):
                    statements = [[sql, *(row[column] for column in columns)] for row in rows[offset:offset + batch_size]]
                    if statements:
                        self.client.transaction(statements)
                counts[table] = len(rows)
        finally:
            connection.close()
        return counts


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="atalk-shadow")
    sub = result.add_subparsers(dest="command", required=True)
    snapshot = sub.add_parser("snapshot")
    snapshot.add_argument("--source", required=True)
    snapshot.add_argument("--output", required=True)
    for name in ("import", "sync", "compare"):
        command = sub.add_parser(name)
        command.add_argument("--snapshot", required=True)
        command.add_argument("--endpoints", required=True, help="comma-separated rqlite HTTP endpoints")
        if name == "import":
            command.add_argument("--confirm-empty-shadow", action="store_true", required=True)
        if name == "sync":
            command.add_argument("--confirm-shadow-only", action="store_true", required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "snapshot":
        print(snapshot_sqlite(args.source, args.output))
        return 0
    endpoints = [value.strip() for value in args.endpoints.split(",") if value.strip()]
    store = RaftSQLStore(endpoints, initialize=args.command == "import")
    migrator = ShadowMigrator(store.client)
    if args.command == "import":
        print(json.dumps(migrator.import_snapshot(args.snapshot), sort_keys=True))
        return 0
    if args.command == "sync":
        print(json.dumps(migrator.sync_snapshot(args.snapshot), sort_keys=True))
        return 0
    report = migrator.compare(args.snapshot)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if all(item["match"] for item in report.values()) else 2


if __name__ == "__main__":
    raise SystemExit(main())
