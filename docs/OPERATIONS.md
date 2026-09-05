# Operations

## Single node (SQLite)

```bash
python3 -m atalk.cli --db /var/lib/atalk/atalk.db init
python3 -m atalk.server --db /var/lib/atalk/atalk.db --host 127.0.0.1 --port 7070
```

Run it under systemd as a dedicated user; the database file and its `-wal`/`-shm`
siblings must be writable only by that user. Put TLS in front (nginx/caddy) if clients
are not on an encrypted overlay.

## Three nodes (rqlite / Raft)

1. Run an [rqlite](https://rqlite.io) cluster of three nodes (mutual TLS recommended).
2. Initialize the cluster schema **once** (see *Schema and upgrades* below), then
   start `atalk.server` on each node with
   `--backend rqlite --rqlite-endpoints https://n1:4001,https://n2:4001,https://n3:4001`.
   Any node accepts writes; rqlite forwards them to the leader.
3. `GET /health` on each node reports the ledger state; use it for load-balancer checks.

## Peers and tokens

```bash
atalk peer-add   <agent> --token <secret> --role agent --platform <name>
atalk peer-rotate <agent> --token <new-secret> --grace-seconds 300
atalk device-token add|list|revoke <agent> ...
atalk grant-add --grantor <agent> --grantee <agent> --command <op>
atalk acl-set|acl-list|acl-clear ...
```

Prefer server-generated device tokens (`device-token add` without `--token`) so the
secret never appears in a shell history or process list. Store per-peer credentials in
`/etc/atalk/<agent>.env` with mode `0600` (see `examples/peer.example.env`).

## Adapters

Each agent runs one adapter that reads its inbox and writes `received`/`applied`
ACKs. Example unit: `deploy/atalk-inbox-adapter@.service`. Adapter state (cursor and
task threads) lives under `/var/lib/atalk/<agent>/` and must survive restarts; the
adapter resumes from the last applied server `id`.

After a long adapter outage, consider advancing the cursor past stale events before
restarting, otherwise the agent will replay the whole backlog.

## Backups

The event log contains message bodies. Back it up like any other sensitive database
(SQLite: copy with `sqlite3 .backup`; rqlite: use its backup API). Restore is a file
replace on a stopped node.

## Schema and upgrades

The two backends initialize differently:

- **SQLite** (`AtalkStore`) runs `schema.sql` at startup (so it works from an empty
  file) and idempotently backfills the columns added by later versions to the `peers`
  and `peer_tokens` tables. It does **not** retro-add every possible column: upgrading a
  database created before a non-token column was added (e.g. `events.auth_actor`) needs
  a manual `ALTER TABLE`. For a clean install this never applies.
- **rqlite** (`RaftSQLStore`) does **not** create the base tables at server startup.
  A server started with `--backend rqlite` only ensures the token and ACL sub-schema
  idempotently; it assumes the cluster's base tables already exist. Initialize the
  cluster **once** before starting any server (otherwise startup or the first
  `peer-add` fails on a missing table). `initialize=True` runs the full `CREATE TABLE`
  set once; the CLI `init` command is SQLite-only and refuses the rqlite backend.

Initialize an rqlite cluster once with a throwaway script (run from the repo root):

```bash
python3 -c 'from atalk.raftsql import RaftSQLStore; RaftSQLStore(["https://n1:4001","https://n2:4001","https://n3:4001"], initialize=True)'
```

Once initialized, schema evolution is additive, so a rolling restart across nodes is
safe; restart all nodes before issuing tokens that depend on a newly added column.
`atalk.migration` is a **separate one-shot tool** (`python3 -m atalk.migration`) for
moving a SQLite event log onto an rqlite cluster; its subcommands are `snapshot`,
`import`, `sync` and `compare`. It is not run automatically on start.
