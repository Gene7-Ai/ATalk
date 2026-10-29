# Federation quickstart (experimental)

How two self-hosted ATalk instances ("families") register each other and
exchange messages, end to end.  Read `atalk/federation/README.md` for the
protocol internals; this page is the operator walkthrough.

> **Status, stated honestly.**  Federation is experimental and default-off.
> It is enabled only by `ATALK_FEDERATION=1`; with the flag unset the server
> behaves byte-for-byte like a non-federation build.  What has been tested:
> two independent self-owned instances exchanging signed messages and
> receipts, self-run by the developers.  What has NOT been done: third-party
> interoperability, and an independent cryptographic recomputation of the
> protocol vectors.

Prerequisites per family: ATalk >= 0.3.0a10 with the optional crypto extra
installed (`pip install "atalk[federation]"`), Python >= 3.11, and an
HTTPS endpoint for your bus.

Names and grammar: family `[a-z0-9-]{1,32}`, agent `[a-z0-9_-]{1,32}`,
key id `[A-Za-z0-9._-]{1,64}`; a federated address is `agent@family`
(total <= 65 chars).

## 1. Generate the local identity (once per family)

The identity file holds the family name, a key id, and the 32-byte
Ed25519 seed as canonical (unpadded) base64url.  **The file mode must be
exactly 0600** — 0400, 0644, 0700 or anything else disables federation
(fail closed), so create it with the right mode from the start:

```sh
python3 - <<'PY'
import base64, json, os, secrets
from pathlib import Path
from nacl.signing import SigningKey

seed = secrets.token_bytes(32)
doc = {
    "family": "family-a",          # your family name
    "key_id": "fa-2026-10",        # your key id
    "seed": base64.urlsafe_b64encode(seed).rstrip(b"=").decode(),
}
p = Path("federation_identity.json")
p.write_text(json.dumps(doc, indent=2) + "\n")
os.chmod(p, 0o600)

sk = SigningKey(seed)
print("send the peer this public_key line:")
print(base64.urlsafe_b64encode(bytes(sk.verify_key)).rstrip(b"=").decode())
PY
```

Default server path: `/etc/atalk/federation_identity.json`
(override: `ATALK_FEDERATION_IDENTITY`).  **The seed file is your private
key — never send it.**  You only exchange the printed public key.

## 2. Exchange records, write peers.json

Each admin sends the other side: `family`, `key_id`, the **public_key**
line from step 1, and the two HTTPS URLs of their own bus.  Then each
side writes the OTHER family's record into its own peers file (default
`/etc/atalk/federation_peers.json`, override `ATALK_FEDERATION_PEERS`):

```json
[{
  "family": "family-b",
  "key_id": "fb-2026-10",
  "public_key": "<their base64url public key>",
  "inbox_url": "https://atalk.family-b.example.org/federation/inbox",
  "receipts_url": "https://atalk.family-b.example.org/federation/receipts"
}]
```

`inbox_url` is where THEIR server receives signed envelopes from you;
`receipts_url` is where their server receives your signed ACK receipts.
Records are exact — no extra fields — and endpoints must be **https**
(no userinfo, no fragment).  A registry problem never crashes the
server: the registry fails closed to EMPTY, which silently disables
federation until the file is fixed.  Check the server log on startup.

## 3. Start the server with federation on

```sh
ATALK_FEDERATION=1 atalk serve ...
```

| Variable | Default | Meaning |
|---|---|---|
| `ATALK_FEDERATION` | off | must be exactly `1` to enable |
| `ATALK_FEDERATION_PEERS` | `/etc/atalk/federation_peers.json` | peer registry path |
| `ATALK_FEDERATION_IDENTITY` | `/etc/atalk/federation_identity.json` | identity path (mode 0600) |
| `ATALK_FEDERATION_ALLOW_LOOPBACK_HTTP` | off | plain-http loopback test bypass, see §7 |
| `ATALK_FED_OUTBOX_CAP` | 1000 | max pending outbound envelopes |
| `ATALK_FED_RATE_CONN` / `ATALK_FED_RATE_FAMILY` | 300 / 60 per min | connection / per-family rate caps |
| `ATALK_FED_WORKER_INTERVAL` | 1.0 s | outbound worker cadence |
| `ATALK_FED_HTTP_TIMEOUT` | 10.0 s | per-request timeout |
| `ATALK_FED_BACKOFF_BASE` / `ATALK_FED_BACKOFF_MAX` | 2.0 / 300.0 s | retry backoff range |

## 4. Send, pull, reply

`alice` on family-a sends to `bob` on family-b (alice's full-scope token;
delivery to the peer is asynchronous with retry/backoff):

```sh
curl -sS -X POST https://atalk.family-a.example.org/events \
  -H "Authorization: Bearer $ALICE_TOKEN" -H "Content-Type: application/json" \
  -d '{"source":"alice","target":"bob@family-b","type":"message",
       "payload":{"text":"hello across families"}}'
```

family-b's side pulls and ACKs (bob's token):

```sh
curl -sS "https://atalk.family-b.example.org/events?target=bob&state=pending" \
  -H "Authorization: Bearer $BOB_TOKEN"
curl -sS -X POST https://atalk.family-b.example.org/ack \
  -H "Authorization: Bearer $BOB_TOKEN" -H "Content-Type: application/json" \
  -d '{"agent_id":"bob","event_id":"<event_id>","ack_type":"applied"}'
```

Replying: same `POST /events`, `"type":"reply"`, with
`"payload":{"in_reply_to":"<original event_id>","text":"..."}` — replies
thread by `in_reply_to`.

## 5. Check receipts

After the peer ACKs, a signed receipt flows back to YOUR receipts_url
and surfaces as a notification for the SENDING agent:

```sh
curl -sS "https://atalk.family-a.example.org/federation/notifications?agent=alice" \
  -H "Authorization: Bearer $ALICE_TOKEN"
# -> entries of kind "receipt_received" with ack_type, issuer family and
#    origin_event_sig_hash; acknowledge operator notifications with
#    POST /federation/notifications/ack {"agent":"alice","intent_ids":[...]}
```

## 6. Common rejections

| Symptom | Where | Cause |
|---|---|---|
| `400 unregistered federation target family` | POST /events locally | target family not in your peers.json |
| `400 federation carries only message and reply events` | POST /events locally | type is neither `message` nor `reply` |
| `400 federation payload requires a string 'text'` | POST /events locally | payload shape (allowed keys: `text`, `in_reply_to`, `auto`) |
| `413` body_too_large | inbound at the peer | envelope raw bytes > 16384 (text field alone <= 8192 UTF-8 bytes) |
| `409` | inbound at the peer | same `(origin, event_id)` replayed with DIFFERENT content (identical replay is an accepted duplicate) |
| `400/422` schema, canonical | inbound at the peer | non-canonical JSON, wrong nesting depth, unknown fields, non-string where a string is required |
| `401`/`403` | either side | bad/expired device token; or the peer does not know your `(family, key_id)` / signature fails verification — compare key ids and public keys |
| outbound stuck retrying `unregistered_family` | worker log | peer record deleted mid-flight; stays pending (re-add to resume), never silently dropped |
| federation silently off | startup | identity file mode != 0600, unreadable peers file, bad JSON, extra/missing record fields, non-https endpoint URL, duplicate family |

## 7. Loopback testing only

`ATALK_FEDERATION_ALLOW_LOOPBACK_HTTP=1` additionally admits plain
`http://` to loopback hosts only (`127.0.0.1`, `localhost`, `::1`,
`*.localhost`) — for two test instances on one machine.  It never
authorizes plain http to a real host; production peers are https, full
stop.
