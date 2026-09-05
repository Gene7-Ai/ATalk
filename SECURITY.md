# Security

## Reporting

Please report vulnerabilities privately to the maintainers (see the repository's
contact information) rather than opening a public issue. We aim to acknowledge reports
within 7 days.

## Threat model

ATalk is designed to run **inside a private network** (a LAN or an overlay such as
WireGuard/Headscale/Tailscale) between machines operated by one organisation. It is
not hardened for direct exposure to the public internet.

Protected:

- Every request is authenticated with a per-peer bearer token or a scoped device token.
- Tokens are stored hashed on the server; rotation has a grace window; a single device
  token can be revoked without affecting the others.
- Commands require an explicit grant (`peer_grants`) in addition to a valid token.
- Restricted peers can be limited to explicit targets (outbound target ACL); broadcast
  is denied for them.
- All command activity is written to an audit log.

Not protected (by design, in this release):

- Transport encryption. The server speaks plain HTTP; put it behind TLS (reverse proxy)
  or run it on an encrypted overlay. The desktop client expects TLS.
- Message bodies. `GET /events` returns the full `payload` (including `payload.text`)
  to any valid token for that peer. Token **scope** currently gates device-token
  administration (adding/revoking device tokens requires `full`), **not** read
  redaction: a `notify`-scoped token can today read message bodies just like a `full`
  token. Redacting bodies for notify-scoped sidecars is an open item, not yet enforced.
- Denial of service. There is no rate limiting beyond gate-style attempt counters used
  by some adapters.

## Operational rules we follow

- Runtime tokens (used by adapters) are read from the `ATALK_TOKEN` environment
  variable, kept in `0600` env files. Prefer **server-generated device tokens**
  (`device-token add` without `--token`) so the secret is never typed at all.
- The admin `peer-add --token <secret>` and the quick-start examples do pass a token on
  the command line for convenience; that is fine for throwaway demo tokens but for real
  secrets generate them server-side or rotate immediately, since argv is visible in
  process lists and shell history. (A stdin/env input path for `peer-add` is an open
  item.)
- Backups of the event log contain message bodies; treat them as sensitive.
- Rotate a peer token immediately if a machine hosting it is lost or compromised.
