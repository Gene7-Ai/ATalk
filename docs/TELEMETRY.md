# Installation telemetry

ATalk installation telemetry is **pseudonymous** and off by default. The installer
does not prompt. Enable it with `--telemetry` or `ATALK_TELEMETRY=1`; disable it with
`--no-telemetry`. Explicit disable takes precedence over every other setting.

A successful fresh install sends one `POST` to `https://t.atalk.ai/i`; a successful
upgrade sends one to `/u`. The JSON body contains exactly:

| Field | Value and purpose |
|---|---|
| `version` | Installed ATalk version, used to understand version adoption. |
| `platform` | Operating system and architecture as `os/arch`, used for compatibility planning. |
| `install_id` | Persistent random UUID, used to distinguish installations without collecting an account or machine name. |
| `mode` | `script-tar` (or `docker` for a future Docker caller), used to compare installation methods. |

The receiving proxy and application transiently process the source IP to serve the
request, but do not persist it. Raw telemetry is retained for 90 days, then only a
daily aggregate is retained.

To disable telemetry, omit the opt-in, unset `ATALK_TELEMETRY`, or pass
`--no-telemetry`. To reset the pseudonymous identifier, delete
`/etc/atalk/install_id`; when `/etc` is not writable, delete
`${XDG_STATE_HOME:-$HOME/.local/state}/atalk/install_id`. A later opted-in install
will create a new UUID. To request deletion of already received records, email
privacy@atalk.ai with the install ID from `sudo cat /etc/atalk/install_id` (or
the fallback path above) and ask for telemetry deletion.

Any website control that maps to this setting must be unchecked by default and must
not enable telemetry without an affirmative user action.
