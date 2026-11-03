# fortinet-fortiedrv2

A FortiSOAR connector for Fortinet FortiEDR: a v2 rebuild of the shipped
`fortinet-fortiedr` 2.1.0 connector with pydantic models, fixed ingestion
semantics, and console-incident operations.

## Why v2: the "no incidents found" ingestion defect

FortiEDR correlates a re-detection of the same process into the **existing**
event: the event's `firstSeen` stays pinned at the first detection and only
`lastSeen` moves (verified live: a `control.exe` event kept absorbing
re-detections for weeks while its incident grew past ten events). The
shipped connector's ingestion playbooks query the pull
window on `firstSeenFrom` and leave `lastSeenFrom` blank, so a scheduled pull
after any re-detection finds **zero** new events -- the ingestion report says
"no incidents found" while the FortiEDR console shows a live incident.

This connector reads the window on **Last Seen** by default (every event
created *or* re-triggered inside the window) and deduplicates through the
ingest playbook's upsert: `sourceId = eventId`, so a window read twice
updates its alerts instead of duplicating them. The created-only behavior
remains selectable ("First Seen (creations only)") for deployments that
want it.

## Operations

- All 31 shipped `fortinet-fortiedr` operations, same names and endpoint
  semantics, so a playbook can be repointed one operation at a time.
- `ingest_events` -- windowed, paginated fetch returning alert payloads;
  `time_field` selects the Last Seen / First Seen window axis.
- `get_incidents`, `get_incident_by_id`, `get_incident_events` -- the
  console-tier incidents (the objects the FortiEDR UI groups events by).
- `delete_exception` -- the API's `exceptions/delete` endpoint, which the
  shipped connector never exposed; without it an exception created for an
  event was permanent for playbook purposes. Exception IDs are required
  unless `Delete All` is explicitly True (mass delete by filters).
- Event reads return parsed `firstSeenEpoch` / `lastSeenEpoch` twins (UTC)
  alongside the raw timestamps.

Events map to alert payloads whose `description` is a rich-text card (bold
headline, severity/classification/action chips, a hairline detail table --
inline styles only, matching the FortiSOAR alert description sanitizer).

Deviations from 2.1.0 are deliberate fixes and each is commented in the
source; the release notes list them.

## Layout

```
connector.py        FortiSOAR entry point
client.py           HTTP client (the only module that touches requests)
operations.py       operation handlers (36 operations)
models.py           pydantic models for events / incidents / collectors ...
field_mapping.py    event -> alert payload mapping (picklist-safe)
ingestion.py        the windowed fetch behind ingest_events
info.json           manifest (regenerate with python3 scripts/gen_info.py)
playbooks/          playbooks.yaml -> build.py -> playbooks.json
tests/              offline suite (responses-mocked) + opt-in live suite
scripts/package.sh  builds the installable .tgz from git ls-files
```

## Testing

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt -r tests/requirements.txt
.venv/bin/pytest tests/test_offline.py     # offline: no appliance needed

cp .env.template .env.live                 # fill in, gitignored
.venv/bin/pytest tests/test_live.py --live # read-only against a tenant
```

The offline suite pins the exact REST request each operation makes, the
Last-Seen-first ingestion window, the playbook/wizard contract, the
client-method boundary (an AST test, because offline mocks hide a renamed
method until a live box fails mid-run), and latin-1 encoding safety.

There are two live suites, both opt-in with `--live`:

- `tests/test_live.py` is read-only: it never creates, updates, deletes,
  isolates, or remediates anything on the tenant.
- `tests/test_live_ops.py` exercises **every** operation, including narrow,
  state-restoring round trips (read toggle, isolate/unisolate, collector
  group, IP set create/update/delete) on an approved sacrificial collector
  and event. Its last test gates that the session really executed all 36
  operations.

The mutating suite takes its targets from `.env.live` keys (documented in
`.env.template`): `EDR_ROUNDTRIP_COLLECTOR` (collector approved for the
isolate/move/state exercises), `EDR_DEMO_EVENT_ID` (a long-lived event
whose pinned `firstSeen` proves the ingestion semantics) and
`EDR_SACRIFICIAL_EVENT_ID` (event approved to carry the exception round
trip, which the suite also removes through `delete_exception`). All three
are optional and tenant-specific; a suite that does not know a target
skips the tests that need it instead of guessing.

Run both together:

```bash
.venv/bin/pytest tests/test_live.py tests/test_live_ops.py --live
```

## Packaging

`scripts/package.sh` builds `dist/fortinet-fortiedrv2-<version>.tgz` from
`git ls-files` (version dots become underscores: the FortiSOAR installer
misroutes a filename with more than one dot).

## Live box: install and verify

`scripts/install_to_fsr.py` installs the built bundle on a FortiSOAR box with
`$replace`, recycles the integrations workers (an upgrade keeps serving the
old in-process module otherwise), and creates/refreshes a configuration and
health-checks it. Installing needs JWT auth -- a username/password pyfsr
alias; an API key is not a JWT and stalls at Draft, which pyfsr refuses up
front:

```bash
python scripts/install_to_fsr.py --instance <pyfsr-alias> --with-config
```

`scripts/verify_ingestion.py` walks the data ingestion chain end to end with
the same calls the Data Ingestion Wizard's Finish makes: get-or-create the
per-configuration ingestion collection, write the Initial Backfill Range into
the cloned Fetch exactly the way the confirm step does, fire
*Trigger Ingestion Now* twice, and assert the contract the chain promises --
alerts keyed `sourceId == eventId`, the rich-text card stored unescaped,
pinned-firstSeen re-detections ingested (the defect v2 exists to fix), upsert
dedup across passes, and the watermark advancing every pass:

```bash
python scripts/verify_ingestion.py --instance <pyfsr-alias>
```

Both scripts run under a pyfsr environment (its checkout's `.venv`); targets
resolve from `~/.pyfsr/instances.toml` and the `EDR_*` environment from
`.env.live`.

## Playbooks

`playbooks/playbooks.yaml` is the source of truth; rebuild the compiled JSON
with `python3 playbooks/build.py` (requires the fsrpb compiler). The
collection ships the Data Ingestion Wizard chain (Init Macros / Fetch /
Ingest) plus the sample collection the wizard discovers by its
`dataingestion` tags. The Fetch step's window read is count-verified and
never paged: on FortiEDR 7.x, a windowed `list-events` request carrying
`pageNumber` answers `200` with an empty page, so the connector asks
`count-events` first, sizes one request to the count, and fails loudly
rather than reading part of a window (See Ingest Events in the release
notes).
