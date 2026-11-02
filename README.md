# fortinet-fortiedrv2

A FortiSOAR connector for Fortinet FortiEDR: a v2 rebuild of the shipped
`fortinet-fortiedr` 2.1.0 connector with pydantic models, fixed ingestion
semantics, and console-incident operations.

## Why v2: the "no incidents found" ingestion defect

FortiEDR correlates a re-detection of the same process into the **existing**
event: the event's `firstSeen` stays pinned at the first detection and only
`lastSeen` moves (verified live: a `control.exe` event created 2026-10-13
kept absorbing detections through 2026-10-29 while its incident grew past
ten events). The shipped connector's ingestion playbooks query the pull
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
- Event reads return parsed `firstSeenEpoch` / `lastSeenEpoch` twins (UTC)
  alongside the raw timestamps.

Deviations from 2.1.0 are deliberate fixes and each is commented in the
source; the release notes list them.

## Layout

```
connector.py        FortiSOAR entry point
client.py           HTTP client (the only module that touches requests)
operations.py       operation handlers (35 operations)
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

The live suite is read-only: it never creates, updates, deletes, isolates,
or remediates anything on the tenant.

## Packaging

`scripts/package.sh` builds `dist/fortinet-fortiedrv2-1_0_0.tgz` from
`git ls-files` (version dots become underscores: the FortiSOAR installer
misroutes a filename with more than one dot).

## Playbooks

`playbooks/playbooks.yaml` is the source of truth; rebuild the compiled JSON
with `python3 playbooks/build.py` (requires the fsrpb compiler). The
collection ships the Data Ingestion Wizard chain (Init Macros / Fetch /
Ingest) plus the sample collection the wizard discovers by its
`dataingestion` tags.
