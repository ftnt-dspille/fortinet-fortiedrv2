# fortinet-fortiedrv2 release notes

## 1.0.1

Scheduled ingestion fix: **the window fetch no longer pages
`GET /management-rest/events/list-events` -- `pageNumber` is never sent.**

Live-observed on FortiEDR 7.2.3: a WINDOWED list-events query that carries
`pageNumber` answers `200` with an EMPTY page whenever `itemsPerPage` sits
at or near the documented default of 100 (and pages come back short,
duplicated or reordered even at page size 5), while the SAME window without
`pageNumber` returns every matching row in one response -- and
`/events/count-events` honors the same window filters exactly. 1.0.0's
ingest loop always sent `pageNumber`, so every scheduled pull answered "no
incidents found" on a populated tenant: the connector reintroduced, in its
own fetch loop, the exact failure it exists to fix. (The shipped 2.1.0
playbooks never sent the parameter.)

The pull is now count-verified rather than paged:

- `/events/count-events` is asked first. A window holding more events than
  **Max Events** FAILS the run instead of silently trimming -- a partial
  read must never advance the pull watermark past unread events.
- The window is fetched in ONE list-events request sized to the count
  (floor 200 items, ceiling the documented maximum of 1000); `pageNumber`
  is never sent.
- An answer short of the count is re-read (the earlier live-observed
  200-with-`[]` flake), then escalated by splitting the window in halves,
  bounded depth, each half verified against its own count; a fetch still
  short at maximum depth raises, naming both numbers.
- Rows that arrive despite a zero count are kept: the verification is
  one-sided (fetched must be at least counted), so a lagging count-events
  can only add noise, not drop events.
- The `itemsPerPage` parameter is REMOVED from the Ingest Events form: it
  only ever sized pages that must not be sent. **Max Events** keeps its
  5000 default and its tooltip now documents the fail-loud semantics, as
  does the bundled Fetch playbook's Maximum Events Per Run form field.

Tests: the offline ingest suite pins the request shape (no `pageNumber`,
a single count-verified request, the split/dedup/loud-failure paths); the
live round trip cross-checks list against count for the same window, so the
vacuous green that let 1.0.0 ship -- shape assertions over what was an
empty list -- is structurally gone.

Also new in this release: box tooling -- `scripts/install_to_fsr.py`
(JWT-auth install, integrations-worker recycle, configuration upsert,
health check) and `scripts/verify_ingestion.py`, which drives the deployed
Data Ingestion Wizard chain end to end through the same API calls the
wizard's Finish button makes.

## 1.0.0

Initial release: a v2 rebuild of the shipped `fortinet-fortiedr` 2.1.0
connector with the ingestion semantics fixed and pydantic models behind every
event/incident read.

Operations: all 31 shipped operations keep their names, endpoints, and
parameter forms so a playbook can be repointed one operation at a time. New
operations:

- **Ingest Events** (`ingest_events`) -- a windowed, paginated fetch that
  returns FortiSOAR-ready alert payloads. The window read is chosen by a
  **Time Field** parameter and defaults to the event's **Last Seen
  (activity)**. FortiEDR links a re-detection of the same process into the
  EXISTING event: its firstSeen stays at the first detection and only its
  lastSeen moves. The shipped ingestion playbooks queried the window on
  firstSeen, so a scheduled pull after a re-detection finds zero new events
  and reports "no incidents found" while the console shows a live incident.
  The stock behavior stays available as "First Seen (creations only)".
- **Get Incidents** / **Get Incident by ID** / **Get Incident Events** -- the
  console-tier incident objects (what the FortiEDR UI groups events by; an
  incident keeps absorbing the re-detections of its process).
- **Delete Exception** (`delete_exception`) -- the API's
  `exceptions/delete` endpoint, which the shipped connector never exposed:
  an exception created for an event was permanent for playbook purposes.
  Exception IDs are required unless **Delete All** is explicitly True
  (mass delete by filters). The connector's live suite now creates AND
  removes its test exception through this op.

Behavior kept from the shipped 2.1.0 connector on purpose: the 400 retry
loop, `message`/`errorMessage` surfacing, `YYYY-MM-DD HH:MM:SS` datetime
normalization, org-qualified usernames, and the IP-set organization
semantics (including the 'Each' quirk where the discovery query lists under
'All organizations').

Deliberate fixes over 2.1.0, all marked with comments where they deviate:

- Update Exception now updates the exception whose ID was requested; the
  shipped connector always posted the first exported exception and
  re-created it untouched when the requested ID did not match. Live testing
  added a second layer: the update scans EVERY raw item of the event for the
  requested ID -- and on FortiEDR 7.x it still reports a plain failure naming
  the id, because exceptions created through Create Exception are stored
  server-side and appear in no raw-item export at all (live-observed on
  7.2.3: the event's sole raw item exports with Exceptions=None while
  get-event-exceptions returns the rule). The shipped connector answered a
  false `success: Exceptions list not found` here; the raw-export edit path
  keeps working for FortiEDR versions that do embed exceptions.
- Update Collector Installer parses a pre-encoded JSON string passed as
  Update Versions -- the body must carry CollectorInstallerRequest objects
  (`osFamily`, `version`, `allowDowngrade`), which the live API enforces
  with a 400 naming the deserializer.
- Update Event now sends its boolean flags (`read`, `handle`, `archive`,
  `mute`, `forceUnmute`) as JSON `true`/`false`. The form selects deliver
  the strings `'True'`/`'False'` and the API answers 200 to a string body
  while ignoring it -- the shipped read/handle/archive toggles were silent
  no-ops (live-observed on 7.2.3). Note for 7.x operators: the API accepts
  the flag updates but does not reflect them back in the event row
  (`seen`/`handled` stay unchanged), and `handle: false` additionally
  triggers a FortiEDR server-side 400 (`batchSize is null`) -- a server
  bug the connector surfaces unchanged, as its own error message.
- Event, incident and IP-set models read a JSON null list field as an
  empty list; the live tenant answers `"loggedUsers": null` for
  unattended-service events, which broke the first live pull that met one.
- Search IOC keeps a `devices` value that already arrived as a list; the
  shipped connector turned it into an empty list.
- Set Collector State stops waiting for the async job after 10 minutes
  instead of polling forever.
- A server URL typed as `http://...` is scheme-stripped instead of producing
  `https://http://...`.
- Retrieved collector files are named after the collector rather than all
  landing as `memdump_None.zip`.
- Event responses gain parsed `firstSeenEpoch` / `lastSeenEpoch` twins (UTC)
  so ingestion field mapping never re-parses timestamps.
- Ingest Events re-requests an empty FIRST page (twice, 2s apart) before
  believing an empty window: list-events was observed (live) answering a
  good paged query once with `200 + []`, then answering the identical query
  with the rows. A scheduled pull that trusted the empty page would skip
  real events AND advance its watermark over them. Later pages are believed
  immediately (a short page already ends the loop).
- Ingested alerts carry a rich-text description card (bold process/device
  headline, severity/classification/action chips, a hairline detail table
  with the rule, users, IP paths and timestamps, all inline styles) --
  rendered by the alert description pane the way the FortiSIEM v2
  ingestion card renders.

Sample playbooks: a Data Ingestion Wizard chain (Init Macros / Fetch /
Ingest) keyed on the activity window, upserting one alert per event on
`sourceId = eventId` so a window read twice updates instead of duplicating.
