# fortinet-fortiedrv2 release notes

## 1.1.4

Allow Event's organization scope, corrected: **`Allow Event (Time-Limited)`
now creates the exception with `allOrganizations=False`** -- the
live-proven wire the connector's own live ops test has used all along.
The step shipped with `allOrganizations=True`, which no non-Admin API
user can create: FortiEDR answers `400 Only a user with an Admin role
can create/modify exceptions for all organizations` and the allow run
dies at the Create Exception step (live-caught driving the playbook on
8.0.1 against a lab tenant whose API user is intentionally non-Admin).
The rule still opens every collector group and every destination --
within the event's own organization, the scope the creating user
actually has. A cross-organization exception remains an Admin's console
action, which the playbook never does on the operator's behalf.

Code-snippet steps, made portable: the three inline-Python steps (`Find
Expired` in the sweep, `Rank Incidents` in the re-detection digest,
`Audit Fleet` in the fleet compliance audit) now compile with
`config: ""` -- the appliance-default sentinel, exactly like every other
step in the collection. They previously carried a per-appliance
configuration UUID that the compiler picked up from the build host's
warmed catalog, so the first run on every OTHER box refused them with
`INTEGRATION-12: Could not find a connector configuration matching the
given configuration id or name ...` (live-caught on 8.0.1: the same
bundle's connected steps all ran while the snippet step died). The build
now fails if any step would carry a non-empty config, so a warmed
catalog can never leak an appliance UUID into the bundle again.

The three playbooks execute that Python through the appliance's own **Code
Snippet** configuration, so an appliance needs two one-time settings before
the sweep, digest or fleet audit can run: the *Custom Code Execution*
toggle on (Settings -> System Settings -> Advanced Development Features --
off on some hardened builds), and a Code Snippet configuration set as the
appliance default (Content Hub -> Connectors -> Code Snippet ->
Configurations; leave Allow Universal Imports off and list the modules you
allow). Without them the playbooks answer `INTEGRATION-12` or `Custom Code
Execution is disabled` at the inline step -- both live-caught on 8.0.1, on
an appliance that had neither.

Task record fields, portability again: the digest's and the fleet audit's
task steps no longer pin `status` and `priority` -- only the task's name
and description. On the engine's write path those fields are picklist
references the appliance resolves by item IRI/uuid, not by label: a bare
`Open` (or `Low`) is refused with `FSR_CH_0000001 ... the provided value
does not match any of the options listed in the specified picklist` even
on an appliance whose TaskStatus picklist *carries* `Open` -- live-caught
on 8.0.1, the engine probing `/api/3/picklists/Open` as though the label
were the item's uuid. The per-item IRIs machine-authored playbooks ship
instead are appliance-local uuids, which this bundle deliberately never
carries. The importing SOC's own task workflow decides the task's state.
The steps are also plain record inserts -- the ingestion chain's own write
path -- not ManualTask steps: the manual-task engine step parks a
playbook run `awaiting` until a human completes the task (live-caught on
8.0.1, the digest run sitting open at its task step with the task
correctly filed). Filed task, finished run.

Upgrade note (in-place upgrades over earlier 1.1.x): each version-stamped
sample collection carries its own copy of the use-case playbooks, and the
import does not retire the old collection's copies -- they stay
active alongside the new ones, so a record's action menu lists one entry
per still-installed version. Delete the older `Sample - Fortinet
FortiEDR v2 - <oldversion>` / `... Use Cases - <oldversion>`
collections after an upgrade so the drive selects the current definition
(and the operator's action menu shows one entry per use case). A fresh
install has no older collections to clean.

## 1.1.1

Ingestion pull filters: **the Data Ingestion Wizard's configuration form
gains four optional filters** -- Classifications, Severities, Device Name
and Collector Groups -- so one ingestion configuration can scope what a
scheduled pull ingests (only Malicious/Suspicious, one device, one
collector group, ...) instead of pulling the whole tenant window. Blank
means unfiltered: a pristine configuration behaves exactly as before.

They ride the same window the whole pull already trusts:

- The wizard-written values (blank by default in the Fetch playbook's
  `Configuration` defaults, which the Data Ingestion Wizard keeps
  1:1 with the Start step's schema fields -- the shipped-connector
  contract) flow into the `Ingest Events` step's params and from there
  into `ingest_events`, which merges them into the ONE query the
  count-verify already builds: `count-events` and `list-events` both see
  the filtered window, so a filtered run that cannot read its whole
  (filtered) window still fails loudly and never advances the watermark.
- Values are normalized to the events API's own comma-separated form: a
  multiselect delivered as a list joins on commas, whitespace-only is
  dropped like blank, and `collector_groups` renames to the wire's
  `collectorGroups`.
- **The watermark contract is deliberate and documented on the form**: a
  filtered pull advances the pull watermark PAST the events its filter
  excluded. Set filters before the first pull and keep them stable; events
  skipped by an earlier filter are never re-read by a later one. Ingestion
  filters, unlike search, are forever -- the field tooltip says exactly
  this.
- `ingest_events` gains matching `device` and `collector_groups` action
  parameters, and the offline suite pins the full wire (both endpoints'
  query strings, the rename, the blank-drop, list-joining) while the live
  suite cross-checks a filtered pull against the filtered count and
  asserts every returned row matches the filter.

Also in this release: `scripts/verify_use_cases.py`, the twelve-phase
live driver the use-case collection was verified with (sacrificial event,
round-trip collector, gate approve/decline, self-cleaning postflight).

## 1.1.0

Operational use cases: **the connector now ships a second, seven-playbook
collection -- `Sample - Fortinet FortiEDR v2 Use Cases` -- covering triage
and response, forensics, exception governance, reporting, hunting, and
fleet compliance.** Same authoring bar as the ingestion chain: strict-compiled
against the pinned fsrpb catalog, offline-pinned in the suite, and every
branch live-driven on a demo tenant before release. The collection carries
`usecase` tags and deliberately NOT the wizard's
`dataingestion`/`fetch`/`ingest`/`create` tags, so the wizard never offers
it as an ingestion configuration.

The playbooks:

- **Triage to Isolation** (record action on an alert): re-reads the live
  event -- severity and the collector may have moved under the static
  ingested card -- warns about exceptions already muting the event, bags
  the binary, then gates `isolate_collector` behind an approval whose
  outcome (approve or decline, plus the reason) lands on the alert as a
  comment.
- **Collect Evidence** (record action, chained into Triage): pulls the
  binary the event fired on (`get-event-file`, Disk mode, addressed by the
  event's own process path and raw-event anchor), uploads it as an
  appliance attachment, and APPENDS it to the alert with the platform's
  `__link` primitive -- a plain fields-write would replace existing
  attachments. A memory pull needs `processId`/`startRange`/`endRange`
  anchors the events API never exposes (checked against the raw-data
  export), so automatic memory dumps stay a console action; an offline
  collector degrades to a comment instead of a dead run.
- **Allow Event (Time-Limited)** (record action): FortiEDR's exception API
  has no expiry -- a rule created today is permanent. This wraps
  `create_exception` with a validity window encoded in the rule's own
  comment (`fortiedrv2-managed expires=<epoch>`, the only ledger both the
  console and the sweep can read), refuses to stack a second allow over
  existing rules, and records the terms on the alert.
- **Exception Expiry Sweep** (scheduled/manual): lists every exception,
  keeps managed rules still in their window, counts -- never touches --
  unmanaged rules, and deletes the expired managed ones via the v2-only
  `delete_exception`. The delete sends exception IDs and nothing else:
  the endpoint's `comment` parameter is a FILTER, not a note (live-observed
  -- a delete carrying a non-matching comment deletes nothing), and the
  organization argument narrows the request the same way.
- **Re-detection Digest** (scheduled/manual): the ingestion defect, told as
  a report. FortiEDR pins an event's `firstSeen` at its first detection, so
  an incident that has been quietly live for weeks is invisible to anything
  incremental-first-seen. This ranks console incidents by how many
  detections each is still absorbing and files the digest as a FortiSOAR
  task for the SOC queue.
- **IOC Retro-Hunt** (Execute-menu action, one hash input): sweeps current
  events, the threat-hunting repository and communicating applications via
  the file-hash search, then upserts one alert per hit event through the
  SAME sourceId = eventId contract the ingestion chain uses -- repeats
  annotate, never duplicate. The hunt deliberately never writes
  `alertDetectionDate`: a hunt that runs months later must not rewrite the
  incident's recorded first detection.
- **Fleet Compliance Audit** (scheduled/manual): reads the collector fleet
  and the available installers, computes per-OS-family installed-vs-
  available (component-wise, 6.1.10 over 6.1.9), files a digest task, and
  when the fleet lags offers an approval-gated `update_collector_installer`
  staging step with an explicit target version and scope.

Schema corrections riding along (both live-observed):

- `get_collector_installers`' organization is no longer marked required --
  the server lists the connector configuration's own organization when it
  is blank, which is exactly what the sample fleet playbook relies on; the
  declared requiredness uncompilable-blank only made failure harder to read.
- The organization SELECT VALUE `"All organizations"` is rejected
  server-side as a name on the tenant-listing endpoints (collectors,
  exceptions); the samples pass a blank or the exact organization name, and
  the fields' descriptions now say so.

Also in this release: `playbooks/build.py` compiles BOTH sample collections
(the chain from `playbooks.yaml`, the use cases from `playbooks/use_cases.yaml`)
and merges them into the single `playbooks.json` the appliance imports, with
the version stamped on both collection names from `info.json`.

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
