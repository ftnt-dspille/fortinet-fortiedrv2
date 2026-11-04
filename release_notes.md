# fortinet-fortiedrv2 release notes

## 1.1.12

**The alert's sourcedata now carries the console's command timeline.** New
`Include Command Timeline` flag on the data ingestion wizard (and on the
`ingest_events` operation, off by default): when on, every fetched event is
enriched through FortiEDR's `rdi-events` endpoint -- the raw-detection
record behind the console event, the same data the console's event
timeline view renders. The process/cmd stacks (what triggered what, with
command lines, paths, hashes, module frames) are trimmed to a whitelist
of fields the timeline widget renders and stored on the alert's
`sourcedata` as `command_timeline`.

- Stored data is trimmed twice: only whitelisted event/stack/stackEntry
  fields survive, and every null, empty string, and emptied container is
  dropped recursively. The console's answer is full of filler
  (`sourceProcessOwner: null`, `moduleFlags: ""`, unlisted booleans), and
  sourcedata carries only what an alert will actually show. The trim also
  sidesteps the code-snippet sandbox's `null` restriction for any
  playbook that later renders the timeline (live-caught in 1.1.11).
- Enrichment fails soft per row: a refused or empty sub-call records
  `command_timeline_error` on that row only and touches nothing else, so
  one dead event cannot sink a pull. Off by default: a large backfill
  window with the flag on is one extra console call per event.
- `sourcedata` is restructured: the rich-text alert `description` HTML
  (by far the largest blob) moves one layer down to `card.description`,
  so the JSON reads as flat scalars first, card and timeline nested
  beneath. The Create Record mapping and the wizard's Data Mapping
  preview moved with it; alert content is unchanged.

## 1.1.11

**Live-caught on the first firing of the Auto-Triage trigger** (the
trigger itself delivered perfectly: the sample-alert insert started the
run through the platform's post_create trigger):

- The code-snippet sandbox rejects the token `null`, and the modeled
  incident rows carry None fields -- embedding them as JSON died with
  "Invalid code snippet: Uses of ['null'] is restricted" before the
  snippet ran a line. The matching now goes through a Jinja flatten step
  that renders one delimited scalar row per incident (fields joined with
  ~, incidents with ||ROW||), and the snippet parses that table with
  string splits only -- no nested JSON crosses the sandbox, ever.
- The console's incident surfaces answer enum-prefixed classification
  values (ClassificationMalicious, ClassificationProbablyMalicious,
  ClassificationInconclusive) while the event API answers the bare words
  the alert columns carry (Malicious, Suspicious, Inconclusive). The
  incident's verdict is normalized to the bare vocabulary before the
  gate compares it, so the trigger filter (sourceType, bare) and the
  incident gate (normalized) speak one language.

**Same-name import does not refresh box content.** Two faces of one
rule, both live-established: a same-version connector replace never
refreshes the served form metadata (1.1.7), and re-importing a sample
collection under the same version-suffixed name keeps the existing
workflow records by name -- no duplicates, no step update. Any
box-visible change to forms OR sample playbook code ships as a new
version. The 1.1.9 and 1.1.10 builds were burned on the lab box before
the second half was understood; their content ships as 1.1.11.

**Malicious alerts answer for themselves.** New use-case playbook
`FortiEDR v2 > Malicious Auto-Triage`: an automatic record trigger fires
the moment the ingestion inserts an alert classified Malicious, re-reads
the parent console incident through Get Incidents with both enrichment
checkboxes ticked, and posts the triage card -- incident rollup,
classification, process identity, owner, collector, and which response
family the fresh rules tripped -- on the alert itself. Process-injection
indicators (Injected Process, Injected Thread, Stack Pivot, Dynamic Code)
or the credential-access analog (Access to Critical System Information,
the rule family hashdump-style tooling trips) hand the alert to the
Containment Chain whole, record passed through: the chain's approval step
still gates every isolation and firewall block, so auto-triage never
auto-contains without a human. A ProbablyMalicious incident -- a verdict
that exists only at the incident level -- is watchlisted with a comment
and never auto-responds; so is a Malicious incident whose fresh rules
carry neither family.

**The ingestion's inserts now wake record triggers.** The ingest Create
Record loop shipped with `__bulk`, which bypasses on-create and on-update
playbook triggers -- right for a high-volume feed, and this feed is tens
of events per pull. Bulk is gone from the ingest loop (the Retro-Hunt
keeps it: a hunt re-annotating old alerts must not wake response
playbooks), so the trigger above actually fires. This also resumes every
other on-create playbook the appliance already binds to alerts -- the
standard system set (indicator extraction, ATT&CK linking, assignment
dates) plus anything site-local -- which is normal platform behavior for
a newly created alert, previously suppressed for FortiEDR ones. A bound
ingestion clone created before this change still bulk-inserts -- tear
that ingestion setup down and re-run the wizard after upgrading.

## 1.1.8

**FortiEDR's own classification lands on the alerts grid.** Every alert
the ingestion writes now carries the event's classification -- Malicious,
Suspicious, Inconclusive, the wording the FortiEDR console itself uses
-- as a first-class column, not only as a chip on the rich-text card.
The stock `sourceType` field ("Source Type") is the home: the alerts
module has no native classification column, its picklist-typed
`emailClassification` holds only Phishing/Non-Phishing, and the stock
FortiEDR connector itself put classification on the description card
alone, so the source's verdict was the one thing a gating playbook had
to dig out of sourcedata. It rides `__fieldsToUpdate`, so the next
ingestion pass back-fills the column on every already-ingested alert,
and the ingestion verifier's module-column read-back now checks it
(the stored `sourceType` must equal the classification the sourcedata
payload claims). A bound ingestion clone created before this change is
stale -- the verifier's preflight flags it -- so tear that ingestion
setup down and re-run the wizard. Gating playbooks read the column
straight off the record.

**The Get Incidents checkboxes render as checkboxes.** The two
enrichment options shipped with form type `boolean`, which the
operation dialog does not implement: every true/false parameter in the
stock fortiedr schema (Archived, Strict Mode, Full Data Requested)
declares form type `checkbox`, the widget the dialog draws a control
for. Under `boolean` the two fields rendered as an unknown control
(live-caught on 8.0.1). Both now declare `checkbox` with the stock
rows' `value: false` default.

**Why the re-version.** The box serves a connector's forms from its
installed record, and a same-version replace never refreshes what it
serves: the fixed build reinstalled over its own installed version
left the dialog on the old metadata even after worker recycles, while
a fresh version took on the first call. Both fixes above therefore
ride one version that reaches a first public release together -- the
1.1.6 and 1.1.7 treads never shipped past the lab.

## 1.1.6

**Get Incidents, enriched in one call.** Two optional checkboxes on Get
Incidents fan out per incident inside the one operation, so a single
playbook step returns the triage context the use-case playbooks otherwise
chain themselves. Neither is checked by default: the request pattern and
the return shape are exactly as shipped until one is ticked, and the
re-detection digest (the operation's existing consumer) is unchanged.

- **Include Events** attaches each incident's linked events as `events`:
  modeled console rows with the epoch twins, capped by **Events Per
  Incident** (10 by default, 500 at most). An incident that reports more
  linked events (`eventsNum`) than the cap returned is flagged
  `eventsTruncated` -- raise the cap for the long-running ones, or page
  through Get Incident Events for the full history. The per-incident
  sub-call is auto-scoped: to the Organization ID parameter when one is
  given, else to the incident row's own console account (`accountId`) --
  the console's per-incident events endpoint answers 200 with an empty
  page when left unscoped, a live-caught trap (the listing endpoint,
  unlike it, honors the authenticated organization).
- **Include Process Detail** re-reads the incident's newest linked event
  through the event API and attaches it as `latestEvent`: the full process
  identity -- `processPath`, `processType`, `processOwner`, the logged
  users, the destinations, the matched rules, the threat details and the
  collector's ip / OS / group. It chains off the incident's events, so
  those are fetched and attached too, and `latestEvent` is `null` when
  the incident carries no events to chain.

Both legs are fail-soft per incident: a refused sub-fetch records
`eventsError` / `latestEventError` on that row and the list carries on --
the same degradation the containment playbooks practice. A missing
enrichment degrades the row, it never kills the list.

**Ingestion default cap lowered to 10 events.** The Fetch playbook's
Maximum Events Per Run now defaults to 10 (was 2000). The cap is what its
tooltip always said -- a safety valve that fails a run loudly rather than
letting a scheduled pull silently stream a backlog (the window fetch is
count-verified and never paged, so an oversized window cannot advance the
watermark half-read). The 10 default suits a lab tenant; on a busier one
raise the cap -- the Data Ingestion Wizard edits the value in place on
the configuration -- or shorten the pull schedule rather than let it
bind.

**The alert type column actually lands now.** The Create Record step
wrote the AlertType picklist under the key `alertType`, which is not a
field of the alerts module -- the API silently drops unknown keys, 200
and all, so the event's real type never reached the column: every alert
kept the module's stock 'Other / Unknown', a Rozena malware alert
included, while severity, the same picklist-pipe shape, resolved fine.
The key is `type`, exactly as the FortiSIEM v2 house recipe writes it,
and the Retro-Hunt use case's hunt-finding upsert carried the same
wrong key, fixed with it. Because `type` rides `__fieldsToUpdate`, the
next ingestion pass back-fills the type of every already-ingested alert
with no delete/re-create. Upgrade note for an existing ingestion
configuration: the bound clone carries the old field set, so the
ingestion verifier's preflight flags it stale -- tear the
configuration's ingestion setup down and re-run the wizard (the
verifier prints both calls) so the fresh clone writes `type`.

**Placeholder threat names are no longer typed Malware.** The console
reports an unresolved signature with placeholder names -- "Unknown",
"N/A", "None" -- and the type clamp read them as signatures,
live-typing every signature-less event Malware (MicrosoftEdgeUpdate.exe
included). They now read as no threat: the alert falls to whatever a
matched rule hints, else to Other / Unknown. A named signature
(Rozena.ABV!tr, Agent.BLY) still means Malware, by name or by family.
The type columns self-correct with the next ingestion pass, the same
back-fill as above.

## 1.1.5

Alerts, enriched for triage: **Scheduled ingestion now writes the pivot
fields an analyst sorts and filters on** -- `eventTime` (the event's last
activity, so a re-detection re-sorts the alert to when it was LAST seen
while `alertDetectionDate` stays first-seen), `sourceIp`/`hostIPAddress`
and `hostName` (the endpoint and its address), `destinationIp` (the first
IP-shaped destination -- the console's destinations array mixes IP
addresses with behavior labels, and a label never lands in the column),
`rule` (the matched rules), `filePath` (the process path), `userName`
(the process owner, else the first logged user) and `userDetails` (every
logged user). Alert names change shape too: what ran, matched by what,
on which device (`control.exe - Suspicious Application on lab-endpoint-01`)
instead of the bare event id -- the eventId stays in `sourceId` and on the
card. On an upsert refresh the enrichment fields update, but the create-only
`state`/`status` do not: a re-detection must never reset an analyst's
in-progress triage back to New/Open. Every field was checked against the
alerts module schema (126 fields) before shipping; object-typed fields with
untested write shapes were left alone rather than guessed at.

Alert cards, deepened: the card carries Handled and Muted chips next to
the classification and action chips, and three overview rows -- process
owner, process type, and the analyst's own comment from the console.

Re-detection digest, wider: the incident table gains Device,
Classification and Isolated columns -- an incident's device list is what
the operator pivots on first, and an isolated incident is already
contained (blank, not "no", so only the exceptional row shouts).

**New use case: Containment Chain** (`FortiEDR v2 > Containment Chain`,
a record action on an ingested alert). One approval, three coordinated
responses: the playbook re-reads the live event, looks the event's user
up in the directory (title, department, mail, manager -- posted to the
alert before the question is asked), then asks the analyst to choose
`Block IP and Isolate`, `Block IP only`, `Isolate only`, or
`Skip Containment`, with a required reason that lands on the alert's
audit trail. The FortiGate leg bans the event's IP-shaped destination
(quarantine-based, time-boxed -- the ban expires on the gate by itself,
so a containment action cannot become a permanent firewall artifact) and
verifies the ban against the device's own list before reporting it as
landed. The isolation leg is the proven triage call, now guarded: a
refused isolation is recorded as an outcome instead of killing the run.

The two action legs ship as fail-soft children (`FortiEDR v2 >
Containment: Lookup User in Directory`, `FortiEDR v2 > Containment:
Block IP at FortiGate`), each also runnable as a record action on its
own. Both degrade to audit comments when their connector is
unconfigured or the call is refused -- a missing side tool degrades the
chain, it never kills it. They need two OPTIONAL connector
configurations on the appliance (the collection installs without
them): an `activedirectory` configuration pointing at the directory
(plain LDAP bind; an AD DS or Samba DC both answer), and a
`fortigate-firewall` configuration pointing at the gate. Every comment
step names its record target explicitly, so the children post to the
parent's alert rather than relying on the trigger-record default.

Upgrade note (1.1.4 -> 1.1.5 specifically): the Data Ingestion Wizard
clones the ingestion chain into a per-configuration collection at setup
time, and the schedule fires that CLONE -- not the sample collection. A
clone made by an earlier version keeps writing the old field set even
after the 1.1.5 connector is installed: the clone's Fetch step calls the
installed connector's mapping, so alert names and the stored source data
do pick up the new values, but the clone's Create Record step references
only the fields that existed when it was cloned, so nothing writes them
into the new alert columns (live-established on 8.0.1: after the upgrade
the alert names showed the new recipe while `eventTime`, `sourceIp`,
`destinationIp` and the other new columns stayed empty). If the new
columns are empty after upgrading, set the configuration's ingestion up
again -- tear the ingestion setup down and re-run the wizard (or simply
re-run the wizard for the configuration) so the fresh clone carries the
1.1.5 field set. The ingestion verifier now checks the bound clone
against the shipped definition at preflight and fails with this remedy
instead of discovering null columns three phases later.

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
