# fortinet-fortiedrv2 release notes

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

Behavior kept from the shipped 2.1.0 connector on purpose: the 400 retry
loop, `message`/`errorMessage` surfacing, `YYYY-MM-DD HH:MM:SS` datetime
normalization, org-qualified usernames, and the IP-set organization
semantics (including the 'Each' quirk where the discovery query lists under
'All organizations').

Deliberate fixes over 2.1.0, all marked with comments where they deviate:

- Update Exception now updates the exception whose ID was requested; the
  shipped connector always posted the first exported exception and
  re-created it untouched when the requested ID did not match.
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

Sample playbooks: a Data Ingestion Wizard chain (Init Macros / Fetch /
Ingest) keyed on the activity window, upserting one alert per event on
`sourceId = eventId` so a window read twice updates instead of duplicating.
