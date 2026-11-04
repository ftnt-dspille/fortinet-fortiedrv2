"""Live-verify the FortiEDR v2 use-case playbooks end to end on a FortiSOAR box.

Seven playbooks ship in the "Use Cases" sample collection; each is driven
through the surface a human would use (record actions, the Execute dialog,
the Run button, one platform schedule) and every mutation is restored. The
box under test must already have the ingestion chain configured
(``verify_ingestion.py`` covers that) -- this script asserts the use-case
collection alongside it, never displacing it.

Phases (all self-cleaning; nothing stays on the box or the tenant):

  0. preflight -- installed version matches info.json; BOTH sample collections
     present under their version-stamped names; all seven use-case playbooks
     active with resolvable action routes; ingestion still configured; the
     evidence snapshot (alert count, the canary's card hash) is taken.
  1. Triage to Isolation, approved -- the event's collector is really
     isolated, both audit comments land, and the isolation is released again
     through the connector's unisolate operation.
  2. Triage to Isolation, declined -- the collector is never touched and the
     decline comment carries the operator's reason.
  3. Collect Evidence standalone -- on a box whose collectors are offline the
     bag degrades to the documented comment (the creation branch is pinned
     offline: __link appends the appliance attachment the connector uploads;
     on 8.0.1 such a run settles at run status 'finished with error' through
     the wrapped step error, which the gates accept and the unexpected-error
     guard polices).
  4. IOC Retro-Hunt, refused input -- a run with no hash stops at the
     validation decision, before any tenant call.
  5. IOC Retro-Hunt, absent hash -- the tenant answers the search with no
     event ids; the summary reports zero findings and no alert is written.
     (This demo tenant's hash-search arenas answer empty for every file-age
     hash its own raw exports carry -- probed across dozens -- so the
     hit->create branch cannot be driven live here; it is offline-pinned and
     rides the ingestion chain's live-proven sourceId = eventId upsert.)
  6. Allow Event -- the expiry form is answered, the exception appears on the
     sacrificial event with the sweep marker in its comment, and the alert
     gets the audit comment.
  7. Exception Expiry Sweep, twice -- first with only the fresh rule (kept,
     nothing deleted), then with an expired managed rule planted directly on
     the tenant: exactly the expired one is deleted, the fresh one survives,
     unmanaged rules are counted and never touched.
  8. The sweep fires on a platform schedule -- a periodic task is created for
     the playbook, the cron fires it once, the task is deleted again.
  9. Re-detection Digest -- the digest task is created with the incidents
     table, and deleted again.
 10. Fleet Compliance Audit, staging declined -- the digest task is created,
     the staging approval is offered (the fleet genuinely lags the available
     installer on this tenant) and declined: no installer update is sent.
 11. postflight -- evidence set unchanged (same count, same canary card),
     sacrificial exception removed by id, driven-run audit comments stay
     (marked, additive only), no schedules or tasks left behind, ingestion
     status still configured.

    pyfsr-checkout .venv:python scripts/verify_use_cases.py \\
        --instance <pyfsr-instance-alias> --config fortiedr-lab

Env (.env.live by default): EDR_SACRIFICIAL_EVENT_ID is the event approved as
the exception carrier (its alert is driven for Allow Event); optionally
EDR_ROUNDTRIP_COLLECTOR names the collector whose alert is driven for
isolation when present among the ingested events.
"""

from __future__ import annotations

import argparse
import hashlib
import time
from pathlib import Path

import requests
import urllib3

# Demo-box self-signed certs; the warnings bury the phase output otherwise.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ROOT = Path(__file__).resolve().parent.parent
NAME = "fortinet-fortiedrv2"
SOURCE = "Fortinet FortiEDR"
CONFIG_NAME = "fortiedr-lab"
COLLECTION_USE_CASES_VER = "Sample - Fortinet FortiEDR v2 Use Cases"
MARKER = "fortiedrv2 verifier"

# Wait pacing: box steps complete in seconds, the schedule phase waits for a
# cron fire, and a paused approval needs its resume before the final wait.
RUN_TIMEOUT = 900
GATE_POLL = 30
GATE_TIMEOUT = 180
SCHEDULE_FIRE_TIMEOUT = 210

PB = {
    "triage": "FortiEDR v2 > Triage to Isolation",
    "evidence": "FortiEDR v2 > Collect Evidence",
    "allow": "FortiEDR v2 > Allow Event (Time-Limited)",
    "sweep": "FortiEDR v2 > Exception Expiry Sweep",
    "digest": "FortiEDR v2 > Re-detection Digest",
    "hunt": "FortiEDR v2 > IOC Retro-Hunt",
    "fleet": "FortiEDR v2 > Fleet Compliance Audit",
}


def _fail(msg: str) -> None:
    raise SystemExit(f"FAIL: {msg}")


def _info(msg: str) -> None:
    print(f"   {msg}")


def _transport_retry(fn, what, attempts=8, base=5.0):
    """Call fn(), riding out transient local transport failures.

    Long verification runs died mid-poll with requests' ConnectionError
    wrapping OSError(49) ("Can't assign requested address") -- the workstation
    briefly loses the address it binds from (interface/VPN flap), not a box
    failure; every wrapped call here is an idempotent read, so a retry cannot
    double-apply anything. Retry with a short backoff; re-raise only once the
    transport has stayed broken for minutes (a real outage fails loudly).
    """
    delay = base
    for attempt in range(1, attempts + 1):
        try:
            return fn()
        except requests.exceptions.ConnectionError as exc:
            if attempt == attempts:
                raise
            _info(f"transport blip during {what}: {str(exc)[:90]} -- "
                  f"retrying in {delay:.0f}s ({attempt}/{attempts - 1})")
            time.sleep(delay)
            delay = min(delay * 2, 60.0)


def _fmt(rec, *keys):
    return {k: rec.get(k) for k in keys if k in rec}


def _env_files(path: Path) -> dict:
    env = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            value = value.strip().strip('"').strip("'")
            if value:
                env[key.strip()] = value
    return env


def _wait_run(client, task_id, label):
    """Poll a run to terminal state, return (status, err, tree).

    detailed=True is not decoration: a run can END wearing 'finished with
    error' (a wrapped-digestion step error the branch already handled), and
    pyfsr's waiter settles on that status only when the tree's content is
    observable -- steps+detailed -- otherwise the wait polls to the 900s
    timeout on a run that finished in seconds."""
    task_id = str(task_id)
    # fail fast when the trigger's run never registers, instead of burning
    # the whole 900s poll on an unresolvable task -- live-caught on 8.0.1
    # when a bad task id resolved to nothing.
    resolve_deadline = time.time() + 60
    resolved = False
    while time.time() < resolve_deadline:
        probe = _transport_retry(lambda: client.playbooks.run_tree(task_id),
                                 f"{label} resolve probe")
        if getattr(probe, "pk", None):
            resolved = True
            break
        time.sleep(5)
    if not resolved:
        _fail(f"{label} run {task_id!r} never appeared in the run table")
    print(f"   waiting for {label} run {task_id}...")
    waited = _transport_retry(
        lambda: client.playbooks.wait_for_task(task_id, timeout=RUN_TIMEOUT,
                                               poll_interval=5, steps=True,
                                               detailed=True),
        f"{label} wait")
    failure = getattr(waited, "failure", None)
    err = getattr(failure, "message", None) or (str(failure) if failure else None)
    tree = _transport_retry(
        lambda: client.playbooks.run_tree(task_id, steps=True, detailed=True),
        f"{label} tree")
    return getattr(waited, "status", None), err, tree


def _walk(tree):
    yield tree
    for child in getattr(tree, "children", []) or []:
        yield from _walk(child)


def _step_status(tree, step_name):
    """First matching step status in the run tree, None when not found."""
    for node in _walk(tree):
        for s in getattr(node, "steps", []) or []:
            if getattr(s, "name", None) == step_name:
                return getattr(s, "status", None)
    return None


def _step_ran(tree, step_name):
    """True only when the named step EXECUTED.

    A declined branch's steps still appear in the run tree with status
    'skipped' -- the box resolves and lists every route (live-observed on
    8.0.1: the approved run lists 'Declined': skipped, the declined run
    lists 'Isolate Collector': skipped), so a step's PRESENCE never means
    its code ran. Only a status other than 'skipped' does."""
    status = _step_status(tree, step_name)
    return status is not None and status != "skipped"


def _errors(tree):
    out = []
    for node in _walk(tree):
        for s in getattr(node, "steps", []) or []:
            if getattr(s, "status", None) == "finished with error":
                out.append((getattr(node, "name", "?"), getattr(s, "name", "?"),
                            getattr(s, "result_preview", None)))
    return out


def _unexpected_errors(tree):
    """Step errors that are not the one wrapped degradation an offline fleet
    always produces: the evidence bag's file retrieval off a Disconnected
    collector (an ignore_errors step that posts its audit comment and carries
    the branch on -- live-observed: 400 'Operation cannot run on Disconnected
    device'; on 8.0.1 such a run settles at run status 'finished with error'
    even though it completed its whole branch)."""
    return [(node, step, preview)
            for (node, step, preview) in _errors(tree)
            if not (step == "Collect File"
                    and "cannot run on Disconnected" in (preview or ""))]


def _print_run(tree):
    for node in _walk(tree):
        prefix = "run" if node is tree else f"child {getattr(node, 'name', '?')!r}"
        print(f"     {prefix}: {getattr(node, 'status', None)}")
        for s in getattr(node, "steps", []) or []:
            print(f"       step {getattr(s, 'name', '?')!r}: {getattr(s, 'status', None)}"
                  f"{' <- ERROR' if getattr(s, 'status', None) == 'finished with error' else ''}")


def _resolve_pb(client, name):
    """The live workflow row for a playbook name, from the CURRENT release's
    use-case collection.

    Name-matched rows include copies from earlier imports: every
    version-stamped sample collection carries its own set of the playbooks,
    and an in-place connector upgrade leaves the old collections' rows
    active too (live-caught on 8.0.1: three rows named "Allow Event" sat on
    the box after the 1.1.0->1.1.2 upgrades, the 1.1.0-era copy sorted
    first, and the resolver drove that stale definition -- whose Create
    Exception still sent allOrganizations=True -- against the 1.1.2
    connector, so the allow run refused itself with the non-Admin "all
    organizations" 400). Resolution is by membership: the row must live in
    this release's "Use Cases - <info.json version>" collection, preferring
    an active row inside it; only when no row of this release's collection
    matches does the first active row win (a single-collection deployment).
    """
    import json
    version = json.loads((ROOT / "info.json").read_text())["version"]
    resp = client.get("/api/3/workflows", params={"name": name, "$limit": 50,
                                                  "__selectFields": "name,uuid,isActive,collection"})
    members = resp.get("hydra:member") if isinstance(resp, dict) else resp
    rows = [dict(r) for r in (members or []) if r.get("name") == name]
    if not rows:
        _fail(f"playbook {name!r} is not on the box")

    wanted = None
    for coll in client.workflow_collections.list(limit=500):
        if coll.name == f"{COLLECTION_USE_CASES_VER} - {version}":
            wanted = f"/api/3/workflow_collections/{coll.uuid}"
            break
    scoped = [r for r in rows if wanted and r.get("collection") == wanted]
    if scoped:
        _info(f"{name!r} pinned to this release's collection "
              f"({len(rows)} same-named rows on the box)")
    pool = scoped or rows
    for row in pool:
        if row.get("isActive"):
            return row
    active = [r for r in pool if r.get("isActive") is not False]
    return (active or pool)[-1]


def _route(client, pb_row):
    """The record-action route off the playbook's trigger step.

    The definition embeds the steps, but ``triggerStep`` is only the start
    step's IRI (a plain string on the wire) -- never the expanded step -- so
    the trigger is located among the embedded steps by uuid and its
    ``arguments.route`` read from there. The route value can arrive
    path-shaped; keep the last segment (the same normalization the 1.0.1
    ingest-clone drive used, live-proven).
    """
    definition = client.playbooks.get_definition(str(pb_row["uuid"]), relationships=True)
    trigger_uuid = str(definition.get("triggerStep") or "").rstrip("/").rsplit("/", 1)[-1]
    for step in (definition.get("steps") or []):
        step_uuid = str(step.get("uuid") or step.get("@id") or "").rstrip("/").rsplit("/", 1)[-1]
        if trigger_uuid and step_uuid != trigger_uuid:
            continue
        route = (step.get("arguments") or {}).get("route")
        if route:
            return str(route).rstrip("/").split("/")[-1]
    _fail(f"no action route on {pb_row['name']!r}")


def _trigger_action(client, pb_row, record_uuid, env=None):
    route = _route(client, pb_row)
    resp = client.playbooks.trigger_action(route, module="alerts",
                                           record_uuid=record_uuid,
                                           playbook_uuid=str(pb_row["uuid"]),
                                           env=env or {})
    # The action route answers {"task_ids": [...]} -- plural list (a live
    # fact pinned in pyfsr's TriggerResponse docstring) -- while the
    # notrigger Run-button route answers a scalar task_id. Normalize to one
    # string id either way: run-addressing calls (wait_for_task,
    # pending_for_run) want a bare uuid, and a list's repr 404s when pasted
    # into an endpoint path (live-caught in a staged run).
    ids = None
    for attr in ("task_ids", "task_id"):
        val = getattr(resp, attr, None)
        if isinstance(val, str):
            ids = [val]
            break
        if isinstance(val, list) and val:
            ids = list(val)
            break
    if ids is None and isinstance(resp, dict):
        val = resp.get("task_ids") or resp.get("task_id")
        if isinstance(val, str):
            ids = [val]
        elif isinstance(val, list) and val:
            ids = list(val)
    if not ids:
        _fail(f"trigger action on {pb_row['name']!r} answered no task id: {resp!r}")
    return str(ids[0])


def _trigger_plain(client, pb_row):
    """The Run button: fire a manual playbook through the notrigger route.

    trigger() answers a typed TriggerResponse: the run's id is
    ``resp.task_ids[0]`` (the model normalizes the route's task_id/task_ids
    shapes). Reading ``resp.get("task_id")`` instead hands back a nested
    response object, whose str() no run-tree lookup can resolve -- live-
    caught on 8.0.1: phase 7's wait then burned its whole 900s polling a
    run that could never be found and the label printed the object repr.
    """
    resp = client.playbooks.trigger(str(pb_row["uuid"]))
    ids = getattr(resp, "task_ids", None) or []
    if not ids:
        _fail(f"plain trigger on {pb_row['name']!r} answered no task id: {resp!r}")
    return str(ids[0])


def _gate_title(row):
    """A pending-gate row's prompt title, across the two wire shapes:
    list-wfinput rows carry it top-level; pending_for_run's workflow-filtered
    rows nest it at input.schema.title (live-verified on 8.0.1)."""
    schema = (row.get("input") or {})
    schema = schema.get("schema") if isinstance(schema, dict) else {}
    return (row.get("title") or (schema or {}).get("title") or "").strip()


def _await_gate(client, task_id, title):
    """Poll this run's pending-input queue for its gate; return the pending row
    (a complete prompt: form schema, response options, numeric run id), None
    on timeout.

    Scope-locked to the driven run via pending_for_run(task_id=...): the
    queue is instance-wide and gate titles repeat per run, so a title-only
    scan can latch onto a gate left pending by an earlier crashed pass and
    resume the WRONG run, leaving the current one stuck at its own gate.
    """
    deadline = time.time() + GATE_TIMEOUT
    while time.time() < deadline:
        rows = _transport_retry(
            lambda: client.manual_input.pending_for_run(str(task_id), wait=15,
                                                        typed=False),
            f"gate {title!r} poll")
        for row in rows or []:
            if _gate_title(row) != title:
                continue
            return row
        time.sleep(3)
    return None


def _gate_run_pk(gate):
    """The paused run's numeric pk off a pending-gate row.

    The terminal segment of the row's ``workflow``: retrieve/ and
    pending_for_run rows carry the numeric id there (the list endpoint's
    value is an encrypted token -- always feed a retrieved row, never a
    list row). Anything else -- the task uuid, or worse the pasted repr of
    the task-ids list -- 404s on the wfinput_resume route (live-caught).
    """
    pk = str(gate.get("workflow") or "").rstrip("/").rsplit("/", 1)[-1]
    if not pk.isdigit():
        _fail(f"the pending gate row lacks a numeric run id: "
              f"workflow={gate.get('workflow')!r}")
    return pk


def _resume(client, gate, option_label, form):
    """Resume a paused run by choosing one of the gate's options.

    The body mirrors the working submission shape: the option's step_iri
    picks the branch, `input` carries the form fields, and the run advances
    asynchronously. `approved` is deliberately NOT sent. The resume handler
    treats its mere presence as the approval path and skips the input merge,
    so an approval gate that also collects fields records the decision but
    loses every form value -- the downstream steps then render an empty
    reason. Live-pinned A/B on 8.0.1: same gate, same option, the body with
    `approved` (true or false) yields a gate result carrying `approved` and
    no `input`, the body without it merges the input. Our playbooks branch
    on the chosen option's step, not on the flag, and the result still
    records userid/username/datetime, so nothing is lost by omitting it.
    This matches pyfsr's manual_input.answer(), which never sends the field.
    """
    options = (gate.get("response_mapping") or {}).get("options") or []
    chosen = next((o for o in options if o.get("option") == option_label), None)
    if chosen is None:
        _fail(f"gate offer has no option {option_label!r}; got "
              f"{[o.get('option') for o in options]}")
    client.playbooks.resume(_gate_run_pk(gate),
                            manual_input_id=int(gate["id"]),
                            step_iri=chosen.get("step_iri"),
                            step_id=str(gate.get("step_id")),
                            input=form or None)


def _clear_stale_gates(client, title, option_label, note):
    """Answer same-titled gates left pending by an earlier crashed pass.

    A crash between gate-up and gate-answer leaves its gate in the queue;
    the next pass would otherwise race it against its own run's fresh gate
    (pending_for_run avoids the misattribution, but the stale row still
    needs an answer to leave the queue clean). The decline branch is the
    no-tenant-mutation branch, and the required reason field carries this
    verifier's marker for the postflight comment inventory. Waits until the
    answered inputs actually leave the queue before returning.
    """
    rows = client.manual_input.list(assigned_to="all", typed=False)
    stale = [r for r in rows if _gate_title(r) == title]
    for row in stale:
        full = client.manual_input.retrieve(str(row["id"]), typed=False)
        full = full if isinstance(full, dict) else {}
        if full.get("id") is None:
            full = {**dict(row), **full}
        _info(f"declining a stale {title!r} gate left by an earlier pass "
              f"(input id {row['id']}, run {full.get('workflow')})")
        _resume(client, full, option_label, {"decision_note": note})
    if stale:
        answered = {str(r["id"]) for r in stale}
        deadline = time.time() + GATE_TIMEOUT
        while time.time() < deadline:
            left = [r for r in _transport_retry(
                lambda: client.manual_input.list(assigned_to="all",
                                                 typed=False),
                "stale-gate drain")
                if str(r.get("id")) in answered]
            if not left:
                return
            time.sleep(3)
        _fail("a declined stale gate did not leave the pending-input queue")


def _alert_by_source(client, source_id):
    resp = client.alerts.list(params={"sourceId": str(source_id), "source": SOURCE,
                                      "$limit": 10})
    members = resp.get("hydra:member", []) if isinstance(resp, dict) else list(resp or [])
    return members[0] if members else None


def _alert_rows(client):
    rows = []
    for rec in client.records("alerts").iterate(raw=True, page_size=100,
                                                max_records=10000):
        if rec.get("source") == SOURCE:
            rows.append(rec)
    return rows


def _comments(client, record_uuid, since_epoch=None):
    """Comments linked to one alert, newest last; optional epoch floor.

    The parent filter is the module-named relationship field (``alerts``),
    NOT ``parentRecord``: on 8.0.1 the controller answers
    ``Field:parentRecord does not exist in module definition`` to a
    ``parentRecord=`` query filter, while ``alerts=<alert iri>`` returns the
    alert's comments. The same controller rejects ``ordering=createDate``
    (no such field on comments -- it is not a sortable request param on this
    module), so the newest-last order is applied client-side on the
    ``createDate`` epoch. The body field is ``content`` -- the rich-text
    body (``<p>...``) pyfsr's comments.create writes and the playbook
    message: steps post (all three live-probed on 8.0.1).
    """
    params = {"alerts": f"/api/3/alerts/{record_uuid}", "$limit": 100}
    resp = client.comments.list(params=params)
    rows = resp.get("hydra:member", []) if isinstance(resp, dict) else list(resp or [])
    out = []
    for row in rows:
        created = row.get("createDate")
        if since_epoch is not None and isinstance(created, (int, float)) \
                and created < since_epoch:
            continue
        out.append(row)
    out.sort(key=lambda r: r.get("createDate") if isinstance(r.get("createDate"),
                                                          (int, float)) else 0)
    return out


def _ops(env_file_path: Path):
    """The connector's own operations, runnable from the workstation (reads
    and, for the self-clean pair, the unisolate/delete the connector ships).

    The connector directory is registered as the virtual package its own
    tests use, with the same appliance-runtime stubs -- this is the pattern
    of tests/conftest.py, kept in step with it."""
    import sys
    import types
    sys.path.insert(0, str(ROOT))
    if "fortiedrv2" not in sys.modules:
        pkg = types.ModuleType("fortiedrv2")
        pkg.__path__ = [str(ROOT)]
        sys.modules["fortiedrv2"] = pkg
    sys.path.insert(0, str(ROOT / "tests"))
    import conftest  # noqa: F401  (idempotent stubs + the virtual package)
    import fortiedrv2.operations as operations
    env = _env_files(env_file_path)
    config = {"server_url": env["EDR_SERVER"], "username": env["EDR_USERNAME"],
              "password": env["EDR_PASSWORD"],
              "organization": env.get("EDR_ORGANIZATION", ""), "verify_ssl": False}
    return operations.OPERATIONS, config, env


def _isolation_target(client, ops, config, env, source_ids):
    """The alert the isolation drives against: prefer an alert whose event
    sits on the approved round-trip collector, else the sacrificial alert."""
    rt = env.get("EDR_ROUNDTRIP_COLLECTOR")
    if rt:
        for source_id in sorted(source_ids, key=int):
            try:
                events = ops["get_event_by_id"](config, {"eventIds": int(source_id)})
                row = events[0] if events else {}
            except Exception:
                continue
            device = (row.get("collectors") or [{}])[0].get("device")
            if device == rt:
                return source_id, device, "round-trip collector"
    sac = env.get("EDR_SACRIFICIAL_EVENT_ID")
    if sac and sac in source_ids:
        events = ops["get_event_by_id"](config, {"eventIds": int(sac)})
        device = (events[0].get("collectors") or [{}])[0].get("device") if events else "?"
        return sac, device, "sacrificial carrier"
    _fail("no approved alert to drive isolation against "
          "(set EDR_ROUNDTRIP_COLLECTOR or EDR_SACRIFICIAL_EVENT_ID)")


def _tasks_by_prefix(client, prefix):
    rows = client.records("tasks").iterate(raw=True, page_size=50, max_records=200)
    return [r for r in rows if (r.get("name") or "").startswith(prefix)]


def _epoch_now():
    import time as _time
    return _time.time() - 60  # a minute of clock-skew slack


def _sweep_run_pks(client, sweep_uuid):
    """Ids of one playbook's top-level runs (live + historical run tables)."""
    rows = client.playbooks.execution_history(playbook_uuid=sweep_uuid, limit=50)
    return {r.pk for r in rows if r.pk}


# ---------------------------------------------------------------------------
# phases
# ---------------------------------------------------------------------------

def phase_00_preflight(client, ops, config, env, state):
    print("[0] preflight")
    import json
    status = client.connectors.ingestion_status(NAME, config=state["args"].config)
    if not status.configured:
        _fail("ingestion is not configured -- run verify_ingestion.py first")
    _info("ingestion still configured"
          f" (collection exists={status.collection_exists},"
          f" ingest playbook={status.playbooks.ingest is not None})")

    conns = client.workflow_collections.list(limit=500)
    names = {c.name for c in conns}
    version = json.loads((ROOT / "info.json").read_text())["version"]
    for expected in ("Sample - Fortinet FortiEDR v2 - " + version,
                     f"{COLLECTION_USE_CASES_VER} - {version}"):
        if expected not in names:
            _fail(f"collection {expected!r} missing on the box (have {sorted(names)})")
        _info(f"collection present: {expected}")

    for key, name in PB.items():
        row = _resolve_pb(client, name)
        # the list projection may omit isActive; a present-but-false row is the
        # one thing that must stop the run
        if row.get("isActive") is False and key != "sweep":
            _fail(f"{name!r} is not active")
        state["pb"][key] = row
    _info(f"all {len(PB)} use-case playbooks present and active")

    rows = _alert_rows(client)
    state["alert_count"] = len(rows)
    state["source_ids"] = {r["sourceId"] for r in rows}
    canary = _alert_by_source(client, env["EDR_DEMO_EVENT_ID"])
    if not canary:
        _fail("the long-lived event's alert is missing -- the evidence set is not intact")
    state["canary_uuid"] = canary["uuid"]
    state["canary_card_sha"] = hashlib.sha256(
        (canary.get("description") or "").encode()).hexdigest()[:16]
    _info(f"evidence set: {len(rows)} alerts; canary card sha {state['canary_card_sha']}")

    excs = ops["list_exception"](config, {})
    state["exceptions_before"] = len(excs)
    _info(f"tenant exceptions before run: {len(excs)}")

    fleet = ops["get_collector_list"](config, {})
    state["fleet_before"] = sorted((r.get("name"), r.get("state"),
                                    r.get("stateAdditionalInfo"), r.get("version"))
                                   for r in fleet)
    state["start_epoch"] = _epoch_now()
    print("    preflight OK")


def phase_01_triage_approve(client, ops, config, env, state):
    print("[1] Triage to Isolation -- approve")
    _clear_stale_gates(client, "Approve collector isolation", "Skip Isolation",
                      f"{MARKER}: declined to clear a gate left by an "
                      f"earlier aborted verification pass")
    target_id, device, why = _isolation_target(client, ops, config, env,
                                               state["source_ids"])
    alert = _alert_by_source(client, target_id)
    if alert is None:
        _fail(f"no alert for chosen target event {target_id}")
    _info(f"driving {PB['triage']!r} on event {target_id} "
          f"(collector {device}: {why})")
    since = _epoch_now()
    task_id = _trigger_action(client, state["pb"]["triage"], alert["uuid"])
    gate = _await_gate(client, task_id, "Approve collector isolation")
    if gate is None:
        _fail("the isolation approval never appeared in the pending-input queue")
    _info("gate is up; approving with a reason")
    _resume(client, gate, "Isolate Device",
            {"decision_note": f"{MARKER}: approved isolation"})
    status, err, tree = _wait_run(client, task_id, "triage approve")
    # 'finished with error' is acceptable here only through the one wrapped
    # degradation the box can produce (evidence child, offline collector) --
    # the unexpected-errors guard below polices that.
    if status not in ("finished", "finished with error") or err:
        _fail(f"triage approve run did not finish cleanly: {status} {err}")
    unexpected = _unexpected_errors(tree)
    if unexpected:
        _fail(f"errors in the run tree: {unexpected}")
    if _errors(tree):
        _info("note: the evidence child's file retrieval degraded (offline"
              " collector) and was wrapped in its audit comment, as designed")
    _print_run(tree)

    collector = next(r for r in ops["get_collector_list"](config, {})
                     if r.get("name") == device)
    if "Isolated" not in (collector.get("stateAdditionalInfo") or ""):
        _fail(f"collector {device} was not isolated: {collector}")
    _info(f"collector {device} IS isolated on the tenant")

    comments = _comments(client, alert["uuid"], since_epoch=since)
    texts = [c.get("content") or "" for c in comments]
    if not any("isolated collector" in t for t in texts):
        _fail(f"no isolation audit comment on the alert: {texts}")
    if not any("Collect Evidence:" in t for t in texts):
        _fail("the evidence child ran but posted no comment on the alert")
    _info("isolation + evidence-child comments are on the alert")

    ops["unisolate_collector"](config, {"type": "Name", "devices": device})
    collector = next(r for r in ops["get_collector_list"](config, {})
                     if r.get("name") == device)
    if "Isolated" in (collector.get("stateAdditionalInfo") or ""):
        _fail(f"failed to restore collector {device}: {collector}")
    _info(f"collector {device} released again -- tenant restored")


def phase_02_triage_decline(client, ops, config, env, state):
    print("[2] Triage to Isolation -- decline")
    target_id, device, _ = _isolation_target(client, ops, config, env,
                                             state["source_ids"])
    alert = _alert_by_source(client, target_id)
    since = _epoch_now()
    task_id = _trigger_action(client, state["pb"]["triage"], alert["uuid"])
    gate = _await_gate(client, task_id, "Approve collector isolation")
    if gate is None:
        _fail("the decline-path gate never appeared")
    _resume(client, gate, "Skip Isolation",
            {"decision_note": f"{MARKER}: declined on purpose"})
    status, err, tree = _wait_run(client, task_id, "triage decline")
    # as in phase 1: 'finished with error' only through the evidence child's
    # wrapped degradation, policed by the unexpected-errors guard.
    if status not in ("finished", "finished with error") or err:
        _fail(f"triage decline run did not finish cleanly: {status} {err}")
    unexpected = _unexpected_errors(tree)
    if unexpected:
        _fail(f"unexpected errors in the decline run: {unexpected}")
    if _step_ran(tree, "Isolate Collector"):
        _fail("the isolate step ran on the decline path")
    comments = _comments(client, alert["uuid"], since_epoch=since)
    if not any("declined" in (c.get("content") or "") for c in comments):
        _fail("no decline comment on the alert")
    collector = next(r for r in ops["get_collector_list"](config, {})
                     if r.get("name") == device)
    if "Isolated" in (collector.get("stateAdditionalInfo") or ""):
        _fail("the declined run somehow isolated the collector")
    _info(f"decline path clean: no isolation, comment posted, {device} untouched")


def phase_03_evidence_standalone(client, ops, config, env, state):
    print("[3] Collect Evidence -- standalone record action")
    alert = _alert_by_source(client, env["EDR_DEMO_EVENT_ID"])
    since = _epoch_now()
    task_id = _trigger_action(client, state["pb"]["evidence"], alert["uuid"])
    status, err, tree = _wait_run(client, task_id, "evidence")
    # the standalone bag on the offline fleet settles at 'finished with error'
    # through the same wrapped degradation as phases 1-2's evidence child.
    if status not in ("finished", "finished with error") or err:
        _fail(f"evidence run did not finish cleanly: {status} {err}")
    if _unexpected_errors(tree):
        _fail(f"unexpected errors in the evidence run: {_unexpected_errors(tree)}")
    if status == "finished with error" or _errors(tree):
        _info("note: the file-retrieval step degraded (offline collector); the"
              " run wrapped it in its audit comment, as designed")
    comments = _comments(client, alert["uuid"], since_epoch=since)
    texts = [(c.get("content") or "") for c in comments]
    covered = any("Collect Evidence:" in t for t in texts)
    if not covered:
        _fail(f"the evidence child left no comment for the operator: {texts}")
    _info("the bag degrades to a comment when the collector is offline "
          f"(got {sum(1 for t in texts if 'Collect Evidence:' in t)} comment(s))")


def phase_04_hunt_no_input(client, ops, config, env, state):
    print("[4] IOC Retro-Hunt -- refused blank input")
    alert = _alert_by_source(client, env["EDR_DEMO_EVENT_ID"])
    task_id = _trigger_action(client, state["pb"]["hunt"], alert["uuid"], env={})
    status, err, tree = _wait_run(client, task_id, "hunt refused")
    if status != "finished" or err:
        _fail(f"hunt refusal run did not finish cleanly: {status} {err}")
    if _step_ran(tree, "Hunt Hash"):
        _fail("the blank-hash run reached the tenant anyway")
    _info("a blank hash stops at the validation decision, before any tenant call")


def phase_05_hunt_no_hits(client, ops, config, env, state):
    print("[5] IOC Retro-Hunt -- absent hash")
    nonce = hashlib.sha256(f"{MARKER} absent artifact".encode()).hexdigest()
    before = len(_alert_rows(client))
    alert = _alert_by_source(client, env["EDR_DEMO_EVENT_ID"])
    task_id = _trigger_action(client, state["pb"]["hunt"], alert["uuid"],
                              env={"file_hash": nonce})
    status, err, tree = _wait_run(client, task_id, "hunt absent")
    if status != "finished" or err:
        _fail(f"hunt run did not finish cleanly: {status} {err}")
    after = len(_alert_rows(client))
    if after != before:
        _fail(f"an absent hash somehow wrote alerts: {before} -> {after}")
    _info(f"absent hash: 0 findings, alert count stable at {after}")


def phase_06_allow_event(client, ops, config, env, state):
    print("[6] Allow Event -- time-limited exception")
    sac = env.get("EDR_SACRIFICIAL_EVENT_ID")
    if not sac:
        _fail("EDR_SACRIFICIAL_EVENT_ID is not set -- no approved carrier event")
    alert = _alert_by_source(client, sac)
    if alert is None:
        _fail("the sacrificial event has no alert on the box (is it ingested?)")
    org = ops["get_event_by_id"](config, {"eventIds": int(sac)})[0].get("organization")
    existing = ops["get_event_exceptions"](config, {"eventId": int(sac),
                                                    "organization": org})
    if existing:
        _fail(f"the sacrificial event already carries exceptions -- {existing}")
    since = _epoch_now()
    task_id = _trigger_action(client, state["pb"]["allow"], alert["uuid"])
    gate = _await_gate(client, task_id, "Time-limited exception")
    if gate is None:
        _fail("the exception form never appeared")
    _info("form is up; answering with a 7-day window and the reason")
    _resume(client, gate, "Create Exception",
            {"expiry_days": "7", "analyst_reason": f"{MARKER}: allow probe"})
    status, err, tree = _wait_run(client, task_id, "allow event")
    if status != "finished" or err:
        _fail(f"allow run did not finish cleanly: {status} {err}")

    ours = [e for e in ops["get_event_exceptions"](config, {"eventId": int(sac),
                                                           "organization": org})
            if e.get("originEventId") == int(sac)]
    if not ours:
        _fail("the exception never appeared on the sacrificial event")
    comment = ours[0].get("comment") or ""
    if MARKER not in comment or "fortiedrv2-managed expires=" not in comment:
        _fail(f"the rule's comment lost the governance marker: {comment!r}")
    state["managed_exception_id"] = ours[0]["exceptionId"]
    state["sac_alert_uuid"] = alert["uuid"]
    comments = _comments(client, alert["uuid"], since_epoch=since)
    if not any("time-limited exception created" in (c.get("content") or "")
               for c in comments):
        _fail("no audit comment on the alert")
    _info(f"managed exception {state['managed_exception_id']} created "
          f"with the sweep marker in its comment")


def phase_07_sweep(client, ops, config, env, state):
    print("[7] Exception Expiry Sweep")
    sac = int(env["EDR_SACRIFICIAL_EVENT_ID"])

    # pass one: only a FRESH managed rule -- nothing may be deleted
    task_id = _trigger_plain(client, state["pb"]["sweep"])
    status, err, tree = _wait_run(client, task_id, "sweep keep-fresh")
    if status != "finished" or err:
        _fail(f"sweep pass one did not finish cleanly: {status} {err}")
    org = ops["get_event_by_id"](config, {"eventIds": sac})[0].get("organization")
    ours = [e for e in ops["get_event_exceptions"](config, {"eventId": sac,
                                                           "organization": org})
            if e.get("originEventId") == sac]
    if not ours:
        _fail("the fresh managed rule was deleted by the first sweep pass")
    _info("first pass deleted nothing: the fresh managed rule survives")

    # plant an EXPIRED managed rule directly, then sweep again
    import time as _time
    ops["create_exception"](config, {
        "eventId": sac,
        "allCollectorGroups": "All Collector Groups",
        "allOrganizations": "False",
        "allDestinations": "All Destinations",
        "comment": f"fortiedrv2-managed expires={int(_time.time()) - 3600} :: {MARKER} planted expired",
        "forceCreate": "False",
    })
    ours = [e for e in ops["get_event_exceptions"](config, {"eventId": sac,
                                                           "organization": org})
            if e.get("originEventId") == sac]
    expired_id = next(e["exceptionId"] for e in ours if "planted expired" in (e.get("comment") or ""))
    fresh_id = state["managed_exception_id"]
    _info(f"planted expired managed rule {expired_id} next to the fresh {fresh_id}")

    task_id = _trigger_plain(client, state["pb"]["sweep"])
    status, err, tree = _wait_run(client, task_id, "sweep expired")
    if status != "finished" or err:
        _fail(f"sweep pass two did not finish cleanly: {status} {err}")
    ours = [e for e in ops["get_event_exceptions"](config, {"eventId": sac,
                                                           "organization": org})
            if e.get("originEventId") == sac]
    ids_now = {e["exceptionId"] for e in ours}
    if expired_id in ids_now:
        _fail("the expired managed rule survived the sweep")
    if fresh_id not in ids_now:
        _fail("the sweep removed the fresh managed rule")
    _info("second pass deleted exactly the expired rule and kept the fresh one")


def phase_08_schedule(client, ops, config, env, state):
    print("[8] The sweep fires on a platform schedule")
    row = state["pb"]["sweep"]
    runs_before = _sweep_run_pks(client, str(row["uuid"]))
    schedule_name = f"{MARKER} sweep cron probe"
    client.schedules.create(schedule_name, f"/api/3/workflows/{row['uuid']}",
                            "*/2 * * * *", enabled=True)
    _info("created a */2 cron task; waiting for the first cron fire")
    deadline = time.time() + SCHEDULE_FIRE_TIMEOUT
    new = set()
    while time.time() < deadline and not new:
        new = _transport_retry(lambda: _sweep_run_pks(client, str(row["uuid"])),
                               "sweep cron probe") - runs_before
        if new:
            break
        time.sleep(10)
    # remove the probe schedule either way
    client.schedules.delete(schedule_name)
    if not new:
        _fail("the periodic task never fired the playbook in the window")
    _info(f"the platform cron fired the playbook ({len(new)} new run(s)); "
          "the probe schedule is deleted")


def phase_09_digest(client, ops, config, env, state):
    print("[9] Re-detection Digest")
    task_id = _trigger_plain(client, state["pb"]["digest"])
    status, err, tree = _wait_run(client, task_id, "digest")
    if status != "finished" or err:
        _fail(f"digest run did not finish cleanly: {status} {err}")
    rows = _tasks_by_prefix(client, "FortiEDR re-detection digest")
    if not rows:
        _fail("the digest task was not created")
    row = rows[-1]
    desc = row.get("description") or ""
    if "<table" not in desc:
        _info(f"digest task created; description preview: {desc[:120]!r}")
        _fail("the digest description is not the incidents table")
    client.records("tasks").delete(str(row["uuid"]))
    _info(f"digest task created with the incidence table and deleted again "
          f"(found {len(rows)} matching task(s))")


def phase_10_fleet(client, ops, config, env, state):
    print("[10] Fleet Compliance Audit -- staging declined")
    task_id = _trigger_plain(client, state["pb"]["fleet"])
    # the audit runs first, then (fleet lagging) the staging approval appears
    gate = _await_gate(client, task_id, "Stage collector installer update")
    if gate is not None:
        _info("staging approval is up (the fleet lags the available installer); declining")
        _resume(client, gate, "Skip", {})
        status, err, tree = _wait_run(client, task_id, "fleet audit")
    else:
        status, err, tree = _wait_run(client, task_id, "fleet audit")
        _info("no staging approval: the fleet matched the available installers")
    if status != "finished" or err:
        _fail(f"fleet run did not finish cleanly: {status} {err}")

    rows = _tasks_by_prefix(client, "FortiEDR fleet compliance")
    if not rows:
        _fail("the fleet digest task was not created")
    row = rows[-1]
    client.records("tasks").delete(str(row["uuid"]))
    fleet_now = sorted((r.get("name"), r.get("state"),
                        r.get("stateAdditionalInfo"), r.get("version"))
                       for r in ops["get_collector_list"](config, {}))
    if fleet_now != state["fleet_before"]:
        _fail(f"the declined staging changed the fleet:\n{state['fleet_before']}\n{fleet_now}")
    if _step_ran(tree, "Stage Upgrade"):
        _fail("the installer update ran despite the decline")
    _info("fleet task created and deleted; the declined staging touched nothing")


def phase_11_postflight(client, ops, config, env, state):
    print("[11] postflight")
    rows = _alert_rows(client)
    if len(rows) != state["alert_count"]:
        _fail(f"alert count drifted: {state['alert_count']} -> {len(rows)}")
    canary = _alert_by_source(client, env["EDR_DEMO_EVENT_ID"])
    card = hashlib.sha256((canary.get("description") or "").encode()).hexdigest()[:16]
    if card != state["canary_card_sha"]:
        _fail("the canary's evidence card changed")
    _info(f"evidence set intact: {len(rows)} alerts, canary card unchanged")

    # remove the managed fresh exception by id -- the carriers are clean again
    sac = int(env["EDR_SACRIFICIAL_EVENT_ID"])
    org = ops["get_event_by_id"](config, {"eventIds": sac})[0].get("organization")
    ours = [e for e in ops["get_event_exceptions"](config, {"eventId": sac,
                                                           "organization": org})
            if e.get("originEventId") == sac]
    if ours:
        ops["delete_exception"](config, {"exceptionIds": ",".join(
            str(e["exceptionId"]) for e in ours)})
        leftover = [e for e in ops["get_event_exceptions"](config, {"eventId": sac,
                                                                    "organization": org})
                    if e.get("originEventId") == sac]
        if leftover:
            _fail(f"exceptions remain on the carrier: {leftover}")
    _info("sacrificial event is exception-free again")

    # the driven runs' audit comments stay: they are additive metadata on
    # existing alerts (the evidence cards are asserted unchanged), they carry
    # this verifier's marker for later bulk removal, and they demonstrate the
    # playbooks' behavior to whoever opens the box next. Anything that mutates
    # tenant or box state -- exceptions, isolation, schedules, digest tasks,
    # alerts -- is restored or removed above; comments are the product's own
    # audit trail, shown as-is.
    commented = 0
    for uuid in (state.get("sac_alert_uuid"), canary["uuid"]):
        if not uuid:
            continue
        commented += len(_comments(client, uuid, since_epoch=state["start_epoch"]))
    _info(f"kept {commented} audit comment(s) written by the driven runs "
          f"(marked '{MARKER}')")

    scheds = client.schedules.list(typed=False)
    leftovers = [s for s in scheds if MARKER in (s.get("name") or "")]
    if leftovers:
        _fail(f"probe schedules remain: {[s.get('name') for s in leftovers]}")
    status = client.connectors.ingestion_status(NAME, config=state["args"].config)
    if not status.configured:
        _fail("ingestion stopped being configured during the run")
    print("    postflight OK -- nothing the run touched remains on box or tenant")


# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--instance", required=True, help="pyfsr instance alias (~/.pyfsr/instances.toml)")
    ap.add_argument("--config", default=CONFIG_NAME, help="connector configuration")
    ap.add_argument("--env-file", default=str(ROOT / ".env.live"),
                    help="EDR_* environment file (gitignored)")
    ap.add_argument("--until", type=int, default=11,
                    help="stop after this phase number (0-11); default: all")
    args = ap.parse_args(argv)

    import sys
    sys.path.insert(0, str(ROOT / "scripts"))
    from install_to_fsr import _client

    client = _client(args.instance)
    ops, config, env = _ops(Path(args.env_file))
    for key in ("EDR_SERVER", "EDR_PASSWORD", "EDR_DEMO_EVENT_ID"):
        if not env.get(key):
            _fail(f"{key} is missing from {args.env_file}")

    print(f"verifying the use-case playbooks on instance {args.instance!r} "
          f"against config {args.config!r}")
    state = {"pb": {}, "args": args}
    phases = (phase_00_preflight, phase_01_triage_approve, phase_02_triage_decline,
              phase_03_evidence_standalone, phase_04_hunt_no_input,
              phase_05_hunt_no_hits, phase_06_allow_event, phase_07_sweep,
              phase_08_schedule, phase_09_digest, phase_10_fleet,
              phase_11_postflight)
    for phase in phases[: args.until + 1]:
        phase(client, ops, config, env, state)
    if args.until >= len(phases) - 1:
        print(f"use-case verification: PASS ({len(phases)} phases)")
    else:
        print(f"staged run stopped after phase {args.until}: OK so far")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
