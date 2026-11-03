"""Live-verify the FortiEDR v2 ingestion chain end to end on a FortiSOAR box.

The data ingestion chain is wizard-driven, so verification goes through the
same calls the UI's Data Ingestion Wizard makes (pyfsr mirrors them field for
field, down to the schedule-name convention the ingestion screen matches on):

  1. preflight -- installed version matches info.json, configuration resolves,
     health is Available, the bundled Sample collection is discoverable and
     its playbooks carry the wizard tags (fetch / ingest / create);
  2. wizard setup -- ``ensure_ingestion``: clone the sample chain into the
     per-configuration collection, stamp the config, activate, create the
     (disabled by default) periodic task, write the data-import metadata;
  3. wizard confirm edit -- patch the cloned Fetch's Configuration step
     (``--backfill-minutes``) exactly the way the wizard's Finish writes the
     form's Initial Backfill Range into the deployed playbook;
  4. Trigger Ingestion Now -- ``trigger_ingestion`` fires the ingest clone;
     assert the run finishes clean, the watermark macro advances, and alerts
     appear in the module;
  5. alerts content -- every written alert carries sourceId == the FortiEDR
     eventId, the rich-text card in its description, and the mapped payload
     in sourcedata; the configured long-lived event proves the defect fix:
     alert_generation_epoch (pinned firstSeen) < last_observed_epoch;
  6. dedup -- fire ingestion again: the re-read window must not duplicate or
     duplicate alerts (the upsert on sourceId), and the macro advances again;
  7. env_setup probe -- fire the ingest clone the way the wizard's mapping
     preview does and report which branch ran (the delivery matrix says this
     route populates ``vars.request``; the report documents what it found).

Repeatable: phases are idempotent (setup is get-or-make, ingest is upsert).
Alerts are left in place -- they are the evidence; delete them by sourceId to
clean up. The schedule stays disabled unless --enable-schedule is passed.

    .venv of a pyfsr checkout: python scripts/verify_ingestion.py \\
        --instance soar143 --config fortiedr-lab

Env (.env.live by default): EDR_DEMO_EVENT_ID (optional) is the tenant's
long-lived event -- the pinned-firstSeen canary the chain exists to fix.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import urllib3
from pyfsr.exceptions import FortiSOARException

# Demo-box self-signed certs; the warnings bury the phase output otherwise.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ROOT = Path(__file__).resolve().parent.parent
NAME = "fortinet-fortiedrv2"
SOURCE = "Fortinet FortiEDR"
CONFIG_NAME = "fortiedr-lab"

STEP_WAIT_TIMEOUT = 900  # a 30-day backfill fetch takes a while; be generous
POLL = 5


def _fail(msg: str) -> None:
    raise SystemExit(f"FAIL: {msg}")


def _macro_name(fetch_uuid: str) -> str:
    return f"FortiEDRLastEventPullTime_{fetch_uuid.replace('-', '_')}"


def _wait_run(client, task_id: str, label: str):
    """Poll a triggered run to terminal state, then return the enriched tree.

    ``wait_for_task`` drives the poll; ``run_tree(steps, detailed)`` then
    re-reads the run WITH its child runs (the Fetch workflow_reference child)
    and per-step snapshots, which is what gets printed and checked.
    """
    print(f"   waiting for {label} run {task_id} (poll {POLL}s)...")
    waited = client.playbooks.wait_for_task(task_id, timeout=STEP_WAIT_TIMEOUT,
                                            poll_interval=POLL, steps=True)
    failure = getattr(waited, "failure", None)
    err = getattr(failure, "message", None) or (str(failure) if failure else None)
    status = getattr(waited, "status", None)
    tree = client.playbooks.run_tree(task_id, steps=True, detailed=True)
    return status, err, tree


def _walk_nodes(tree):
    """The run node and its descendants, depth-first."""
    yield tree
    for child in getattr(tree, "children", []) or []:
        yield from _walk_nodes(child)


def _collect_errors(tree) -> list:
    """(node name, step name, preview) for every errored step in the tree."""
    errors = []
    for node in _walk_nodes(tree):
        for s in getattr(node, "steps", []) or []:
            if getattr(s, "status", None) == "finished with error":
                errors.append((getattr(node, "name", "?"), getattr(s, "name", "?"),
                               getattr(s, "result_preview", None)))
    return errors


def _print_run(tree) -> None:
    for node in _walk_nodes(tree):
        prefix = "run" if node is tree else f"child {getattr(node, 'name', '?')!r}"
        print(f"   {prefix}: {getattr(node, 'status', None)}")
        for s in getattr(node, "steps", []) or []:
            st = getattr(s, "status", None)
            extra = " <- ERROR" if st == "finished with error" else ""
            preview = getattr(s, "result_preview", None) or ""
            tail = f" | result: {preview}" if preview and len(preview) < 200 else ""
            print(f"     step {getattr(s, 'name', '?')!r}: {st}{extra}{tail}")


def _read_macro(client, name: str):
    """The dynamic-variable row for `name`, or None when it does not exist."""
    resp = client.get("/api/wf/api/dynamic-variable/",
                      params={"format": "json", "name": name})
    members = resp.get("hydra:member", []) if isinstance(resp, dict) else []
    return members[0] if members else None


def _alert_rows(client):
    """All alerts written by this connector, paged (client-side source filter).

    The box's full alert list is walked with the paged iterator -- a plain
    one-shot list call would silently truncate at the API's own page size.
    """
    rows = []
    for rec in client.records("alerts").iterate(raw=True, page_size=100,
                                                max_records=10000):
        if rec.get("source") == SOURCE:
            rows.append(rec)
    return rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Verify the FortiEDR v2 data ingestion chain on a live box.")
    ap.add_argument("--instance", required=True,
                    help="pyfsr instance alias (~/.pyfsr/instances.toml)")
    ap.add_argument("--env-file", type=Path, default=ROOT / ".env.live",
                    help="KEY=VALUE file for EDR_DEMO_EVENT_ID etc. (never committed)")
    ap.add_argument("--config", default=CONFIG_NAME,
                    help="connector configuration (default: %(default)s)")
    ap.add_argument("--backfill-minutes", default="43200",
                    help="Initial Backfill Range the confirm step writes (default: 30 days)")
    ap.add_argument("--reset-watermark", action="store_true",
                    help="reset the pull watermark macro to '0' before the first run, so"
                         " it re-reads the Initial Backfill Range; use after an earlier"
                         " run advanced the watermark past events it failed to read")
    ap.add_argument("--cron", default="*/15 * * * *",
                    help="cron for the periodic task (created DISABLED by default)")
    ap.add_argument("--enable-schedule", action="store_true",
                    help="leave the periodic task enabled after setup")
    args = ap.parse_args(argv)

    from install_to_fsr import _client, _load_env_file  # same dir, house helpers

    if args.env_file.is_file():
        _load_env_file(args.env_file)

    client = _client(args.instance)
    conns = client.connectors

    # ---------------------------------------------------------------- [1] preflight
    print(f"[1] preflight on {client.base_url}")
    version = json.loads((ROOT / "info.json").read_text())["version"]
    live_ver = conns.resolve_version(NAME)
    if live_ver != version:
        _fail(f"installed {NAME} is {live_ver!r}, repo builds {version!r}")
    chosen = next((c for c in conns.configurations(NAME)
                   if c.name == args.config), None)
    if chosen is None:
        names = ", ".join(c.name for c in conns.configurations(NAME))
        _fail(f"configuration {args.config!r} not found (have: {names})")
    health = conns.healthcheck(NAME, config=args.config)
    status_str = str(getattr(health, "status", "") or "")
    print(f"   connector {NAME} {version}, config {args.config!r} "
          f"(id {chosen.config_id}), health {status_str!r}")
    if status_str.strip().lower() != "available":
        _fail(f"health is {status_str!r}, not 'Available'")

    sample_uuid = conns.find_sample_ingestion_collection(NAME, version=version)
    if not sample_uuid:
        _fail("the wizard cannot find the bundled Sample collection")
    coll = client.get(f"/api/3/workflow_collections/{sample_uuid}")
    print(f"   sample collection: {coll.get('name')!r}")
    buckets = conns.ingestion_playbooks(NAME, collection=sample_uuid)
    for role in ("fetch", "ingest"):
        pb = getattr(buckets, role, None)
        if pb is None:
            _fail(f"no {role!r}-tagged playbook in the sample collection")
        print(f"   {role}: {pb.name!r} (tags: {pb.tag!r})")

    # ---------------------------------------------------------------- [2] wizard setup
    print("[2] data ingestion wizard setup (get-or-make)")
    result = conns.ensure_ingestion(NAME, config=args.config,
                                    cron=args.cron, enabled=args.enable_schedule,
                                    timezone="UTC")
    existed = getattr(result, "existed", False)
    print(f"   collection {result.collection_name!r} "
          f"({'already configured' if existed else 'cloned'})")
    for pb in result.playbooks or []:
        print(f"   playbook {pb.name!r} (tags: {pb.tag!r}) active={pb.isActive}")
    print(f"   schedule {result.schedule_name!r} enabled={result.scheduled}")

    # ---------------------------------------------------------------- [3] confirm edit
    print(f"[3] wizard-confirm edit: Initial Backfill Range -> {args.backfill_minutes} min")
    clone_buckets = conns.ingestion_playbooks(NAME, collection=result.collection_uuid)
    fetch = getattr(clone_buckets, "fetch", None)
    if fetch is None:
        _fail("cannot find the cloned fetch playbook to patch")
    definition = client.playbooks.get_definition(fetch.uuid)
    step = next((s for s in (definition.get("steps") or [])
                 if s.get("name") == "Configuration"), None)
    if step is None:
        _fail("no 'Configuration' step on the fetch clone")
    step_uuid = step.get("uuid") or str(step.get("@id") or "").rstrip("/").split("/")[-1]
    if not step_uuid:
        _fail("the Configuration step record carries no uuid/@id")
    step_args = dict(step.get("arguments") or {})
    print(f"   fetch_last_minutes was {step_args.get('fetch_last_minutes')!r}, "
          f"time_field {step_args.get('time_field')!r}")
    step_args["fetch_last_minutes"] = str(args.backfill_minutes)
    client.put(f"/api/3/workflow_steps/{step_uuid}", data={"arguments": step_args})
    check = client.playbooks.get_definition(fetch.uuid)
    now_value = next(s for s in (check.get("steps") or [])
                     if s.get("name") == "Configuration")["arguments"]["fetch_last_minutes"]
    if str(now_value) != str(args.backfill_minutes):
        _fail(f"confirm edit did not stick: fetch_last_minutes={now_value!r}")
    print(f"   fetch Configuration step patched: fetch_last_minutes={now_value!r}")

    macro = _macro_name(fetch.uuid)
    before = _read_macro(client, macro)
    print(f"   watermark macro {macro!r}: "
          f"{('value=' + str(before.get('value')) if before else 'absent')} "
          f"(first run reads the backfill window)")
    if args.reset_watermark and before:
        # The same PUT the playbook's Update step makes. Resets a watermark a
        # prior (broken) run advanced past events it never actually read.
        client.put(f"/api/wf/api/dynamic-variable/{before['id']}/",
                   data={"name": macro, "value": "0"})
        before = _read_macro(client, macro)
        if str((before or {}).get("value")) != "0":
            _fail(f"--reset-watermark did not stick: {before!r}")
        print("   watermark reset to '0' (re-runs the Initial Backfill Range)")

    # ---------------------------------------------------------------- [4] ingest 1
    print("[4] Trigger Ingestion Now (first pass, cold watermark)")
    before_ids = {r.get("sourceId") for r in _alert_rows(client)}
    resp = conns.trigger_ingestion(NAME, config=args.config)
    task_id = (resp or {}).get("task_id") if isinstance(resp, dict) else None
    if not task_id:
        _fail(f"trigger_ingestion returned no task_id: {resp!r}")
    status, err, tree = _wait_run(client, task_id, "ingest-1")
    if status != "finished":
        _print_run(tree)
        _fail(f"ingest-1 did not finish cleanly: status={status!r} err={err!r}")
    errored = _collect_errors(tree)
    if errored:
        _print_run(tree)
        _fail(f"ingest-1 has errored steps: {errored}")
    after = _read_macro(client, macro)
    if not after:
        _fail("watermark macro was never created (Init Macros branch did not run)")
    wm1 = str(after.get("value"))
    print(f"   run finished; watermark advanced to {wm1!r}")
    if wm1 in ("", "0", "initial"):
        _fail(f"watermark not advanced by the ingest run: {wm1!r}")

    # ---------------------------------------------------------------- [5] alerts content
    print("[5] alert content (upsert on sourceId == eventId, rich-text card)")
    rows = _alert_rows(client)
    new_rows = [r for r in rows if r.get("sourceId") not in before_ids]
    if not new_rows:
        _fail("the first ingest run created no alerts "
              "(window empty or Create Record failed)")
    print(f"   alerts from this connector: {len(rows)} total, {len(new_rows)} new")
    ids = [r.get("sourceId") for r in rows]
    if len(set(ids)) != len(ids):
        _fail("duplicate alerts for one sourceId -- upsert did not dedup")
    bad = []
    for r in new_rows:
        desc = r.get("description") or ""
        if "<table" not in desc or "border-collapse" not in desc:
            bad.append(f"{r.get('sourceId')}: description is not the rich-text card")
        try:
            stored = r.get("sourcedata")
            payload = stored if isinstance(stored, dict) else json.loads(stored or "")
            ex_id, gen, obs = (payload.get("external_id"),
                               payload.get("alert_generation_epoch"),
                               payload.get("last_observed_epoch"))
            if ex_id and str(ex_id) != str(r.get("sourceId")):
                bad.append(f"{r.get('sourceId')}: sourcedata external_id {ex_id!r} mismatch")
            if gen is None or obs is None or int(gen) > int(obs):
                bad.append(f"{r.get('sourceId')}: generation not <= observation ({gen}, {obs})")
        except (ValueError, TypeError) as e:
            bad.append(f"{r.get('sourceId')}: sourcedata not JSON: {e}")
    if bad:
        _fail("; ".join(bad))
    print("   every alert: sourceId == payload external_id, generation <= observation, "
          "card markup in description")

    import os
    demo_id = os.environ.get("EDR_DEMO_EVENT_ID")
    demo = next((r for r in rows if str(r.get("sourceId")) == str(demo_id)), None) if demo_id else None
    if demo_id and demo is None:
        print(f"   NOTE: demo event {demo_id} is not among the fetched alerts "
              "(its lastSeen may sit outside the backfill window on this tenant)")
    if demo is not None:
        stored = demo.get("sourcedata")
        payload = stored if isinstance(stored, dict) else json.loads(stored or "{}")
        gen, obs = payload.get("alert_generation_epoch"), payload.get("last_observed_epoch")
        # THE defect fix: a re-triggered event keeps firstSeen pinned, so the
        # alert's detection time (firstSeen) predates its last activity.
        if int(gen) < int(obs):
            print(f"   defect-fix canary: event {demo_id} mapped with pinned "
                  f"firstSeen {gen} < lastSeen {obs} -- re-detections are ingested "
                  "(the shipped chain reported 'no incidents found' here)")
        else:
            print(f"   NOTE: event {demo_id} has firstSeen == lastSeen (no re-detection "
                  "in window); the canary shape is not observable in this run")

    # ---------------------------------------------------------------- [6] dedup pass
    print("[6] dedup pass: Trigger Ingestion Now again")
    resp = conns.trigger_ingestion(NAME, config=args.config)
    task_id = (resp or {}).get("task_id") if isinstance(resp, dict) else None
    if not task_id:
        _fail(f"trigger_ingestion returned no task_id: {resp!r}")
    status, err, tree = _wait_run(client, task_id, "ingest-2")
    if status != "finished":
        _print_run(tree)
        _fail(f"ingest-2 did not finish cleanly: status={status!r} err={err!r}")
    rows2 = _alert_rows(client)
    ids2 = [r.get("sourceId") for r in rows2]
    if len(ids2) != len(rows):
        _fail(f"second pass changed the alert count: {len(rows)} -> {len(ids2)} "
              "(duplicates or missing records)")
    if len(set(ids2)) != len(ids2):
        _fail("duplicate alerts after the second pass")
    wm_after = _read_macro(client, macro)
    wm2 = str((wm_after or {}).get("value"))
    print(f"   alert count stable at {len(ids2)}, sourceIds unique; "
          f"watermark advanced {wm1!r} -> {wm2!r}")
    if wm2 == wm1:
        _fail("watermark did not advance on the second pass")

    # ---------------------------------------------------------------- [7] env_setup probe
    print("[7] wizard mapping-preview probe (env_setup delivery)")
    ingest_clone = getattr(clone_buckets, "ingest", None)
    if ingest_clone is None:
        outcome = "no ingest clone found to probe"
    else:
        definition = client.playbooks.get_definition(ingest_clone.uuid,
                                                    relationships=True)
        route = None
        for s in (definition.get("steps") or []):
            r = (s.get("arguments") or {}).get("route")
            if r:
                route = str(r).rstrip("/").split("/")[-1]
                break
        record_uuid = next((r.get("uuid") or (r.get("@id") or "").rstrip("/").split("/")[-1]
                            for r in rows if r.get("uuid") or r.get("@id")), None)
        if route and record_uuid:
            try:
                probe = client.playbooks.trigger_action(
                    route, module="alerts", record_uuid=record_uuid,
                    env={"env_setup": True})
                probe_ids = (getattr(probe, "task_ids", None)
                             or [getattr(probe, "task_id", None)])
                pid = next((t for t in probe_ids if t), None)
                if pid:
                    status, err, ptree = _wait_run(client, pid, "preview probe")
                    names = [s.name for s in (getattr(ptree, "steps", []) or [])]
                    if "Return Sample" in names:
                        outcome = ("preview branch: the action route delivers "
                                   "body keys into vars.request")
                    elif "Create Record" in names:
                        outcome = ("REAL ingest branch: the env key does NOT reach "
                                  "vars.request from the API; the UI wizard's own "
                                  "preview flow is the only live test of that branch")
                    else:
                        outcome = f"unknown branch; steps ran: {names}"
                    if status != "finished":
                        outcome += f" -- run status {status!r}: {err}"
                else:
                    outcome = f"action route returned no task id: {probe!r}"
            except FortiSOARException as e:
                outcome = f"action route refused: {getattr(e, 'message', e)}"
        else:
            outcome = "no route or no record to probe with (run after alerts exist)"
    print(f"   probe outcome: {outcome}")
    print("   (the UI wizard's own preview is the last word; this probe records "
          "what the API can deliver)")

    # ---------------------------------------------------------------- [8] final status
    print("[8] ingestion status as the Data Ingestion screen sees it")
    st = conns.ingestion_status(NAME, config=args.config)
    print(f"   configured collection: {st.configured}")
    print(f"   schedule {st.schedule_name!r} enabled={st.schedule_enabled}")
    print(f"   alerts written: {len(rows2)} (source {SOURCE!r})")
    print("done: ingestion chain verified end to end.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
