#!/usr/bin/env python3
"""Build playbooks.json from playbooks.yaml.

The connector ships ONLY the basic ingestion chain. The operational use-case
playbooks are a standalone deliverable (../fortinet-fortiedrv2-usecases/)
with their own build, version and install path -- a connector upgrade never
touches them and a playbook change never forces a connector release.

Compiles the YAML with the fsrpb compiler. The Data Ingestion Wizard contract
is expressed natively in the YAML dialect:

  1. collection-level ``exported_tags`` - the wizard filters the connector's
     playbook export by these before it will offer an ingestion configuration;
  2. ``configuration_schema`` on the Fetch playbook's Start step - the YAML
     the compiler serializes to ``step_variables._configuration_schema`` (the
     JSON that renders the wizard's configuration form);
  3. the action-trigger fields on the Ingest playbook's Start step (``module``,
     ``button_label``, ``requires_record`` ...) which the compiler expands to
     the canonical ``route``/``resources``/``displayConditions``/...
     ``noRecordExecution``/``singleRecordExecution`` shape.

The only post-compile work left is deterministic housekeeping: stamping the
sample collection's name with the version from ``info.json`` and pinning
``lastModifyDate`` so a rebuild is byte-identical.

Usage:  python playbooks/build.py [--fsrpb /path/to/fsrpb]
"""

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
YAML_IN = HERE / "playbooks.yaml"
JSON_OUT = HERE / "playbooks.json"

CONNECTOR = "fortinet-fortiedrv2"


def _freeze_timestamps(doc):
    """Pin every ``lastModifyDate`` so a rebuild is byte-identical.

    The compiler stamps each workflow with the wall-clock time of the build, so
    two runs over an unchanged source produce two different files, carrying no
    information. That noise hides the one-line change you actually made when
    reviewing, and makes it impossible to tell from a diff whether the compiled
    artefact was rebuilt or edited.

    The value tracks the YAML's own mtime, so it still moves when the source
    genuinely changes. ``SOURCE_DATE_EPOCH`` overrides it, per the usual
    reproducible-builds convention.
    """
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    stamp = int(epoch) if epoch and epoch.isdigit() else YAML_IN.stat().st_mtime

    def walk(node):
        if isinstance(node, dict):
            if "lastModifyDate" in node:
                node["lastModifyDate"] = stamp
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(doc)
    return doc


def _sync_collection_version(doc):
    """Retag the sample collection with the version from ``info.json``.

    FortiSOAR deletes a connector's sample collection on upgrade and re-imports
    it under the new name, so a collection still carrying the previous version
    leaves the appliance with a stale name - or, if the old collection was
    removed by hand, no ingestion playbooks at all. Keeping the name derived
    from ``info.json`` means the version only has to be bumped in one place.
    """
    info = json.loads((HERE.parent / "info.json").read_text())
    version = info.get("version")
    if not version:
        return doc
    for collection in doc.get("data", []):
        name = collection.get("name") or ""
        collection["name"] = re.sub(r"\d+\.\d+\.\d+$", version, name) if re.search(
            r"\d+\.\d+\.\d+$", name) else name
    return doc


def _assert_portable_configs(doc):
    """Refuse any per-appliance configuration value in the compiled output.

    Every step in this bundle must run against whatever configuration the
    importing appliance resolves at play time: the connector steps and the
    code-snippet steps alike pin ``config: ''`` -- the FortiSOAR "use the
    default configuration" sentinel. The compiler fills an empty config from
    the per-appliance ``connector_configs`` catalog of the machine the build
    runs on (fsrpb's resolver: ``resolve_config_id(connector) or ""``), so a
    host whose catalog was warmed against a live box silently bakes that
    box's configuration UUID into the bundle -- and every OTHER appliance
    then answers the step with ``INTEGRATION-12: Could not find a connector
    configuration matching the given configuration id or name`` while CI,
    which compiles a cold catalog, ships bytes that were never tested
    (live-caught on 8.0.1: the sweep's, digest's and fleet audit's snippet
    steps all died this way on their first run away from the build host).
    This check makes the break loud at build time instead.
    """
    offenders = []
    for collection in doc.get("data", []):
        for wf in collection.get("workflows", []):
            for st in wf.get("steps", []):
                args = st.get("arguments")
                if not isinstance(args, dict):
                    continue
                if "config" in args and args["config"] not in ("", None):
                    offenders.append(
                        f"{collection.get('name', '?')} / {wf.get('name', '?')} / "
                        f"{st.get('name', '?')}: connector="
                        f"{args.get('connector')!r} config={args['config']!r}")
    if offenders:
        sys.stderr.write(
            "refusing to write playbooks.json: per-appliance config value(s) "
            "would make the bundle non-portable:\n  "
            + "\n  ".join(offenders)
            + "\nfix: the fsrpb reference store's per-appliance catalog has "
              "rows for that connector (data/fsr_reference.db, table "
              "connector_configs). Delete them and rebuild.\n")
        sys.exit(2)
    return doc


def _assert_portable_task_fields(doc):
    """Refuse picklist-typed fields in create_task resources.

    A task write's status/priority are picklist *references* on the engine's
    path: the appliance resolves them by picklist-item IRI/uuid, never by
    label -- a bare string that even IS a real TaskStatus item dies as the
    engine probes ``/api/3/picklists/<label>`` and answers ``FSR_CH_0000001
    ... the provided value does not match any of the options listed in the
    specified picklist`` (live-caught on 8.0.1: the digest's ``status:
    Open`` step, on an appliance whose TaskStatus picklist carried ``Open``,
    with ``priority: Low`` one field behind it on the same path).
    Machine-authored playbooks ship per-appliance picklist IRIs instead,
    which this bundle must never carry: the item uuids are appliance-local.
    A create_task step here therefore pins only the appliance-neutral task
    fields -- name and description -- and the importing SOC's own task
    workflow decides status and priority. Same contract as
    _assert_portable_configs: make the break loud at build time instead of
    on the customer's box.
    """
    allowed = {"name", "description"}
    offenders = []
    for collection in doc.get("data", []):
        for wf in collection.get("workflows", []):
            for st in wf.get("steps", []):
                args = st.get("arguments")
                col = args.get("collection") if isinstance(args, dict) else None
                if not isinstance(col, str) or col.rstrip("/").rsplit("/", 1)[-1] != "tasks":
                    continue
                resource = args.get("resource")
                if not isinstance(resource, dict):
                    continue
                extra = sorted(set(resource) - allowed)
                if extra:
                    offenders.append(
                        f"{collection.get('name', '?')} / {wf.get('name', '?')} / "
                        f"{st.get('name', '?')}: appliance-bound task field(s) {extra}")
    if offenders:
        sys.stderr.write(
            "refusing to write playbooks.json: create_task step(s) pin task "
            "fields the importing appliance must own:\n  "
            + "\n  ".join(offenders)
            + "\nfix: drop status/priority (and any other picklist-typed "
              "field) from the task resource; pin only name and description "
              "and let the SOC's own task workflow decide the state.\n")
        sys.exit(2)
    return doc


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--fsrpb", default="fsrpb", help="path to the fsrpb executable")
    args = ap.parse_args()

    tmp_path = HERE / ".build.tmp.json"

    def _compile(lax=False):
        cmd = [args.fsrpb, "compile", str(YAML_IN), "-o", str(tmp_path)]
        if lax:
            cmd.insert(3, "--lax")
        return subprocess.run(cmd, capture_output=True, text=True)

    proc = _compile()
    if proc.returncode != 0 and "unknown connector" in (proc.stdout + proc.stderr):
        # The reference store has not been told about this connector yet, so
        # every step referencing it fails validation. Fall back to --lax so the
        # build still works, but say how to fix it properly - under --lax a
        # genuinely misspelled operation slips through as a warning too.
        sys.stderr.write(
            f"warning: the fsrpb catalog does not know {CONNECTOR!r}; compiling "
            f"with --lax, which also demotes real typos to warnings.\n"
            f"         fix: fsrpb provision {HERE.parent}\n",
        )
        proc = _compile(lax=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout + proc.stderr)
        return proc.returncode
    # A successful compile can still carry warnings (severity=warning
    # findings don't flip the exit code); the fsrpb CLI prints them on
    # success -- don't swallow them here. Warnings are how the
    # reference-catalog gaps surface (unknown jinja tests, decision
    # conditions that don't render strict bools, message: blocks
    # without an explicit record:) -- all three were live-caught the
    # hard way on runs that compiled "clean".
    if proc.stderr:
        sys.stderr.write(proc.stderr)
    doc = json.loads(tmp_path.read_text())
    tmp_path.unlink(missing_ok=True)

    doc = _sync_collection_version(doc)
    doc = _freeze_timestamps(doc)
    doc = _assert_portable_configs(doc)
    doc = _assert_portable_task_fields(doc)
    JSON_OUT.write_text(json.dumps(doc, indent=2) + "\n")

    total = sum(len(c.get("workflows", [])) for c in doc.get("data", []))
    collections = ", ".join(c.get("name", "?") for c in doc.get("data", []))
    print(f"wrote {JSON_OUT} ({total} playbooks in {len(doc.get('data', []))} collections: {collections})")
    print(f"     exported_tags={doc.get('exported_tags')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
