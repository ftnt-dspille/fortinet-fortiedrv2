#!/usr/bin/env python3
"""Build playbooks.json from playbooks.yaml.

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

The only post-compile work left is deterministic housekeeping: stamping every
sample collection's name with the version from ``info.json`` and pinning
``lastModifyDate`` so a rebuild is byte-identical.

The output lists BOTH collections FortiSOAR installs with the connector: the
ingestion chain (playbooks.yaml) and the operational use cases
(use_cases.yaml). Both compile, then merge -- the use-cases collection
carries no dataingestion/fetch/ingest/create tags, so the Data Ingestion
Wizard never mistakes it for an ingestion candidate.

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
USE_CASES_IN = HERE / "use_cases.yaml"
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
    stamp = int(epoch) if epoch and epoch.isdigit() else max(
        YAML_IN.stat().st_mtime,
        USE_CASES_IN.stat().st_mtime if USE_CASES_IN.exists() else 0,
    )

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


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--fsrpb", default="fsrpb", help="path to the fsrpb executable")
    args = ap.parse_args()

    sources = [YAML_IN]
    if USE_CASES_IN.exists():
        sources.append(USE_CASES_IN)
    tmp_paths = [HERE / f".build_{i}.tmp.json" for i in range(len(sources))]

    def _compile(idx, lax=False):
        cmd = [args.fsrpb, "compile", str(sources[idx]), "-o", str(tmp_paths[idx])]
        if lax:
            cmd.insert(3, "--lax")
        return subprocess.run(cmd, capture_output=True, text=True)

    doc = None
    for idx, yaml_in in enumerate(sources):
        proc = _compile(idx)
        if proc.returncode != 0 and "unknown connector" in (proc.stdout + proc.stderr):
            # The reference store has not been told about this connector yet, so
            # every step referencing it fails validation. Fall back to --lax so the
            # build still works, but say how to fix it properly - under --lax a
            # genuinely misspelled operation slips through as a warning too.
            sys.stderr.write(
                f"warning: the fsrpb catalog does not know {CONNECTOR!r}; compiling "
                f"{yaml_in.name} with --lax, which also demotes real typos to warnings.\n"
                f"         fix: fsrpb provision {HERE.parent}\n",
            )
            proc = _compile(idx, lax=True)
        if proc.returncode != 0:
            sys.stderr.write(proc.stdout + proc.stderr)
            return proc.returncode
        part = json.loads(tmp_paths[idx].read_text())
        if doc is None:
            doc = part
        else:
            # Merge: the appliance imports one playbook.json listing every
            # collection. The chain stays first (it is what the Data Ingestion
            # Wizard scans), and the exported tag union covers both.
            doc["data"].extend(part["data"])
            for tag in part.get("exported_tags") or []:
                if tag not in (doc.get("exported_tags") or []):
                    doc.setdefault("exported_tags", []).append(tag)

    for tmp in tmp_paths:
        tmp.unlink(missing_ok=True)

    doc = _sync_collection_version(doc)
    doc = _freeze_timestamps(doc)
    JSON_OUT.write_text(json.dumps(doc, indent=2) + "\n")

    total = sum(len(c.get("workflows", [])) for c in doc.get("data", []))
    collections = ", ".join(c.get("name", "?") for c in doc.get("data", []))
    print(f"wrote {JSON_OUT} ({total} playbooks in {len(doc.get('data', []))} collections: {collections})")
    print(f"     exported_tags={doc.get('exported_tags')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
