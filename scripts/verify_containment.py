"""
Live verification for the Containment Chain use case (1.1.5).

Drives ``FortiEDR v2 > Containment Chain`` on a real alert through its
record-action route, answers its approval gate with ONE action from the
matrix, and checks the outcome on the tenant, on the alert's comments,
and -- for the block leg -- on the FortiGate's own ban list. Every mode
restores what it touched: the isolate leg releases the collector, the
block leg unbans the address (the ban is time-boxed anyway; the release
makes the check instant).

The chain's fail-soft legs make several "degradations" CORRECT outcomes:
a directory lookup on a box without an AD/LDAP connector lands a
"returned no entries" comment; a block on a box without a FortiGate
configuration lands "did not land". This verifier distinguishes the two
windows by expectation:

  --action isolate   (collector window)  the round-trip collector's alert;
                      gate answered "Isolate only": collector isolated,
                      then released. No block comment may appear.
  --action block     (FortiGate window)  an alert whose event carries an
                      IP-shaped destination; gate answered "Block IP only":
                      ban verified on the device, then unbanned. No
                      isolation may happen.
  --action declined  (any window)        gate answered "Skip Containment":
                      no isolation, no block, decline comment on the alert.

Env (.env.live by default), the same contract the other verifiers use:
EDR_ROUNDTRIP_COLLECTOR names the collector whose alert drives the
isolate leg; EDR_SACRIFICIAL_EVENT_ID is the alert the block/decline
legs drive; EDR_PASSWORD carries the connector credential. FGT_CONFIG
(optional) names the fortigate-firewall configuration the device-side
checks use; blank means the connector's default configuration.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import urllib3

# Demo-box self-signed certs; the warnings bury the phase output otherwise.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.insert(0, str(Path(__file__).resolve().parent))

from verify_use_cases import (          # noqa: E402  (house helpers, live-proven)
    MARKER,
    _alert_by_source,
    _alert_rows,
    _await_gate,
    _clear_stale_gates,
    _comments,
    _env_files,
    _errors,
    _fail,
    _fmt,
    _info,
    _isolation_target,
    _ops,
    _resolve_pb,
    _route,
    _trigger_action,
    _unexpected_errors,
    _wait_run,
)

ROOT = Path(__file__).resolve().parent.parent
CHAIN = "FortiEDR v2 > Containment Chain"
GATE_TITLE = "Approve containment actions"

OPT_ISOLATE = "Isolate only"
OPT_BLOCK = "Block IP only"
OPT_SKIP = "Skip Containment"


def _is_ip(text):
    parts = str(text or "").strip().split(".")
    return (len(parts) == 4
            and all(p.isdigit() and int(p) <= 255 for p in parts))


def _pick_alert(client, ops, config, env, want_ip):
    """The alert to drive: for the block leg one whose event carries an
    IP-shaped destination (the block child needs an address); otherwise the
    approved isolation target."""
    if want_ip:
        sac = env.get("EDR_SACRIFICIAL_EVENT_ID")
        if sac:
            alert = _alert_by_source(client, sac)
            if alert:
                events = ops["get_event_by_id"](config, {"eventIds": int(sac)})
                for d in ((events[0] if events else {}).get("destinations") or []):
                    text = str(d or "").strip()
                    if _is_ip(text):
                        return alert, text
        _fail("no alert with an IP-shaped destination to drive the block leg")
    rows = _alert_rows(client)
    source_ids = [str(r["sourceId"]) for r in rows
                  if str(r.get("sourceId") or "").isdigit()]
    source_id, device, why = _isolation_target(client, ops, config, env, source_ids)
    alert = _alert_by_source(client, source_id)
    if not alert:
        _fail(f"no alert on the box for sourceId {source_id}")
    _info(f"driving the {why}'s alert (event {source_id}, device {device})")
    return alert, device


def _drive(client, pb_row, alert, option_label, note):
    """Trigger the chain on the alert and answer its gate; return
    (task_id, since_epoch)."""
    _clear_stale_gates(client, GATE_TITLE, OPT_SKIP,
                       f"{MARKER}: declined to clear a containment gate left"
                       f" by an earlier aborted verification pass")
    since = time.time() - 60  # a minute of clock-skew slack
    task_id = _trigger_action(client, pb_row, alert["uuid"],
                              env={"verification": MARKER})
    gate = _await_gate(client, task_id, GATE_TITLE)
    if gate is None:
        _fail("the containment gate never appeared in the pending-input queue")
    _info("gate is up; answering with the reason")
    _resume(client, gate, option_label, {"decision_note": note})
    return task_id, since


def _assert_clean_finish(status, err, tree, what):
    if status not in ("finished", "finished with error") or err:
        _fail(f"{what} run did not finish cleanly: {status} {err}")
    unexpected = _unexpected_errors(tree)
    if unexpected:
        _fail(f"errors in the run tree: {unexpected}")
    if _errors(tree):
        _info("note: a fail-soft leg degraded and was wrapped in its audit"
              " comment, as designed")


def _comment_with(texts, needle):
    return next((t for t in texts if needle in t), None)


def _fgt_json(client, env, operation, params):
    res = client.connectors.execute(
        "fortigate-firewall", operation,
        config=(env.get("FGT_CONFIG") or None),
        params=params)
    return json.dumps(res.data if hasattr(res, "data") else res)


def action_isolate(client, ops, config, env, args):
    alert, device = _pick_alert(client, ops, config, env, want_ip=False)
    pb_row = _resolve_pb(client, CHAIN)
    _route(client, pb_row)
    note = f"{MARKER}: approved ISOLATE ONLY"
    task_id, since = _drive(client, pb_row, alert, OPT_ISOLATE, note)
    status, err, tree = _wait_run(client, task_id, "containment isolate")
    _assert_clean_finish(status, err, tree, "containment isolate")

    collector = next(r for r in ops["get_collector_list"](config, {})
                     if r.get("name") == device)
    if "Isolated" not in (collector.get("stateAdditionalInfo") or ""):
        _fail(f"collector {device} was not isolated: "
              f"{_fmt(collector, 'name', 'stateAdditionalInfo')}")
    _info(f"collector {device} IS isolated on the tenant")

    texts = [c.get("content") or "" for c in
             _comments(client, alert["uuid"], since_epoch=since)]
    iso = _comment_with(texts, "Containment Chain: isolated collector")
    if not iso:
        _fail(f"no isolation audit comment on the alert: {texts}")
    if note.split(": ", 1)[1] not in iso:
        _fail(f"the isolation comment does not carry the reason: {iso}")
    if not _comment_with(texts, "Directory Lookup:"):
        _fail("the directory leg posted no comment on the alert")
    if _comment_with(texts, "FortiGate Block:"):
        _fail("the block leg ran on an ISOLATE ONLY approval")
    _info("isolation + directory comments are on the alert; no block ran")

    ops["unisolate_collector"](config, {"type": "Name", "devices": device})
    collector = next(r for r in ops["get_collector_list"](config, {})
                     if r.get("name") == device)
    if "Isolated" in (collector.get("stateAdditionalInfo") or ""):
        _fail(f"failed to restore collector {device}")
    _info(f"collector {device} released again -- tenant restored")


def action_block(client, ops, config, env, args):
    alert, block_ip = _pick_alert(client, ops, config, env, want_ip=True)
    _info(f"block target: {block_ip}")
    pb_row = _resolve_pb(client, CHAIN)
    note = f"{MARKER}: approved BLOCK ONLY"
    task_id, since = _drive(client, pb_row, alert, OPT_BLOCK, note)
    status, err, tree = _wait_run(client, task_id, "containment block")
    _assert_clean_finish(status, err, tree, "containment block")

    texts = [c.get("content") or "" for c in
             _comments(client, alert["uuid"], since_epoch=since)]
    landed = _comment_with(texts, f"banned {block_ip} on the gate")
    if not landed:
        degraded = _comment_with(texts, "did not land")
        if degraded:
            _fail(f"the block degraded (connector configured? gate reachable?)"
                  f": {degraded}")
        _fail(f"no block outcome comment on the alert: {texts}")
    _info(f"the gate confirms the ban: {landed.strip()}")

    banned = _fgt_json(client, env, "get_blocked_ip", {"method": "Quarantine Based"})
    if f'"{block_ip}"' not in banned:
        _fail(f"{block_ip} not in the device's ban list as seen from the SOAR")
    _info("the ban list read back from the SOAR agrees with the device")

    _fgt_json(client, env, "unblock_ip",
              {"method": "Quarantine Based", "ip_addresses": block_ip})
    banned = _fgt_json(client, env, "get_blocked_ip", {"method": "Quarantine Based"})
    if f'"{block_ip}"' in banned:
        _fail(f"failed to unban {block_ip} -- the gate still carries it")
    _info(f"{block_ip} unbanned -- the gate is clean again")

    rt = env.get("EDR_ROUNDTRIP_COLLECTOR")
    if rt:
        collector = next((r for r in ops["get_collector_list"](config, {})
                          if r.get("name") == rt), None)
        if collector and "Isolated" in (collector.get("stateAdditionalInfo") or ""):
            _fail("the BLOCK ONLY approval isolated the collector anyway")


def action_declined(client, ops, config, env, args):
    alert, device = _pick_alert(client, ops, config, env, want_ip=False)
    pb_row = _resolve_pb(client, CHAIN)
    note = f"{MARKER}: containment declined"
    task_id, since = _drive(client, pb_row, alert, OPT_SKIP, note)
    status, err, tree = _wait_run(client, task_id, "containment declined")
    _assert_clean_finish(status, err, tree, "containment declined")

    texts = [c.get("content") or "" for c in
             _comments(client, alert["uuid"], since_epoch=since)]
    if not _comment_with(texts, "containment declined for event"):
        _fail(f"no decline comment on the alert: {texts}")
    if _comment_with(texts, "Containment Chain: isolated collector"):
        _fail("the declined run somehow isolated the collector")
    if _comment_with(texts, "FortiGate Block: banned"):
        _fail("the declined run somehow blocked at the gate")
    collector = next(r for r in ops["get_collector_list"](config, {})
                     if r.get("name") == device)
    if "Isolated" in (collector.get("stateAdditionalInfo") or ""):
        _fail(f"collector {device} is isolated after a declined containment")
    _info("decline path clean: no isolation, no block, comment posted")


ACTIONS = {
    "isolate": action_isolate,
    "block": action_block,
    "declined": action_declined,
}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Containment Chain live verifier")
    ap.add_argument("--instance", required=True,
                    help="pyfsr instance alias (~/.pyfsr/instances.toml)")
    ap.add_argument("--env-file", default=str(ROOT / ".env.live"),
                    help="EDR_* environment file (gitignored)")
    ap.add_argument("--action", choices=sorted(ACTIONS), required=True,
                    help="which gate answer to drive and verify")
    args = ap.parse_args(argv)

    from install_to_fsr import _client
    client = _client(args.instance)
    ops, config, env = _ops(Path(args.env_file))
    for key in ("EDR_SERVER", "EDR_PASSWORD", "EDR_SACRIFICIAL_EVENT_ID"):
        if not env.get(key):
            _fail(f"{key} is missing from {args.env_file}")

    print(f"[containment] {args.action} on {client.base_url}")
    ACTIONS[args.action](client, ops, config, env, args)
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
