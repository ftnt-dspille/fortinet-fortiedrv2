"""Live tests: EVERY operation against the real FortiEDR tenant.

Opt in with pytest --live (credentials in a gitignored .env.live, see
conftest.py). Both live test files execute their operations through the
``call_op`` fixture; the last test in this file asserts the session
registry covers every operation ``fortinet-fortiedrv2`` ships, so an
operation that only ever ran offline is a test failure, not an oversight.

This is MUTATING coverage, in narrow ways approved by the tenant owner
before the first run (a demo tenant whose collectors are all offline lab
VMs):

- every round trip restores prior state exactly (read toggle, isolate,
  collector group, IP set create -> update -> delete);
- the exception created on the sacrificial event is DELETED again by the
  suite through v2's delete_exception; nothing the suite touches stays
  behind;
- set_collector_state is exercised enable-direction only: on this tenant
  the console job behind a state change never completes (every collector
  is offline), so what the op can prove live is the accepted, authed
  request and its bounded 10-minute poll rather than a state flip;
- ops that need a live collector (remediate_device, get_file) can only be
  validated up to the tenant's own clean rejection on this tenant: every
  collector answers 'Operation cannot run on Disconnected device'. The
  tests pin that the request path, auth and error surfacing all work end
  to end.

Targets are per-tenant and configured through .env.live (never hardcodes
in this file): the configured org, the collector approved for the round
trips (EDR_ROUNDTRIP_COLLECTOR), the long-lived event the ingestion
semantics depend on (EDR_DEMO_EVENT_ID) and the event approved as the
sacrificial carrier for the exception ops (EDR_SACRIFICIAL_EVENT_ID). A
missing target skips the tests that need it rather than guessing.
"""
import json
import time
from datetime import UTC, datetime, timedelta

import pytest
from connectors.core.connector import ConnectorError
from fortiedrv2.operations import OPERATIONS

pytestmark = pytest.mark.live

IPSET = 'zfortiedrv2-selftest'        # created and deleted again by its test


def _now():
    return datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S')


def _ago(**kwargs):
    return (datetime.now(UTC) - timedelta(**kwargs)).strftime('%Y-%m-%d %H:%M:%S')


@pytest.fixture()
def fast_400s(monkeypatch):
    """Make the stock 400-retry loop (5 tries, 10s apart) instantaneous.

    The events endpoints are known to answer an occasional 400 for a valid
    query, so the client retries every 400 -- but the deliberate clean
    rejections asserted below (disconnected collector, file not part of the
    event) are certain 400s; waiting 4 minutes of dead retry sleeps per test
    would prove nothing (the live run has already paid it once to observe
    the messages).
    """
    monkeypatch.setattr(time, 'sleep', lambda seconds: None)


# ----------------------------------------------------------------- session context

@pytest.fixture(scope='session')
def org_id(call_op, live_config):
    """The console organizationId of the configured org.

    list-organizations names it ``organizationId`` (live 7.2.3); ``id`` is
    accepted as a fallback for API revisions that spell it differently.
    """
    org_name = live_config.get('organization')
    for row in call_op('get_organizations') or []:
        if isinstance(row, dict) and row.get('name') == org_name:
            value = row.get('organizationId', row.get('id'))
            if value is not None:
                return value
    pytest.skip('organization {0!r} not found in list-organizations'.format(org_name))


@pytest.fixture(scope='session')
def collectors(call_op):
    rows = call_op('get_collector_list', {}) or []
    return {row.get('name'): row for row in rows}


@pytest.fixture(scope='session')
def approved_collector(collectors, roundtrip_collector):
    """Row (list-collectors shape) of the collector approved for the state
    round trips, from EDR_ROUNDTRIP_COLLECTOR."""
    row = collectors.get(roundtrip_collector) if roundtrip_collector else None
    if not row:
        pytest.skip("the round-trip collector EDR_ROUNDTRIP_COLLECTOR="
                    "{0!r} is not set in .env.live or not visible".format(roundtrip_collector))
    return row


def _collector(call_op, name):
    rows = call_op('get_collector_list', {'type': 'Name', 'devices': name}) or [{}]
    return rows[0]


def _event(call_op, event_id):
    rows = call_op('get_event_by_id', {'eventIds': str(event_id)}) or []
    return rows[0] if rows else None


@pytest.fixture(scope='session')
def demo_event(call_op, demo_event_id):
    """The tenant's long-lived event (re-detections absorb into it without
    moving its firstSeen) -- the shape the ingestion fix exists for."""
    if not demo_event_id:
        pytest.skip('EDR_DEMO_EVENT_ID not set (.env.live): the ingestion '
                    'semantics canaries need a long-lived event id')
    event = _event(call_op, demo_event_id)
    if not event:
        pytest.skip('the configured EDR_DEMO_EVENT_ID event is no longer visible')
    return event


@pytest.fixture(scope='session')
def sacrificial_event(call_op, sacrificial_event_id):
    """The event approved as the carrier for the exception round trip (an
    event nobody minds an exception rule on -- here, app-control noise)."""
    if not sacrificial_event_id:
        pytest.skip('EDR_SACRIFICIAL_EVENT_ID not set (.env.live): the '
                    'exception round trip needs an approved carrier event')
    event = _event(call_op, sacrificial_event_id)
    if not event:
        pytest.skip('the configured EDR_SACRIFICIAL_EVENT_ID event is no longer visible')
    return event


# ----------------------------------------------------------------- read-only ops

def test_get_collector_list_names_groups_and_state(call_op, collectors, roundtrip_collector):
    """list-collectors answers the fields the round-trip tests verify against:
    name, id, state, stateAdditionalInfo and collectorGroupName
    (live-observed shape)."""
    assert roundtrip_collector in collectors
    row = collectors[roundtrip_collector]
    assert row.get('id') and row.get('state')
    assert row.get('collectorGroupName'), 'list-collectors shapes changed: no collectorGroupName'


def test_get_agent_group_lists_the_built_in_groups(call_op):
    groups = call_op('get_agent_group', {}) or []
    names = {g.get('name') for g in groups}
    assert 'Default Collector Group' in names


def test_get_system_summary_counts_collectors(call_op, live_config):
    summary = call_op('get_system_summary', {'organization': 'Exact Organization Name',
                                             'org_name': live_config['organization']})
    assert isinstance(summary, dict)
    assert isinstance(summary.get('collectorsState'), dict), \
        'list-system-summary shapes changed: no collectorsState'


def test_get_collector_installers_lists_versions(call_op, live_config):
    result = call_op('get_collector_installers', {'organization': live_config['organization']})
    installers = (result or {}).get('availableCollectorInstallers')
    assert installers, 'no collector installers visible'
    assert all(i.get('osFamily') and i.get('version') for i in installers)


def test_get_event_list_rows_in_an_activity_window(call_op):
    """The list-events read whose no-pageNumber shape the scheduled pull
    relies on. Live-observed on 7.2.3: a windowed list-events query that
    CARRIES pageNumber at the default page size answers 200 + [] even on
    a populated window (which is why ingest_events never sends it), while
    this query without it returns the rows. A 200 + [] flake on a good
    query has also been seen, so the read retries a couple of times before
    failing."""
    rows = []
    for _ in range(3):
        rows = call_op('get_event_list', {'lastSeenFrom': _ago(days=45),
                                          'lastSeenTo': _now(), 'itemsPerPage': 100}) or []
        if rows:
            break
    assert isinstance(rows, list)
    for row in rows:
        assert row.get('eventId')


def test_get_event_list_extended_is_a_deduped_union(call_op, demo_event, demo_event_id):
    """List Events Extended queries archived=True and archived=False and keys
    the union on eventId; the demo event answers exactly one row."""
    rows = call_op('get_event_list_extended', {'eventIds': str(demo_event_id)})
    assert rows, 'the demo event is invisible to list-events-extended'
    assert [r.get('eventId') for r in rows] == [demo_event_id]


def test_get_raw_data_items_and_json_export(call_op, demo_event, demo_event_id):
    items = call_op('get_raw_data_items', {'eventId': demo_event_id})
    assert items, 'no raw data items for the demo event'
    raw_id = items[0]['rawEventId']
    export = call_op('get_raw_json_event_data', {'rawItemIds': str(raw_id)})
    assert isinstance(export, dict)
    assert export.get('Alerts'), 'the raw export is not the expected event JSON'


def test_search_reports_an_absent_hash_cleanly(call_op):
    rows = call_op('search', {'fileHashes': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'})
    assert isinstance(rows, list) and len(rows) == 1
    assert rows[0]['eventIds'] == [], 'the empty-file SHA has events?!'


def test_search_ioc_queries_recent_events(call_op, sacrificial_event):
    device = (sacrificial_event.get('collectors') or [{}])[0].get('device')
    if not device:
        pytest.skip('no collector name on the sacrificial event')
    rows = call_op('search_ioc', {'category': 'Event Log',
                                  'devices': device, 'time': 'Last 7 Days'})
    assert isinstance(rows, list)
    if not rows:
        pytest.skip('no threat-hunting rows for this device in the last 7 days')


def test_generic_rest_api_call_reads_an_endpoint(call_op):
    rows = call_op('generic_rest_api_call',
                  {'endpoint': 'management-rest/organizations/list-organizations',
                   'method': 'GET'})
    assert isinstance(rows, list) and rows


# ----------------------------------------------------------------- round trips

def test_update_event_accepts_both_read_directions(call_op, sacrificial_event):
    """Mark-read then mark-unread on the sacrificial event, asserting the two
    things this op can actually prove against a live 7.2.3 tenant:

    - the request path works: the update is accepted in BOTH directions,
      with a real JSON boolean body (the form's selects deliver the strings
      'True'/'False'; the API ignores a string body silently -- the state
      the shipped connector never moved);
    - the round trip is residue-free: the event's own row flags (seen /
      handled / archived / muted) are exactly as they were.

    Live-verified on 7.2.3: neither read nor handle is reflected back in the
    list-events row (`seen`, `handled` stay unchanged whatever the update
    does to the per-user audit), and `handle: false` additionally triggers a
    server-side 400 NPE ('batchSize is null') -- a FortiEDR server bug this
    test deliberately does not exercise."""
    event_id = sacrificial_event['eventId']
    before = {key: _event(call_op, event_id).get(key)
              for key in ('seen', 'handled', 'archived', 'muted')}

    mark = call_op('update_event', {'eventIds': str(event_id),
                                    'update_fields': ['Read'], 'read': 'True'})
    assert mark is not None
    after_mark = {key: _event(call_op, event_id).get(key)
                  for key in ('seen', 'handled', 'archived', 'muted')}
    assert after_mark == before, 'mark-read changed the row flags: {0}'.format(after_mark)

    restore = call_op('update_event', {'eventIds': str(event_id),
                                       'update_fields': ['Read'], 'read': 'False'})
    assert restore is not None

    after_restore = {key: _event(call_op, event_id).get(key)
                     for key in ('seen', 'handled', 'archived', 'muted')}
    assert after_restore == before, 'the read round trip left residue: {0}'.format(after_restore)


def test_isolate_and_unisolate_round_trip(call_op, approved_collector):
    name = approved_collector['name']
    call_op('isolate_collector', {'type': 'Name', 'devices': name})
    row = _collector(call_op, name)
    assert 'Isolated' in (row.get('stateAdditionalInfo') or ''), \
        'isolate answers OK but the collector state is {0!r}'.format(row.get('stateAdditionalInfo'))
    call_op('unisolate_collector', {'type': 'Name', 'devices': name})
    row = _collector(call_op, name)
    assert 'Isolated' not in (row.get('stateAdditionalInfo') or ''), \
        'failed to restore the isolation state of {0}'.format(name)


def test_move_collectors_round_trip(call_op, approved_collector):
    name = approved_collector['name']
    original = (approved_collector.get('collectorGroupName')
                or _collector(call_op, name).get('collectorGroupName'))
    assert original, 'cannot learn the current group of {0}'.format(name)
    if original == 'High Security Collector Group':
        pytest.skip('the round-trip collector already sits in the target group')

    call_op('move_collectors', {'collectors': name,
                                'targetCollectorGroup': 'High Security Collector Group'})
    row = _collector(call_op, name)
    assert row.get('collectorGroupName') == 'High Security Collector Group'

    call_op('move_collectors', {'collectors': name, 'targetCollectorGroup': original})
    row = _collector(call_op, name)
    assert row.get('collectorGroupName') == original


def test_update_collector_installer_sends_objects_up_to_the_org_policy(call_op, approved_collector, live_config,
                                                                       fast_400s):
    """The request must reach the server's POLICY layer, which is as far as
    this tenant lets the op go: it runs a dedicated Core with a lower
    revision and update-collector-installer answers a clean 400 explaining
    exactly that (with or without the organization query), on any version
    pinned.

    The object body is what got it there -- with bare version strings (and
    with the pre-encoded JSON string the shipped form tolerated) the server
    rejected the request earlier, at its deserializer, naming
    CollectorInstallerRequest."""
    version = approved_collector.get('version')
    group = approved_collector.get('collectorGroupName') or _collector(call_op, approved_collector['name']).get('collectorGroupName')
    os_family = next((f for f in ('Linux', 'OSX', 'Windows')
                      if (approved_collector.get('osFamily') or '').startswith(f)), None)
    if not (version and group and os_family):
        pytest.skip('no collector version/group/os family to pin')
    with pytest.raises(ConnectorError, match='dedicated Core with a lower revision'):
        call_op('update_collector_installer',
                {'collectorGroups': group, 'organization': live_config['organization'],
                 'updateVersions': [{'osFamily': os_family, 'version': version,
                                     'allowDowngrade': True}]})


def test_set_collector_state_bounds_its_wait_on_an_offline_collector(call_op, org_id, approved_collector, monkeypatch):
    """The state change is an async console job polled to completion, bounded
    at 10 minutes (the FortiSOAR playbook step ceiling). Live-observed on this
    tenant: every collector is offline, and the job for an enable/disable
    request never reaches 100% -- the request itself is accepted and authed
    (the pre-org-id 400 'Missing required parameter(s) - organizationId' was
    the earlier failure mode), but the state flag only applies with the job.

    So the correct observable here is the BOUNDED TIMEOUT, and the test
    shrinks only its own polling patience (2s x 3) so the run stays seconds
    instead of minutes -- the op's contract is unchanged. The request
    direction is enable-only: enabling an already-enabled collector cannot
    disable it, so no round trip is left half-done on a timeout."""
    from fortiedrv2 import operations

    original_wait = operations._wait_for_async_job

    def quick_wait(client, job_id, poll_seconds=5, max_polls=120):
        return original_wait(client, job_id, poll_seconds=2, max_polls=3)

    monkeypatch.setattr(operations, '_wait_for_async_job', quick_wait)

    timed_out = False
    result = None
    try:
        result = call_op('set_collector_state',
                         {'collectorIds': str(approved_collector['id']),
                          'organizationId': org_id, 'enabled': 'True'})
    except ConnectorError as err:
        timed_out = 'Timed out waiting for job' in str(err)
    assert timed_out or (isinstance(result, dict) and 'percentage' in result), \
        'expected the bounded job poll to time out (or to return a completed job)'
    # the (enable) request cannot have left the collector disabled
    row = _collector(call_op, approved_collector['name'])
    assert row.get('state') != 'Disabled', row.get('state')


def test_ipset_create_update_delete_round_trip(call_op, live_config):
    """A fully self-cleaning round trip scoped to the configured org: the
    set is deleted again even if the update assertion fails."""
    exact_org = {'organization': 'Exact Organization Name', 'org_name': live_config['organization']}
    try:
        listed = call_op('get_ipset_list', dict(exact_org)) or []
        if any((row or {}).get('name') == IPSET for row in listed):
            call_op('delete_ipset', dict({'ipSets': IPSET}, **exact_org))

        created = call_op('create_ipset', dict({'name': IPSET,
                                                'description': 'fortiedrv2 live selftest (auto-cleanup)',
                                                'include': '192.0.2.123'}, **exact_org))
        assert 'Successfully created' in created['result'], created

        call_op('update_ipset', dict({'name': IPSET,
                                      'description': 'fortiedrv2 live selftest (auto-cleanup)',
                                      'add_items': 'true', 'include': '203.0.113.99'}, **exact_org))
        listed = call_op('get_ipset_list', dict(exact_org)) or []
        mine = next(row for row in listed if (row or {}).get('name') == IPSET)
        assert set(mine['include']) >= {'192.0.2.123', '203.0.113.99'}, \
            'update-ip-set did not merge the include list: {0}'.format(mine['include'])
    finally:
        call_op('delete_ipset', dict({'ipSets': IPSET}, **exact_org))
    listed = call_op('get_ipset_list', dict(exact_org)) or []
    assert not any((row or {}).get('name') == IPSET for row in listed), \
        'the selftest IP set was left behind'


# ----------------------------------------------------------------- the exception

def test_the_exception_round_trip_on_the_sacrificial_event(call_op, sacrificial_event,
                                                           sacrificial_event_id, live_config):
    """create -> get_event_exceptions -> update -> delete -> gone, all on the
    approved sacrificial event (EDR_SACRIFICIAL_EVENT_ID).

    Create is NOT idempotent (each call mints a further exception rule), so
    the cleanup deletes EVERY exception whose originEventId is the sacrificial
    event -- including leftovers from earlier runs of the probe scripts, whose
    comments mark them as ours -- and the final assertion is a clean slate.

    The UPDATE step is where the shipped connector's update_exception
    answered a false success: v2 posts the requested ExceptionId and reports
    a plain failure when it cannot be found. On this 7.2.3 tenant the failure
    is the honest observable: exceptions created through create-exception are
    stored server-side and never appear in any raw-item export
    (live-verified: the event's sole raw item exports with Exceptions=None
    while get-event-exceptions returns the rule). The edit path remains for
    FortiEDR versions that embed exceptions in raw exports.

    The suite then DELETES its artifacts -- v2 exposes the API's
    exceptions/delete endpoint the shipped connector never did -- and
    verifies a clean slate.
    """
    org = sacrificial_event.get('organization') or live_config['organization']
    exact_org = {'organization': 'Exact Organization Name', 'org_name': live_config['organization']}
    event_id = sacrificial_event_id

    def exceptions_on_event():
        excs = call_op('get_event_exceptions', {'eventId': event_id, 'organization': org})
        return [e for e in excs if e.get('originEventId') == event_id]

    try:
        created = call_op('create_exception', {'eventId': event_id,
                                               'allCollectorGroups': 'All Collector Groups',
                                               'allOrganizations': 'False',
                                               'allDestinations': 'All Destinations',
                                               'comment': 'fortiedrv2 live selftest exception (auto-removed)',
                                               'forceCreate': 'False'})
        assert created is not None

        ours = exceptions_on_event()
        assert ours, 'the exception did not appear on the event'
        exception_id = ours[0]['exceptionId']

        updated = call_op('update_exception', {'eventId': event_id,
                                               'exceptionId': exception_id,
                                               'organization': org,
                                               'comment': ' [fortiedrv2 selftest]'})
        assert updated.get('status') == 'failure', \
            'a 7.x raw export never embeds the exception; a non-failure answer means it lied'
        assert str(exception_id) in updated.get('message', ''), updated

        listed = call_op('list_exception', dict(exact_org)) or []
        assert any(e.get('exceptionId') == exception_id for e in listed)
    finally:
        # every exception this event carries should be a selftest artifact
        # (this run's, or a leftover marked as ours); a foreign rule is a
        # fail-loud stop, not something silently deleted for a clean slate.
        all_ids = []
        for exception in exceptions_on_event():
            assert 'fortiedrv2' in (exception.get('comment') or ''), \
                'refusing to delete a foreign exception: {0}'.format(json.dumps(exception)[:120])
            all_ids.append(str(exception['exceptionId']))
        if all_ids:
            call_op('delete_exception', dict({'exceptionIds': ','.join(all_ids)}, **exact_org))

    assert exceptions_on_event() == [], 'exceptions remain on the sacrificial event after cleanup'


# --------------------------------------------------- clean tenant-state rejections

def test_get_event_file_rejects_a_file_that_is_not_part_of_the_event(call_op, demo_event,
                                                                      demo_event_id, fast_400s):
    """The tenant answers this forbidden file request with a clean 400
    ('Action is not permitted because the requested file is not part of the
    event') -- which is precisely the end-to-end validation available on a
    tenant whose collectors are all offline."""
    items = call_op('get_raw_data_items', {'eventId': demo_event_id})
    assert items
    with pytest.raises(ConnectorError, match='not part of the event'):
        call_op('get_event_file', {'rawEventId': str(items[0]['rawEventId']),
                                   'retrieve_from': 'Disk',
                                   'filePaths': 'C:/nonexistent/fortiedrv2-selftest.bin',
                                   'organization': demo_event.get('organization')})


def test_get_file_rejects_an_offline_collector(call_op, approved_collector, live_config, fast_400s):
    """forensics/get-file on an offline collector: the server 400s (its NPE
    about the missing aggregator surfaces verbatim in the error). Request
    path, auth and error surfacing are the things this proves."""
    with pytest.raises(ConnectorError, match='Get File Response'):
        call_op('get_file', {'type': 'Name', 'device': approved_collector['name'],
                             'filePaths': '/tmp/fortiedrv2-selftest-nonexistent',
                             'organization': live_config['organization']})


def test_remediate_device_rejects_an_offline_collector(call_op, approved_collector, live_config, fast_400s):
    with pytest.raises(ConnectorError, match='Disconnected device'):
        call_op('remediate_device', {'type': 'Name', 'device': approved_collector['name'],
                                     'remediate_action': 'Delete File',
                                     'executablesToRemove': '/usr/local/fortiedrv2-selftest-nonexistent',
                                     'organization': live_config['organization']})


# ----------------------------------------------------------------- coverage gate

def test_every_operation_was_exercised_live(call_op):
    """The registry of operations this session actually executed must equal
    the connector's full operation surface -- no op left offline-only.

    (check_health is not an operation; the gate tracks the entries of
    fortiedrv2.operations.OPERATIONS only.)"""
    missing = sorted(set(OPERATIONS) - call_op.covered)
    assert not missing, 'these operations never ran against the live tenant: {0}'.format(
        ', '.join(missing))
    unexpected = sorted(call_op.covered - set(OPERATIONS))
    assert not unexpected, 'the live suite executed unknown operations: {0}'.format(
        ', '.join(unexpected))
