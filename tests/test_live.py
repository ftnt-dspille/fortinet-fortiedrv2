"""Live tests: read-only round-trips against a real FortiEDR tenant.

Opt in with pytest --live; credentials come from a gitignored .env.live at
the repo root (EDR_SERVER / EDR_USERNAME / EDR_PASSWORD / EDR_ORGANIZATION /
EDR_VERIFY_SSL) or the process environment. Every test here is read-only:
nothing creates, updates, deletes, isolates, or remediates, and the tenant
is not modified in any way. The mutating round trips live in
tests/test_live_ops.py.

Both files execute their operations through the ``call_op`` fixture, which
records every operation name in a session registry; the final test in
test_live_ops.py asserts that registry covers every operation the connector
ships.
"""
from datetime import UTC, datetime, timedelta

import pytest

pytestmark = pytest.mark.live

SEVERITIES = ('Critical', 'High', 'Medium', 'Low', 'Minimal')


def _now():
    return datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S')


def _ago(**kwargs):
    return (datetime.now(UTC) - timedelta(**kwargs)).strftime('%Y-%m-%d %H:%M:%S')


def test_health(connector, live_config):
    assert connector.check_health(live_config) is True


def test_organizations(call_op):
    orgs = call_op('get_organizations')
    assert isinstance(orgs, list) and orgs, 'no organizations visible to this account'


def test_an_activity_window_covers_everything_a_creation_window_does(call_op):
    """The semantics the connector exists to fix, checked on real data: with
    the window end at now, every event whose FIRST seen falls in the window
    also has its LAST seen in the window (lastSeen >= firstSeen, and never in
    the future), but not the other way around -- a re-detected process keeps
    its original firstSeen and only moves lastSeen."""
    created = call_op('count_events',
                      {'firstSeenFrom': _ago(days=30), 'firstSeenTo': _now()})
    activity = call_op('count_events',
                       {'lastSeenFrom': _ago(days=30), 'lastSeenTo': _now()})
    assert created['event_count'] >= 0
    assert activity['event_count'] >= created['event_count'], \
        'firstSeen window ({0}) cannot exceed the lastSeen window ({1})'.format(
            created['event_count'], activity['event_count'])


def test_a_long_lived_event_keeps_its_first_seen(call_op, demo_event_id):
    """The canonical repro: an event that keeps absorbing re-detections has
    firstSeen != lastSeen. The demo event is tenant-specific, so its ID comes
    from EDR_DEMO_EVENT_ID; without it this canary has no subject."""
    if not demo_event_id:
        pytest.skip('EDR_DEMO_EVENT_ID not set (.env.live): the long-lived '
                    'event whose pinned firstSeen proves the correlation model '
                    'is a per-tenant stable id, not something this repo hardcodes')
    rows = call_op('get_event_by_id', {'eventIds': str(demo_event_id)})
    if not rows:
        pytest.skip('the configured EDR_DEMO_EVENT_ID event is no longer visible')
    row = rows[0]
    assert row['firstSeenEpoch'] < row['lastSeenEpoch'], \
        'expected the pinned-firstSeen shape, got {0} / {1}'.format(row['firstSeen'], row['lastSeen'])


def test_ingest_events_round_trip(call_op):
    """The window fetch, cross-checked against the count the server itself
    reports for the same window. The 1.0.0 round trip asserted shape over
    what could be -- and once was, through a pageNumber-poisoned request --
    an empty list; the count agreement makes that vacuous green impossible.
    (The two calls run back to back; on an actively-detecting tenant they
    may legitimately differ by events arriving between them.)"""
    window = {'from': _ago(days=45), 'to': _now()}
    counted = call_op('count_events',
                      {'lastSeenFrom': window['from'],
                       'lastSeenTo': window['to']})['event_count']
    alerts = call_op('ingest_events', dict(window))
    assert len(alerts) == counted, \
        'ingest_events read {0} of the {1} event(s) count-events reports ' \
        'for the same window'.format(len(alerts), counted)
    for alert in alerts:
        assert alert['external_id']
        assert alert['severity'] in SEVERITIES, alert['severity']
        assert isinstance(alert['source_payload'], dict)
        assert alert['alert_generation_epoch'] or alert['last_observed_epoch']
        # the description arrives as the house rich-text card, HTML included
        assert '<table' in alert['description']
        assert 'FortiEDR event' in alert['description'] or ' on ' in alert['description']


def test_ingest_events_filtered_window_narrows_and_matches_its_own_count(call_op):
    """The wizard's optional pull filters ride the one query the count
    verifies: a filtered ingest_events must agree with count-events over
    the SAME filtered window, return only rows the filter admits, and
    never report more than the unfiltered window holds. Read-only: the op
    fetches and maps; it never writes alerts or advances the watermark
    (that is the ingest playbook's job)."""
    window = {'from': _ago(days=45), 'to': _now()}
    alerts = call_op('ingest_events', dict(window, classifications='Malicious'))
    counted = call_op('count_events', {'lastSeenFrom': window['from'],
                                       'lastSeenTo': window['to'],
                                       'classifications': 'Malicious'})['event_count']
    assert len(alerts) == counted, \
        'filtered ingest_events read {0} of the {1} event(s) count-events ' \
        'reports for the same filtered window'.format(len(alerts), counted)
    for alert in alerts:
        raw = alert['source_payload']
        assert str(raw.get('classification')).strip() == 'Malicious', raw.get('classification')
    unfiltered = call_op('count_events', {'lastSeenFrom': window['from'],
                                          'lastSeenTo': window['to']})['event_count']
    assert counted <= unfiltered


def test_console_incidents_round_trip(call_op):
    result = call_op('get_incidents', {'time_filter': 'Last30days', 'page_size': 10})
    assert result['totalCount'] >= 0
    for incident in result['incidents']:
        assert incident['id']
        assert isinstance(incident['eventsNum'], int)
    if not result['incidents']:
        pytest.skip('no unhandled incidents in the last 30 days')
    first = result['incidents'][0]
    one = call_op('get_incident_by_id', {'incident_id': first['id']})
    assert one['id'] == first['id']
    events = call_op('get_incident_events', {'incident_id': first['id'], 'page_size': 10})
    assert isinstance(events, list)

    # The enrichment checkboxes, checked live: the same one operation now
    # returns what the round trip above had to chain by hand, and the chain
    # rides on the identity the enrichment depends on -- a console
    # incident-event id IS the event API's eventId.
    enriched = call_op('get_incidents', {'time_filter': 'Last30days', 'page_size': 5,
                                         'include_events': True,
                                         'include_process_detail': True,
                                         'events_page_size': 20})
    assert enriched['incidents'], 'the unfiltered list above had incidents'
    for incident in enriched['incidents']:
        assert 'events' in incident, 'Include Events must attach the incident\'s events'
        assert 'eventsError' not in incident, incident.get('eventsError')
        if incident['events']:
            assert 'latestEvent' in incident
            assert 'latestEventError' not in incident, incident.get('latestEventError')
            assert (incident['latestEvent'] or {}).get('eventId') \
                in [e['id'] for e in incident['events']], \
                'the re-read detail must key one of the very rows the incidents came with'
        else:
            assert incident['latestEvent'] is None
