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
from datetime import datetime, timedelta, timezone

import pytest

pytestmark = pytest.mark.live

SEVERITIES = ('Critical', 'High', 'Medium', 'Low', 'Minimal')


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')


def _ago(**kwargs):
    return (datetime.now(timezone.utc) - timedelta(**kwargs)).strftime('%Y-%m-%d %H:%M:%S')


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


def test_a_long_lived_event_keeps_its_first_seen(call_op):
    """The canonical repro: an event that keeps absorbing re-detections has
    firstSeen != lastSeen. Verified against a live tenant; skipped quietly if
    that event is no longer present."""
    rows = call_op('get_event_by_id', {'eventIds': 1493703})
    if not rows:
        pytest.skip('known long-lived event 1493703 is no longer visible')
    row = rows[0]
    assert row['firstSeenEpoch'] < row['lastSeenEpoch'], \
        'expected the pinned-firstSeen shape, got {0} / {1}'.format(row['firstSeen'], row['lastSeen'])


def test_ingest_events_round_trip(call_op):
    alerts = call_op('ingest_events',
                     {'from': _ago(days=45), 'to': _now(), 'max_events': '50'})
    assert isinstance(alerts, list)
    for alert in alerts:
        assert alert['external_id']
        assert alert['severity'] in SEVERITIES, alert['severity']
        assert isinstance(alert['source_payload'], dict)
        assert alert['alert_generation_epoch'] or alert['last_observed_epoch']
        # the description arrives as the house rich-text card, HTML included
        assert '<table' in alert['description']
        assert 'FortiEDR event' in alert['description'] or ' on ' in alert['description']


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
