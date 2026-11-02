"""Offline tests: no FortiEDR appliance needed. The management API is mocked
with `responses`, so these pin the exact REST request each operation makes,
the ingestion window semantics (Last Seen vs First Seen -- the defect this
connector exists to fix), the alert mapping, and the repo/manifest gates the
release CI depends on.
"""
import ast
import base64
import json
import re
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
import responses
from connectors.core.connector import ConnectorError
from fortiedrv2 import ingestion
from fortiedrv2.client import FortiEDRClient
from fortiedrv2.connector import FortiEDR
from fortiedrv2.field_mapping import map_event_to_alert, resolve_alert_type, resolve_severity
from fortiedrv2.models import ConsoleIncident, Event, IPSet
from fortiedrv2.operations import OPERATIONS

REPO = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / 'fixtures'
INFO = json.loads((REPO / 'info.json').read_text())
PLAYBOOKS = json.loads((REPO / 'playbooks' / 'playbooks.json').read_text())

BASE = 'https://edr.example.com'
MGMT = BASE + '/management-rest'
LIST_EVENTS = MGMT + '/events/list-events'

CONFIG = {'server_url': 'edr.example.com', 'username': 'lab', 'password': 'secret',
          'organization': 'Demo Org', 'verify_ssl': False}


def run(operation, params=None, config=None):
    return FortiEDR().execute(dict(config or CONFIG), operation, dict(params or {}))


def fixture(name):
    return json.loads((FIXTURES / (name + '.json')).read_text())


def query(call):
    return parse_qs(urlparse(call.request.url).query)


def body(call):
    return json.loads(call.request.body) if call.request.body else None


_active = {}


def calls(method, fragment):
    return [c for c in _active['mock'].calls
            if c.request.method == method and fragment in c.request.url]


@pytest.fixture
def edr():
    with responses.RequestsMock(assert_all_requests_are_fired=False) as mock:
        _active['mock'] = mock
        yield mock


def list_events_handler(rows_by_page):
    """Answer list-events from the pageNumber in the query string."""
    def handler(request):
        qs = parse_qs(urlparse(request.url).query)
        page = int(qs.get('pageNumber', ['1'])[0])
        return 200, {}, json.dumps(rows_by_page.get(page, []))
    return handler


# --------------------------------------------------------------------------- metadata gates

def test_every_info_operation_is_implemented():
    listed = {op['operation'] for op in INFO['operations']}
    assert listed == set(OPERATIONS)


def test_scheduled_ingestion_is_declared():
    assert INFO['ingestion_supported'] is True
    assert INFO['ingestion_modes'] == ['scheduled']
    assert INFO['ingestion_preferences'] == {'modules': ['alerts']}


def test_version_and_release_notes_agree():
    # No hard version pin: a pin is churn on every release and trains
    # reflexive edits of the expected number. What IS worth asserting is
    # coherence -- the version info.json declares must be the one the
    # release notes describe, in both directions.
    notes = (REPO / 'release_notes.md').read_text()
    version = INFO['version']
    assert re.search(rf'^## {re.escape(version)}\b', notes, re.M), \
        f"info.json declares {version} but release_notes.md has no '## {version}' section"
    newest = re.search(r'^## (\S+)', notes, re.M)
    assert newest and newest.group(1) == version, \
        f"release_notes.md's newest section is {newest.group(1) if newest else 'none'}, info.json is {version}"


def test_select_defaults_are_valid_options():
    """A select's default must be one of its options; otherwise playbooks keep a value the
    code does not recognise."""
    bad = []

    def walk(op, params):
        for p in params:
            if p.get('type') == 'select' and p.get('value') not in (None, '') and p.get('options'):
                if p['value'] not in p['options']:
                    bad.append((op, p['name'], p['value']))
            for sub in (p.get('onchange') or {}).values():
                walk(op, sub)
    for op in INFO['operations']:
        walk(op['operation'], op['parameters'])
    assert bad == []


def test_no_duplicate_parameter_names_per_branch():
    dupes = []

    def walk(op, params):
        names = [p['name'] for p in params]
        dupes.extend((op, n) for n in set(names) if names.count(n) > 1)
        for p in params:
            for sub in (p.get('onchange') or {}).values():
                walk(op, sub)
    for op in INFO['operations']:
        walk(op['operation'], op['parameters'])
    assert dupes == []


def test_v2_operations_are_dispatched_not_generic():
    """The v2 additions have no endpoint metadata: everything about them runs through
    the connector's own handler, so they must be declared as handler ops."""
    for name in ('ingest_events', 'get_incidents', 'get_incident_by_id',
                 'get_incident_events', 'delete_exception'):
        op = next(o for o in INFO['operations'] if o['operation'] == name)
        assert op['handler_method'] is True, name
        assert op['annotation'] == name
        assert not op.get('http_method'), name
        assert not op.get('endpoint'), name


# --------------------------------------------------------------------------- playbook contract

def _workflow(name):
    collection = PLAYBOOKS['data'][0]
    return next(w for w in collection['workflows'] if w['name'] == name)


def _step(workflow, name):
    return next(s for s in _workflow(workflow)['steps'] if s['name'] == name)


def test_the_collection_is_tagged_for_the_data_ingestion_wizard():
    collection = PLAYBOOKS['data'][0]
    assert collection['name'].endswith(INFO['version'])
    assert 'dataingestion' in collection['recordTags']
    assert {'dataingestion', 'fetch', 'create', 'ingest'} <= set(PLAYBOOKS['exported_tags'])


def test_the_ingestion_chain_is_init_fetch_ingest_with_the_wizard_tags():
    for name, tags in [
        ('>> FortiEDR v2 > Init Macros', {'dataingestion'}),
        ('> FortiEDR v2 > Fetch', {'dataingestion', 'fetch'}),
        ('FortiEDR v2 > Ingest', {'dataingestion', 'ingest', 'create'}),
    ]:
        assert tags <= set(_workflow(name)['recordTags']), name


def test_fetch_reads_events_since_the_watermark_on_last_seen():
    fetch = _step('> FortiEDR v2 > Fetch', 'Ingest Events')
    assert fetch['arguments']['operation'] == 'ingest_events'
    params = fetch['arguments']['params']
    assert params['from'] == '{{vars.window_from}}'
    assert params['to'] == '{{vars.curr_timestamp}}'
    assert params['time_field'] == '{{vars.time_field}}'
    assert params['max_events'] == '{{vars.max_events}}'

    # The window's default time field is the activity axis -- FortiEDR pins an
    # event's firstSeen at its first detection and only moves lastSeen, so a
    # firstSeen window misses every re-triggered event.
    assert _step('> FortiEDR v2 > Fetch', 'Configuration')['arguments']['time_field'] \
        == 'Last Seen (activity)'
    schema = json.loads(
        _step('> FortiEDR v2 > Fetch', 'Start')['arguments']['step_variables']['_configuration_schema'])
    assert [f['name'] for f in schema] == ['fetch_last_minutes', 'time_field', 'max_events']
    assert schema[1]['value'] == 'Last Seen (activity)'
    assert 'Last Seen (activity)' in schema[1]['options']
    assert 'First Seen (creations only)' in schema[1]['options']


def test_create_record_upserts_each_event_on_its_eventid():
    create = _step('FortiEDR v2 > Ingest', 'Create Record')
    args = create['arguments']
    assert args['collection'] == '/api/3/upsert/alerts'
    resource = dict(args['resource'])
    resource.pop('__replace')
    resource.pop('__fieldsToUpdate')
    assert set(resource) == {'name', 'source', 'sourceId', 'severity', 'alertType',
                             'alertDetectionDate', 'userName', 'processName', 'description', 'sourcedata'}
    assert resource['sourceId'] == '{{ vars.item.external_id }}'
    assert resource['source'] == 'Fortinet FortiEDR'
    assert resource['sourcedata'] == '{{ vars.item | toJSON }}'
    assert resource['severity'] == '{{ "Severity" | picklist(vars.item.severity | default("Medium")) }}'
    assert resource['alertType'] == '{{ "AlertType" | picklist(vars.item.alert_type | default("Other / Unknown")) }}'
    assert create['arguments']['resource']['__replace'] == 'true'
    assert "'sourcedata'" in create['arguments']['resource']['__fieldsToUpdate']
    assert "'severity'" in create['arguments']['resource']['__fieldsToUpdate']


def test_the_watermark_moves_only_after_the_alerts_are_written():
    routes = {r['name'] for r in _workflow('FortiEDR v2 > Ingest')['routes']}
    assert 'Create Record -> Update Last Pull Time' in routes
    update = _step('FortiEDR v2 > Ingest', 'Update Last Pull Time')
    assert update['arguments']['operation'] == 'updatemacro'
    assert update['arguments']['params']['value'] == '{{vars.steps.Fetch_Events.current_time}}'
    fetch_routes = {r['name'] for r in _workflow('> FortiEDR v2 > Fetch')['routes']}
    assert 'Ingest Events -> Save Result' in fetch_routes


# --------------------------------------------------------------------------- transport / config

def test_org_qualified_username_and_https(edr):
    edr.get(LIST_EVENTS, json=[])
    run('get_event_list', {'pageNumber': 1})
    call = calls('GET', 'list-events')[0]
    creds = 'Demo Org\\lab:secret'.encode('ascii')
    assert call.request.headers['Authorization'] == 'Basic {0}'.format(base64.b64encode(creds).decode())
    assert call.request.url.startswith('https://edr.example.com/')


def test_http_scheme_is_stripped_not_stacked(edr):
    """The shipped connector builds 'https://http://host' for an http:// URL; v2
    must strip the scheme instead."""
    edr.get(LIST_EVENTS, json=[])
    run('get_event_list', {}, dict(CONFIG, server_url='http://edr.example.com', organization=''))
    call = calls('GET', 'list-events')[0]
    assert call.request.url.startswith('https://edr.example.com/')


def test_unknown_operation_is_refused(edr):
    with pytest.raises(ConnectorError, match='Unknown operation'):
        run('no_such_operation', {})


def test_check_health_ok(edr):
    edr.get(LIST_EVENTS, json=[])
    assert FortiEDR().check_health(dict(CONFIG)) is True
    assert calls('GET', 'list-events')[0].request.url.endswith('itemsPerPage=1')


def test_check_health_reports_the_api_message(edr):
    edr.get(LIST_EVENTS, json={'message': 'Bad credentials'}, status=401)
    with pytest.raises(ConnectorError) as err:
        FortiEDR().check_health(dict(CONFIG))
    assert 'Bad credentials' in str(err.value)


# --------------------------------------------------------------------------- build_payload

def _payload(params, operation='get_event_list'):
    return FortiEDRClient(CONFIG).build_payload(params, operation)


def test_datetime_params_normalize_to_native_format():
    payload = _payload({'firstSeenFrom': '2026-10-29T13:30:00Z',
                        'lastSeenFrom': '2026-10-29T13:30:00.000Z',
                        'lastSeenTo': '2026-10-29 14:30:00'})
    assert payload['firstSeenFrom'] == '2026-10-29 13:30:00'
    assert payload['lastSeenFrom'] == '2026-10-29 13:30:00'
    assert payload['lastSeenTo'] == '2026-10-29 14:30:00'


def test_unknown_datetime_is_named_in_the_error():
    with pytest.raises(ConnectorError, match='Unrecognized datetime'):
        _payload({'firstSeenFrom': 'yesterday'})


def test_collector_ids_coercion():
    assert _payload({'collectorIds': 701})['collectorIds'] == [701]
    assert _payload({'collectorIds': '701, 702'})['collectorIds'] == ['701', '702']
    assert _payload({'collectorIds': 'one'})['collectorIds'] == ['one']
    assert _payload({'collectorIds': [1, 2]})['collectorIds'] == [1, 2]


def test_sorting_is_json_encoded():
    payload = _payload({'sorting': [{'field': 'lastSeen', 'order': -1}]}, 'get_raw_data_items')
    assert json.loads(payload['sorting']) == [{'field': 'lastSeen', 'order': -1}]


def test_boolean_strings_and_type_removal():
    payload = _payload({'enabled': 'False', 'type': 'Event'}, 'set_collector_state')
    assert payload['enabled'] is False
    assert 'type' not in payload
    payload = _payload({'enabled': 'True'})
    assert payload['enabled'] is True


def test_file_actions_split_retrieve_from():
    payload = _payload({'retrieve_from': 'Disk', 'device': 'lab-endpoint-01'}, 'get_file')
    assert payload == {'device': 'lab-endpoint-01', 'disk': True, 'memory': False}
    payload = _payload({'retrieve_from': 'Memory'}, 'get_event_file')
    assert payload == {'disk': False, 'memory': True}


def test_remediate_action_maps_to_persistence_data_action():
    payload = _payload({'remediate_action': 'Flag', 'persistenceDataAction': 'Delete Key'},
                      'remediate_device')
    assert payload == {'persistenceDataAction': 'DeleteKey'}


# --------------------------------------------------------------------------- events

def test_get_event_by_id_pins_the_query_and_adds_epoch_fields(edr):
    edr.get(LIST_EVENTS, json=fixture('events_full_page'))
    rows = run('get_event_by_id', {'eventIds': 1492374})
    assert query(calls('GET', 'list-events')[0])['eventIds'] == ['1492374']
    assert [r['eventId'] for r in rows] == [1492374, 1493703]
    # The epoch twins the ingestion/playbook field mapping reads.
    assert rows[0]['firstSeenEpoch'] == 1791893420
    assert rows[0]['lastSeenEpoch'] == 1792067092
    assert rows[1]['lastSeenEpoch'] == 1793280778


def test_get_event_list_keeps_unknown_fields(edr):
    row = fixture('events_full_page')[0]
    row['certified'] = 'Cynthetic'
    edr.get(LIST_EVENTS, json=[row])
    rows = run('get_event_list', {})
    assert rows[0]['certified'] == 'Cynthetic'


def test_count_events(edr):
    edr.get(MGMT + '/events/count-events', body='12', status=200)
    assert run('count_events', {'firstSeenFrom': '2026-10-29 00:00:00'}) == {'event_count': 12}


def test_extended_event_list_reads_archived_then_unarchived(edr):
    def handler(request):
        archived = parse_qs(urlparse(request.url).query).get('archived', [''])[0]
        rows = fixture('events_full_page') if archived == 'false' \
            else fixture('events_full_page') + fixture('events_archived_page')
        return 200, {}, json.dumps(rows)
    edr.add_callback(responses.GET, LIST_EVENTS, callback=handler, content_type='application/json')

    rows = run('get_event_list_extended', {'pageNumber': 1})
    archived_flags = [query(c)['archived'][0].lower() for c in calls('GET', 'list-events')]
    assert archived_flags == ['true', 'false']
    # The archived page repeats full_page's rows: the union must dedupe on eventId.
    assert [r['eventId'] for r in rows] == [1492374, 1493703, 1440000]


def test_update_event_splits_body_and_query(edr):
    edr.put(MGMT + '/events', json={'result': True})
    run('update_event', {'update_fields': 'Handled', 'eventIds': '1493703',
                         'handle': True, 'classification': 'Malicious'})
    call = calls('PUT', '/management-rest/events?')[0]
    assert query(call)['eventIds'] == ['1493703']
    assert 'update_fields' not in query(call)
    assert body(call) == {'handle': True, 'classification': 'Malicious'}


def test_update_event_string_flags_become_real_booleans(edr):
    """The form selects deliver 'True'/'False' strings; the API accepts the
    string body with a 200 but silently ignores it (live-observed on 7.2.3, so
    the stock read/handle/archive toggles were no-ops). v2 posts JSON true /
    false. Non-flag strings (classification, muteDuration, comment) pass
    through untouched."""
    edr.put(MGMT + '/events', json={'result': True})
    run('update_event', {'eventIds': '1493703', 'read': 'True', 'archive': 'False',
                         'forceUnmute': 'true', 'muteDuration': 'Week',
                         'comment': 'mark handled'})
    data = body(calls('PUT', '/management-rest/events?')[0])
    assert data == {'read': True, 'archive': False, 'forceUnmute': True,
                    'muteDuration': 'Week', 'comment': 'mark handled'}


def test_search_rows_carry_filehash(edr):
    edr.get(MGMT + '/hash/search', json={'abc123': {'found': True}})
    assert run('search', {'fileHash': 'abc123'}) == [{'filehash': 'abc123', 'found': True}]


def test_get_raw_data_items(edr):
    edr.get(MGMT + '/events/list-raw-data-items', json=fixture('raw_data_items'))
    rows = run('get_raw_data_items', {'eventId': 1493703})
    assert query(calls('GET', 'raw-data-items')[0])['eventId'] == ['1493703']
    assert rows[0]['rawEventId'] == 771733


# --------------------------------------------------------------------------- exceptions

def test_create_exception_flags(edr):
    edr.post(MGMT + '/events/create-exception', body='created', status=200)
    run('create_exception', {'eventId': 1493703, 'allCollectorGroups': 'All Collector Groups',
                             'exceptionJson': {'process': 'cloud.exe'}})
    call = calls('POST', 'create-exception')[0]
    assert query(call)['allCollectorGroups'] == ['True']
    assert query(call)['allDestinations'] == ['False']
    assert body(call) == {'process': 'cloud.exe'}


def test_update_exception_merges_ip_sets_and_comment(edr):
    edr.get(MGMT + '/events/list-raw-data-items', json=fixture('raw_data_items'))
    edr.get(MGMT + '/events/export-raw-data-items-json', json=fixture('raw_export'))
    edr.post(MGMT + '/exceptions/create-or-edit-exception', json={'result': 'ok'})

    result = run('update_exception', {'eventId': 1493703, 'exceptionId': 9001,
                                      'ip_set_name': 'blocklist', 'comment': 'approved'})

    call = calls('POST', 'create-or-edit-exception')[0]
    assert query(call)['confirmEdit'] == ['True']
    data = body(call)
    assert data['IpGroups'][-1]['Name'] == 'blocklist'
    assert data['AllDestinations'] is False
    assert data['Comment'] == 'approved'
    assert result == {'result': 'ok'}


def test_update_exception_reports_a_missing_raw_item(edr):
    edr.get(MGMT + '/events/list-raw-data-items', json=[])
    with pytest.raises(ConnectorError, match='Raw data Items is not available'):
        run('update_exception', {'eventId': 1, 'exceptionId': 9})


def test_update_exception_refuses_an_unknown_exception_id(edr):
    edr.get(MGMT + '/events/list-raw-data-items', json=fixture('raw_data_items'))
    edr.get(MGMT + '/events/export-raw-data-items-json', json=fixture('raw_export'))
    result = run('update_exception', {'eventId': 1493703, 'exceptionId': 4242,
                                       'ip_set_name': 'blocklist'})
    assert result['status'] == 'failure'
    assert not calls('POST', 'create-or-edit-exception')


def test_update_exception_finds_the_exception_on_a_later_raw_item(edr):
    """Live-observed on 7.2.3 (event 1503820, exception 1507477): an event
    correlates one raw item per detection batch and the exception is embedded
    in the export of ITS origin raw item -- which is not necessarily the
    first. Every raw item is exported until the requested id shows up."""
    items = [fixture('raw_data_items')[0],
             {'rawEventId': 885244, 'device': 'lab-endpoint-01',
              'collectorGroup': 'Workstations', 'organizationId': 1101}]
    edr.get(MGMT + '/events/list-raw-data-items', json=items)

    exports = {'771733': {'Exceptions': [{'ExceptionId': 9001}]},
               '885244': {'Exceptions': [{'ExceptionId': 9002, 'Comment': '',
                                          'IpGroups': [], 'AllDestinations': True,
                                          'AgentGroups': [], 'AllAgentGroups': False,
                                          'AllAccountsAgentGroups': False}]}}
    # a stale exception 9001 IS visible on the first raw item: the requested
    # 9002 must still be found on the second, and 9001 must not be posted.

    def export_handler(request):
        raw_id = parse_qs(urlparse(request.url).query)['rawItemIds'][0]
        return 200, {}, json.dumps(exports.get(raw_id, {}))

    edr.add_callback(responses.GET, MGMT + '/events/export-raw-data-items-json',
                     callback=export_handler, content_type='application/json')
    edr.post(MGMT + '/exceptions/create-or-edit-exception', json={'result': 'ok'})

    result = run('update_exception', {'eventId': 1493703, 'exceptionId': 9002,
                                       'ip_set_name': 'blocklist', 'comment': 'approved'})

    call = calls('POST', 'create-or-edit-exception')[0]
    assert result == {'result': 'ok'}
    assert str(body(call)['ExceptionId']) == '9002'
    assert body(call)['Comment'] == 'approved'
    assert 'rawItemIds' not in query(call)
    assert query(call)['confirmEdit'] == ['True']


def test_update_exception_fails_when_no_raw_item_carries_the_id(edr):
    """The pre-fix op returned 'success: Exceptions list not found' here --
    a live run proved that shape is a silent lie (exception 1507477 existed
    on a later raw item). With no raw item carrying the id at all, the only
    honest answer is failure."""
    items = [fixture('raw_data_items')[0],
             {'rawEventId': 885244, 'device': 'lab-endpoint-01',
              'collectorGroup': 'Workstations', 'organizationId': 1101}]
    edr.get(MGMT + '/events/list-raw-data-items', json=items)
    edr.get(MGMT + '/events/export-raw-data-items-json', json={'EventCoreOnly': {}})

    result = run('update_exception', {'eventId': 1493703, 'exceptionId': 9002,
                                       'ip_set_name': 'blocklist'})
    assert result['status'] == 'failure'
    assert '9002' in result['message']
    assert not calls('POST', 'create-or-edit-exception')


# --------------------------------------------------------------------------- IP sets

def test_create_ipset_posts_the_json_body(edr):
    edr.post(MGMT + '/ip-sets/create-ip-set', body='', status=200)
    run('create_ipset', {'name': 'blocklist', 'include': '198.51.100.7, 203.0.113.5',
                         'organization': 'Each'})
    call = calls('POST', 'create-ip-set')[0]
    assert body(call)['name'] == 'blocklist'
    assert body(call)['include'] == ['198.51.100.7', '203.0.113.5']
    assert body(call)['organization'] == 'each'


def test_update_ipset_merges_and_keeps_the_stock_org_quirk(edr):
    """Organization = 'Each' must UPDATE under 'each' but LIST under
    'All organizations' -- a shipped-connector quirk the API pair behaves with."""
    edr.get(MGMT + '/ip-sets/list-ip-sets', json=fixture('ipsets'))
    edr.put(MGMT + '/ip-sets/update-ip-set', body='', status=200)

    result = run('update_ipset', {'name': 'blocklist', 'include': '203.0.113.9',
                                  'add_items': 'true', 'organization': 'Each'})

    list_call = calls('GET', 'list-ip-sets')[0]
    assert query(list_call)['organization'] == ['All organizations']
    update_call = calls('PUT', 'update-ip-set')[0]
    assert query(update_call)['organization'] == ['each']
    assert set(body(update_call)['include']) == {'198.51.100.7', '203.0.113.9'}
    assert result['result'].startswith('Successfully Updated blocklist IP set')


def test_update_ipset_removes_when_add_items_is_false(edr):
    edr.get(MGMT + '/ip-sets/list-ip-sets', json=fixture('ipsets'))
    edr.put(MGMT + '/ip-sets/update-ip-set', body='', status=200)
    run('update_ipset', {'name': 'blocklist', 'include': '198.51.100.7',
                         'add_items': 'false', 'organization': 'All Organizations'})
    assert body(calls('PUT', 'update-ip-set')[0])['include'] == []
    assert query(calls('PUT', 'update-ip-set')[0])['organization'] == ['All organizations']


def test_update_ipset_needs_an_ip(edr):
    with pytest.raises(ConnectorError, match='include and exclude'):
        run('update_ipset', {'name': 'blocklist'})


def test_delete_ipset(edr):
    edr.delete(MGMT + '/ip-sets/delete-ip-set', body='', status=200)
    result = run('delete_ipset', {'ipSets': ['blocklist']})
    assert query(calls('DELETE', 'delete-ip-set')[0])['ipSets'] == ['blocklist']
    assert 'blocklist' in result['result']


# --------------------------------------------------------------------------- collectors / threat hunting

@pytest.mark.parametrize('operation, word', [('isolate_collector', 'isolate'),
                                              ('unisolate_collector', 'unisolate')])
def test_isolation_endpoints(edr, operation, word):
    edr.put(MGMT + '/inventory/{0}-collectors'.format(word), body='', status=200)
    result = run(operation, {'collectorIds': 701})
    assert word in calls('PUT', word + '-collectors')[0].request.url
    assert query(calls('PUT', word + '-collectors')[0])['collectorIds'] == ['701']
    assert result == {'result': 'Successfully executed {0}'.format(operation)}


def test_move_collectors(edr):
    edr.put(MGMT + '/inventory/move-collectors', body='', status=200)
    run('move_collectors', {'collectors': '701,702', 'collectorGroup': 'Workstations'})
    assert query(calls('PUT', 'move-collectors')[0])['collectors'] == ['701', '702']


def test_search_ioc_converts_its_params(edr):
    edr.post(MGMT + '/threat-hunting/search', json={'result': []})
    run('search_ioc', {'devices': 'dev1,dev2', 'category': 'Event Log', 'time': 'Custom',
                       'fromTime': '2026-10-29T13:00:00.000Z', 'toTime': '2026-10-29T14:00:00.000Z',
                       'sorting': 'yes', 'field': 'Action', 'order': 'Ascending', 'priority': '1'})
    data = body(calls('POST', 'threat-hunting/search')[0])
    assert data['devices'] == ['dev1', 'dev2']
    assert data['category'] == 'Log'
    assert data['time'] == 'custom'
    assert data['fromTime'] == '2026-10-29 13:00:00'
    assert data['sorting'] == [{'field': 'Action', 'order': 1, 'priority': '1'}]


def test_search_ioc_keeps_an_already_list_devices_value(edr):
    edr.post(MGMT + '/threat-hunting/search', json=[])
    run('search_ioc', {'devices': ['dev1', 'dev2']})
    assert body(calls('POST', 'threat-hunting/search')[0])['devices'] == ['dev1', 'dev2']


def test_set_collector_state_waits_for_the_job(edr, monkeypatch):
    monkeypatch.setattr(time, 'sleep', lambda _s: None)
    edr.put(BASE + '/api/inventory/collectors/state', json={'id': 55})
    edr.get(BASE + '/api/admin/progress-bar/55', json={'percentage': 50})
    edr.get(BASE + '/api/admin/progress-bar/55', json={'percentage': 100})

    result = run('set_collector_state', {'collectorIds': [701], 'state': 'Suspended'})

    assert body(calls('PUT', 'collectors/state')[0]) == {'collectorIds': [701], 'state': 'Suspended'}
    assert len(calls('GET', 'progress-bar/55')) == 2
    assert result == {'percentage': 100}


def test_update_collector_installer_posts_version_objects(edr):
    """updateVersions travels as CollectorInstallerRequest OBJECTS -- the
    live 7.2.3 API rejects a bare version string (or a pre-encoded JSON string
    pasted as-is) with a 400 naming CollectorInstallerRequest."""
    edr.post(MGMT + '/admin/update-collector-installer', json={})
    result = run('update_collector_installer',
                 {'collectorGroups': 'Default Collector Group',
                  'organization': 'Palm Labs',
                  'updateVersions': [{'osFamily': 'Linux', 'version': '6.2.0.1350',
                                      'allowDowngrade': False}]})
    call = calls('POST', 'update-collector-installer')[0]
    assert query(call)['collectorGroups'] == ['Default Collector Group']
    assert query(call)['organization'] == ['Palm Labs']
    assert body(call) == {'updateVersions': [{'osFamily': 'Linux', 'version': '6.2.0.1350',
                                               'allowDowngrade': False}]}
    assert result == {'message': 'Update collector installer process started successfully',
                      'status': 'success'}


def test_update_collector_installer_parses_a_pre_encoded_json_string(edr):
    edr.post(MGMT + '/admin/update-collector-installer', json={})
    run('update_collector_installer',
        {'collectorGroups': 'Default Collector Group',
         'updateVersions': '[{"osFamily": "Linux", "version": "6.2.0.1350"}]'})
    assert body(calls('POST', 'update-collector-installer')[0])['updateVersions'] == [
        {'osFamily': 'Linux', 'version': '6.2.0.1350'}]


def test_delete_exception_sends_the_ids(edr):
    edr.delete(MGMT + '/exceptions/delete', json={'result': 'gone'})
    result = run('delete_exception', {'exceptionIds': '1507477',
                                      'organization': 'Exact Organization Name',
                                      'org_name': 'Palm Labs'})
    call = calls('DELETE', 'exceptions/delete')[0]
    assert query(call)['exceptionIds'] == ['1507477']
    assert query(call)['deleteAll'] == ['False']
    assert query(call)['organization'] == ['Palm Labs']
    assert not body(call)
    assert result == {'result': 'gone'}


def test_delete_exception_requires_ids_or_delete_all(edr):
    with pytest.raises(ConnectorError, match='needs Exception IDs'):
        run('delete_exception', {'organization': 'All organizations'})


def test_delete_exception_delete_all_is_opt_in(edr):
    edr.delete(MGMT + '/exceptions/delete', json={})
    run('delete_exception', {'deleteAll': 'True', 'process': 'cloud.exe',
                             'organization': 'All organizations'})
    call = calls('DELETE', 'exceptions/delete')[0]
    assert query(call)['deleteAll'] == ['True']
    assert query(call)['process'] == ['cloud.exe']


# --------------------------------------------------------------------------- console incidents

def test_get_incidents_reads_result_items(edr):
    edr.get(BASE + '/api/incidents', json=fixture('console_incidents'))
    result = run('get_incidents', {'organization_id': 1101})
    qs = query(calls('GET', '/api/incidents?')[0])
    assert qs['organizationId'] == ['1101']
    assert qs['pageSize'] == ['50']
    assert result['totalCount'] == 2
    assert [i['id'] for i in result['incidents']] == [1492384, 1503822]
    # Console time format 'd-b-YYYY, HH:MM:SS' parses into the epoch twins.
    assert result['incidents'][0]['firstSeenEpoch'] == 1791893420
    assert result['incidents'][0]['lastSeenEpoch'] == 1793281859


def test_get_incident_by_id(edr):
    edr.get(BASE + '/api/incidents/1492384', json=fixture('console_incident'))
    result = run('get_incident_by_id', {'incident_id': 1492384, 'organization_id': 1101})
    assert '1492384' in calls('GET', '/api/incidents/1492384')[0].request.url
    assert query(calls('GET', '/api/incidents/1492384')[0])['organizationId'] == ['1101']
    assert result['id'] == 1492384
    assert result['eventsNum'] == 13


def test_get_incident_events(edr):
    edr.get(BASE + '/api/incidents/1492384/events', json=fixture('console_incident_events'))
    rows = run('get_incident_events', {'incident_id': 1492384})
    assert [r['id'] for r in rows] == [1492374, 1493703]


def test_incident_id_is_required(edr):
    with pytest.raises(ConnectorError, match='incident_id is required'):
        run('get_incident_by_id', {})


def test_generic_rest_api_call(edr):
    edr.get(BASE + '/api/anything', json={'ok': True})
    result = run('generic_rest_api_call', {'endpoint': 'api/anything', 'method': 'GET',
                                           'query_params': {'x': '1'}})
    assert result == {'ok': True}
    assert query(calls('GET', '/api/anything')[0])['x'] == ['1']


# --------------------------------------------------------------------------- ingestion (the fix)

def _mock_events(edr, rows_by_page):
    edr.add_callback(responses.GET, LIST_EVENTS, callback=list_events_handler(rows_by_page),
                     content_type='application/json')


def test_ingest_windows_on_last_seen_by_default(edr):
    _mock_events(edr, {1: fixture('events_full_page')})
    alerts = run('ingest_events', {'from': '2026-10-29 13:00:00', 'to': '2026-10-29 14:00:00',
                                   'max_events': '10'})
    qs = query(calls('GET', 'list-events')[0])
    assert qs['lastSeenFrom'] == ['2026-10-29 13:00:00']
    assert qs['lastSeenTo'] == ['2026-10-29 14:00:00']
    assert 'firstSeenFrom' not in qs
    assert 'firstSeenTo' not in qs
    assert len(alerts) == 2


def test_ingest_first_seen_option_is_still_selectable(edr):
    _mock_events(edr, {1: fixture('events_full_page')})
    run('ingest_events', {'from': '2026-10-29 13:00:00', 'to': '2026-10-29 14:00:00',
                          'time_field': 'First Seen (creations only)', 'max_events': '10'})
    qs = query(calls('GET', 'list-events')[0])
    assert qs['firstSeenFrom'] == ['2026-10-29 13:00:00']
    assert qs['firstSeenTo'] == ['2026-10-29 14:00:00']
    assert 'lastSeenFrom' not in qs


def test_ingest_pages_until_a_short_page(edr):
    _mock_events(edr, {1: fixture('events_full_page'), 2: fixture('events_tail_page')})
    alerts = run('ingest_events', {'from': '2026-10-29 13:00:00', 'max_events': '50',
                                    'itemsPerPage': '2'})
    pages = [query(c)['pageNumber'][0] for c in calls('GET', 'list-events')]
    assert pages == ['1', '2']
    assert len(alerts) == 3
    assert all(query(c)['itemsPerPage'] == ['2'] for c in calls('GET', 'list-events'))


def test_ingest_respects_max_events(edr):
    _mock_events(edr, {1: fixture('events_full_page'), 2: fixture('events_full_page')})
    alerts = run('ingest_events', {'from': '2026-10-29 13:00:00', 'max_events': '3',
                                    'itemsPerPage': '2'})
    assert len(alerts) == 3
    assert len(calls('GET', 'list-events')) == 2


def test_ingest_stops_on_an_empty_window(edr, monkeypatch):
    # A genuinely empty window costs the empty-first-page retries: the SAME
    # page-1 request is answered empty 1 + EMPTY_PAGE_RETRIES times before
    # the window is believed empty and the run returns [].
    monkeypatch.setattr(ingestion, 'EMPTY_PAGE_RETRY_WAIT', 0)
    _mock_events(edr, {1: []})
    assert run('ingest_events', {'from': '2026-10-29 13:00:00'}) == []
    page_one = calls('GET', 'list-events')
    assert len(page_one) == 1 + ingestion.EMPTY_PAGE_RETRIES
    assert [query(c)['pageNumber'][0] for c in page_one] == ['1'] * (1 + ingestion.EMPTY_PAGE_RETRIES)


def _mock_events_sequence(edr, answers):
    """Answer list-events from a fixed per-call sequence (not per page)."""
    remaining = list(answers)

    def handler(request):
        rows = remaining.pop(0) if remaining else []
        return 200, {}, json.dumps(rows)

    edr.add_callback(responses.GET, LIST_EVENTS, callback=handler, content_type='application/json')


def test_ingest_recovers_a_transient_empty_first_page(edr, monkeypatch):
    """The live-observed failure mode: the first page answers 200 + [] once,
    while count-events reports rows for the same window; the next identical
    request returns the rows. The fetch re-requests the first page instead of
    advancing the watermark over a window it never received."""
    monkeypatch.setattr(ingestion, 'EMPTY_PAGE_RETRY_WAIT', 0)
    _mock_events_sequence(edr, [[], fixture('events_full_page')])
    alerts = run('ingest_events', {'from': '2026-10-29 13:00:00', 'itemsPerPage': '2',
                                   'max_events': '50'})
    # page 1 empty -> re-request page 1 -> recovered (2 rows = a full page,
    # so the scroll advances: the third call is PAGE 2, answered [] by the
    # exhausted sequence and believed as a short-scroll end).
    pages = [query(c)['pageNumber'][0] for c in calls('GET', 'list-events')]
    assert pages == ['1', '1', '2']
    assert len(alerts) == 2


def test_ingest_believes_an_empty_page_after_the_first(edr):
    """Only the FIRST page is retried: a full page already ends the loop when
    followed by an empty one, so a mid-scroll transient costs at most the
    window's tail, and the pull never dead-loops on later pages."""
    _mock_events(edr, {1: fixture('events_full_page'), 2: []})
    alerts = run('ingest_events', {'from': '2026-10-29 13:00:00', 'itemsPerPage': '2',
                                   'max_events': '50'})
    pages = [query(c)['pageNumber'][0] for c in calls('GET', 'list-events')]
    assert pages == ['1', '2']
    assert len(alerts) == 2


def test_ingest_bad_time_field_is_named(edr):
    with pytest.raises(ConnectorError, match='Unknown time_field'):
        run('ingest_events', {'from': 'x', 'time_field': 'Middle Seen'})


def test_ingest_requires_from(edr):
    with pytest.raises(ConnectorError, match="window start"):
        run('ingest_events', {})


def test_ingest_maps_rows_to_alert_payloads(edr):
    _mock_events(edr, {1: fixture('events_full_page')})
    alerts = run('ingest_events', {'from': '2026-10-29 13:00:00'})
    by_id = {a['external_id']: a for a in alerts}

    upstream = by_id['1493703']
    assert upstream['severity'] == 'Critical'
    assert upstream['alert_type'] == 'Data Exfiltration'
    assert upstream['source'] == 'Fortinet FortiEDR'
    assert upstream['source_ip'] == '203.0.113.5'
    assert upstream['source_hostname'] == 'lab-endpoint-01'
    assert upstream['dest_ip'] == '198.51.100.7'
    assert upstream['user_names'] == 'labuser'
    assert upstream['process_name'] == 'cloud.exe'
    assert upstream['alert_generation_epoch'] == 1792065558
    assert upstream['last_observed_epoch'] == 1793280778
    assert '<table' in upstream['description']
    assert '1493703' in upstream['description']
    assert 'cloud.exe on lab-endpoint-01' in upstream['description']
    assert '2026-10-29 13:32:58' in upstream['description']
    assert upstream['source_payload']['eventId'] == 1493703

    plain = by_id['1492374']
    assert plain['alert_type'] == 'Other / Unknown'


# --------------------------------------------------------------------------- description card

def test_the_description_is_the_house_rich_text_card():
    row = next(r for r in fixture('events_full_page') if r['eventId'] == 1493703)
    card = map_event_to_alert(Event(**row))['description']
    # the card recipe: bold headline, chip row, hairline table (see
    # field_mapping.build_description), all styles inline.
    assert card.startswith('<p style="margin:0 0 8px 0;font-size:16px;font-weight:700"')
    assert 'cloud.exe on lab-endpoint-01</p>' in card
    assert '<span style="display:inline-block' in card          # chip row
    assert '>Critical</span>' in card                            # severity
    assert '>Malicious</span>' in card                           # classification
    assert '>SimulationBlock</span>' in card                     # action
    assert '<table style="width:100%;max-width:760px;' in card
    assert '>Event ID</td>' in card and '>1493703</td>' in card
    assert '>Last seen</td>' in card and '2026-10-29 13:32:58' in card
    # the tooltip line about the preserved raw payload closes the card
    assert card.endswith('</i></p>')
    # ascii-only: FortiSOAR rich text and the repo's latin-1 gate both hold
    card.encode('latin-1')


def test_the_description_escapes_markup_and_braces_in_values():
    """A hostile or merely ugly EVENT VALUE must not break out of the card:
    tags are entity-escaped and `{...}` runs neutralised (FortiSOAR templating
    treats a `{...}` run in a rendered value as a literal to evaluate)."""
    event = Event(eventId=7, process='<script>alert(1)</script>',
                  rules=['{ bogus_collect }'], severity='High',
                  collectors=[{'device': 'lab-endpoint-01', 'ip': '203.0.113.5'}])
    card = map_event_to_alert(event)['description']
    assert '<script' not in card
    assert '&lt;script&gt;' in card
    assert '{ bogus_collect }' not in card
    assert '&#123; bogus_collect &#125;' in card


def test_a_bare_event_still_renders_a_card():
    event = Event(eventId=1)
    card = map_event_to_alert(event)['description']
    assert 'FortiEDR event on unknown device' in card
    assert '<table' in card                       # the Event ID row alone
    assert '>Event ID</td>' in card and '>1</td>' in card
    # empty labels never render rows
    assert '>Logged users</td>' not in card


def test_null_list_fields_read_as_empty_lists():
    """Live-observed on 7.2.3: a Linux service event carries
    "loggedUsers": null (oldest rows can null rules/destinations too), and
    the first live pull that met one raised a pydantic list_type error. Every
    list-typed field accepts null as []."""
    event = Event(eventId=9, loggedUsers=None, rules=None, destinations=None,
                  collectors=None, severity='Medium')
    assert event.loggedUsers == [] and event.rules == [] and event.destinations == []
    assert event.collectors == []
    alert = map_event_to_alert(event)
    assert alert['user_names'] == '' and alert['rule'] == '' and alert['dest_ips'] == ''
    assert alert['source_hostname'] == ''          # no collectors, no crash

    incident = ConsoleIncident(devices=None, tags=None)
    assert incident.devices == [] and incident.tags == []
    ipset = IPSet(name='x', include=None, exclude=None)
    assert ipset.include == [] and ipset.exclude == []

    # a null macAddresses on a collector entry reads the same way
    col = Event(eventId=9, collectors=[{'device': 'localhost', 'macAddresses': None}])
    assert col.collectors[0].macAddresses == []


# --------------------------------------------------------------------------- models / mapping

def test_events_parse_the_native_datetimes():
    row = fixture('events_full_page')[0]
    event = Event(**row)
    assert event.eventId == 1492374
    assert event.collectors[0].device == 'lab-endpoint-01'
    assert event.firstSeenEpoch == 1791893420
    assert event.lastSeenEpoch == 1792067092


def test_console_incidents_parse_console_datetimes():
    incident = ConsoleIncident(**fixture('console_incident'))
    assert incident.firstSeenEpoch == 1791893420
    assert incident.lastSeenEpoch == 1793281859


def test_epoch_millisecond_strings_scale_down():
    assert Event(firstSeen='1793281859000').firstSeenEpoch == 1793281859
    assert ConsoleIncident(lastSeen='1793281859000').lastSeenEpoch == 1793281859


def test_unparseable_times_are_none_not_crashes():
    assert Event(firstSeen='whenever').firstSeenEpoch is None
    assert ConsoleIncident(firstSeen='').firstSeenEpoch is None


def test_severity_clamps_to_the_picklist():
    assert resolve_severity('High') == 'High'
    assert resolve_severity('Catastrophic') == 'Medium'
    assert resolve_severity(None) == 'Medium'


def test_alert_type_clamps_to_the_picklist():
    event = Event(eventId=1, rules=['Ransomware behavior'])
    assert resolve_alert_type(event) == 'Ransomware'
    event = Event(eventId=1, classification='Malicious')
    assert resolve_alert_type(event) == 'Other / Unknown'
    event = Event(eventId=1, rules=['Ransomware Behavior C2 beacon'])
    assert resolve_alert_type(event) == 'Ransomware'


def test_mapped_alert_shape_matches_the_create_record_contract():
    alert = map_event_to_alert(Event(**fixture('events_full_page')[0]))
    expected = {'name', 'external_id', 'severity', 'alert_state', 'status', 'alert_type',
                'source', 'source_ip', 'source_hostname', 'dest_ips', 'dest_ip', 'user_names',
                'rule', 'process_name', 'process_path', 'description', 'alert_generation_epoch',
                'last_observed_epoch', 'event_count', 'source_payload'}
    assert set(alert) == expected
    assert alert['external_id'] == '1492374'
    assert alert['name'] == '1492374 - lab-endpoint-01'


# --------------------------------------------------------------------------- library boundary (AST)

def test_operations_only_call_client_methods_that_exist():
    tree = ast.parse((REPO / 'operations.py').read_text())
    receivers = {'client'}
    called = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            recv = node.func.value
            if isinstance(recv, ast.Name) and recv.id in receivers:
                called.add(node.func.attr)
    assert called, 'no client calls found -- the parser contract broke'
    missing = sorted(m for m in called if not hasattr(FortiEDRClient, m))
    assert not missing, f"operations.py calls methods the client does not have: {missing}"


def test_only_client_imports_requests():
    """The HTTP library may be touched in exactly one place, so offline tests
    that mock it mock everything. The reference is module level imports --
    operations.py deliberately keeps the appliance-only `from requests import
    post` inside a function body, exactly where the runtime needs it."""
    offenders = set()
    for path in sorted(REPO.glob('*.py')):
        tree = ast.parse(path.read_text())
        for node in tree.body:
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or '']
            if any(n == 'requests' or n.startswith('requests.') for n in names):
                offenders.add(path.name)
    assert offenders == {'client.py'}, sorted(offenders)


def test_files_are_latin1_safe():
    """FortiSOAR loads connector sources as latin-1: an en/em dash or any other
    non-latin-1 code point breaks the install on the appliance."""
    bad = []
    for path in sorted(REPO.rglob('*')):
        rel = path.relative_to(REPO)
        if any(part in ('.venv', '.git', '__pycache__', '.pytest_cache', '.ruff_cache', 'dist',
                        'FortiEDR') for part in rel.parts):
            continue
        if path.suffix not in ('.py', '.json', '.md', '.yaml', '.yml', '.txt', '.ini', '.sh', '.cfg'):
            continue
        try:
            path.read_text(encoding='utf-8').encode('latin-1')
        except (UnicodeEncodeError, UnicodeDecodeError):
            bad.append(str(rel))
    assert bad == [], f"files with non-latin-1 code points: {bad}"
