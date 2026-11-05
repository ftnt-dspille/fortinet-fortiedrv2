"""
Copyright start
Copyright (C) 2008 - 2026 FortinetInc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end

Operation handlers for the FortiEDR v2 connector.

Operation names match the shipped ``fortinet-fortiedr`` 2.1.0 connector so a
playbook can be repointed one operation at a time, plus the v2 additions:

- ``ingest_events`` -- windowed fetch already mapped to alert payloads, with
  the Last Seen / First Seen window choice (see ingestion.py);
- ``get_incidents`` / ``get_incident_by_id`` / ``get_incident_events`` -- the
  console-tier incident objects (an incident is what the FortiEDR console UI
  groups events by; it absorbs re-detections of the same process).
  ``get_incidents`` carries two OPTIONAL enrichment checkboxes that fan out
  per incident inside the one call: Include Events attaches the incident's
  linked events, Include Process Detail re-reads the newest of them through
  the event API (``latestEvent``, the full process identity). Both fail
  soft per incident and are off by default;
- ``delete_exception`` -- the API's ``exceptions/delete`` endpoint, which the
  shipped connector never exposed; without it an exception created for an
  event was permanent for playbook purposes.

Handlers are behaviour-faithful ports of the shipped 2.1.0 connector except
where a comment says otherwise.
"""

import json
import os
import time

from connectors.core.connector import get_logger

from .client import MGMT_PREFIX, ConnectorError, FortiEDRClient
from .ingestion import ingest_events  # noqa: F401  (re-exported op)
from .models import ConsoleIncident, ConsoleIncidentEvent, Event, RawDataItem

logger = get_logger('fortinet-fortiedrv2')

TMP_LOC = os.path.dirname(os.path.realpath(__file__)) + '/FortiEDR'

TIME_DURATION = {
    'Last Hour': 'lastHour',
    'Last 12 Hours': 'last12hours',
    'Last 24 Hours': 'last24hours',
    'Last 7 Days': 'last7days',
    'Last 30 Days': 'last30days',
    'Custom': 'custom',
}
CATEGORY_MAP = {'Event Log': 'Log'}
SORTING_ORDER = {'Ascending': 1, 'Descending': -1}

E = MGMT_PREFIX + '/events'
X = MGMT_PREFIX + '/exceptions'


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

def _events(config, params, operation, extra=None):
    client = FortiEDRClient(config)
    query = dict(params)
    query.pop('update_fields', None)
    if extra:
        query.update(extra)
    response = client.get(operation.title(), E + '/list-events', query, operation)
    rows = client.json_or_empty(response)
    if not isinstance(rows, list):
        raise ConnectorError('Unexpected response from list-events: expected a JSON array')
    return [Event(**row).model_dump() for row in rows]


def get_event_by_id(config, params):
    return _events(config, params, 'get_event_by_id')


def get_event_list(config, params):
    return _events(config, params, 'get_event_list')


def get_event_list_extended(config, params):
    """Archived + unarchived in one shot.

    The shipped connector queries with archived=True then archived=False and
    concatenates without deduplicating; v2 keys the union on eventId so the
    two partitions cannot double-report a row if the server ever overlaps
    them, and v2 does not mutate the caller's params dict to do it.
    """
    archived = _events(config, params, 'get_event_list_extended', extra={'archived': True})
    fresh = _events(config, params, 'get_event_list_extended', extra={'archived': False})
    seen = set()
    merged = []
    for row in archived + fresh:
        key = row.get('eventId')
        if key in seen:
            continue
        seen.add(key)
        merged.append(row)
    return merged


def count_events(config, params):
    client = FortiEDRClient(config)
    response = client.get('Get Event Count', E + '/count-events', params, 'count_events')
    return {'event_count': response.json()}


# Flags the update-event body carries as real JSON booleans. The form's
# selects deliver the literal strings 'True'/'False'; the API answers 200 to a
# string body but leaves the flag untouched (live-observed on 7.2.3: a read
# toggle returned success while the event's seen flag stayed false), so the
# shipped connector's read/handle/archive toggles were silent no-ops.
BOOLEAN_EVENT_FLAGS = ('mute', 'handle', 'archive', 'read', 'forceUnmute')


def update_event(config, params):
    # Body keys per the shipped 2.1.0 connector: everything else travels as a
    # query-string filter.
    body_keys = ('mute', 'handle', 'archive', 'comment', 'classification', 'read',
                 'muteDuration', 'forceUnmute')
    client = FortiEDRClient(config)
    payload = client.build_payload(params, 'update_event')
    body = {}
    for key in body_keys:
        if key in payload:
            value = payload.pop(key)
            if key in BOOLEAN_EVENT_FLAGS and isinstance(value, str):
                value = value.strip().lower() == 'true'
            body[key] = value
    payload.pop('update_fields', None)
    headers, stream = client.build_headers('update_event')
    response = client.make_rest_api_call('Update Events', 'PUT', E, headers,
                                         payload=payload, stream=stream, data=json.dumps(body))
    if response.text:
        return response.json()
    return {'result': 'Successfully executed update_event'}


def get_raw_data_items(config, params):
    client = FortiEDRClient(config)
    response = client.get('Get Raw Data Items', E + '/list-raw-data-items', params, 'get_raw_data_items')
    rows = client.json_or_empty(response)
    return [RawDataItem(**row).model_dump() for row in rows] if isinstance(rows, list) else rows


def get_raw_json_event_data(config, params):
    client = FortiEDRClient(config)
    response = client.get('Get Raw JSON Event Data', E + '/export-raw-data-items-json',
                          params, 'get_raw_json_event_data')
    return response.json() if response.text else []


def search(config, params):
    client = FortiEDRClient(config)
    response = client.get('Search Filehash', MGMT_PREFIX + '/hash/search', params, 'search')
    data = response.json()
    rows = []
    for key, details in (data or {}).items():
        row = {'filehash': key}
        if isinstance(details, dict):
            row.update(details)
        rows.append(row)
    return rows


def get_event_exceptions(config, params):
    client = FortiEDRClient(config)
    return client.json_get('Get Event Exceptions', X + '/get-event-exceptions', params, 'get_event_exceptions')


def delete_exception(config, params):
    """DELETE /management-rest/exceptions/delete -- in the API since before
    2.1.0 but never shipped in the connector, which left an exception created
    for an event permanent for playbook purposes.

    The narrow path is Exception IDs; Delete All widens the delete to the
    same filters list-exceptions accepts (comment, process, rules, path), so
    it defaults False and IDs are required unless it is explicitly set.
    """
    client = FortiEDRClient(config)
    payload = client.build_payload(params, 'delete_exception')
    delete_all = payload.get('deleteAll')
    payload['deleteAll'] = delete_all in ('True', 'true', True)
    if not payload.get('exceptionIds') and not payload.get('deleteAll'):
        raise ConnectorError('delete_exception needs Exception IDs, or Delete All '
                             'True with explicit filters')
    headers, stream = client.build_headers('delete_exception')
    response = client.make_rest_api_call('Delete Exception', 'DELETE', X + '/delete',
                                         headers, payload=payload, stream=stream)
    return response.json() if response.text else {'result': 'Successfully deleted the exception(s)'}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

def create_exception(config, params):
    client = FortiEDRClient(config)
    payload = client.build_payload(params, 'create_exception')
    # Shipped-connector semantics: these two selects are boolean flags on the
    # wire (an omitted flag is just False after build_payload drops blanks).
    payload['allCollectorGroups'] = payload.get('allCollectorGroups') == 'All Collector Groups'
    payload['allDestinations'] = payload.get('allDestinations') == 'All Destinations'
    exception_json = payload.pop('exceptionJson', {}) or {}
    headers, stream = client.build_headers('create_exception')
    response = client.make_rest_api_call('Create Exception', 'POST', E + '/create-exception',
                                         headers, payload=payload, stream=stream,
                                         data=json.dumps(exception_json))
    return {'result': response.text}


def list_exception(config, params):
    client = FortiEDRClient(config)
    return client.json_get('Get Exception List', X + '/list-exceptions', params, 'list_exception')


def update_exception(config, params):
    client = FortiEDRClient(config)

    # Raw items for the source event -> rawItemIds -> the raw event JSON
    raw_rows = get_raw_data_items(config, {'eventId': params.get('eventId')})
    if not raw_rows:
        raise ConnectorError('Raw data Items is not available for provided Event ID: {0}'
                             .format(params.get('eventId')))

    # v2 fix #1 (the shipped connector posts the FIRST exception object of
    # the FIRST raw item, mutated only when it happens to be the requested
    # one): find the requested ExceptionId and mutate that one.
    #
    # v2 fix #2, live-observed on 7.2.3: an event correlates one raw item
    # per detection batch, and an exception embedded in a raw export lives
    # in the export of the raw item that was its origin. The stock
    # connector (and fix #1) only ever looked at the FIRST raw item, so an
    # update that targeted any other raw item reported
    # "success: Exceptions list not found" while updating nothing. v2
    # exports each raw item until one carries the requested ExceptionId.
    #
    # v2 honesty note, live-observed on 7.2.3: exceptions created through
    # create-exception are stored server-side and NO raw-item export embeds
    # them, so against a 7.x tenant this operation reports a plain failure
    # naming the id that could not be found (the stock connector answered a
    # false "success" here). The raw-export edit path remains for FortiEDR
    # versions that do embed exceptions in raw exports.
    input_exception_id = params.get('exceptionId')
    match = None
    edit_query = None
    for raw in raw_rows:
        if not isinstance(raw, dict):
            continue
        temp_params = {'organization': params.get('organization'),
                       'rawItemIds': raw.get('rawEventId')}
        export = client.get('Get Raw JSON Event Data', E + '/export-raw-data-items-json',
                            temp_params, 'get_raw_json_event_data')
        payload = export.json() if export.text else {}
        existing = payload.get('Exceptions') if isinstance(payload, dict) else None
        if not isinstance(existing, list):
            continue
        for exception in existing:
            if str((exception or {}).get('ExceptionId')) == str(input_exception_id):
                match = dict(exception)
                break
        if match is None:
            continue
        temp_params.pop('rawItemIds', None)
        temp_params['confirmEdit'] = True
        edit_query = client.build_payload(temp_params, 'update_exception')
        break
    if match is None:
        return {'status': 'failure',
                'message': 'Exception ID {0} not found on Event ID {1}'.format(
                    input_exception_id, params.get('eventId'))}

    destination = params.get('destination')
    all_destination = destination == 'All Destinations'
    input_ip_sets = client.convert_str_list(params.get('ip_set_name')) or []
    if not all_destination and input_ip_sets:
        ip_group = match.get('IpGroups') or []
        curr_time = round(time.time() * 1000)
        for ipset in input_ip_sets:
            ip_group.append({'Name': ipset, 'updateTime': curr_time})
        match['IpGroups'] = ip_group
        match['AllDestinations'] = False
    else:
        match['AllDestinations'] = all_destination

    collector_grp = params.get('collector_grp')
    if collector_grp == 'All Groups':
        match['AllAgentGroups'] = True
        match['AllAccountsAgentGroups'] = False
    elif collector_grp == 'All Organizations':
        match['AllAccountsAgentGroups'] = True
        match['AllDestinations'] = True
        match['AllAgentGroups'] = False
    elif collector_grp == 'Exact Collector Group':
        collector_groups = client.convert_str_list(params.get('collector_group')) or []
        agent_groups = match.get('AgentGroups') or []
        for group in collector_groups:
            agent_groups.append({'Name': group})
        match['AgentGroups'] = agent_groups
        match['AllAgentGroups'] = False
        match['AllAccountsAgentGroups'] = False

    comment = params.get('comment')
    if comment:
        existing_comment = match.get('Comment')
        if existing_comment:
            match['Comment'] = existing_comment[:1] + comment + existing_comment[1:]
        else:
            match['Comment'] = comment

    headers, stream = client.build_headers('update_exception')
    response = client.make_rest_api_call('Update Exception', 'POST', X + '/create-or-edit-exception',
                                         headers, payload=edit_query, stream=stream, data=json.dumps(match))
    return response.json() if response.text else {'result': 'Successfully updated the exception'}


# ---------------------------------------------------------------------------
# IP sets
# ---------------------------------------------------------------------------

def _org_value(params):
    """Map the Organization select onto the value create/update-ip-set expect."""
    org_type = params.get('organization')
    if org_type == 'Exact Organization Name':
        params['organization'] = params.get('org_name')
        params.pop('org_name', None)
    elif org_type == 'All Organizations':
        params['organization'] = 'All organizations'
    elif org_type == 'Each':
        params['organization'] = 'each'
    return params


def create_ipset(config, params):
    client = FortiEDRClient(config)
    params = dict(params)
    params['include'] = client.convert_str_list(params.get('include'))
    params['exclude'] = client.convert_str_list(params.get('exclude'))
    params = _org_value(params)
    body = client.build_payload(params, 'create_ipset')
    headers, stream = client.build_headers('create_ipset')
    client.make_rest_api_call('Create IPSet', 'POST', MGMT_PREFIX + '/ip-sets/create-ip-set',
                              headers, payload=None, stream=stream, data=json.dumps(body))
    return {'result': 'Successfully created {0} IP set'.format(params.get('name'))}


def get_ipset_list(config, params):
    client = FortiEDRClient(config)
    return client.json_get('Get IPSet List', MGMT_PREFIX + '/ip-sets/list-ip-sets', params, 'get_ipset_list')


def _merge(existing, additions, add_remove=True):
    if add_remove:
        return list(set(list(existing or []) + list(additions or [])))
    result = list(existing or [])
    for item in additions or []:
        if item in result:
            result.remove(item)
    return result


def update_ipset(config, params):
    client = FortiEDRClient(config)
    params = dict(params)
    include = client.convert_str_list(params.get('include')) or []
    exclude = client.convert_str_list(params.get('exclude')) or []
    if not include and not exclude:
        raise ConnectorError('Both the include and exclude inputs are blank')
    add_items = params.pop('add_items', True)
    if isinstance(add_items, str):
        add_items = add_items.lower() != 'false'

    # Shipped-connector quirk kept: the discovery query lists under
    # 'All organizations' for BOTH the 'All Organizations' and the 'Each'
    # selections, even though the update itself uses 'each'.
    org_type = params.get('organization')
    list_params = {}
    if org_type in ('All Organizations', 'Each'):
        list_params['organization'] = 'All organizations'
    elif org_type == 'Exact Organization Name':
        list_params['organization'] = params.get('org_name')
    params = _org_value(params)

    listed = get_ipset_list(config, list_params)
    found = None
    for item in listed or []:
        if item.get('name') == params.get('name'):
            found = item
            break
    if not found:
        raise ConnectorError('Failed to locate the provided IP SET. IP Set name [{0}] not found'
                             .format(params.get('name')))
    # update-ip-set overwrites the include/exclude lists, so read the current
    # set first and merge (shipped-connector behaviour; empties just become
    # the given list).
    params['include'] = _merge(found.get('include'), include, add_items) if include else found.get('include')
    params['exclude'] = _merge(found.get('exclude'), exclude, add_items) if exclude else found.get('exclude')

    body = client.build_payload(params, 'update_ipset')
    query = {'organization': body.pop('organization', None)}
    headers, stream = client.build_headers('update_ipset')
    client.make_rest_api_call('Update IPSet', 'PUT', MGMT_PREFIX + '/ip-sets/update-ip-set',
                              headers, payload=query, stream=stream, data=json.dumps(body))
    return {'result': 'Successfully Updated {0} IP set'.format(params.get('name'))}


def delete_ipset(config, params):
    client = FortiEDRClient(config)
    headers, stream = client.build_headers('delete_ipset')
    client.make_rest_api_call('Delete IPSet', 'DELETE', MGMT_PREFIX + '/ip-sets/delete-ip-set',
                              headers, payload=client.build_payload(params, 'delete_ipset'), stream=stream)
    return {'result': 'Successfully deleted IP set(s) {0}'.format(params.get('ipSets'))}


# ---------------------------------------------------------------------------
# Inventory (collectors, groups, organizations, system)
# ---------------------------------------------------------------------------

def _generic_get(config, params, title, endpoint, operation):
    client = FortiEDRClient(config)
    return client.json_get(title, endpoint, params, operation)


def get_collector_list(config, params):
    return _generic_get(config, params, 'Get Collector List',
                        MGMT_PREFIX + '/inventory/list-collectors', 'get_collector_list')


def get_agent_group(config, params):
    return _generic_get(config, params, 'Get Agent Groups',
                        MGMT_PREFIX + '/inventory/list-collector-groups', 'get_agent_group')


def get_organizations(config, params):
    return _generic_get(config, params, 'Get Organizations',
                        MGMT_PREFIX + '/organizations/list-organizations', 'get_organizations')


def get_system_summary(config, params):
    return _generic_get(config, params, 'Get System Summary',
                        MGMT_PREFIX + '/admin/list-system-summary', 'get_system_summary')


def isolate_collector(config, params):
    return _isolate(config, params, unisolate=False)


def unisolate_collector(config, params):
    return _isolate(config, params, unisolate=True)


def _isolate(config, params, unisolate=False):
    client = FortiEDRClient(config)
    endpoint = MGMT_PREFIX + ('/inventory/unisolate-collectors' if unisolate else '/inventory/isolate-collectors')
    title = 'Unisolate Collector' if unisolate else 'Isolate Collector'
    operation = 'unisolate_collector' if unisolate else 'isolate_collector'
    query = client.build_payload(params, operation)
    headers, stream = client.build_headers(operation)
    response = client.make_rest_api_call(title, 'PUT', endpoint, headers, payload=query, stream=stream)
    return response.json() if response.text else {'result': 'Successfully executed {0}'.format(operation)}


def move_collectors(config, params):
    client = FortiEDRClient(config)
    params = dict(params)
    if isinstance(params.get('collectors'), str):
        params['collectors'] = client.convert_str_list(params['collectors'])
    headers, stream = client.build_headers('move_collectors')
    query = client.build_payload(params, 'move_collectors')
    response = client.make_rest_api_call('Move Collectors', 'PUT',
                                         MGMT_PREFIX + '/inventory/move-collectors',
                                         headers, payload=query, stream=stream)
    return response.json() if response.text else {'result': 'Successfully moved collectors'}


def _split_entries(value):
    """A filter value as its real, non-blank entries.

    The console binds these filters as comma-separated query parameters, and a
    BLANK list must never be sent: ``''``, ``','``, ``' , '``, ``[]`` and
    ``[None, '']`` all mean "no ids given" and must not count as a filter.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [e.strip() for e in value.split(',') if e.strip()]
    if isinstance(value, (list, tuple, set)):
        return [str(e).strip() for e in value if str(e or '').strip()]
    return [str(value).strip()]


def _collector_lifecycle_filters(payload, keys, what):
    """The device filters an inventory lifecycle call will actually send.

    Every parameter of these endpoints is a QUERY parameter: the console's
    Spring DTO binds ``devicesIds`` / ``devices`` / ``lastSeenEnd`` from the
    URL and silently ignores a JSON request body entirely (a body with an
    unrecognised key answers 200 on delete-collectors and deletes EVERYTHING
    -- live-established). So the filters must survive into the query string,
    cleaned of blank entries, and a call whose lists carry no real entry at
    all must never be sent: with ``deleteAll=true`` and no filter the console
    deletes every collector record in the organization.
    """
    filters = {}
    for k in keys:
        entries = _split_entries(payload.get(k))
        if entries:
            filters[k] = ','.join(entries)
    if not filters:
        raise ConnectorError(
            '{0} refused: no device filter was given. At least one of {1} must '
            'carry a real entry (a blank or empty list does not count), because '
            'the console requires the explicit deleteAll=true confirmation and '
            'with no filter that deletes every collector record in the '
            'organization.'.format(what, ', '.join(keys)))
    return filters


def delete_collectors(config, params):
    """Delete collector records from the console inventory.

    DELETE /inventory/delete-collectors?deleteAll=true with the targets as
    query parameters: ``devicesIds`` (collector IDs), ``devices`` (names) or
    ``lastSeenEnd`` (collectors whose last console connection is before this
    date). The console requires the explicit ``deleteAll=true`` confirmation,
    which this operation always sends -- and which means what it says: with
    no filter it deletes EVERY collector record in the organization, so an
    empty request is refused here before it is ever sent.

    Deleting a RECORD does not touch the agent: a collector that is still
    installed and running re-registers on its next heartbeat. To uninstall
    the agent itself, use ``uninstall_collectors``.
    """
    client = FortiEDRClient(config)
    params = dict(params)
    query = client.build_payload(params, 'delete_collectors')
    filters = _collector_lifecycle_filters(query, ('devicesIds', 'devices', 'lastSeenEnd'),
                                           'Delete Collectors')
    filters['deleteAll'] = 'true'
    headers, _ = client.build_headers('delete_collectors')
    response = client.make_rest_api_call('Delete Collectors', 'DELETE',
                                         MGMT_PREFIX + '/inventory/delete-collectors',
                                         headers, payload=filters)
    return response.json() if response.text else {'result': 'Collector records deleted'}


def uninstall_collectors(config, params):
    """Uninstall the collector agent from devices and remove their records.

    POST /inventory/uninstall-collectors with ``devicesIds`` / ``devices``
    query parameters. Unlike ``delete_collectors`` this reaches the endpoint
    and removes the agent: a collector removed this way does not re-register,
    and brings the agent back only through a fresh install. At least one
    device filter is required; an empty request is refused here.
    """
    client = FortiEDRClient(config)
    params = dict(params)
    query = client.build_payload(params, 'uninstall_collectors')
    filters = _collector_lifecycle_filters(query, ('devicesIds', 'devices'),
                                           'Uninstall Collectors')
    headers, _ = client.build_headers('uninstall_collectors')
    response = client.make_rest_api_call('Uninstall Collectors', 'POST',
                                         MGMT_PREFIX + '/inventory/uninstall-collectors',
                                         headers, payload=filters)
    return response.json() if response.text else {'result': 'Uninstall requested'}


def search_ioc(config, params):
    client = FortiEDRClient(config)
    params = dict(params)
    # v2 fix: the shipped connector turns an already-list 'devices' value into
    # [] -- only a comma-separated string can carry devices through.
    devices = params.get('devices')
    if isinstance(devices, str):
        params['devices'] = client.convert_str_list(devices)
    elif not devices:
        params['devices'] = []
    params['category'] = CATEGORY_MAP.get(params.get('category'), params.get('category'))
    filters = params.get('filters')
    if filters and not isinstance(filters, list):
        params['filters'] = [filters]
    params['time'] = TIME_DURATION.get(params.get('time'))
    if params.get('time') == 'custom':
        params['fromTime'] = _convert_datetime_format(params.get('fromTime'))
        params['toTime'] = _convert_datetime_format(params.get('toTime'))
    if params.get('sorting'):
        field = params.pop('field', '')
        order = SORTING_ORDER.get(params.pop('order', ''))
        priority = params.pop('priority', '')
        params['sorting'] = [{'field': field, 'order': order, 'priority': priority}]
    body = {k: v for k, v in params.items() if v is not None and v != ''}
    headers, stream = client.build_headers('search_ioc')
    response = client.make_rest_api_call('Search IOC', 'POST', MGMT_PREFIX + '/threat-hunting/search',
                                         headers, stream=stream, data=json.dumps(body))
    return response.json() if response.text else []


def _convert_datetime_format(input_str):
    from datetime import datetime as _dt
    return _dt.strptime(input_str, '%Y-%m-%dT%H:%M:%S.%fZ').strftime('%Y-%m-%d %H:%M:%S')


# ---------------------------------------------------------------------------
# Forensics
# ---------------------------------------------------------------------------

def get_file(config, params):
    return _fetch_file(config, params,
                       endpoint=MGMT_PREFIX + '/forensics/get-file',
                       title='Get File', operation='get_file')


def get_event_file(config, params):
    return _fetch_file(config, params,
                       endpoint=MGMT_PREFIX + '/forensics/get-event-file',
                       title='Retrieve File or Memory', operation='get_event_file')


def _fetch_file(config, params, endpoint, title, operation):
    client = FortiEDRClient(config)
    query = client.build_payload(params, operation)
    headers, stream = client.build_headers(operation)
    response = client.make_rest_api_call(title, 'GET', endpoint, headers, payload=query, stream=stream)
    # v2 fix: the shipped connector compares the operation name against the
    # operation TITLE ('Get File'), so a collector file also lands as
    # memdump_None.zip. Name by operation here.
    if operation == 'get_file':
        file_path = query.get('filePaths')
        file_name = 'collector_{0}_file.zip'.format(query.get('device'))
        if isinstance(file_path, list):
            file_path = file_path[0] if file_path else ''
        description = 'FortiEDR: File {0} has been retrieved from the collector {1}'.format(
            file_path, query.get('device'))
    else:
        file_name = 'memdump_{0}.zip'.format(params.get('rawEventId'))
        description = 'FortiEDR: Collected memory dump for raw event {0}'.format(params.get('rawEventId'))
    path = _save_file(file_name, response)
    return _upload_attachment(file_name, path, description)


def remediate_device(config, params):
    client = FortiEDRClient(config)
    headers, stream = client.build_headers('remediate_device')
    query = client.build_payload(params, 'remediate_device')
    response = client.make_rest_api_call('Remediate Device', 'PUT',
                                         MGMT_PREFIX + '/forensics/remediate-device',
                                         headers, payload=query, stream=stream)
    return response.json() if response.text else {'result': 'Successfully remediated'}


# ---------------------------------------------------------------------------
# Administrator / management
# ---------------------------------------------------------------------------

def set_collector_state(config, params):
    client = FortiEDRClient(config)
    body = client.build_payload(params, 'set_collector_state')
    headers, stream = client.build_headers('set_collector_state')
    response = client.make_rest_api_call('Set Collector State', 'PUT', '/api/inventory/collectors/state',
                                         headers, stream=stream, data=json.dumps(body))
    job = response.json() if response.text else {}
    job_id = job.get('id')
    if not job_id:
        return job
    return _wait_for_async_job(client, job_id)


def _wait_for_async_job(client, job_id, poll_seconds=5, max_polls=120):
    # v2 fix: the shipped connector polls the progress-bar endpoint forever;
    # 120 polls of 5s is the 10-minute FortiSOAR playbook step ceiling.
    headers, stream = client.build_headers('get_async_job_progress')
    for _ in range(max_polls):
        time.sleep(poll_seconds)
        response = client.make_rest_api_call('Get Async Job Progress', 'GET',
                                             '/api/admin/progress-bar/{0}'.format(job_id), headers)
        status = response.json() if response.text else {}
        if 'percentage' not in status:
            raise ConnectorError('Failed to get the job progress for job {0}'.format(job_id))
        if status.get('percentage', 0) >= 100:
            return status
    raise ConnectorError('Timed out waiting for job {0} to complete'.format(job_id))


def update_collector_installer(config, params):
    """Re-pin a collector group's target installer version.

    updateVersions is a JSON list of objects ({'osFamily', 'version',
    'allowDowngrade'}); the form resolves a [json] parameter to the parsed
    object, but a playbook step delivering pre-encoded JSON (a string) is
    parsed here instead of being wrapped into a one-string list, which the
    server rejects with a 400 naming CollectorInstallerRequest
    (live-observed on 7.2.3).
    """
    client = FortiEDRClient(config)
    query = {}
    if params.get('collectorGroups'):
        query['collectorGroups'] = params.get('collectorGroups')
    if params.get('organization'):
        query['organization'] = params.get('organization')
    update_versions = params.get('updateVersions')
    if isinstance(update_versions, str):
        try:
            update_versions = json.loads(update_versions)
        except ValueError:
            update_versions = [update_versions]
    if update_versions and not isinstance(update_versions, list):
        update_versions = [update_versions]
    body = {'updateVersions': update_versions}
    headers, stream = client.build_headers('update_collector_installer')
    response = client.make_rest_api_call('Update Collector Installer', 'POST',
                                         MGMT_PREFIX + '/admin/update-collector-installer',
                                         headers, payload=query, stream=stream, data=json.dumps(body))
    if response.ok:
        return {'message': 'Update collector installer process started successfully', 'status': 'success'}
    raise ConnectorError('Update collector installer failed')


def get_collector_installers(config, params):
    return _generic_get(config, params, 'Get Collector Installers',
                        MGMT_PREFIX + '/admin/list-collector-installers', 'get_collector_installers')


def generic_rest_api_call(config, params):
    client = FortiEDRClient(config)
    endpoint = params.get('endpoint') or ''
    if not endpoint.startswith('/'):
        endpoint = '/{0}'.format(endpoint)
    method = params.get('method', 'GET')
    query = params.get('query_params') or {}
    payload = params.get('payload')
    data = json.dumps(payload) if payload is not None else None
    headers, stream = client.build_headers('generic_rest_api_call')
    response = client.make_rest_api_call('Execute an API Request', method, endpoint,
                                         headers, payload=query, stream=stream, data=data)
    return response.json() if response.text else {'result': 'Successfully executed the request'}


# ---------------------------------------------------------------------------
# Console incidents (v2)
# ---------------------------------------------------------------------------

CONSOLE_INCIDENTS = '/api/incidents'


def _console_incident_params(params):
    query = {}
    if params.get('time_filter'):
        query['timeFilter'] = params.get('time_filter')
    if params.get('status_filter'):
        query['statusFilter'] = params.get('status_filter')
    if params.get('type_filter'):
        query['typeFilter'] = params.get('type_filter')
    if params.get('free_text_search'):
        query['freeTextSearch'] = params.get('free_text_search')
    if params.get('organization_id') not in (None, ''):
        query['organizationId'] = params.get('organization_id')
    if params.get('sorting'):
        query['sorting'] = params.get('sorting')
    return query


def _console_items(payload):
    """Rows out of a console list envelope, tolerant of the two shapes the
    console API answers with: ``{result: {items: [...]}}`` and a bare list."""
    items = payload.get('result') if isinstance(payload, dict) else payload
    items = items.get('items') if isinstance(items, dict) else items
    return items if isinstance(items, list) else []


def _truthy(value):
    """Normalize a checkbox param: the UI delivers a real boolean, but a
    playbook step or an API caller can spell the checked state the way the
    manifest's selects do ('True'). Same contract as deleteAll."""
    if isinstance(value, str):
        return value.strip().lower() == 'true'
    return bool(value)


DEFAULT_EVENTS_PER_INCIDENT = 10


def _enrichment_params(params):
    """(events_page_size, organization_id) for the per-incident sub-calls.

    The page cap keeps one ticked checkbox from turning a 50-incident page
    into an unbounded read of every linked event; the organization threading
    keeps multi-org tenants reading the same org they listed incidents from.
    """
    try:
        page_size = int(params.get('events_page_size') or DEFAULT_EVENTS_PER_INCIDENT)
    except (TypeError, ValueError):
        page_size = DEFAULT_EVENTS_PER_INCIDENT
    page_size = max(1, min(500, page_size))
    organization_id = params.get('organization_id')
    return page_size, organization_id


def _incident_events_rows(client, incident_id, events_page_size, organization_id):
    """The events linked into one incident, modeled (console rows with the
    epoch twins). The same endpoint get_incident_events reads, called inside
    get_incidents so both enrichment flags chain off ONE shared sub-call."""
    endpoint = '{0}/{1}/events'.format(CONSOLE_INCIDENTS, incident_id)
    query = {'pageSize': events_page_size, 'offset': 0}
    if organization_id not in (None, ''):
        query['organizationId'] = organization_id
    response = client.get('Get Incident Events', endpoint, query, 'get_incident_events')
    payload = response.json() if response.text else {}
    return [ConsoleIncidentEvent(**row).model_dump() for row in _console_items(payload)]


def _newest_event_row(rows):
    """The row the process detail chains from: the incident's newest event.

    Modeled rows carry the lastSeenEpoch twin, so the max epoch wins; ties
    and epoch-less rows fall back to the console's own order, which answers
    an incident's events ascending (observed), so the later row is the
    newer one of two that claim the same instant.
    """
    if not rows:
        return None

    def rank(index):
        return (rows[index].get('lastSeenEpoch') or 0, index)
    return rows[max(range(len(rows)), key=rank)]


def _event_detail_rows(client, event_id):
    """The full management-rest event row behind one console event id.

    The console's incident-event row says what happened (device, process,
    severity); the event row carries the identity a responder acts on: path,
    type, owner, logged users, destinations, rules, threat details, and the
    collector's ip / OS / group. The two APIs key the same detection by the
    same id (the console event id IS the eventId), so the detail is fetched
    strictly on that id and nothing else.
    """
    response = client.get('Get Event by ID', E + '/list-events',
                          {'eventIds': event_id}, 'get_event_by_id')
    rows = client.json_or_empty(response)
    if not isinstance(rows, list):
        raise ConnectorError('Unexpected response from list-events: expected a JSON array')
    return [Event(**row).model_dump() for row in rows]


def _sub_call_org(organization_id, incident):
    """The organizationId the per-incident sub-calls travel with.

    The console's incident LISTING answers without one (it scopes to the
    authenticated organization), but the per-incident events endpoint does
    not honor that implicit scope: asked without an explicit organizationId
    it answers 200 with an empty page (live on the demo tenant). Every
    incident row carries the console account id the UI itself sends as
    organizationId (``accountId``), so the sub-call is always scoped -- to
    the caller's Organization ID when one was given, else to the row's own
    accountId.
    """
    if organization_id not in (None, ''):
        return organization_id
    return incident.get('accountId')


def _enrich_incident(client, incident, events_page_size, organization_id, want_detail):
    """Attach the requested enrichment to one incident row, fail-soft per leg.

    Both flags share ONE events sub-call: the events list IS the detail's
    chain source. A successfully read incident gains, whether Include Events
    was ticked or not (Include Process Detail needs the same list):

    - ``events``: the incident's linked events, modeled console rows;
    - ``eventsTruncated``: the incident reports more linked events
      (eventsNum) than the Events Per Incident cap returned -- raise the cap
      for the long-running ones;
    - ``latestEvent`` (Include Process Detail): the newest linked event
      re-read through the event API -- the full process identity -- or None
      when the incident carries no events to chain.

    A refused sub-fetch never kills the batch: the failed leg records
    ``eventsError`` / ``latestEventError`` on the row and the list carries
    on, the same degradation the containment playbooks practice (a missing
    enrichment degrades the row, it never kills the list).
    """
    rows = None
    events_error = None
    if incident.get('id') in (None, ''):
        events_error = 'the incident carried no id to read events from'
    else:
        try:
            rows = _incident_events_rows(client, incident['id'], events_page_size,
                                         _sub_call_org(organization_id, incident))
        except Exception as err:
            events_error = str(err)
            logger.error('Get Incidents: could not read the events of incident {0}: {1}'
                         .format(incident.get('id'), err))
    if rows is not None:
        incident['events'] = rows
        total = incident.get('eventsNum')
        incident['eventsTruncated'] = bool(isinstance(total, int) and total > len(rows))
    elif events_error is not None:
        incident['eventsError'] = events_error
    if not want_detail:
        return
    if events_error is not None:
        incident['latestEventError'] = 'the incident\'s events could not be read ({0})'\
            .format(events_error)
        return
    newest = _newest_event_row(rows)
    if newest is None:
        incident['latestEvent'] = None
        return
    try:
        detail = _event_detail_rows(client, newest.get('id'))
        # One id keys at most one event row; take the first rather than assume.
        incident['latestEvent'] = detail[0] if detail else None
    except Exception as err:
        incident['latestEventError'] = str(err)
        logger.error('Get Incidents: could not re-read the process detail of incident {0} '
                     '(event {1}): {2}'.format(incident.get('id'), newest.get('id'), err))


def get_incidents(config, params):
    """List console incidents (each is the FortiEDR UI's grouping of events).

    Two OPTIONAL checkboxes enrich each incident inside this one call, so a
    single step returns the triage context the use-case playbooks otherwise
    chain themselves: Include Events attaches the incident's linked events,
    and Include Process Detail re-reads the newest of them through the event
    API and attaches it as latestEvent (full process identity). Both
    unchecked: one request, the shipped return shape unchanged.
    """
    client = FortiEDRClient(config)
    query = _console_incident_params(params)
    try:
        page_size = int(params.get('page_size') or 50)
    except (TypeError, ValueError):
        page_size = 50
    offset = int(params.get('offset') or 0)
    headers, _ = client.build_headers('get_incidents')
    response = client.make_rest_api_call('Get Incidents', 'GET', CONSOLE_INCIDENTS, headers,
                                         payload=dict(query, pageSize=page_size, offset=offset))
    payload = response.json() if response.text else {}
    incidents = [ConsoleIncident(**row).model_dump() for row in _console_items(payload)]
    if _truthy(params.get('include_events')) or _truthy(params.get('include_process_detail')):
        want_detail = _truthy(params.get('include_process_detail'))
        events_page_size, organization_id = _enrichment_params(params)
        for incident in incidents:
            _enrich_incident(client, incident, events_page_size, organization_id, want_detail)
    return {'totalCount': payload.get('totalCount') if isinstance(payload, dict) else len(incidents),
            'incidents': incidents}


def get_incident_by_id(config, params):
    incident_id = params.get('incident_id')
    if not incident_id:
        raise ConnectorError('incident_id is required')
    client = FortiEDRClient(config)
    endpoint = '{0}/{1}'.format(CONSOLE_INCIDENTS, incident_id)
    query = {}
    if params.get('organization_id') not in (None, ''):
        query['organizationId'] = params.get('organization_id')
    response = client.get('Get Incident by ID', endpoint, query, 'get_incident_by_id')
    payload = response.json() if response.text else {}
    return ConsoleIncident(**payload).model_dump() if isinstance(payload, dict) else payload


def get_incident_events(config, params):
    incident_id = params.get('incident_id')
    if not incident_id:
        raise ConnectorError('incident_id is required')
    client = FortiEDRClient(config)
    endpoint = '{0}/{1}/events'.format(CONSOLE_INCIDENTS, incident_id)
    query = _console_incident_params(params)
    try:
        page_size = int(params.get('page_size') or 100)
    except (TypeError, ValueError):
        page_size = 100
    query['pageSize'] = page_size
    query['offset'] = int(params.get('offset') or 0)
    response = client.get('Get Incident Events', endpoint, query, 'get_incident_events')
    payload = response.json() if response.text else {}
    return _console_items(payload)


# ---------------------------------------------------------------------------
# Attachment helpers (FortiSOAR runtime only)
# ---------------------------------------------------------------------------

def _save_file(filename, response):
    if not os.path.isdir(TMP_LOC):
        os.makedirs(TMP_LOC, exist_ok=True)
    path = '{0}/{1}'.format(TMP_LOC, filename)
    with open(path, 'wb') as handle:
        for chunk in response.iter_content(chunk_size=512):
            handle.write(chunk)
    return path


def _upload_attachment(file_name, file_path, description):
    """Upload to FortiSOAR attachments; fall back to the saved path offline."""
    try:
        with open(file_path, 'rb') as content:
            return upload_file_to_cyops(file_name, content, description)
    except Exception as err:
        logger.error('Attachment upload failed: {0}; file kept at {1}'.format(err, file_path))
        return {'file_name': file_name, 'saved_path': file_path,
                'result': 'Attachment upload unavailable; file saved on the appliance at {0}'.format(file_path)}


def upload_file_to_cyops(file_name, file_content, file_description):
    try:
        from integrations.crudhub import make_request
        # Conditional import based on the FortiSOAR version.
        try:
            from integrations.crudhub import make_file_upload_request
            response = make_file_upload_request(file_name, file_content, 'application/octet-stream')
        except Exception:
            from cshmac.requests import HmacAuth
            from django.conf import settings
            from integrations.crudhub import maybe_json_or_raise
            from requests import post

            url = settings.CRUD_HUB_URL + '/api/3/files'
            auth = HmacAuth(url, 'POST', settings.APPLIANCE_PUBLIC_KEY,
                            settings.APPLIANCE_PRIVATE_KEY,
                            settings.APPLIANCE_PUBLIC_KEY.encode('utf-8'))
            files = {'file': (file_name, file_content, {'Expire': 0})}
            response = maybe_json_or_raise(post(url, auth=auth, files=files, verify=False))
        file_id = response['@id']
        return make_request('/api/3/attachments', 'POST',
                            {'name': file_name, 'file': file_id, 'description': file_description})
    except Exception as err:
        logger.exception('An exception occurred: {0}'.format(str(err)))
        raise ConnectorError('An exception occurred: {0}'.format(str(err)))


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

def check_health_ex(config):
    """Cheap authenticated round-trip: one event (or an empty list)."""
    client = FortiEDRClient(config)
    response = client.get('Health Check', E + '/list-events', {'itemsPerPage': 1}, 'get_event_list')
    if response.ok:
        return True
    raise ConnectorError('FortiEDR health check failed')


OPERATIONS = {
    'get_event_by_id': get_event_by_id,
    'get_event_list': get_event_list,
    'get_event_list_extended': get_event_list_extended,
    'count_events': count_events,
    'update_event': update_event,
    'get_raw_data_items': get_raw_data_items,
    'get_raw_json_event_data': get_raw_json_event_data,
    'search': search,
    'get_event_exceptions': get_event_exceptions,
    'create_exception': create_exception,
    'list_exception': list_exception,
    'update_exception': update_exception,
    'delete_exception': delete_exception,
    'create_ipset': create_ipset,
    'get_ipset_list': get_ipset_list,
    'update_ipset': update_ipset,
    'delete_ipset': delete_ipset,
    'get_collector_list': get_collector_list,
    'get_agent_group': get_agent_group,
    'get_organizations': get_organizations,
    'get_system_summary': get_system_summary,
    'isolate_collector': isolate_collector,
    'unisolate_collector': unisolate_collector,
    'move_collectors': move_collectors,
    'delete_collectors': delete_collectors,
    'uninstall_collectors': uninstall_collectors,
    'search_ioc': search_ioc,
    'get_file': get_file,
    'get_event_file': get_event_file,
    'remediate_device': remediate_device,
    'set_collector_state': set_collector_state,
    'update_collector_installer': update_collector_installer,
    'get_collector_installers': get_collector_installers,
    'generic_rest_api_call': generic_rest_api_call,
    'get_incidents': get_incidents,
    'get_incident_by_id': get_incident_by_id,
    'get_incident_events': get_incident_events,
    'ingest_events': ingest_events,
}
