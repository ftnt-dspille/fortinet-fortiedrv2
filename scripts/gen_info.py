#!/usr/bin/env python3
"""Regenerate info.json for fortinet-fortiedrv2.

Two sources:
- the shipped fortinet-fortiedr 2.1.0 info.json (all 31 parity operations with
  their full parameter schemas), renamed and re-versioned;
- the v2 additions defined below (ingest window, console incidents).

Run from the repo root:
    python3 scripts/gen_info.py [path-to-stock-info.json]

The stock file is the RPM extraction at
fortisoar-rpm-extracted/fortinet-fortiedr/fortinet-fortiedr/info.json.
"""

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_STOCK = (Path.home() / 'PycharmProjects/Miscellaneous/fortisoar/corpus_builder/repos/'
                 'fortisoar-rpm-extracted/fortinet-fortiedr/fortinet-fortiedr/info.json')

NAME = 'fortinet-fortiedrv2'
VERSION = '1.1.7'


def _param(title, name, ptype, required=False, value=None, options=None,
           description=None, placeholder=None, minimum=None, maximum=None,
           onchange=None):
    # The operation dialog renders a fixed set of form widget types: text,
    # select, multiselect, integer, datetime, checkbox (live-verified on
    # 8.0.1). 'boolean' is not one of them -- the stock schema spells every
    # true/false parameter 'checkbox' (Archived, Strict Mode, Full Data
    # Requested), and a 'boolean' row renders as an unknown control.
    field = {
        'title': title,
        'name': name,
        'type': ptype,
        'required': required,
        'editable': True,
        'visible': True,
        'value': value if value is not None else '',
    }
    if options is not None:
        field['options'] = options
    if description:
        field['description'] = description
        field['tooltip'] = description
    if placeholder:
        field['placeholder'] = placeholder
    if minimum is not None:
        field['minimum'] = minimum
    if maximum is not None:
        field['maximum'] = maximum
    if onchange is not None:
        field['onchange'] = onchange
    return field


def _new_operations():
    ops = []

    ops.append({
        'operation': 'ingest_events',
        'title': 'Ingest Events',
        'description': ('Fetches every event whose Last Seen (or First Seen, per '
                        'Time Field) falls in [From, To] and returns them already '
                        'mapped to FortiSOAR alert payloads (external_id = eventId, '
                        'severity clamped to the picklist). Built for the scheduled '
                        'ingestion playbooks. FortiEDR links re-detections of the '
                        'same process into the EXISTING event -- its firstSeen never '
                        'moves -- so the default window is on Last Seen; a firstSeen '
                        'window misses re-triggered events. '
                        'The window is count-verified rather than paged: count-events '
                        'is asked first, the fetch is one list-events request sized '
                        'to that count (pageNumber is never sent; on FortiEDR 7.x it '
                        'answers 200 with an empty page), and a short answer is '
                        're-read, then escalated by splitting the window, failing '
                        'loudly rather than returning part of a window. Optional '
                        'filters (Classifications, Severities, Device Name, '
                        'Collector Groups, Organization) narrow the one query '
                        'count-events and list-events share, so the count-verify '
                        'holds on the filtered window.'),
        'category': 'investigation',
        'annotation': 'ingest_events',
        'handler_method': True,
        'enabled': True,
        'parameters': [
            _param('From', 'from', 'datetime', required=True,
                   description='Window start (the time field is chosen by Time Field).'),
            _param('To', 'to', 'datetime',
                   description='Window end; blank means now.'),
            _param('Time Field', 'time_field', 'select', value='Last Seen (activity)',
                   options=['Last Seen (activity)', 'First Seen (creations only)'],
                   description=('Last Seen (activity): every event created or '
                                're-triggered in the window -- the default. First '
                                'Seen (creations only): only events first detected '
                                'in the window (the shipped connector behavior).')),
            _param('Classifications', 'classifications', 'multiselect',
                   options=['Malicious', 'Suspicious', 'Inconclusive', 'PUP',
                            'Likely Safe', 'Safe'],
                   description=('Optional: pull only these classifications. The '
                                'pull watermark advances past non-matching '
                                'events, so set the filter before the first '
                                'pull and keep it stable.')),
            _param('Severities', 'severities', 'multiselect',
                   options=['Critical', 'High', 'Medium'],
                   description='Optional: pull only these severities. Same watermark note as Classifications.'),
            _param('Device Name', 'device', 'text',
                   description='Optional: pull only events on this device name. Blank means all devices.'),
            _param('Collector Groups', 'collector_groups', 'text',
                   description=('Optional: comma-separated collector group '
                                'names to pull from. Blank means all groups.')),
            _param('Max Events', 'max_events', 'integer', value=5000, minimum=1,
                   description=('Safety cap on one ingestion run (default 5000). A '
                                'window whose count-events exceeds it fails the run '
                                'instead of silently skipping events -- raise the '
                                'cap or shorten the pull schedule.')),
            _param('Organization', 'organization', 'text',
                   description='Optional exact organization name.'),
        ],
        'output_schema': [
            {'name': '', 'external_id': '', 'severity': '', 'alert_type': '',
             'source_ip': '', 'dest_ip': '', 'rule': '', 'process_name': '',
             'alert_generation_epoch': 0, 'last_observed_epoch': 0,
             'description': '', 'source_payload': {}},
        ],
    })

    ops.append({
        'operation': 'get_incidents',
        'title': 'Get Incidents',
        'description': ('Lists FortiEDR console incidents -- the object the '
                        'FortiEDR UI groups events by (typically one per '
                        'process). An incident absorbs re-detections of the same '
                        'process: firstSeen is when it was created, lastSeen '
                        'when the latest event was linked into it. Two optional '
                        'checkboxes enrich every incident inside this one call: '
                        'Include Events attaches the incident\'s linked events '
                        '(events), and Include Process Detail re-reads its '
                        'newest event through the event API as latestEvent, the '
                        'full process identity (path, type, owner, users, '
                        'destinations, rules, threat, collector ip/OS/group). '
                        'Both fail soft per incident: a refused sub-fetch '
                        'records eventsError / latestEventError on that row.'),
        'category': 'investigation',
        'annotation': 'get_incidents',
        'handler_method': True,
        'enabled': True,
        'parameters': [
            _param('Time Filter', 'time_filter', 'text', value='Last30days',
                   placeholder='e.g. Last30days, Last7days, Last24hours',
                   description='Console time filter by incident activity (lastSeen).'),
            _param('Status Filter', 'status_filter', 'text', value='Unhandled',
                   placeholder='e.g. Unhandled, Handled'),
            _param('Type Filter', 'type_filter', 'text', value='SecurityEvents',
                   placeholder='e.g. SecurityEvents'),
            _param('Free Text Search', 'free_text_search', 'text'),
            _param('Organization ID', 'organization_id', 'integer',
                   description='Numeric organization id; leave blank for the '
                               'authenticated user organization.'),
            _param('Page Size', 'page_size', 'integer', value=50, minimum=1,
                   maximum=500),
            _param('Offset', 'offset', 'integer', value=0),
            _param('Sorting', 'sorting', 'text', placeholder='{"lastSeen": true}',
                   description='JSON sorting, e.g. {"lastSeen": true}.'),
            _param('Include Events', 'include_events', 'checkbox', value=False,
                   description=('Check to attach each incident\'s linked events as '
                                '`events` (modeled console rows, epoch twins '
                                'included). An incident reporting more linked '
                                'events than Events Per Incident returned is '
                                'flagged `eventsTruncated`. Unchecked by '
                                'default: the plain incident list is unchanged. '
                                'The per-incident sub-call is auto-scoped: to '
                                'Organization ID when given, else to the '
                                'incident\'s own console account.')),
            _param('Events Per Incident', 'events_page_size', 'integer', value=10,
                   minimum=1, maximum=500,
                   description=('Cap on the events list attached per incident by '
                                'the enrichment checkboxes. Default 10; raise it '
                                'for long-running incidents, or page through Get '
                                'Incident Events for the full history.')),
            _param('Include Process Detail', 'include_process_detail', 'checkbox',
                   value=False,
                   description=('Check to also re-read each incident\'s newest '
                                'linked event through the event API and attach it '
                                'as `latestEvent`: the full process identity '
                                '(path, type, owner, logged users, destinations, '
                                'rules, threat details, collector ip/OS/group). It '
                                'chains off the incident\'s events, so those are '
                                'fetched and attached too. `latestEvent` is null '
                                'when the incident carries no events to chain.')),
        ],
        'output_schema': [
            {'id': 0, 'name': '', 'type': '', 'eventsNum': 0, 'classification': '',
             'firstSeen': '', 'lastSeen': '', 'firstSeenEpoch': 0, 'lastSeenEpoch': 0,
             'isolated': False, 'tags': [], 'events': [], 'eventsTruncated': False,
             'latestEvent': {}},
        ],
    })

    ops.append({
        'operation': 'get_incident_by_id',
        'title': 'Get Incident by ID',
        'description': 'Fetches one FortiEDR console incident.',
        'category': 'investigation',
        'annotation': 'get_incident_by_id',
        'handler_method': True,
        'enabled': True,
        'parameters': [
            _param('Incident ID', 'incident_id', 'integer', required=True),
            _param('Organization ID', 'organization_id', 'integer'),
        ],
        'output_schema': [
            {'id': 0, 'name': '', 'type': '', 'eventsNum': 0, 'firstSeen': '',
             'lastSeen': '', 'firstSeenEpoch': 0, 'lastSeenEpoch': 0},
        ],
    })

    ops.append({
        'operation': 'get_incident_events',
        'title': 'Get Incident Events',
        'description': 'Lists the events linked into one FortiEDR console incident.',
        'category': 'investigation',
        'annotation': 'get_incident_events',
        'handler_method': True,
        'enabled': True,
        'parameters': [
            _param('Incident ID', 'incident_id', 'integer', required=True),
            _param('Organization ID', 'organization_id', 'integer'),
            _param('Time Filter', 'time_filter', 'text', placeholder='e.g. Last30days'),
            _param('Status Filter', 'status_filter', 'text', placeholder='e.g. Unhandled'),
            _param('Type Filter', 'type_filter', 'text', placeholder='e.g. SecurityEvents'),
            _param('Page Size', 'page_size', 'integer', value=100, minimum=1, maximum=500),
            _param('Offset', 'offset', 'integer', value=0),
        ],
        'output_schema': [
            {'id': 0, 'device': '', 'process': '', 'processPath': '',
             'severity': '', 'firstSeen': '', 'lastSeen': '', 'eventCount': 0},
        ],
    })
    ops.append({
        'operation': 'delete_exception',
        'title': 'Delete Exception',
        'description': ('Deletes exception rules the shipped connector could '
                        'never remove (the API has had /exceptions/delete '
                        'all along). Exception IDs is the narrow path and is '
                        'required unless Delete All is True, which widens '
                        'the delete to the given filters.'),
        'category': 'containment',
        'annotation': 'delete_exception',
        'handler_method': True,
        'enabled': True,
        'parameters': [
            _param('Exception IDs', 'exceptionIds', 'text', required=True,
                   description='Comma-separated exception IDs (from Get Event '
                               'Exceptions or Get Exception List).'),
            _param('Delete All', 'deleteAll', 'select', value='False',
                   options=['True', 'False'],
                   description=('True: delete every exception matching the '
                               'filters below (mass delete). False (default): '
                               'only the IDs listed above.')),
            _param('Comment', 'comment', 'text',
                   description='Filter (Delete All only): the rule comment.'),
            _param('Process', 'process', 'text',
                   description='Filter (Delete All only): the process name.'),
            _param('Rules', 'rules', 'text',
                   description='Filter (Delete All only): the rule name.'),
            _param('Path', 'path', 'text',
                   description='Filter (Delete All only): the process path.'),
            _param('Organization', 'organization', 'select',
                   options=['Exact Organization Name', 'All organizations'],
                   description='Which organization the rules belong to.',
                   onchange={'Exact Organization Name': [
                       _param('Organization Name', 'org_name', 'text', required=True,
                              description='The exact organization name (must match the '
                                          'FortiEDR organization name exactly).'),
                   ]}),
        ],
        'output_schema': [
            {'result': ''},
        ],
    })
    return ops


def main():
    stock_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_STOCK
    info = json.loads(stock_path.read_text())

    info['name'] = NAME
    info['label'] = 'Fortinet FortiEDR v2'
    info['version'] = VERSION
    info['description'] = ('FortiEDR protects endpoints pre and post infection, stopping data '
                           'breaches in real-time and automatically orchestrating incident '
                           'investigation and response. This connector covers events, forensics, '
                           'collectors, exceptions, IP sets, console incidents and scheduled '
                           'ingestion keyed on event activity (lastSeen).')
    info['icon_small_name'] = 'small.png'
    info['icon_large_name'] = 'large.png'
    info['ingestion_supported'] = True
    info['ingestion_modes'] = ['scheduled']
    info['ingestion_preferences'] = {'modules': ['alerts']}
    # Keep the stock 31 operations verbatim (titles, parameter schemas, onchange
    # trees) so a playbook repointed from fortinet-fortiedr sees the same form.
    stock_ops = {op['operation'] for op in info['operations']}
    info['operations'] = [op for op in info['operations'] if op['operation'] in stock_ops]
    info['operations'].extend(_new_operations())

    # Events gain epoch fields (models.py emits them; declare them so the
    # playbook UI offers the variables).
    for op in info['operations']:
        if op['operation'] in ('get_event_by_id', 'get_event_list', 'get_event_list_extended'):
            schema = op.get('output_schema')
            if isinstance(schema, list) and schema and isinstance(schema[0], dict):
                schema[0].setdefault('firstSeenEpoch', 0)
                schema[0].setdefault('lastSeenEpoch', 0)

    # The stock schema marks get_collector_installers.organization required,
    # but the server does not: a request with it blank lists installers for
    # the connector's OWN configured organization (live-verified -- the
    # sample fleet playbook relies on exactly that default). The declared
    # requiredness made a blank-organization playbook uncompilable and an
    # on-box failure harder, not easier, to understand.
    for op in info['operations']:
        if op['operation'] == 'get_collector_installers':
            for field in op.get('parameters') or []:
                if field.get('name') == 'organization' and field.get('required'):
                    field['required'] = False
                    field['description'] = ('Optional. Blank lists the installers of the '
                                             'connector configuration\'s own organization; '
                                             'fill only to read another organization. '
                                             'The select value "All organizations" is '
                                             'rejected by the server as a name.')
                    field['tooltip'] = field['description']

    out = REPO / 'info.json'
    out.write_text(json.dumps(info, indent=2, sort_keys=False) + '\n')
    print('wrote {0} ({1} bytes, {2} operations)'.format(out, out.stat().st_size, len(info['operations'])))
    for op in info['operations']:
        print('  -', op['operation'], '|', op['title'])


if __name__ == '__main__':
    main()
