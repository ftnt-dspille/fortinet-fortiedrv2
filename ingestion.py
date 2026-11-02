"""
Copyright start
Copyright (C) 2008 - 2026 FortinetInc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end

Scheduled ingestion: pull FortiEDR events by activity window.

Why a time_field choice exists
------------------------------
FortiEDR correlates a re-detection of the same process into the EXISTING
event/incident: the event's ``firstSeen`` stays at the first detection and
only ``lastSeen`` moves (verified live under 7.2: a control.exe event created
2026-10-13 kept absorbing detections until 2026-10-29; a VSSVC.exe event
created 2026-06-08 was still absorbing them in mid-October). The shipped
``fortinet-fortiedr`` ingestion playbooks query ``firstSeenFrom`` and leave
``lastSeenFrom`` blank, so a scheduled pull re-running the same detection finds
zero new events -- the reporter sees the ingestion report 'no incidents found'
while the FortiEDR console shows live activity.

This connector defaults the window to ``lastSeen`` (activity) so a pull finds
every event that was created OR re-triggered inside the window. Re-seen
events are deduplicated by the ingest playbook's upsert (``sourceId`` =
``eventId``). ``firstSeen`` remains selectable for deployments that want the
old created-only semantics.
"""

from typing import Any, Dict, List, Optional

from .client import MGMT_PREFIX, ConnectorError, FortiEDRClient, logger
from .field_mapping import map_events
from .models import Event

LIST_EVENTS = MGMT_PREFIX + '/events/list-events'

# /events/list-events ceilings (the shipped connector's info documents
# itemsPerPage default 100, maximum 1000).
DEFAULT_PAGE_SIZE = 200
MAX_PAGE_SIZE = 1000

# Safety ceiling on one ingestion run, so a wide backfill window cannot pull
# an unbounded result set into memory and stall the playbook (FortiSIEM v2
# uses the same ceiling rationale).
MAX_EVENTS_PER_RUN = 5000

TIME_FIELD_MAP = {
    'Last Seen (activity)': ('lastSeenFrom', 'lastSeenTo'),
    'First Seen (creations only)': ('firstSeenFrom', 'firstSeenTo'),
}
DEFAULT_TIME_FIELD = 'Last Seen (activity)'


def _page_size(params) -> int:
    try:
        size = int(params.get('itemsPerPage') or DEFAULT_PAGE_SIZE)
    except (TypeError, ValueError):
        size = DEFAULT_PAGE_SIZE
    return min(max(size, 1), MAX_PAGE_SIZE)


def _max_events(params) -> int:
    try:
        cap = int(params.get('max_events') or MAX_EVENTS_PER_RUN)
    except (TypeError, ValueError):
        cap = MAX_EVENTS_PER_RUN
    return max(cap, 1)


def _time_field(params) -> str:
    time_field = params.get('time_field') or DEFAULT_TIME_FIELD
    if time_field not in TIME_FIELD_MAP:
        raise ConnectorError('Unknown time_field {0!r}; expected one of {1}'
                             .format(time_field, ', '.join(TIME_FIELD_MAP)))
    return time_field


def fetch_window_events(client: FortiEDRClient, from_value, to_value: Optional[str],
                        filters: Optional[Dict[str, Any]] = None,
                        page_size: int = DEFAULT_PAGE_SIZE, cap: int = MAX_EVENTS_PER_RUN,
                        time_field: str = DEFAULT_TIME_FIELD) -> List[Event]:
    """Page through list-events for [from, to] and return normalized Events."""
    from_key, to_key = TIME_FIELD_MAP[time_field]
    query: Dict[str, Any] = {from_key: from_value, to_key: to_value}
    if filters:
        query.update({k: v for k, v in filters.items() if v not in (None, '')})

    collected: List[Event] = []
    page = 1
    retries = [0]
    while len(collected) < cap:
        response = client.make_rest_api_call(
            'Ingest Events', 'GET', LIST_EVENTS,
            headers=client.build_headers('get_event_list')[0],
            payload=client.build_payload(dict(query, itemsPerPage=page_size, pageNumber=page),
                                         'get_event_list'),
            retries=retries)
        rows = client.json_or_empty(response)
        if not isinstance(rows, list):
            raise ConnectorError('Unexpected response from list-events: expected a JSON array')
        if not rows:
            break
        collected.extend(Event(**row) for row in rows)
        if len(rows) < page_size:
            break
        page += 1
    return collected[:cap]


def ingest_events(config, params) -> List[Dict[str, Any]]:
    """Op: fetch events in [from, to] and map them to alert payloads."""
    from_value = params.get('from')
    if not from_value:
        raise ConnectorError("'from' (window start) is required for ingest_events")
    client = FortiEDRClient(config)
    time_field = _time_field(params)
    events = fetch_window_events(
        client, from_value, params.get('to'),
        filters={'classifications': params.get('classifications'),
                 'severities': params.get('severities'),
                 'organization': params.get('organization'),
                 'archived': params.get('archived')},
        page_size=_page_size(params), cap=_max_events(params), time_field=time_field)
    logger.info('ingest_events: fetched {0} event(s), window [{1} .. {2}] on {3}'
                .format(len(events), from_value, params.get('to') or 'now', time_field))
    return map_events(events)
