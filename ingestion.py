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
only ``lastSeen`` moves (verified live under 7.2: one control.exe event kept
absorbing re-detections for weeks on end while its incident grew past ten
events, and a VSSVC.exe event from mid-year was still absorbing them months
later). The shipped
``fortinet-fortiedr`` ingestion playbooks query ``firstSeenFrom`` and leave
``lastSeenFrom`` blank, so a scheduled pull re-running the same detection finds
zero new events -- the reporter sees the ingestion report 'no incidents found'
while the FortiEDR console shows live activity.

This connector defaults the window to ``lastSeen`` (activity) so a pull finds
every event that was created OR re-triggered inside the window. Re-seen
events are deduplicated by the ingest playbook's upsert (``sourceId`` =
``eventId``). ``firstSeen`` remains selectable for deployments that want the
old created-only semantics.

How the window is fetched (live-verified on 7.2.3)
---------------------------------------------------
GET /management-rest/events/list-events answers a date-windowed query that
carries ``pageNumber`` with 200 and an empty page -- at every page size near
the documented default of 100, and inconsistently (short, duplicated or
dropped pages) even at ``itemsPerPage=5`` -- while the SAME window without
``pageNumber`` answers every matching row in one call (79 rows observed in a
single response at ``itemsPerPage=1000``). Meanwhile
GET /management-rest/events/count-events honors the same window filters and
reports the true match count.

So the pull NEVER sends ``pageNumber``. (The stock connector's playbooks
never sent it either -- injecting it server-side into the paged loop was a
regression of this very rewrite, and its live-test windows were asserting
over an empty list, so every check passed vacuously. Only live-verifying the
deployed ingestion chain caught it.) The fetch is built to fail LOUD instead
of silently skipping, because the ingest playbook advances the watermark as
soon as the run succeeds:

  * /events/count-events is asked for the window first, and a count above
    max_events fails the run outright -- a scheduled pull must never trim a
    window and then advance past the events it did not read;
  * the window is fetched ONCE, ``itemsPerPage`` sized to the count (capped
    at the documented maximum of 1000);
  * fetched rows are cross-checked against the count: an empty answer with a
    positive count is re-requested (a 200-with-empty-body flake has been
    observed on this endpoint), and a fetch that stays short of its count
    escalates by splitting the window in halves -- bounded depth -- so a
    withholding server is walked slice by slice;
  * a slice that still disagrees with its count at maximum depth fails the
    run naming both numbers. The watermark advances only over a window the
    pull has actually read.
"""

import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from .client import MGMT_PREFIX, ConnectorError, FortiEDRClient, logger
from .field_mapping import map_events
from .models import Event

LIST_EVENTS = MGMT_PREFIX + '/events/list-events'
COUNT_EVENTS = MGMT_PREFIX + '/events/count-events'

# /events/list-events ceilings (the shipped connector's info documents
# itemsPerPage default 100, maximum 1000).
DEFAULT_PAGE_SIZE = 200
MAX_PAGE_SIZE = 1000

# Safety ceiling on one ingestion run, so a wide backfill window cannot pull
# an unbounded result set into memory and stall the playbook (FortiSIEM v2
# uses the same ceiling rationale). The count check turns a window bigger
# than this cap into an operator-visible error instead of a silent trim.
MAX_EVENTS_PER_RUN = 5000

# A 200-with-empty-body answer from list-events has been observed live on an
# otherwise good query; an empty answer is re-requested when the window's
# count says rows exist. Believed immediately when the count agrees with 0.
EMPTY_PAGE_RETRIES = 2

# Backoff between those re-requests, kept short: a transient clear is a
# one-request blink, and ingestion latency matters on a tight schedule.
EMPTY_PAGE_RETRY_WAIT = 2

# How deep a withholding window is split in halves before the run gives up
# loudly: depth 3 splits the window at most 8 ways (15 slices). A server
# that withholds past that is a support case, not something to paper over.
MAX_SLICE_DEPTH = 3

TIME_FIELD_MAP = {
    'Last Seen (activity)': ('lastSeenFrom', 'lastSeenTo'),
    'First Seen (creations only)': ('firstSeenFrom', 'firstSeenTo'),
}
DEFAULT_TIME_FIELD = 'Last Seen (activity)'

TIME_FORMAT = '%Y-%m-%d %H:%M:%S'


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


def _count_window(client: FortiEDRClient, query: Dict[str, Any]) -> int:
    """How many events /events/count-events reports for this window."""
    response = client.get('Count Events', COUNT_EVENTS, dict(query), 'count_events')
    value = client.json_or_empty(response)
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ConnectorError('Unexpected answer from count-events: {0!r}'
                             .format(value)[:200])


def _fetch_slice(client: FortiEDRClient, query: Dict[str, Any], expect: int) -> List[dict]:
    """One list-events request sized to `expect` -- pageNumber is never sent.

    An empty answer is re-requested while the window's count says rows exist
    (this endpoint has been observed live answering a good query once with
    200 + an empty body); an empty window is believed on the first answer
    unless rows arrive anyway, which the caller keeps.
    """
    size = min(MAX_PAGE_SIZE, max(DEFAULT_PAGE_SIZE, expect))
    attempts = 0
    while True:
        response = client.get('Ingest Events', LIST_EVENTS,
                               dict(query, itemsPerPage=size), 'get_event_list')
        rows = client.json_or_empty(response)
        if not isinstance(rows, list):
            raise ConnectorError('Unexpected response from list-events:'
                                 ' expected a JSON array')
        if rows or expect == 0 or attempts >= EMPTY_PAGE_RETRIES:
            return rows
        attempts += 1
        logger.info('Ingest Events: empty answer for a window whose count is {0},'
                    ' re-requesting ({1}/{2})'.format(expect, attempts, EMPTY_PAGE_RETRIES))
        time.sleep(EMPTY_PAGE_RETRY_WAIT)


def _parse_dt(value):
    """A window bound as a datetime, in the formats the client accepts."""
    if isinstance(value, datetime):
        return value
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%dT%H:%M:%SZ'):
        try:
            return datetime.strptime(str(value), fmt)
        except ValueError:
            continue
    raise ConnectorError('Unreadable window bound {0!r}; expected YYYY-MM-DD HH:MM:SS'
                         .format(value))


def _window_bounds(query: Dict[str, Any]):
    """(start, end) datetimes of a window query, from its From/To keys.

    A blank end is read as 'around now': the split escalation only ever
    halves the START side of an open-ended window, since the right half
    keeps no end bound.
    """
    values = [v for k, v in query.items() if k.endswith('From') or k.endswith('To')]
    start = _parse_dt(values[0])
    if len(values) > 1 and values[1]:
        end = _parse_dt(values[1])
    else:
        end = datetime.utcnow()
    return start, end


def _split_query(query: Dict[str, Any], midpoint: datetime) -> List[Dict[str, Any]]:
    """Two half-window queries: [from, mid] and [mid, to].

    The halves deliberately share the midpoint instant: a row last seen
    exactly at the midpoint may be answered in both, and the merged fetch
    deduplicates on eventId. Independent per-half counts make each half
    verify on its own numbers, not the parent's.
    """
    from_key = next(k for k in query if k.endswith('From'))
    to_key = next(k for k in query if k.endswith('To'))
    text = midpoint.strftime(TIME_FORMAT)
    left = dict(query)
    left[to_key] = text
    right = dict(query)
    right[from_key] = text
    return [left, right]


def _collect_window(client: FortiEDRClient, query: Dict[str, Any],
                    depth: int = 0, expect: Optional[int] = None) -> List[dict]:
    """Fetch a window, escalating by halves while the server withholds rows.

    Each level fetches first and compares against its count (the caller may
    pass its own as ``expect`` so the top window is counted once): a fetch at
    least as long as the count is returned as-is, a shorter one escalates by
    splitting the window, and a fetch still short at maximum depth RAISES
    instead of presenting a partial view -- the ingest playbook advances its
    watermark the moment a run succeeds, so a partial window must never be
    one.
    """
    count = _count_window(client, query) if expect is None else expect
    rows = _fetch_slice(client, query, count)
    if len(rows) >= count:
        if rows and count == 0:
            logger.warning('Ingest Events: list-events answered {0} row(s) for a window'
                           ' count-events reports as empty; keeping them'.format(len(rows)))
        return rows
    if depth >= MAX_SLICE_DEPTH:
        raise ConnectorError(
            'list-events returned {0} of the {1} event(s) count-events reports for this'
            ' window even after splitting it {2} levels deep; refusing to advance the pull'
            ' past unread events - raise Max Events, shorten the pull schedule or open a'
            ' FortiEDR support case for the withheld pages'
            .format(len(rows), count, MAX_SLICE_DEPTH))
    start, end = _window_bounds(query)
    if end <= start:
        raise ConnectorError('cannot split the window [{0} .. {1}] that count-events says'
                             ' holds {2} unread event(s); pass "to" explicitly'
                             .format(start, end, count))
    midpoint = start + (end - start) / 2
    merged: List[dict] = []
    for half in _split_query(query, midpoint):
        merged.extend(_collect_window(client, half, depth + 1))
    return merged


def _dedupe_rows(rows: List[dict]) -> List[dict]:
    """Drop rows the overlap of split windows may have answered twice."""
    seen = set()
    merged = []
    for row in rows:
        key = row.get('eventId')
        if key in seen:
            continue
        if key is not None:
            seen.add(key)
        merged.append(row)
    return merged


def fetch_window_events(client: FortiEDRClient, from_value, to_value: Optional[str] = None,
                        filters: Optional[Dict[str, Any]] = None,
                        cap: int = MAX_EVENTS_PER_RUN,
                        time_field: str = DEFAULT_TIME_FIELD) -> List[Event]:
    """Fetch EVERY event with activity in [from, to], count-verified.

    The count is checked against the cap first (a window too big is an
    error, never a silent trim), the window is read with the count-verified
    fetch, the merged rows are deduplicated (split halves share their
    midpoint on purpose), and a fetch still short of the count is an error:
    the pull never reports a partial window.
    """
    from_key, to_key = TIME_FIELD_MAP[time_field]
    query: Dict[str, Any] = {from_key: from_value, to_key: to_value}
    if filters:
        query.update({k: v for k, v in filters.items() if v not in (None, '')})

    count = _count_window(client, query)
    if count > cap:
        raise ConnectorError(
            'this window holds {0} event(s), more than Max Events ({1}); raise the cap'
            ' or shorten the pull schedule so no run silently skips events the pull'
            ' watermark would then advance past'.format(count, cap))

    collected = _collect_window(client, query, expect=count)
    collected = _dedupe_rows(collected)
    if len(collected) < count:
        raise ConnectorError(
            'list-events returned {0} of the {1} event(s) count-events reports for the'
            ' window [{2} .. {3}]; refusing to advance the pull past unread events'
            .format(len(collected), count, query[from_key], query[to_key] or 'now'))
    return [Event(**row) for row in collected]


def ingest_events(config, params) -> List[Dict[str, Any]]:
    """Op: fetch every event in [from, to] and map them to alert payloads."""
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
        cap=_max_events(params), time_field=time_field)
    logger.info('ingest_events: fetched {0} event(s), window [{1} .. {2}] on {3}'
                .format(len(events), from_value, params.get('to') or 'now', time_field))
    return map_events(events)
