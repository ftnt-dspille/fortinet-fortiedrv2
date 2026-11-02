"""
Copyright start
Copyright (C) 2008 - 2026 FortinetInc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end

Pydantic models for FortiEDR API responses.

The models record only the fields the connector actually reads; every model
keeps unknown fields (``extra='allow'``) so a playbook still receives
everything the API returned, even where this module has not spelled a field
out -- the shipped FortiEDR API predates any stable schema document, and new
FortiEDR releases add fields per version.

Time normalization
------------------
- ``management-rest`` event times: ``2026-10-15 12:24:55`` (no timezone).
- Console ``/api/incidents`` times: ``15-Oct-2026, 11:46:13``.
Every model that carries one of those shapes also carries the matching
``*Epoch`` field (seconds since epoch, UTC), computed after validation, so
field mapping can feed ``/api/3/upsert/alerts`` date fields without re-parsing.
"""

from datetime import datetime, timezone
from typing import Annotated, Any, Dict, List, Optional

from pydantic import BaseModel, BeforeValidator, ConfigDict, model_validator


def _parse_epoch(value, formats):
    """Best-effort parse to epoch seconds (int, UTC). Returns None on any failure.

    UTC on purpose: the ingestion playbooks format their window timestamps in
    UTC, so a timezone-agnostic parse keeps the derived epochs identical on
    any appliance or CI runner regardless of the local timezone.
    """
    if value is None or value == '':
        return None
    if isinstance(value, (int, float)):
        # Console endpoints accept/echo epoch milliseconds; management-rest
        # event rows have never been observed doing so, but be tolerant.
        v = float(value)
        return int(v / 1000) if v > 10 ** 12 else int(v)
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text.isdigit():
        v = int(text)
        return v // 1000 if v > 10 ** 12 else v
    for fmt in formats:
        try:
            return int(datetime.strptime(text, fmt).replace(tzinfo=timezone.utc).timestamp())
        except ValueError:
            continue
    return None


MGMT_TIME_FORMATS = ('%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%dT%H:%M:%SZ')
CONSOLE_TIME_FORMATS = ('%d-%b-%Y, %H:%M:%S',)


# The API answers JSON null for a list field it has nothing to say about
# (live-observed: a Linux service event on 7.2.3 carries "loggedUsers": null,
# which broke the first live list-events pull that saw one). Every list-typed
# field therefore accepts null and reads it as the empty list.
def _none_to_list(value):
    return [] if value is None else value


TolerantList = Annotated[List[Any], BeforeValidator(_none_to_list)]


class EDRModel(BaseModel):
    """Base: tolerant of extra fields, keeps them in ``model_dump()`` output."""

    model_config = ConfigDict(extra='allow', str_strip_whitespace=False)

    def _fill_epoch(self, seen_field, epoch_field, formats):
        """Compute the epoch twin when it was absent from the response row.

        An ``after`` model validator, not a field validator: pydantic skips
        field validators for fields that take their default, so a field
        validator would never fire for the epoch the API does not send.
        """
        if getattr(self, epoch_field) is None:
            setattr(self, epoch_field, _parse_epoch(getattr(self, seen_field), formats))
        return self


class CollectorRef(EDRModel):
    """One entry of an event's ``collectors`` array (management-rest events)."""

    id: Optional[Any] = None
    device: str = ''
    ip: str = ''
    collectorGroup: Optional[str] = None
    operatingSystem: Optional[str] = None
    lastSeen: Optional[str] = None
    macAddresses: TolerantList = []


class ThreatDetails(EDRModel):
    threatName: Optional[str] = None
    threatFamily: Optional[str] = None
    threatType: Optional[str] = None


# Event.collectors keeps its element typing (field_mapping calls
# .model_dump() on entries); only the null parent is normalized.
TolerantCollectorList = Annotated[List[CollectorRef], BeforeValidator(_none_to_list)]


class Event(EDRModel):
    """A FortiEDR security event (management-rest ``/events/list-events`` row)."""

    eventId: Optional[int] = None
    firstSeen: Optional[str] = None
    lastSeen: Optional[str] = None
    severity: str = ''
    classification: str = ''
    action: Optional[str] = None
    organization: Optional[str] = None
    process: str = ''
    processPath: Optional[str] = None
    processOwner: Optional[str] = None
    processType: Optional[str] = None
    rules: TolerantList = []
    destinations: TolerantList = []
    loggedUsers: TolerantList = []
    collectors: TolerantCollectorList = []
    threatDetails: Optional[ThreatDetails] = None
    archived: Optional[bool] = None
    handled: Optional[bool] = None
    seen: Optional[bool] = None
    muted: Optional[bool] = None
    comment: Optional[str] = None
    firstSeenEpoch: Optional[int] = None
    lastSeenEpoch: Optional[int] = None

    @model_validator(mode='after')
    def _epochs(self):
        self._fill_epoch('firstSeen', 'firstSeenEpoch', MGMT_TIME_FORMATS)
        self._fill_epoch('lastSeen', 'lastSeenEpoch', MGMT_TIME_FORMATS)
        return self


class RawDataItem(EDRModel):
    rawEventId: Optional[int] = None
    device: Optional[str] = None
    collectorGroup: Optional[str] = None
    organizationId: Optional[Any] = None
    eventTime: Optional[str] = None


class Organization(EDRModel):
    id: Optional[Any] = None
    name: Optional[str] = None
    type: Optional[str] = None
    maxAgents: Optional[Any] = None


class Collector(EDRModel):
    name: Optional[str] = None
    ipAddress: Optional[str] = None
    ip: Optional[str] = None
    operatingSystem: Optional[str] = None
    state: Optional[str] = None
    version: Optional[str] = None
    id: Optional[Any] = None


class IPSet(EDRModel):
    name: str = ''
    include: TolerantList = []
    exclude: TolerantList = []


class AgentGroup(EDRModel):
    name: Optional[str] = None
    builtIn: Optional[bool] = None
    defaultGroup: Optional[bool] = None


class ConsoleIncident(EDRModel):
    """A FortiEDR console incident (``GET /api/incidents`` row).

    An incident groups events by process and keeps absorbing re-detections:
    ``firstSeen`` is when the incident was created, ``lastSeen`` when the
    latest event was linked into it. See ingestion.py before filtering on
    either.
    """

    id: Optional[int] = None
    name: Optional[str] = None
    type: Optional[str] = None
    eventsNum: Optional[int] = None
    classification: Optional[str] = None
    classificationValue: Optional[str] = None
    organization: Optional[Any] = None
    devices: TolerantList = []
    tags: TolerantList = []
    action: Optional[Any] = None
    hostState: Optional[Any] = None
    isolated: Optional[bool] = None
    incidentHandlingState: Optional[Any] = None
    firstSeen: Optional[str] = None
    lastSeen: Optional[str] = None
    firstSeenEpoch: Optional[int] = None
    lastSeenEpoch: Optional[int] = None

    @model_validator(mode='after')
    def _epochs(self):
        self._fill_epoch('firstSeen', 'firstSeenEpoch', CONSOLE_TIME_FORMATS)
        self._fill_epoch('lastSeen', 'lastSeenEpoch', CONSOLE_TIME_FORMATS)
        return self


class ConsoleIncidentEvent(EDRModel):
    """One event row under a console incident (``GET /api/incidents/{id}/events``)."""

    id: Optional[int] = None
    device: Optional[str] = None
    deviceId: Optional[Any] = None
    process: Optional[str] = None
    processPath: Optional[str] = None
    classification: Optional[str] = None
    severity: Optional[str] = None
    firstSeen: Optional[str] = None
    lastSeen: Optional[str] = None
    eventCount: Optional[Any] = None
    firstSeenEpoch: Optional[int] = None
    lastSeenEpoch: Optional[int] = None

    @model_validator(mode='after')
    def _epochs(self):
        self._fill_epoch('firstSeen', 'firstSeenEpoch', CONSOLE_TIME_FORMATS)
        self._fill_epoch('lastSeen', 'lastSeenEpoch', CONSOLE_TIME_FORMATS)
        return self


DictOrEvent = Dict[str, Any]
__all__ = [
    'EDRModel', 'Event', 'RawDataItem', 'Organization', 'Collector', 'CollectorRef',
    'IPSet', 'AgentGroup', 'ConsoleIncident', 'ConsoleIncidentEvent', 'ThreatDetails',
    'DictOrEvent',
]
