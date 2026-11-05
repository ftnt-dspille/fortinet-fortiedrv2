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

from datetime import UTC, datetime
from typing import Annotated, Any, Dict, List

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
            return int(datetime.strptime(text, fmt).replace(tzinfo=UTC).timestamp())
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

    id: Any | None = None
    device: str = ''
    ip: str = ''
    collectorGroup: str | None = None
    operatingSystem: str | None = None
    lastSeen: str | None = None
    macAddresses: TolerantList = []


class ThreatDetails(EDRModel):
    threatName: str | None = None
    threatFamily: str | None = None
    threatType: str | None = None


# Event.collectors keeps its element typing (field_mapping calls
# .model_dump() on entries); only the null parent is normalized.
TolerantCollectorList = Annotated[List[CollectorRef], BeforeValidator(_none_to_list)]


class Event(EDRModel):
    """A FortiEDR security event (management-rest ``/events/list-events`` row)."""

    eventId: int | None = None
    firstSeen: str | None = None
    lastSeen: str | None = None
    severity: str = ''
    classification: str = ''
    action: str | None = None
    organization: str | None = None
    process: str = ''
    processPath: str | None = None
    processOwner: str | None = None
    processType: str | None = None
    rules: TolerantList = []
    destinations: TolerantList = []
    loggedUsers: TolerantList = []
    collectors: TolerantCollectorList = []
    threatDetails: ThreatDetails | None = None
    archived: bool | None = None
    handled: bool | None = None
    seen: bool | None = None
    muted: bool | None = None
    comment: str | None = None
    firstSeenEpoch: int | None = None
    lastSeenEpoch: int | None = None

    @model_validator(mode='after')
    def _epochs(self):
        self._fill_epoch('firstSeen', 'firstSeenEpoch', MGMT_TIME_FORMATS)
        self._fill_epoch('lastSeen', 'lastSeenEpoch', MGMT_TIME_FORMATS)
        return self


class RawDataItem(EDRModel):
    rawEventId: int | None = None
    device: str | None = None
    collectorGroup: str | None = None
    organizationId: Any | None = None
    eventTime: str | None = None


class Organization(EDRModel):
    id: Any | None = None
    name: str | None = None
    type: str | None = None
    maxAgents: Any | None = None


class Collector(EDRModel):
    name: str | None = None
    ipAddress: str | None = None
    ip: str | None = None
    operatingSystem: str | None = None
    state: str | None = None
    version: str | None = None
    id: Any | None = None


class IPSet(EDRModel):
    name: str = ''
    include: TolerantList = []
    exclude: TolerantList = []


class AgentGroup(EDRModel):
    name: str | None = None
    builtIn: bool | None = None
    defaultGroup: bool | None = None


class ConsoleIncident(EDRModel):
    """A FortiEDR console incident (``GET /api/incidents`` row).

    An incident groups events by process and keeps absorbing re-detections:
    ``firstSeen`` is when the incident was created, ``lastSeen`` when the
    latest event was linked into it. See ingestion.py before filtering on
    either.
    """

    id: int | None = None
    name: str | None = None
    type: str | None = None
    eventsNum: int | None = None
    classification: str | None = None
    classificationValue: str | None = None
    organization: Any | None = None
    devices: TolerantList = []
    tags: TolerantList = []
    action: Any | None = None
    hostState: Any | None = None
    isolated: bool | None = None
    incidentHandlingState: Any | None = None
    firstSeen: str | None = None
    lastSeen: str | None = None
    firstSeenEpoch: int | None = None
    lastSeenEpoch: int | None = None

    @model_validator(mode='after')
    def _epochs(self):
        self._fill_epoch('firstSeen', 'firstSeenEpoch', CONSOLE_TIME_FORMATS)
        self._fill_epoch('lastSeen', 'lastSeenEpoch', CONSOLE_TIME_FORMATS)
        return self


class ConsoleIncidentEvent(EDRModel):
    """One event row under a console incident (``GET /api/incidents/{id}/events``)."""

    id: int | None = None
    device: str | None = None
    deviceId: Any | None = None
    process: str | None = None
    processPath: str | None = None
    classification: str | None = None
    severity: str | None = None
    firstSeen: str | None = None
    lastSeen: str | None = None
    eventCount: Any | None = None
    firstSeenEpoch: int | None = None
    lastSeenEpoch: int | None = None

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
