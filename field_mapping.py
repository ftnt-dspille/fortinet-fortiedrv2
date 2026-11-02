"""
Copyright start
Copyright (C) 2008 - 2026 FortinetInc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end

Event-to-alert field mapping for Scheduled ingestion.

Every value this module emits is a value the ingestion playbook's
``resolveRange`` maps can consume -- an unmapped severity or alert type makes
the alert POST fail with a picklist 400 (the FortiSIEM v2 connector's
ingestion playbook failed exactly that way before these clamps existed).
"""

import json
from typing import Any, Dict, List, Optional

from .models import Event

# FortiEDR event severities observed on /management-rest/events/list-events
# (Critical, High, Medium on 7.x). Unknown values clamp to Medium rather than
# leaking a raw string into the Severity picklist.
SEVERITY_MAP = {
    'Critical': 'Critical',
    'High': 'High',
    'Medium': 'Medium',
    'Low': 'Low',
    'Minimal': 'Minimal',
}
DEFAULT_SEVERITY = 'Medium'

# Members of the FortiSOAR AlertType picklist (payload keys of the ingestion
# playbook's alerts_type_map). Anything outside it clamps to Other / Unknown.
VALID_ALERT_TYPES = (
    'Actionable Threat Feeds', 'Brute Force Attempts', 'Command and Control',
    'Concurrent Login', 'Data Exfiltration', 'Denial of Service', 'Lateral Movement',
    'MITRE ATT&CK', 'Malware', 'Other / Unknown', 'Phishing', 'Policy Violation',
    'Ransomware', 'Reconnaissance',
)

VALID_ALERT_STATES = ('New', 'Open', 'Closed', 'In Progress', 'Resolved')

_RULE_TYPE_HINTS = (
    ('ransom', 'Ransomware'),
    ('exfil', 'Data Exfiltration'),
    ('exfiltration', 'Data Exfiltration'),
    ('c2', 'Command and Control'),
    ('beacon', 'Command and Control'),
    ('malware', 'Malware'),
    ('phishing', 'Phishing'),
    ('brute', 'Brute Force Attempts'),
    ('sweep', 'Reconnaissance'),
    ('scan', 'Reconnaissance'),
)


def resolve_severity(severity: Optional[str]) -> str:
    if not severity:
        return DEFAULT_SEVERITY
    return SEVERITY_MAP.get(str(severity).strip(), DEFAULT_SEVERITY)


def resolve_alert_type(event: Event) -> str:
    """Clamp a FortiEDR event to a FortiSOAR AlertType picklist member."""
    parts: List[str] = [event.classification or '', event.process or '']
    parts.extend(str(r) for r in event.rules)
    if event.threatDetails:
        parts.append(event.threatDetails.threatName or '')
        parts.append(event.threatDetails.threatFamily or '')
    haystack = ' '.join(parts).lower()
    for needle, alert_type in _RULE_TYPE_HINTS:
        if needle in haystack:
            return alert_type
    if (event.threatDetails and (event.threatDetails.threatName or event.threatDetails.threatFamily)):
        return 'Malware'
    return 'Other / Unknown'


def _first_collector(event: Event) -> Dict[str, Any]:
    return event.collectors[0].model_dump() if event.collectors else {}


def _dest_string(event: Event) -> str:
    return ', '.join(str(d) for d in event.destinations if d not in (None, ''))


def _rule_string(event: Event) -> str:
    return ', '.join(str(r) for r in event.rules if r not in (None, ''))


def _description(event: Event) -> str:
    collector = _first_collector(event)
    lines = [
        'Event ID: {0}'.format(event.eventId),
        'Classification: {0}'.format(event.classification or 'Unknown'),
        'Organization: {0}'.format(event.organization or ''),
        'Device: {0}'.format(collector.get('device') or ''),
        'Device IP: {0}'.format(collector.get('ip') or ''),
        'Process: {0}'.format(event.process or ''),
        'Process Path: {0}'.format(event.processPath or ''),
        'Action: {0}'.format(event.action or ''),
        'Rules: {0}'.format(_rule_string(event)),
        'First Seen: {0}'.format(event.firstSeen or ''),
        'Last Seen: {0}'.format(event.lastSeen or ''),
    ]
    return '\n'.join(lines)


def map_event_to_alert(event: Event) -> Dict[str, Any]:
    """Map one FortiEDR event to the alert payload the Ingest playbook writes.

    Keys intentionally mirror the FortiSIEM v2 ingestion contract
    (external_id, severity as picklist members, *_epoch fields, source_payload)
    so the playbook's create_record step is a straight resolveRange pipeline.
    ``sourceId = external_id = eventId``: a re-seen event upserts its
    existing alert instead of duplicating.
    """
    collector = _first_collector(event)
    payload = event.model_dump()
    alert = {
        'name': '{0} - {1}'.format(event.eventId, collector.get('device') or event.process or 'FortiEDR event'),
        'external_id': str(event.eventId) if event.eventId is not None else '',
        'severity': resolve_severity(event.severity),
        'alert_state': 'New',
        'status': 'Open',
        'alert_type': resolve_alert_type(event),
        'source': 'Fortinet FortiEDR',
        'source_ip': collector.get('ip') or '',
        'source_hostname': collector.get('device') or '',
        'dest_ips': _dest_string(event),
        'dest_ip': (_dest_string(event).split(', ')[0] if event.destinations else ''),
        'user_names': ', '.join(str(u) for u in event.loggedUsers if u not in (None, '')),
        'rule': _rule_string(event),
        'process_name': event.process or '',
        'process_path': event.processPath or '',
        'description': _description(event),
        'alert_generation_epoch': event.firstSeenEpoch,
        'last_observed_epoch': event.lastSeenEpoch,
        'event_count': 1,
        'source_payload': payload,
    }
    return alert


def map_events(records: List[Event]) -> List[Dict[str, Any]]:
    return [map_event_to_alert(r) for r in records]


def dumps_no_html(alert: Dict[str, Any]) -> str:
    """source_payload minus the rendered description, JSON-encoded.

    Mirrors the FortiSOAR playbook rule: ``| toJSON`` must be applied to
    already-serialised JSON or the field stores the literal string Array.
    """
    trimmed = dict(alert)
    trimmed.pop('description', None)
    return json.dumps(trimmed)
