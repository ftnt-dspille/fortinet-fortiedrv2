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

import re
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

# The console's "no signature resolved" names, seen live on 8.0.1 events
# (threat name or family): non-empty strings that carry no threat signal,
# which the clamp used to read as signatures -- typing unsigned events
# Malware. They mean no threat at all.
_PLACEHOLDER_THREATS = ('unknown', 'n/a', 'na', 'none', 'clear')

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
    # A resolved signature means malware -- but the console reports "no
    # signature" with placeholder names (Unknown, N/A, None, Clear), which
    # read as no threat: an unsigned event falls through to Other / Unknown,
    # or to whatever a matched rule hinted above.
    if event.threatDetails:
        name = (event.threatDetails.threatName or '').strip().lower()
        family = (event.threatDetails.threatFamily or '').strip().lower()
        if ((name and name not in _PLACEHOLDER_THREATS)
                or (family and family not in _PLACEHOLDER_THREATS)):
            return 'Malware'
    return 'Other / Unknown'


def _first_collector(event: Event) -> Dict[str, Any]:
    return event.collectors[0].model_dump() if event.collectors else {}


def _dest_string(event: Event) -> str:
    return ', '.join(str(d) for d in event.destinations if d not in (None, ''))


_IPV4_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')


def _first_ip_destination(event: Event) -> str:
    """The first IP-shaped destination, or '' when destinations carries none.

    ``destinations`` mixes IP addresses with behavior labels ("Service Access",
    "Modify OS Settings"), so the destinationIp column takes the first value
    that parses as an IPv4 address -- never a label.
    """
    for d in event.destinations:
        text = str(d or '').strip()
        if _IPV4_RE.match(text):
            return text
    return ''


def _rule_string(event: Event) -> str:
    return ', '.join(str(r) for r in event.rules if r not in (None, ''))


# ---------------------------------------------------------------------------
# Rich-text description
#
# The alert description is sanitised rich text, so every style is inline and
# no <style> blocks or classes exist. The recipe is the house one (the
# FortiSIEM v2 connector's alert card): translucent tints over `inherit` let
# the card read on both the dark and light FortiSOAR themes, and values are
# escaped including braces -- FortiSOAR templating treats a `{...}` run in a
# rendered value as a literal to evaluate, and `&#123;` survives that pass.
# ---------------------------------------------------------------------------
_MUTED = 'opacity:.62'
_HAIRLINE = '1px solid rgba(128,128,128,.22)'
_MONO = 'font-family:SFMono-Regular,Menlo,Consolas,monospace;font-size:12px'

_SEVERITY_COLOR = {
    'critical': '#e5484d', 'high': '#f76b15', 'medium': '#e2a400',
    'low': '#30a46c', 'minimal': '#8b8d98',
}
_CLASSIFICATION_COLOR = {
    'malicious': '#e5484d', 'suspicious': '#f76b15', 'inconclusive': '#8b8d98',
    'pup': '#e2a400', 'likely safe': '#3e63dd', 'safe': '#30a46c',
}
_ACTION_COLOR = {'block': '#e5484d', 'simulationblock': '#f76b15', 'log': '#8b8d98'}


def _esc(value) -> str:
    if value is None:
        return ''
    text = (str(value).replace('&', '&amp;').replace('<', '&lt;')
            .replace('>', '&gt;').replace('"', '&quot;'))
    return text.replace('{', '&#123;').replace('}', '&#125;')


def _chip(text, color, mono=False):
    """A small rounded tag tinted with `color`."""
    style = ('display:inline-block;margin:0 6px 4px 0;padding:2px 10px;'
             'border-radius:999px;font-size:11px;font-weight:600;letter-spacing:.4px;'
             'border:1px solid {c};background:{c}26;color:{c};{m}'
             ).format(c=color, m=_MONO if mono else '')
    return '<span style="{0}">{1}</span>'.format(style, _esc(text))


def _heading(text):
    """Small section heading with an accent bar."""
    return ('<p style="margin:14px 0 6px 0;padding-left:8px;border-left:3px solid #3e63dd;'
            'font-size:11px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;'
            'opacity:.8">{0}</p>'.format(_esc(text)))


def _table(rows):
    return ('<table style="width:100%;max-width:760px;border-collapse:collapse;border:0;'
            'margin:0">{0}</table>'.format(''.join(rows)))


def _rows(pairs, mono=()):
    """Render label/value pairs as table rows, dropping the empty ones.

    Labels in `mono` get a monospace value (paths, IPs, rule names).
    """
    out = []
    for label, value in pairs:
        if value in (None, '', [], {}):
            continue
        value_style = ('padding:6px 0;border:0;border-bottom:{0};vertical-align:top;'
                       'word-break:break-word'.format(_HAIRLINE))
        if label in mono:
            value_style += ';' + _MONO
        out.append(
            '<tr>'
            '<td style="width:150px;padding:6px 16px 6px 0;border:0;border-bottom:{0};'
            'vertical-align:top;white-space:nowrap;font-size:11px;font-weight:600;'
            'letter-spacing:.5px;text-transform:uppercase;{1}">{2}</td>'
            '<td style="{3}">{4}</td>'
            '</tr>'.format(_HAIRLINE, _MUTED, _esc(label), value_style, _esc(value)))
    return out


def build_description(event: Event, alert: Dict[str, Any]) -> str:
    """Build the rich-text alert description from one FortiEDR event.

    ``event`` is the modelled event; ``alert`` is the already-normalised alert
    dict, so the clamped severity and the joined strings are reused instead of
    re-derived. The layout shows what an analyst triages first: what ran, on
    which device, how FortiEDR classified and acted on it, then the process,
    rule and time detail.
    """
    collector = _first_collector(event)
    device = collector.get('device') or alert.get('source_hostname') or ''
    headline = '{0} on {1}'.format(event.process or 'FortiEDR event', device or 'unknown device')

    parts = ['<p style="margin:0 0 8px 0;font-size:16px;font-weight:700">{0}</p>'
             .format(_esc(headline))]

    chips = []
    severity = alert.get('severity')
    if severity:
        chips.append(_chip(severity, _SEVERITY_COLOR.get(str(severity).lower(), '#8b8d98')))
    if event.classification:
        chips.append(_chip(event.classification,
                           _CLASSIFICATION_COLOR.get(str(event.classification).lower(), '#8b8d98')))
    if event.action:
        chips.append(_chip(event.action, _ACTION_COLOR.get(str(event.action).lower(), '#8b8d98')))
    if event.handled:
        chips.append(_chip('Handled', '#30a46c'))
    if event.muted:
        chips.append(_chip('Muted', '#e5484d'))
    if chips:
        parts.append('<p style="margin:0 0 10px 0">{0}</p>'.format(''.join(chips)))

    overview = _rows([
        ('Event ID', alert.get('external_id')),
        ('Organization', event.organization),
        ('Device', alert.get('source_hostname')),
        ('Device IP', alert.get('source_ip')),
        ('Logged users', alert.get('user_names')),
        ('Process owner', alert.get('process_owner')),
        ('Process type', alert.get('process_type')),
        ('Analyst comment', alert.get('analyst_comment')),
        ('Action', event.action),
        ('Rules', alert.get('rule')),
        ('Destinations', alert.get('dest_ips')),
        ('Process', alert.get('process_name')),
        ('Process path', alert.get('process_path')),
        ('First seen', event.firstSeen),
        ('Last seen', event.lastSeen),
    ], mono=('Event ID', 'Device IP', 'Rules', 'Process path', 'First seen', 'Last seen'))
    if overview:
        parts.append(_table(overview))

    threat = event.threatDetails
    if threat and (threat.threatName or threat.threatFamily or threat.threatType):
        rows = _rows([
            ('Threat name', threat.threatName),
            ('Threat family', threat.threatFamily),
            ('Threat type', threat.threatType),
        ])
        parts.append(_heading('Threat details'))
        parts.append(_table(rows))

    parts.append('<p style="margin:12px 0 0 0;font-size:12px;{0}"><i>The raw event payload is '
                 'preserved in this alert\'s source data.</i></p>'.format(_MUTED))
    return ''.join(parts)


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
    threat = event.threatDetails
    threat_name = (threat.threatName or '') if threat else ''
    first_rule = str(event.rules[0]) if event.rules else ''
    # The name is what the grid shows: what ran, matched by what, on which
    # device. The eventId stays in sourceId and on the card.
    middle = threat_name or first_rule or event.classification or 'event'
    name = '{0} - {1} on {2}'.format(
        event.process or 'FortiEDR event', middle,
        collector.get('device') or 'unknown device')
    alert = {
        'name': name,
        'external_id': str(event.eventId) if event.eventId is not None else '',
        'severity': resolve_severity(event.severity),
        'alert_state': 'New',
        'status': 'Open',
        'alert_type': resolve_alert_type(event),
        'source': 'Fortinet FortiEDR',
        'source_ip': collector.get('ip') or '',
        'source_hostname': collector.get('device') or '',
        'dest_ips': _dest_string(event),
        'dest_ip': _first_ip_destination(event),
        'user_names': ', '.join(str(u) for u in event.loggedUsers if u not in (None, '')),
        'primary_user': event.processOwner or (str(event.loggedUsers[0]) if event.loggedUsers else ''),
        'process_owner': event.processOwner or '',
        'process_type': event.processType or '',
        'analyst_comment': event.comment or '',
        'threat_name': threat_name,
        'rule': _rule_string(event),
        'process_name': event.process or '',
        'process_path': event.processPath or '',
        'alert_generation_epoch': event.firstSeenEpoch,
        'last_observed_epoch': event.lastSeenEpoch,
        'event_count': 1,
        'source_payload': payload,
    }
    alert['description'] = build_description(event, alert)
    return alert


def map_events(records: List[Event]) -> List[Dict[str, Any]]:
    return [map_event_to_alert(r) for r in records]
