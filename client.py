"""
Copyright start
Copyright (C) 2008 - 2026 FortinetInc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end

HTTP client for the FortiEDR REST API.

Two API tiers live on the same host:

- ``/management-rest/...`` -- the documentable REST API (events, collectors,
  exceptions, IP sets, organizations, ...). Auth: HTTP Basic, the username
  must be org-qualified (``<org>\\<user>``) when the Organization config field
  is blank, exactly as in the shipped FortiEDR connector.
- ``/api/...`` -- the console-tier API (incidents, collector state, async job
  progress), documented in the same swagger but behaving like the UI.

Behaviour kept from the shipped 2.1.0 connector on purpose:
- transient 400s are retried (up to 5 times, 10s apart); the events endpoints
  are known to answer an occasional 400 for a valid query;
- 'message' / 'errorMessage' JSON fields are surfaced in ConnectorError;
- 'sorting' params are JSON-encoded, collectorIds coerced to a list, and
  datetime params normalized to '%Y-%m-%d %H:%M:%S'.
"""

import base64
import json
import time
from datetime import datetime

import requests
from connectors.core.connector import ConnectorError, get_logger
from requests import exceptions as req_exceptions

logger = get_logger('fortinet-fortiedrv2')

MAX_RETRIES = 5
WAIT_TIME = 10
REQUEST_TIMEOUT = 120

DATE_TIME_PARAMS = ('firstSeen', 'lastSeen', 'firstSeenFrom', 'firstSeenTo',
                     'lastSeenFrom', 'lastSeenTo', 'createdBefore', 'createdAfter',
                     'updatedBefore', 'updatedAfter')
PERSISTENCE_DATA_ACTION = {'Delete Key': 'DeleteKey', 'Delete Value': 'DeleteValue', 'Update': 'Update'}
FILE_ACTIONS = ('get_file', 'get_event_file')

MGMT_PREFIX = '/management-rest'


class FortiEDRClient:

    def __init__(self, config):
        self.username = config.get('username')
        self.password = config.get('password')
        self.organization = config.get('organization')
        if self.organization:
            self.username = '{0}\\{1}'.format(self.organization, self.username)
        self.verify_ssl = config.get('verify_ssl', True)
        host = (config.get('server_url') or '').strip('/')
        if host[:7] == 'http://':
            host = 'https://{0}'.format(host[len('http://'):])
        elif not host[:8] == 'https://':
            host = 'https://{0}'.format(host)
        self.host = host

    # ------------------------------------------------------------- payload
    def build_payload(self, params, operation=''):
        """Normalize operation params into a query payload (stock behaviour)."""
        payload = {k: v for k, v in params.items() if v is not None and v != ''}

        if operation in FILE_ACTIONS:
            if 'retrieve_from' in payload:
                if payload['retrieve_from'] == 'Disk':
                    payload['disk'] = True
                    payload['memory'] = False
                else:
                    payload['disk'] = False
                    payload['memory'] = True
                payload.pop('retrieve_from')
            return payload

        for key in [k for k in payload if k in DATE_TIME_PARAMS]:
            if payload.get(key):
                payload[key] = self._normalize_datetime(payload[key], key)
        payload.pop('type', None)
        if 'remediate_action' in payload:
            payload['persistenceDataAction'] = PERSISTENCE_DATA_ACTION.get(payload.get('persistenceDataAction'))
            payload.pop('remediate_action')
        if 'sorting' in payload:
            payload['sorting'] = json.dumps(payload['sorting'])
        if payload.get('organization') == 'Exact Organization Name':
            payload['organization'] = payload.get('org_name')
            payload.pop('org_name', None)
        if 'collectorIds' in payload:
            value = payload['collectorIds']
            if isinstance(value, int):
                payload['collectorIds'] = [value]
            elif isinstance(value, str):
                payload['collectorIds'] = [v for v in value.replace(' ', '').split(',') if v]
            elif isinstance(value, list):
                payload['collectorIds'] = value
        if 'enabled' in payload:
            if payload['enabled'] in ('False', 'false'):
                payload['enabled'] = False
            elif payload['enabled'] in ('True', 'true'):
                payload['enabled'] = True
        return payload

    @staticmethod
    def _normalize_datetime(value, key):
        if not isinstance(value, str):
            return value
        for fmt, out in (('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M:%S'),
                         ('%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%d %H:%M:%S'),
                         ('%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%d %H:%M:%S')):
            try:
                return datetime.strptime(value, fmt).strftime(out)
            except ValueError:
                continue
        raise ConnectorError('Unrecognized datetime {0!r} for {1}; expected YYYY-MM-DD HH:MM:SS or ISO-8601'
                             .format(value, key))

    # ------------------------------------------------------------- headers
    def build_headers(self, action=''):
        stream = False
        encode_creds = '{0}:{1}'.format(self.username, self.password).encode('ascii')
        creds = base64.b64encode(encode_creds).decode('ascii')
        headers = {'Authorization': 'Basic {0}'.format(creds)}
        if action == 'get_raw_json_event_data':
            return headers, stream
        headers['Content-Type'] = 'application/json; charset=utf-8'
        if action in FILE_ACTIONS:
            headers['Accept'] = 'application/octet-stream'
            stream = True
        else:
            headers['Accept'] = 'application/json'
        return headers, stream

    # ------------------------------------------------------------- request
    def make_rest_api_call(self, title, method, endpoint, headers=None, payload=None,
                           stream=False, data=None, max_retries=MAX_RETRIES):
        """One HTTP call with the stock retry/error semantics.

        ``endpoint`` is host-absolute: needs ``/management-rest/...`` or
        ``/api/...``. A 400 for a valid query (a known events-endpoint
        transient) is retried up to ``max_retries`` times, 10s apart.
        """
        url = '{0}{1}'.format(self.host, endpoint)
        try:
            response = None
            attempts = 0
            while True:
                response = self._dispatch(method, url, headers, payload, stream, data)
                if response.ok:
                    return response
                attempts += 1
                if response.status_code == 400 and attempts < max_retries:
                    logger.debug('Received 400 for {0}, retrying ({1}/{2})'.format(endpoint, attempts, max_retries))
                    time.sleep(WAIT_TIME)
                    continue
                self._raise_for_status(response, title)

        except req_exceptions.SSLError:
            raise ConnectorError('An SSL error occurred')
        except req_exceptions.ConnectionError:
            raise ConnectorError('A connection error occurred')
        except req_exceptions.Timeout:
            raise ConnectorError('The request timed out')
        except req_exceptions.RequestException as err:
            logger.error(str(err))
            raise ConnectorError('There was an error while handling the request')

    def _dispatch(self, method, url, headers, payload, stream, data):
        method = (method or 'GET').upper()
        kwargs = dict(headers=headers, verify=self.verify_ssl, timeout=REQUEST_TIMEOUT)
        if stream:
            kwargs['stream'] = True
        if method == 'GET':
            return requests.get(url, params=payload, **kwargs)
        if method == 'PUT':
            return requests.put(url, params=payload, data=data, **kwargs)
        if method == 'POST':
            return requests.post(url, params=payload, data=data, **kwargs)
        if method == 'DELETE':
            return requests.delete(url, params=payload, data=data, **kwargs)
        raise ConnectorError('Unsupported HTTP method {0}'.format(method))

    @staticmethod
    def _raise_for_status(response, title):
        try:
            err = response.json()
            detail = err.get('message') or err.get('errorMessage')
        except Exception:
            detail = None
        if detail:
            error_msg = '{0} Response [{1}:{2}]'.format(title, response.status_code, detail)
        else:
            error_msg = 'Error:Response Code: {0} Response:{1}'.format(response.status_code, response.text[:500])
        logger.error(error_msg)
        raise ConnectorError(error_msg)

    # ------------------------------------------------------------- convenience
    def get(self, title, endpoint, params=None, operation='', stream=False):
        payload = self.build_payload(params or {}, operation)
        headers, _stream = self.build_headers(operation)
        return self.make_rest_api_call(title, 'GET', endpoint, headers, payload,
                                       stream=stream or _stream)

    def json_get(self, title, endpoint, params=None, operation=''):
        response = self.get(title, endpoint, params, operation)
        if response.text:
            return response.json()
        return {'result': 'Successfully executed {0}'.format(operation or title)}

    @staticmethod
    def json_or_empty(response):
        return response.json() if response.text else []

    def convert_str_list(self, param):
        if not isinstance(param, str):
            return param
        return [x.strip() for x in param.split(',') if x and x.strip()]
