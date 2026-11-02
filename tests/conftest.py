"""
Test fixtures for the FortiEDR v2 connector.

- Registers the connector directory (which has a hyphen in its name) as the
  virtual package ``fortiedrv2`` so its relative imports resolve.
- Stubs the appliance-only runtime packages (connectors.core.connector,
  integrations.crudhub, django, cshmac) so the connector imports standalone.
- ``--live`` opts in to tests/test_live.py against a real FortiEDR tenant;
  credentials come from a gitignored ``.env.live`` at the repo root with
  EDR_SERVER / EDR_USERNAME / EDR_PASSWORD / EDR_ORGANIZATION keys, plus the
  optional per-tenant suite targets EDR_DEMO_EVENT_ID, EDR_SACRIFICIAL_EVENT_ID
  and EDR_ROUNDTRIP_COLLECTOR (tests needing an unset target skip themselves).
"""

import logging
import os
import sys
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

# --- virtual package 'fortiedrv2' over the hyphenated connector directory ---
if 'fortiedrv2' not in sys.modules:
    pkg = types.ModuleType('fortiedrv2')
    pkg.__path__ = [str(REPO)]
    sys.modules['fortiedrv2'] = pkg

# --- stub FortiSOAR SDK modules so the connector imports offline ---
if 'connectors' not in sys.modules:
    pkg = types.ModuleType('connectors')
    pkg.__path__ = []
    core = types.ModuleType('connectors.core')
    core.__path__ = []
    conn_mod = types.ModuleType('connectors.core.connector')

    class ConnectorError(Exception):
        pass

    class Connector:
        def execute(self, config, operation, params, **kwargs):
            raise NotImplementedError('Connector.execute is stubbed')

    def get_logger(name):
        return logging.getLogger(name)

    conn_mod.ConnectorError = ConnectorError
    conn_mod.Connector = Connector
    conn_mod.get_logger = get_logger
    pkg.core = core
    core.connector = conn_mod
    sys.modules['connectors'] = pkg
    sys.modules['connectors.core'] = core
    sys.modules['connectors.core.connector'] = conn_mod

    cyops = types.ModuleType('connectors.cyops_utilities')
    cyops.__path__ = []
    builtins_mod = types.ModuleType('connectors.cyops_utilities.builtins')

    def download_file_from_cyops(*a, **kw):
        return None

    builtins_mod.download_file_from_cyops = download_file_from_cyops
    cyops.builtins = builtins_mod
    sys.modules['connectors.cyops_utilities'] = cyops
    sys.modules['connectors.cyops_utilities.builtins'] = builtins_mod

if 'integrations' not in sys.modules:
    pkg = types.ModuleType('integrations')
    pkg.__path__ = []
    crudhub = types.ModuleType('integrations.crudhub')
    crudhub.__path__ = []
    crudhub.make_request = lambda *a, **kw: {}
    crudhub.maybe_json_or_raise = lambda response: {}
    crudhub.make_file_upload_request = lambda *a, **kw: {'@id': '/api/3/files/1'}
    pkg.crudhub = crudhub
    sys.modules['integrations'] = pkg
    sys.modules['integrations.crudhub'] = crudhub

if 'django' not in sys.modules:
    pkg = types.ModuleType('django')
    pkg.__path__ = []
    conf = types.ModuleType('django.conf')

    class _Settings:
        CRUD_HUB_URL = 'https://soar.example.com'
        APPLIANCE_PUBLIC_KEY = 'stub'
        APPLIANCE_PRIVATE_KEY = 'stub'

    conf.settings = _Settings()
    pkg.conf = conf
    sys.modules['django'] = pkg
    sys.modules['django.conf'] = conf

if 'cshmac' not in sys.modules:
    pkg = types.ModuleType('cshmac')
    pkg.__path__ = []
    requests_mod = types.ModuleType('cshmac.requests')

    class HmacAuth:
        def __init__(self, *a, **kw):
            pass

    requests_mod.HmacAuth = HmacAuth
    pkg.requests = requests_mod
    sys.modules['cshmac'] = pkg
    sys.modules['cshmac.requests'] = requests_mod


def pytest_addoption(parser):
    parser.addoption('--live', action='store_true', default=False,
                     help='run tests against the live FortiEDR tenant in .env.live')


def pytest_configure(config):
    config.addinivalue_line('markers', 'live: needs a reachable FortiEDR tenant (run with --live)')


def pytest_collection_modifyitems(config, items):
    if config.getoption('--live'):
        return
    skip = pytest.mark.skip(reason='live test; pass --live')
    for item in items:
        if 'live' in item.keywords:
            item.add_marker(skip)


def load_env(path=REPO / '.env.live'):
    env = {}
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, _, value = line.partition('=')
                value = value.strip().strip('"').strip("'")
                if value:
                    env[key.strip()] = value
    env.update({k: v for k, v in os.environ.items() if k.startswith('EDR_')})
    return env


@pytest.fixture(scope='session')
def env():
    values = load_env()
    if not values.get('EDR_SERVER') or not values.get('EDR_PASSWORD'):
        pytest.skip('EDR_SERVER / EDR_PASSWORD not set (.env.live)')
    return values


@pytest.fixture(scope='session')
def live_config(env):
    """Connector configuration dict, shaped like the FortiSOAR config form."""
    config = {
        'server_url': env['EDR_SERVER'],
        'username': env['EDR_USERNAME'],
        'password': env['EDR_PASSWORD'],
        'organization': env.get('EDR_ORGANIZATION', ''),
        'verify_ssl': env.get('EDR_VERIFY_SSL', 'false').lower() == 'true',
    }
    return config


# ---------------------------------------------------------------------------
# Live-suite targets. The tenants these tests run against are demo tenants and
# the suite must ship without their identifiers: which event is the canonical
# long-lived event, which is the approved sacrificial carrier for the
# exception round trip, and which collector tolerates the state round trips
# are configured per tenant through .env.live (all optional -- a suite that
# does not know a target skips the tests that need it instead of guessing).
# ---------------------------------------------------------------------------


@pytest.fixture(scope='session')
def demo_event_id(env):
    """Event ID of a long-lived event (firstSeen << lastSeen) on this tenant."""
    value = env.get('EDR_DEMO_EVENT_ID')
    # the API rows carry numeric event ids; an env value arrives as a string
    # and every comparison in the suite is against the row value
    return int(value) if value else None


@pytest.fixture(scope='session')
def sacrificial_event_id(env):
    """Event ID approved as the sacrificial carrier for the exception ops."""
    value = env.get('EDR_SACRIFICIAL_EVENT_ID')
    return int(value) if value else None


@pytest.fixture(scope='session')
def roundtrip_collector(env):
    """Collector name approved for the isolate/move/state round trips."""
    return env.get('EDR_ROUNDTRIP_COLLECTOR')



@pytest.fixture(scope='session')
def connector():
    from fortiedrv2.connector import FortiEDR
    return FortiEDR()


@pytest.fixture(scope='session')
def call_op(connector, live_config):
    """execute() plus a session registry of which operations ran live.

    ``call_op(op, params, config=None)`` executes against ``live_config`` by
    default and records ``op``; the full-op live suite ends with a gate that
    asserts the registry equals every operation the connector ships, so an op
    that only ever ran offline is a test failure, not an oversight.
    """

    def _call(op, params=None, config=None):
        _call.covered.add(op)
        return connector.execute(config or live_config, op, dict(params or {}))

    _call.covered = set()
    return _call


FIXTURES = Path(__file__).resolve().parent / 'fixtures'


@pytest.fixture()
def fixture():
    """Load a JSON fixture from tests/fixtures."""

    def _load(name):
        return json_fixture(name)

    return _load


def json_fixture(name):
    import json
    return json.loads((FIXTURES / name).read_text())
