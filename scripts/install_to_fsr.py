"""Install the built connector tarball onto a live FortiSOAR, recycle the
integrations workers, and optionally create/refresh a configuration.

Thin wrapper over the pyfsr SDK -- the install, worker-recycle, and config
upsert are all pyfsr ConnectorsAPI calls (no hand-built requests, same shape
as the house installers):

    client.connectors.install_from_file(tgz, replace=True, wait=True)
    client.connectors.republish(NAME)                   # recycle workers
    client.connectors.upsert_configuration(NAME, cfg, name=..., default=...)

Repeatable: $replace upgrades in place (connector CONFIGURATIONS survive a
same-name upgrade); the republish is what clears the stale in-process module
after an upgrade -- without it uwsgi keeps serving the old code.

The installer also ensures the two appliance prerequisites the use-case
sample playbooks need for their inline-Python steps: the Custom Code
Execution setting (a box-settings gate; with it off the step fails with
"Custom Code Execution is disabled") and a default Code Snippet
configuration (with none, the step fails with INTEGRATION-12 -- a snippet
step's config resolves the appliance default at play time). Both are
idempotent; a refusal is a warned prerequisite gap, not a failed install.

NOTE: installing a connector needs a JWT (username/password) client. An
API-key alias cannot install -- the install forwards the caller's credential
to the integrations service as a Bearer token, and an API key is not a JWT,
so pyfsr refuses up front (the import would stall at Draft). Pick an alias
with username/password auth for --instance.

Target: --instance <pyfsr alias> (resolved from ~/.pyfsr/instances.toml) or
the FSR_* environment via pyfsr's EnvConfig as a fallback. The product
credentials for the configuration come from the EDR_* environment (the same
keys the live test suite reads; see .env.template):

    set -a && . .env.live && set +a
    python scripts/install_to_fsr.py --instance <alias> --with-config
    python scripts/install_to_fsr.py --instance <alias>                # install only

Needs a Python with pyfsr installed (pyfsr ships its own venv).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import urllib3
from pyfsr.exceptions import FortiSOARException

# SOAR boxes use self-signed certs; without this every verify_ssl-off call
# prints an InsecureRequestWarning that buries the actual progress lines.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ROOT = Path(__file__).resolve().parent.parent
NAME = "fortinet-fortiedrv2"
CONFIG_NAME = "fortiedr-lab"

# Entering the Connector Studio dev workspace (the worker recycle in
# republish) clones the installed tree; generous because slow boxes exist.
_CLIENT_TIMEOUT = int(os.environ.get("FSR_INSTALL_TIMEOUT", "300"))


def _version() -> str:
    return json.loads((ROOT / "info.json").read_text())["version"]


def _client(alias: str | None):
    if alias:
        from pyfsr.instances import InstanceRegistry
        registry = InstanceRegistry.load()
        resolved = registry.resolve(alias)
        cfg = registry.configs[resolved]
        cfg = cfg.model_copy(update={"timeout": _CLIENT_TIMEOUT})
        return cfg.client()
    from pyfsr.config import EnvConfig
    return EnvConfig.from_env().client(timeout=_CLIENT_TIMEOUT)


def _config_values() -> tuple[dict, str] | None:
    """The FortiEDR connector config built from the EDR_* environment, or
    None (with a printed reason) when the credentials are missing."""
    server = os.environ.get("EDR_SERVER")
    if not (server and os.environ.get("EDR_USERNAME") and os.environ.get("EDR_PASSWORD")):
        print("[4] --with-config given but EDR_SERVER / EDR_USERNAME / EDR_PASSWORD "
              "are not all set (source .env.live); skipping")
        return None
    cfg = {
        "server_url": server,
        "username": os.environ["EDR_USERNAME"],
        "password": os.environ["EDR_PASSWORD"],
        "verify_ssl": (os.environ.get("EDR_VERIFY_SSL", "false").lower() == "true"),
    }
    if os.environ.get("EDR_ORGANIZATION"):
        cfg["organization"] = os.environ["EDR_ORGANIZATION"]
    desc = "server={} org={} verify_ssl={}".format(
        server, cfg.get("organization", "(login-qualified)"), cfg["verify_ssl"])
    return cfg, desc


def _load_env_file(path: Path) -> None:
    """Populate os.environ from a KEY=VALUE file (.env.live shape), without
    overwriting what the real environment already set. Quotes are stripped
    the same way the test conftest strips them."""
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip().strip('"').strip("'")
        if value and key.strip() not in os.environ:
            os.environ[key.strip()] = value


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--instance", help="pyfsr instance alias (~/.pyfsr/instances.toml)")
    ap.add_argument("--env-file", type=Path, default=ROOT / ".env.live",
                    help="KEY=VALUE file for the EDR_* credentials "
                         "(default: %(default)s; never committed)")
    ap.add_argument("--tarball", help="path to the .tgz (default: dist/<name>-<version>.tgz)")
    ap.add_argument("--with-config", action="store_true",
                    help="create/refresh a configuration from the EDR_* environment")
    ap.add_argument("--config-name", default=CONFIG_NAME,
                    help="configuration name (default: %(default)s)")
    ap.add_argument("--no-default", action="store_true",
                    help="create/refresh the config WITHOUT marking it the default")
    ap.add_argument("--no-publish", action="store_true",
                    help="skip the post-install worker recycle")
    ap.add_argument("--no-health", action="store_true",
                    help="skip the post-config health check")
    args = ap.parse_args(argv)

    if args.env_file and args.env_file.is_file():
        _load_env_file(args.env_file)

    version = _version()
    tgz = Path(args.tarball) if args.tarball else ROOT / "dist" / f"{NAME}-{version.replace('.', '_')}.tgz"
    if not tgz.is_file():
        sys.exit(f"tarball not found: {tgz} (run scripts/package.sh)")

    try:
        client = _client(args.instance)
    except Exception as e:  # noqa: BLE001 -- a missing alias/env is a usage error
        sys.exit(f"cannot build a client for {args.instance or 'FSR_* env'}: {e}")
    conns = client.connectors

    print(f"[1] install {NAME} {version} ({tgz.name}, {tgz.stat().st_size // 1024} KB) "
          f"with $replace -> {client.base_url}")
    _t = time.time()
    try:
        conns.install_from_file(str(tgz), replace=True, wait=True, timeout=_CLIENT_TIMEOUT)
    except FortiSOARException as e:
        print(f"   FAILED after {time.time() - _t:.0f}s: {e.status_code} {e.message}")
        return 1
    conns.clear_cache()
    live_ver = conns.resolve_version(NAME)
    print(f"   installed: live version={live_ver} ({time.time() - _t:.0f}s)")
    if live_ver != version:
        print(f"   WARN: live version {live_ver} != built {version}")

    if not args.no_publish:
        print("[2] republish to recycle integrations workers (clear stale module)")
        try:
            res = conns.republish(NAME)
            print(f"   publish OK (dev_id={res.get('dev_id')}) - workers recycling (~5s)")
        except Exception as e:  # noqa: BLE001 -- install already succeeded; recycle is best-effort
            print(f"   WARN: worker recycle failed ({type(e).__name__}: {e}); "
                  "workers may serve stale code until the next restart")

    print("[3] ensure the appliance can run the use-case playbooks' inline-Python steps")
    try:
        client.system_settings.set_custom_code_execution(True)
        have_default = any(c.default for c in conns.configurations("code-snippet"))
        if not have_default:
            conns.upsert_configuration(
                "code-snippet",
                {"allow_imports": False, "restrict_imports": "json,datetime,re,time"},
                name="Default Configuration", default=True)
        print("   custom code execution enabled; code-snippet default config "
              + ("already present" if have_default else "created"))

    except Exception as e:  # noqa: BLE001 -- install succeeded; these are playbook prerequisites
        print(f"   WARN: could not ensure the snippet prerequisites "
              f"({type(e).__name__}: {e}); the sweep/digest/fleet playbooks "
              "will refuse at their snippet step until an admin enables "
              "Custom Code Execution and creates a default Code Snippet "
              "configuration")

    if args.with_config:
        built = _config_values()
        if built is None:
            return 0
        cfg_values, desc = built
        print(f"[4] create/refresh config {args.config_name!r} ({desc})")
        try:
            cfg = conns.upsert_configuration(
                NAME, cfg_values, name=args.config_name, version=version,
                default=not args.no_default, validate=False)
        except FortiSOARException as e:
            print(f"   config FAILED: {e.status_code} {e.message}")
            return 1
        cid = (cfg.get("config_id") or cfg.get("id")) if hasattr(cfg, "get") else getattr(cfg, "config_id", None)
        print(f"   config_id={cid}")
        if not args.no_health:
            print(f"[5] health check {NAME} with config {args.config_name!r}")
            time.sleep(3)  # let the recycled workers pick the module
            try:
                result = conns.healthcheck(NAME, config=args.config_name)
            except FortiSOARException as e:
                print(f"   health FAILED: {e.status_code} {e.message}")
                return 1
            if result is not True and not (result.get("status") if isinstance(result, dict) else result):
                print(f"   health FAILED: {result}")
                return 1
            print("   health: OK")

    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
