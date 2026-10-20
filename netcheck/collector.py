"""Runs the checks on each device (in parallel) and fills a DeviceReport."""
from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

from .analyzer import analyze
from .config import AppConfig, DeviceConfig
from .connector import BaseConnector, ConnectionFailed
from .models import DeviceReport, Finding, Severity
from .parsers import is_cli_error, parse_interfaces, parse_ping, parse_routes, parse_traceroute

log = logging.getLogger(__name__)
ConnectorFactory = Callable[..., BaseConnector]


def _run(conn: BaseConnector, rep: DeviceReport, command: str) -> str | None:
    """Execute one command; a failing command must not abort the whole device."""
    try:
        output = conn.send(command)
    except Exception as exc:  # noqa: BLE001 - timeouts, channel closed, ...
        log.warning("%s: command '%s' failed: %s", rep.name, command, exc)
        rep.findings.append(Finding(Severity.WARNING, "command", f"'{command}' failed: {exc}"))
        return None
    rep.raw[command] = output
    if is_cli_error(output):
        rep.findings.append(Finding(Severity.WARNING, "command", f"'{command}' not supported / rejected by device"))
        return None
    return output


def check_device(dev: DeviceConfig, cfg: AppConfig, factory: ConnectorFactory) -> DeviceReport:
    rep = DeviceReport(name=dev.name, host=dev.host, role=dev.role)
    started = time.monotonic()
    log.info("%s (%s): starting", dev.name, dev.host)
    try:
        with factory(dev, cfg.settings) as conn:
            rep.reachable = True
            cmds = cfg.commands
            if "ping" in dev.checks:
                for target in dev.ping_targets:
                    out = _run(conn, rep, cmds.ping.format(target=target))
                    if out is not None:
                        rep.pings.append(parse_ping(target, out))
            if "traceroute" in dev.checks:
                for target in dev.traceroute_targets:
                    out = _run(conn, rep, cmds.traceroute.format(target=target))
                    if out is not None:
                        rep.traces.append(parse_traceroute(target, out))
            if "routes" in dev.checks:
                out = _run(conn, rep, cmds.routes)
                if out is not None:
                    rep.routes = parse_routes(out, dev.expected_routes)
            if "interfaces" in dev.checks:
                out = _run(conn, rep, cmds.interface_cmd(dev.role))
                if out is not None:
                    rep.interfaces = parse_interfaces(out)
    except ConnectionFailed as exc:
        rep.error = str(exc)
        log.error("%s: %s", dev.name, exc)
    except Exception as exc:  # noqa: BLE001 - last line of defence, one device must not kill the run
        rep.error = f"Unexpected error: {exc}"
        log.exception("%s: unexpected error", dev.name)
    analyze(rep, dev, cfg.thresholds)
    rep.duration_s = round(time.monotonic() - started, 2)
    log.info("%s: done in %.1fs -> %s", dev.name, rep.duration_s, rep.status.name)
    return rep


def collect_all(devices: list[DeviceConfig], cfg: AppConfig, factory: ConnectorFactory) -> list[DeviceReport]:
    """Parallel collection; result order == config order."""
    workers = max(1, min(cfg.settings.max_workers, len(devices)))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="netcheck") as pool:
        return list(pool.map(lambda d: check_device(d, cfg, factory), devices))
