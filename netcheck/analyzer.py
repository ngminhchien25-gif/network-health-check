"""Turns parsed data into findings (severity + message). All thresholds come from config."""
from __future__ import annotations

from .config import DeviceConfig, Thresholds
from .models import DeviceReport, Finding, Severity

_LONG_TO_SHORT = (("tengigabitethernet", "te"), ("gigabitethernet", "gi"), ("fastethernet", "fa"))


def _norm(name: str) -> str:
    """GigabitEthernet0/1 and Gi0/1 must compare equal."""
    n = name.lower()
    for long, short in _LONG_TO_SHORT:
        if n.startswith(long):
            return short + n[len(long):]
    return n


def analyze(rep: DeviceReport, dev: DeviceConfig, thr: Thresholds) -> None:
    add = lambda sev, cat, msg: rep.findings.append(Finding(sev, cat, msg))  # noqa: E731

    if not rep.reachable:
        add(Severity.CRITICAL, "connectivity", f"Cannot reach device: {rep.error}")
        return

    for p in rep.pings:
        if p.error:
            p.severity = Severity.WARNING
            add(Severity.WARNING, "ping", f"Ping to {p.target}: {p.error}")
        elif p.loss_pct >= thr.loss_critical_pct:
            p.severity = Severity.CRITICAL
            add(Severity.CRITICAL, "ping", f"Ping to {p.target}: {p.loss_pct:g}% packet loss")
        elif p.loss_pct > 0:
            p.severity = Severity.WARNING
            add(Severity.WARNING, "ping", f"Ping to {p.target}: {p.loss_pct:g}% packet loss")
        if not p.error and p.rtt_avg is not None and p.rtt_avg > thr.latency_warning_ms:
            p.severity = max(p.severity, Severity.WARNING)
            add(Severity.WARNING, "ping",
                f"Ping to {p.target}: high latency (avg {p.rtt_avg} ms > {thr.latency_warning_ms} ms)")

    for t in rep.traces:
        if not t.reached:
            t.severity = Severity.WARNING
            last = next((ip for _, ip in reversed(t.hops) if ip != "*"), None)
            add(Severity.WARNING, "traceroute",
                f"Traceroute to {t.target} did not reach destination (last responding hop: {last or 'none'})")

    if rep.routes is not None:
        for prefix in rep.routes.missing:
            add(Severity.CRITICAL, "routing", f"Expected route {prefix} is missing from the routing table")
        if dev.require_default_route and not rep.routes.default_route:
            add(Severity.WARNING, "routing", "No default route (gateway of last resort not set)")

    critical = {_norm(n) for n in dev.critical_interfaces}
    admin_down = 0
    for i in rep.interfaces:
        is_critical = _norm(i.name) in critical
        if i.status == "err-disabled":
            i.severity, i.note = Severity.CRITICAL, "err-disabled"
            add(Severity.CRITICAL, "interface", f"{i.name} is err-disabled")
        elif is_critical and i.status != "connected":
            i.severity, i.note = Severity.CRITICAL, "critical interface not up"
            add(Severity.CRITICAL, "interface", f"Critical interface {i.name} is {i.status}")
        elif i.status == "protocol-down":
            i.severity, i.note = Severity.WARNING, "line protocol down"
            add(Severity.WARNING, "interface", f"{i.name}: link up but line protocol is down")
        elif i.status == "notconnect" and dev.role != "switch":
            # unused switch ports are normal; a down router interface is not
            i.severity, i.note = Severity.WARNING, "down"
            add(Severity.WARNING, "interface", f"{i.name} is down")
        elif i.status == "connected":
            if i.duplex == "half":
                i.severity, i.note = Severity.WARNING, "half duplex"
                add(Severity.WARNING, "interface", f"{i.name}: half duplex (possible duplex mismatch)")
            if i.speed == "10":
                i.severity, i.note = Severity.WARNING, (i.note + "; " if i.note else "") + "10 Mbps"
                add(Severity.WARNING, "interface", f"{i.name}: negotiated only 10 Mbps")
        elif i.status == "disabled":
            admin_down += 1
    if admin_down:
        add(Severity.INFO, "interface", f"{admin_down} interface(s) administratively disabled")
