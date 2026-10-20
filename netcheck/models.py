"""Plain data containers shared by every module (no logic besides tiny helpers)."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Ordered so that max() gives the worst state."""
    OK = 0
    INFO = 1       # informational only, never affects device status
    WARNING = 2
    CRITICAL = 3


@dataclass
class Finding:
    severity: Severity
    category: str          # connectivity | ping | traceroute | routing | interface | command
    message: str


@dataclass
class PingResult:
    target: str
    sent: int = 0
    received: int = 0
    loss_pct: float = 100.0
    rtt_min: int | None = None
    rtt_avg: int | None = None
    rtt_max: int | None = None
    error: str = ""
    severity: Severity = Severity.OK
    raw: str = ""


@dataclass
class TraceResult:
    target: str
    hops: list[tuple[int, str]] = field(default_factory=list)   # (hop number, ip or "*")
    reached: bool = False
    severity: Severity = Severity.OK
    raw: str = ""


@dataclass
class InterfaceInfo:
    name: str
    status: str            # connected | notconnect | disabled | err-disabled | protocol-down | ...
    vlan: str = ""
    duplex: str = ""
    speed: str = ""
    ip: str = ""
    description: str = ""
    severity: Severity = Severity.OK
    note: str = ""


@dataclass
class RouteSummary:
    total: int = 0
    by_protocol: dict[str, int] = field(default_factory=dict)
    default_route: bool = False
    gateway: str = ""
    missing: list[str] = field(default_factory=list)


@dataclass
class DeviceReport:
    name: str
    host: str
    role: str
    reachable: bool = False
    error: str = ""
    duration_s: float = 0.0
    pings: list[PingResult] = field(default_factory=list)
    traces: list[TraceResult] = field(default_factory=list)
    interfaces: list[InterfaceInfo] = field(default_factory=list)
    routes: RouteSummary | None = None
    findings: list[Finding] = field(default_factory=list)
    raw: dict[str, str] = field(default_factory=dict)     # command -> raw output

    @property
    def status(self) -> Severity:
        """Worst WARNING/CRITICAL finding; INFO findings never degrade the device."""
        worst = [f.severity for f in self.findings if f.severity >= Severity.WARNING]
        return max(worst, default=Severity.OK)
