"""Parsers: raw CLI text -> data objects. Pure functions, no I/O (easy to unit test)."""
from __future__ import annotations

import re

from .models import InterfaceInfo, PingResult, RouteSummary, TraceResult

_PING_RE = re.compile(
    r"Success rate is (?P<pct>\d+) percent \((?P<ok>\d+)/(?P<sent>\d+)\)"
    r"(?:, round-trip min/avg/max = (?P<mn>\d+)/(?P<avg>\d+)/(?P<mx>\d+)\s*ms)?"
)
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_HOP_RE = re.compile(r"^\s*(\d+)\s+(.+)$")


def is_cli_error(raw: str) -> bool:
    """IOS error markers: unsupported / malformed command."""
    return raw.lstrip().startswith("%") or "% Invalid input" in raw or "% Incomplete command" in raw


def parse_ping(target: str, raw: str) -> PingResult:
    result = PingResult(target=target, raw=raw)
    m = _PING_RE.search(raw)
    if not m:
        result.error = "Unable to parse ping output"
        return result
    sent, ok = int(m["sent"]), int(m["ok"])
    result.sent, result.received = sent, ok
    result.loss_pct = round((sent - ok) / sent * 100, 1) if sent else 100.0
    if m["avg"] is not None:
        result.rtt_min, result.rtt_avg, result.rtt_max = int(m["mn"]), int(m["avg"]), int(m["mx"])
    return result


_TTL_MAX = 30                                   # IOS default max TTL
_UNREACH_FLAG = re.compile(r"![A-Z]")           # !H !N !U !P ... = "unreachable" markers


def parse_traceroute(target: str, raw: str) -> TraceResult:
    """IOS stops probing as soon as the destination answers, so "reached" means either the last hop is
    the target, or the trace ended early on a responding hop without !H/!N-style markers (the target may
    answer from another local address, e.g. a loopback target answered from the ingress interface)."""
    result = TraceResult(target=target, raw=raw)
    last_line = ""
    for line in raw.splitlines():
        m = _HOP_RE.match(line)
        if not m:
            continue
        ips = _IP_RE.findall(m.group(2))
        result.hops.append((int(m.group(1)), ips[0] if ips else "*"))
        last_line = m.group(2)
    if result.hops:
        last_ip = result.hops[-1][1]
        result.reached = last_ip == target or (
            last_ip != "*" and len(result.hops) < _TTL_MAX and not _UNREACH_FLAG.search(last_line)
        )
    return result


# ---- interfaces ------------------------------------------------------------------------
# "show ip interface brief" (routers)
_BRIEF_RE = re.compile(
    r"^(?P<name>\S+)\s+(?P<ip>\S+)\s+(?:YES|NO)\s+\S+\s+"
    r"(?P<status>administratively down|up|down|deleted)\s+(?P<proto>up|down)\s*$",
    re.IGNORECASE,
)
# "show interfaces status" (switches). The status keyword anchors the row, the port name may be empty.
_STATUS_RE = re.compile(
    r"^(?P<port>\S+)\s+(?:(?P<name>.*?)\s+)?"
    r"(?P<status>connected|notconnect|disabled|err-disabled|inactive|monitoring|suspended|sfp-mismatch|routed|faulty)"
    r"\s+(?P<vlan>\S+)\s+(?P<duplex>\S+)\s+(?P<speed>\S+)\s*(?P<type>.*?)\s*$"
)


def parse_interfaces(raw: str) -> list[InterfaceInfo]:
    """Auto-detects the output format (router brief vs switch status)."""
    interfaces: list[InterfaceInfo] = []
    for line in raw.splitlines():
        m = _BRIEF_RE.match(line.strip())
        if m:
            admin, proto = m["status"].lower(), m["proto"].lower()
            if admin.startswith("administratively"):
                status = "disabled"
            elif admin == "up" and proto == "up":
                status = "connected"
            elif admin == "up":
                status = "protocol-down"
            else:
                status = "notconnect"
            ip = "" if m["ip"].lower() == "unassigned" else m["ip"]
            interfaces.append(InterfaceInfo(name=m["name"], status=status, ip=ip))
            continue
        m = _STATUS_RE.match(line.rstrip())
        if m:
            interfaces.append(InterfaceInfo(
                name=m["port"],
                description=(m["name"] or "").strip(),
                status=m["status"],
                vlan=m["vlan"],
                duplex=m["duplex"].removeprefix("a-"),
                speed=m["speed"].removeprefix("a-"),
            ))
    return interfaces


# ---- routing table ---------------------------------------------------------------------
_PROTOCOLS = {
    "C": "Connected", "L": "Local", "S": "Static", "R": "RIP", "B": "BGP", "D": "EIGRP",
    "O": "OSPF", "i": "IS-IS", "I": "IGRP", "M": "Mobile", "E": "EGP", "o": "ODR", "P": "Periodic",
}
_ROUTE_RE = re.compile(r"^\s*(?P<code>[A-Za-z\*][A-Za-z0-9\* ]{0,4}?)\s+(?P<net>\d{1,3}(?:\.\d{1,3}){3})(?:/\d+)?\b")
_GATEWAY_RE = re.compile(r"Gateway of last resort is (\S+)")


def parse_routes(raw: str, expected: list[str] | None = None) -> RouteSummary:
    summary = RouteSummary()
    networks: set[str] = set()
    for line in raw.splitlines():
        m = _ROUTE_RE.match(line)
        if not m:
            continue
        proto = _PROTOCOLS.get(m["code"].split()[0][0], m["code"].strip())
        summary.by_protocol[proto] = summary.by_protocol.get(proto, 0) + 1
        summary.total += 1
        networks.add(m["net"])
    g = _GATEWAY_RE.search(raw)
    if g and g.group(1).lower() != "not":
        summary.default_route, summary.gateway = True, g.group(1)
    # expected prefixes are matched on their network address ("2.2.2.2/32" -> "2.2.2.2")
    summary.missing = [p for p in (expected or []) if p.split("/")[0] not in networks]
    return summary
