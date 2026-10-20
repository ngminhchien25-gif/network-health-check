"""YAML configuration loader.

Features:
  * ``${VAR}`` and ``${VAR:-default}`` expansion so secrets stay out of the YAML.
  * Optional ``.env`` file loader (tiny, no extra dependency).
  * ``defaults:`` block merged into every device.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


class ConfigError(Exception):
    """Raised for any invalid configuration."""


_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-(.*?))?\}")


def load_dotenv(path: Path) -> None:
    """Load KEY=VALUE lines into os.environ (existing variables win)."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def _expand(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV_RE.sub(
            lambda m: os.environ.get(m.group(1), m.group(2) if m.group(2) is not None else ""),
            value,
        )
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v) for v in value]
    return value


def _to_bool(value: Any) -> bool:
    return value if isinstance(value, bool) else str(value).strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Settings:
    max_workers: int = 5          # devices checked in parallel
    conn_timeout: int = 15        # seconds to open the SSH session
    command_timeout: int = 60     # seconds to wait for one command (traceroute can be slow)


@dataclass
class Thresholds:
    loss_critical_pct: float = 50.0     # loss >= this -> CRITICAL, 0 < loss < this -> WARNING
    latency_warning_ms: int = 100       # average RTT above this -> WARNING


@dataclass
class Commands:
    ping: str = "ping {target} repeat 5"
    traceroute: str = "traceroute {target}"
    routes: str = "show ip route"
    # Routers do not support "show interfaces status" -> role specific command.
    interfaces: dict[str, str] = field(default_factory=lambda: {
        "router": "show ip interface brief",
        "switch": "show interfaces status",
        "default": "show ip interface brief",
    })

    def interface_cmd(self, role: str) -> str:
        return self.interfaces.get(role) or self.interfaces.get("default", "show ip interface brief")


@dataclass
class ReportConfig:
    title: str = "Network Health Check Report"
    output_dir: str = "reports"
    pdf: bool = True


@dataclass
class SmtpConfig:
    host: str = "localhost"
    port: int = 25
    use_starttls: bool = False
    use_ssl: bool = False
    username: str = ""
    password: str = ""
    sender: str = "netcheck@localhost"
    recipients: list[str] = field(default_factory=list)
    timeout: int = 30


@dataclass
class DeviceConfig:
    name: str
    host: str
    device_type: str = "cisco_ios"          # any Netmiko device_type
    role: str = "router"                    # router | switch | (other -> default interface cmd)
    username: str = ""
    password: str = ""
    secret: str = ""
    port: int = 22
    checks: list[str] = field(default_factory=lambda: ["ping", "traceroute", "routes", "interfaces"])
    ping_targets: list[str] = field(default_factory=list)
    traceroute_targets: list[str] = field(default_factory=list)
    expected_routes: list[str] = field(default_factory=list)       # prefixes that MUST be present
    critical_interfaces: list[str] = field(default_factory=list)   # must be connected/up
    require_default_route: bool = False


@dataclass
class AppConfig:
    settings: Settings
    thresholds: Thresholds
    commands: Commands
    report: ReportConfig
    smtp: SmtpConfig
    devices: list[DeviceConfig]


def _build(cls, data: dict, where: str):
    try:
        return cls(**data)
    except TypeError as exc:
        raise ConfigError(f"Invalid '{where}' section: {exc}") from exc


def load_config(path: str | Path) -> AppConfig:
    path = Path(path)
    if not path.is_file():
        raise ConfigError(f"Config file not found: {path}")
    raw = _expand(yaml.safe_load(path.read_text(encoding="utf-8")) or {})

    smtp_raw = dict(raw.get("smtp", {}))
    for key in ("use_starttls", "use_ssl"):
        if key in smtp_raw:
            smtp_raw[key] = _to_bool(smtp_raw[key])
    for key in ("port", "timeout"):
        if key in smtp_raw:
            smtp_raw[key] = int(smtp_raw[key])
    if isinstance(smtp_raw.get("recipients"), str):
        smtp_raw["recipients"] = [r.strip() for r in smtp_raw["recipients"].split(",") if r.strip()]

    defaults = raw.get("defaults", {})
    devices: list[DeviceConfig] = []
    for item in raw.get("devices", []):
        if "name" not in item or "host" not in item:
            raise ConfigError(f"Every device needs 'name' and 'host': {item}")
        devices.append(_build(DeviceConfig, {**defaults, **item}, f"device {item['name']}"))
    if not devices:
        raise ConfigError("No devices defined in config")

    commands_raw = dict(raw.get("commands", {}))
    if "interfaces" in commands_raw:
        commands_raw["interfaces"] = {**Commands().interfaces, **commands_raw["interfaces"]}

    return AppConfig(
        settings=_build(Settings, raw.get("settings", {}), "settings"),
        thresholds=_build(Thresholds, raw.get("thresholds", {}), "thresholds"),
        commands=_build(Commands, commands_raw, "commands"),
        report=_build(ReportConfig, raw.get("report", {}), "report"),
        smtp=_build(SmtpConfig, smtp_raw, "smtp"),
        devices=devices,
    )
