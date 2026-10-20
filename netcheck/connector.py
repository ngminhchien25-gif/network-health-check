"""Device connectors.

NetmikoConnector -> real SSH sessions (GNS3 lab / production devices).
DemoConnector    -> canned outputs, lets you run the whole pipeline without any device.
"""
from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod

from .config import DeviceConfig, Settings

log = logging.getLogger(__name__)


class ConnectionFailed(Exception):
    """Device unreachable / authentication failed (message is shown in the report)."""


class BaseConnector(ABC):
    def __init__(self, dev: DeviceConfig, settings: Settings):
        self.dev = dev
        self.settings = settings

    @abstractmethod
    def connect(self) -> None: ...

    @abstractmethod
    def send(self, command: str) -> str: ...

    @abstractmethod
    def disconnect(self) -> None: ...

    def __enter__(self) -> "BaseConnector":
        self.connect()
        return self

    def __exit__(self, *exc) -> bool:
        self.disconnect()
        return False


class NetmikoConnector(BaseConnector):
    """SSH connector based on Netmiko (imported lazily so --demo works without it)."""

    _conn = None

    def connect(self) -> None:
        from netmiko import ConnectHandler
        from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
        from paramiko.ssh_exception import SSHException

        d, s = self.dev, self.settings
        params = {
            "device_type": d.device_type,
            "host": d.host,
            "port": d.port,
            "username": d.username,
            "password": d.password,
            "secret": d.secret,
            "conn_timeout": s.conn_timeout,
            "auth_timeout": s.conn_timeout,
            "banner_timeout": s.conn_timeout,
        }
        try:
            self._conn = ConnectHandler(**params)
            if d.secret and not self._conn.check_enable_mode():
                self._conn.enable()
        except NetmikoAuthenticationException as exc:
            raise ConnectionFailed(f"Authentication failed for user '{d.username}'") from exc
        except NetmikoTimeoutException as exc:
            raise ConnectionFailed(f"Timeout connecting to {d.host}:{d.port}") from exc
        except SSHException as exc:
            raise ConnectionFailed(f"SSH error: {exc}") from exc
        except OSError as exc:
            raise ConnectionFailed(f"Network error: {exc}") from exc

    def send(self, command: str) -> str:
        return self._conn.send_command(command, read_timeout=self.settings.command_timeout)

    def disconnect(self) -> None:
        if self._conn is not None:
            try:
                self._conn.disconnect()
            except Exception:  # noqa: BLE001 - never fail a run on logout
                log.debug("disconnect error ignored", exc_info=True)


class DemoConnector(BaseConnector):
    """Returns canned CLI output from demo_data.py."""

    def connect(self) -> None:
        from .demo_data import DEMO_FAILURES, DEMO_OUTPUTS

        time.sleep(0.05)
        if self.dev.name in DEMO_FAILURES:
            raise ConnectionFailed(DEMO_FAILURES[self.dev.name])
        self._outputs = DEMO_OUTPUTS.get(self.dev.name, {})

    def send(self, command: str) -> str:
        time.sleep(0.01)
        return self._outputs.get(command, f"% Invalid input detected at '^' marker. ({command})")

    def disconnect(self) -> None:
        pass
