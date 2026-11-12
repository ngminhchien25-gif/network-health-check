"""Lưu trạng thái lần chạy trước và phát hiện thay đổi giữa các lần chạy.

Chỉ phụ thuộc thư viện chuẩn. Không biết gì về Netmiko / collector, nên test được độc lập.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

SEVERITY = {"OK": 0, "WARNING": 1, "CRITICAL": 2}


def severity(status: str) -> int:
    # Trạng thái lạ được coi là CRITICAL để không bỏ sót.
    return SEVERITY.get(str(status).upper(), 2)


def _norm_finding(text: str) -> str:
    """Thay số bằng '#' để 'latency 41ms' -> 'latency 43ms' không bị coi là thay đổi."""
    return re.sub(r"\d+(?:\.\d+)?", "#", text).strip().lower()


def _norm_set(findings: Iterable[str]) -> set[str]:
    return {_norm_finding(f) for f in findings}


@dataclass
class DeviceResult:
    """Kết quả một thiết bị trong một lần chạy (adapter từ analyzer của bạn)."""
    name: str
    status: str                      # "OK" | "WARNING" | "CRITICAL"
    findings: list[str] = field(default_factory=list)


@dataclass
class DeviceState:
    status: str
    findings: list[str]
    since: str                       # ISO time trạng thái hiện tại bắt đầu
    last_notified: Optional[str] = None
    pending_status: Optional[str] = None   # chống flapping
    pending_count: int = 0


@dataclass
class Change:
    device: str
    kind: str                        # new | degraded | improved | recovered | findings_changed | reminder
    old: Optional[str]
    new: str
    findings: list[str]
    added: list[str] = field(default_factory=list)      # finding mới xuất hiện
    resolved: list[str] = field(default_factory=list)   # finding đã hết
    duration_s: Optional[float] = None                  # thời gian ở trạng thái cũ (dùng cho recovered)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def _parse(s: str) -> datetime:
    return datetime.fromisoformat(s)


class StateStore:
    """JSON file lưu trạng thái mỗi thiết bị.

    confirm_runs     : số lần chạy liên tiếp phải thấy trạng thái mới mới báo (1 = báo ngay).
    reminder_after_s : nếu vẫn lỗi sau ngần này giây kể từ lần báo cuối thì nhắc lại (None/0 = tắt).
    """

    def __init__(self, path: str | os.PathLike, confirm_runs: int = 1,
                 reminder_after_s: Optional[float] = None):
        self.path = Path(path)
        self.confirm_runs = max(1, int(confirm_runs))
        self.reminder_after_s = reminder_after_s or None
        self.devices: dict[str, DeviceState] = {}
        self.load()

    # ---------- persistence ----------
    def load(self) -> None:
        self.devices = {}
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            for name, d in raw.get("devices", {}).items():
                self.devices[name] = DeviceState(**d)
        except (ValueError, TypeError, OSError):
            # File hỏng: giữ lại bản .bak rồi bắt đầu lại từ trạng thái trống.
            try:
                self.path.replace(self.path.with_suffix(".bak"))
            except OSError:
                pass
            self.devices = {}

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"devices": {n: asdict(d) for n, d in self.devices.items()}}
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, ensure_ascii=False)
            os.replace(tmp, self.path)          # ghi nguyên tử, an toàn khi bị ngắt giữa chừng
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    # ---------- core ----------
    def update(self, results: Iterable[DeviceResult], now: Optional[datetime] = None) -> list[Change]:
        now = now or _now()
        now_s = _iso(now)
        changes: list[Change] = []

        for res in results:
            status = res.status.upper()
            findings = list(res.findings)
            prev = self.devices.get(res.name)

            # Lần đầu thấy thiết bị: ghi baseline; chỉ báo nếu đã có lỗi.
            if prev is None:
                bad = status != "OK"
                self.devices[res.name] = DeviceState(
                    status=status, findings=findings, since=now_s,
                    last_notified=now_s if bad else None)
                if bad:
                    changes.append(Change(res.name, "new", None, status, findings, added=findings))
                continue

            if status != prev.status:
                # Chống flapping: cần confirm_runs lần liên tiếp mới xác nhận.
                if self.confirm_runs > 1:
                    if prev.pending_status == status:
                        prev.pending_count += 1
                    else:
                        prev.pending_status, prev.pending_count = status, 1
                    if prev.pending_count < self.confirm_runs:
                        continue
                old = prev.status
                if severity(status) > severity(old):
                    kind = "degraded"
                elif status == "OK":
                    kind = "recovered"
                else:
                    kind = "improved"
                old_norm, new_norm = _norm_set(prev.findings), _norm_set(findings)
                changes.append(Change(
                    res.name, kind, old, status, findings,
                    added=[f for f in findings if _norm_finding(f) not in old_norm],
                    resolved=[f for f in prev.findings if _norm_finding(f) not in new_norm],
                    duration_s=(now - _parse(prev.since)).total_seconds()))
                prev.status, prev.findings, prev.since = status, findings, now_s
                prev.last_notified = now_s
                prev.pending_status, prev.pending_count = None, 0
                continue

            # Cùng trạng thái.
            prev.pending_status, prev.pending_count = None, 0
            if status != "OK":
                old_norm, new_norm = _norm_set(prev.findings), _norm_set(findings)
                if old_norm != new_norm:
                    changes.append(Change(
                        res.name, "findings_changed", status, status, findings,
                        added=[f for f in findings if _norm_finding(f) not in old_norm],
                        resolved=[f for f in prev.findings if _norm_finding(f) not in new_norm]))
                    prev.last_notified = now_s
                elif (self.reminder_after_s and prev.last_notified and
                      (now - _parse(prev.last_notified)).total_seconds() >= self.reminder_after_s):
                    changes.append(Change(
                        res.name, "reminder", status, status, findings,
                        duration_s=(now - _parse(prev.since)).total_seconds()))
                    prev.last_notified = now_s
            prev.findings = findings

        return changes