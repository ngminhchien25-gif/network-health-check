"""Gửi mail khi có thay đổi trạng thái. Dùng đúng biến môi trường như README (.env)."""
from __future__ import annotations

import html
import logging
import os
import smtplib
import ssl
import time
from email.message import EmailMessage
from pathlib import Path
from typing import Optional, Sequence

from .state import Change, DeviceResult, severity

log = logging.getLogger("netcheck.notify")

ICON = {"OK": "🟢", "WARNING": "🟡", "CRITICAL": "🔴"}
KIND_TEXT = {
    "new": "Phát hiện lỗi",
    "degraded": "Xấu đi",
    "improved": "Đã cải thiện (chưa hết lỗi)",
    "recovered": "Đã phục hồi",
    "findings_changed": "Thay đổi chi tiết lỗi",
    "reminder": "Nhắc lại: vẫn đang lỗi",
}
MAX_ATTACH_BYTES = 8 * 1024 * 1024


def _env_bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def fmt_duration(seconds: Optional[float]) -> str:
    if seconds is None:
        return ""
    s = int(seconds)
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    return f"{h}h{m:02d}m" if h else (f"{m}m{sec:02d}s" if m else f"{sec}s")


def build_subject(changes: Sequence[Change]) -> str:
    if all(c.kind == "recovered" for c in changes):
        level = "RECOVERED"
    else:
        level = max((c.new for c in changes if c.new != "OK"), key=severity, default="OK")
    first = changes[0]
    extra = f" (+{len(changes) - 1} thiết bị khác)" if len(changes) > 1 else ""
    old = first.old or "new"
    return f"[NetCheck][{level}] {first.device}: {old} -> {first.new}{extra}"


def build_text(changes: Sequence[Change], results: Sequence[DeviceResult]) -> str:
    lines = ["NetCheck - thay đổi trạng thái mạng", ""]
    for c in changes:
        lines.append(f"{ICON.get(c.new, '')} {c.device}: {c.old or '-'} -> {c.new}  [{KIND_TEXT.get(c.kind, c.kind)}]")
        if c.kind == "recovered" and c.duration_s is not None:
            lines.append(f"   Thời gian gián đoạn: {fmt_duration(c.duration_s)}")
        if c.kind == "reminder" and c.duration_s is not None:
            lines.append(f"   Đã lỗi liên tục: {fmt_duration(c.duration_s)}")
        for f in c.added:
            lines.append(f"   + {f}")
        for f in c.resolved:
            lines.append(f"   - (đã hết) {f}")
        if not c.added and c.new != "OK" and c.kind in ("reminder",):
            for f in c.findings:
                lines.append(f"   * {f}")
    lines += ["", "Tổng quan hiện tại:"]
    for r in results:
        lines.append(f"  {ICON.get(r.status.upper(), '')} {r.name}: {r.status.upper()}")
    return "\n".join(lines)


def build_html(changes: Sequence[Change], results: Sequence[DeviceResult]) -> str:
    color = {"OK": "#2e7d32", "WARNING": "#f9a825", "CRITICAL": "#c62828"}
    rows = []
    for c in changes:
        items = "".join(f"<li>+ {html.escape(f)}</li>" for f in c.added)
        items += "".join(f"<li><s>{html.escape(f)}</s> (đã hết)</li>" for f in c.resolved)
        if c.kind == "reminder":
            items += "".join(f"<li>{html.escape(f)}</li>" for f in c.findings)
        dur = ""
        if c.duration_s is not None:
            label = "Thời gian gián đoạn" if c.kind == "recovered" else "Đã lỗi liên tục"
            dur = f"<div><small>{label}: {fmt_duration(c.duration_s)}</small></div>"
        rows.append(
            f"<div style='border-left:6px solid {color.get(c.new, '#c62828')};padding:8px 12px;margin:10px 0;background:#fafafa'>"
            f"<b>{html.escape(c.device)}</b>: {html.escape(c.old or '-')} &rarr; "
            f"<b style='color:{color.get(c.new, '#c62828')}'>{html.escape(c.new)}</b> "
            f"<small>({html.escape(KIND_TEXT.get(c.kind, c.kind))})</small>{dur}<ul>{items}</ul></div>")
    overview = "".join(
        f"<tr><td style='padding:2px 10px'>{html.escape(r.name)}</td>"
        f"<td style='padding:2px 10px;color:{color.get(r.status.upper(), '#c62828')}'><b>{html.escape(r.status.upper())}</b></td></tr>"
        for r in results)
    return (f"<html><body style='font-family:Arial,sans-serif'><h3>NetCheck - thay đổi trạng thái mạng</h3>"
            f"{''.join(rows)}<h4>Tổng quan hiện tại</h4><table>{overview}</table></body></html>")


class SmtpNotifier:
    """Callable: notifier(changes, results, report_path=None). Ném exception nếu gửi thất bại."""

    def __init__(self, host: str, port: int, sender: str, recipients: Sequence[str],
                 user: str = "", password: str = "", starttls: bool = False, use_ssl: bool = False,
                 timeout: float = 20, retries: int = 3, retry_delay: float = 5):
        if not recipients:
            raise ValueError("Chưa cấu hình người nhận (ADMIN_EMAIL)")
        self.host, self.port, self.sender = host, port, sender
        self.recipients = list(recipients)
        self.user, self.password = user, password
        self.starttls, self.use_ssl = starttls, use_ssl
        self.timeout, self.retries, self.retry_delay = timeout, max(1, retries), retry_delay

    @classmethod
    def from_env(cls) -> "SmtpNotifier":
        recipients = [x.strip() for x in os.getenv("ADMIN_EMAIL", "").split(",") if x.strip()]
        user = os.getenv("SMTP_USER", "")
        return cls(
            host=os.getenv("SMTP_HOST", "localhost"),
            port=int(os.getenv("SMTP_PORT", "1025")),
            sender=os.getenv("SMTP_FROM") or user or "netcheck@localhost",
            recipients=recipients, user=user, password=os.getenv("SMTP_PASSWORD", ""),
            starttls=_env_bool("SMTP_STARTTLS"), use_ssl=_env_bool("SMTP_SSL"))

    def _message(self, changes, results, report_path) -> EmailMessage:
        msg = EmailMessage()
        msg["Subject"] = build_subject(changes)
        msg["From"] = self.sender
        msg["To"] = ", ".join(self.recipients)
        msg.set_content(build_text(changes, results))
        msg.add_alternative(build_html(changes, results), subtype="html")
        if report_path:
            p = Path(report_path)
            if p.is_file() and p.stat().st_size <= MAX_ATTACH_BYTES:
                msg.add_attachment(p.read_bytes(), maintype="text", subtype="html", filename=p.name)
        return msg

    def _send_once(self, msg: EmailMessage) -> None:
        ctx = ssl.create_default_context()
        if self.use_ssl:
            server = smtplib.SMTP_SSL(self.host, self.port, timeout=self.timeout, context=ctx)
        else:
            server = smtplib.SMTP(self.host, self.port, timeout=self.timeout)
        with server:
            if self.starttls and not self.use_ssl:
                server.starttls(context=ctx)
            if self.user:
                server.login(self.user, self.password)
            server.send_message(msg)

    def __call__(self, changes: Sequence[Change], results: Sequence[DeviceResult],
                 report_path: Optional[str] = None) -> None:
        msg = self._message(changes, results, report_path)
        last: Optional[Exception] = None
        for attempt in range(1, self.retries + 1):
            try:
                self._send_once(msg)
                log.info("Đã gửi mail: %s", msg["Subject"])
                return
            except (smtplib.SMTPException, OSError) as exc:
                last = exc
                log.warning("Gửi mail lần %d/%d thất bại: %s", attempt, self.retries, exc)
                if attempt < self.retries:
                    time.sleep(self.retry_delay)
        raise RuntimeError(f"Không gửi được mail sau {self.retries} lần: {last}")