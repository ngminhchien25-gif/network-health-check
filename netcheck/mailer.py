"""SMTP delivery of the report (HTML body + HTML/PDF attachments)."""
from __future__ import annotations

import logging
import mimetypes
import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path

from .config import SmtpConfig

log = logging.getLogger(__name__)


def send_report(smtp: SmtpConfig, subject: str, text_body: str, html_body: str, attachments: list[Path]) -> None:
    if not smtp.recipients:
        raise ValueError("smtp.recipients is empty")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = smtp.sender
    msg["To"] = ", ".join(smtp.recipients)
    msg.set_content(text_body)                       # plain-text fallback
    msg.add_alternative(html_body, subtype="html")   # rich body (compact report)

    for path in attachments:
        ctype, _ = mimetypes.guess_type(path.name)
        maintype, _, subtype = (ctype or "application/octet-stream").partition("/")
        msg.add_attachment(path.read_bytes(), maintype=maintype, subtype=subtype, filename=path.name)

    context = ssl.create_default_context()
    client: smtplib.SMTP
    if smtp.use_ssl:                                  # implicit TLS (usually port 465)
        client = smtplib.SMTP_SSL(smtp.host, smtp.port, timeout=smtp.timeout, context=context)
    else:
        client = smtplib.SMTP(smtp.host, smtp.port, timeout=smtp.timeout)
    with client:
        if smtp.use_starttls and not smtp.use_ssl:    # explicit TLS (usually port 587)
            client.starttls(context=context)
        if smtp.username:
            client.login(smtp.username, smtp.password)
        client.send_message(msg)
    log.info("Report e-mailed to %s via %s:%s", msg["To"], smtp.host, smtp.port)
