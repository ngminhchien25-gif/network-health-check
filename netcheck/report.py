"""HTML (Jinja2) and PDF (xhtml2pdf, optional) report rendering."""
from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .config import AppConfig
from .models import DeviceReport, Severity

log = logging.getLogger(__name__)
TEMPLATE_DIR = Path(__file__).parent / "templates"


def summarize(reports: list[DeviceReport]) -> dict:
    """Aggregate numbers for the dashboard cards, subject line and exit code."""
    count = lambda sev: sum(1 for r in reports if r.status == sev)  # noqa: E731
    return {
        "total": len(reports),
        "ok": count(Severity.OK),
        "warning": count(Severity.WARNING),
        "critical": count(Severity.CRITICAL),
        "unreachable": sum(1 for r in reports if not r.reachable),
        "overall": max((r.status for r in reports), default=Severity.OK),
    }


def compact_path(hops: list[tuple[int, str]]) -> str:
    """Join hop addresses; consecutive non-responding hops collapse to '* (xN)'."""
    parts: list[str] = []
    stars = 0
    for _, ip in hops + [(0, "")]:
        if ip == "*":
            stars += 1
            continue
        if stars:
            parts.append("*" if stars == 1 else f"* (x{stars})")
            stars = 0
        if ip:
            parts.append(ip)
    return " \u2192 ".join(parts)


def render_html(reports: list[DeviceReport], cfg: AppConfig, generated_at: datetime, compact: bool = False) -> str:
    """compact=True drops raw CLI output (used for the e-mail body and the PDF)."""
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["compact_path"] = compact_path
    return env.get_template("report.html.j2").render(
        title=cfg.report.title,
        generated_at=generated_at.strftime("%Y-%m-%d %H:%M:%S"),
        reports=reports,
        summary=summarize(reports),
        compact=compact,
        Severity=Severity,
    )


def html_to_pdf(html: str, dest: Path) -> bool:
    """Returns False (and logs why) when xhtml2pdf is missing or conversion fails."""
    try:
        from xhtml2pdf import pisa
    except ImportError:
        log.warning("xhtml2pdf not installed -> PDF skipped (pip install xhtml2pdf)")
        return False
    with dest.open("wb") as fh:
        result = pisa.CreatePDF(html, dest=fh, encoding="utf-8")
    if result.err:
        log.error("PDF generation reported %s error(s)", result.err)
        dest.unlink(missing_ok=True)
        return False
    return True
