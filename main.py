#!/usr/bin/env python3
"""NetCheck entry point.

Exit codes (handy for cron / CI):  0 = all OK | 1 = warnings | 2 = critical | 3 = report e-mail failed
"""
from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime
from pathlib import Path

from netcheck.collector import collect_all
from netcheck.config import ConfigError, load_config, load_dotenv
from netcheck.connector import DemoConnector, NetmikoConnector
from netcheck.mailer import send_report
from netcheck.models import Severity
from netcheck.report import html_to_pdf, render_html, summarize

ROOT = Path(__file__).resolve().parent
log = logging.getLogger("netcheck")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Automated network health check -> HTML/PDF report -> e-mail")
    p.add_argument("-c", "--config", default=str(ROOT / "config" / "config.yaml"), help="YAML config file")
    p.add_argument("--demo", action="store_true", help="use canned outputs instead of real SSH (no devices needed)")
    p.add_argument("--only", help="comma separated device names to check, e.g. R1,SW1")
    p.add_argument("--no-email", action="store_true", help="generate the report but do not send it")
    p.add_argument("--no-pdf", action="store_true", help="skip PDF generation")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    return p.parse_args(argv)


def setup_logging(verbose: bool) -> None:
    (ROOT / "logs").mkdir(exist_ok=True)
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(threadName)s %(name)s: %(message)s",
        handlers=[logging.StreamHandler(), logging.FileHandler(ROOT / "logs" / "netcheck.log", encoding="utf-8")],
    )
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    logging.getLogger("netmiko").setLevel(logging.WARNING)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    setup_logging(args.verbose)
    load_dotenv(ROOT / ".env")

    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        log.error("Configuration error: %s", exc)
        return 64

    devices = cfg.devices
    if args.only:
        wanted = {n.strip() for n in args.only.split(",")}
        devices = [d for d in devices if d.name in wanted]
        if not devices:
            log.error("--only matched no device (known: %s)", ", ".join(d.name for d in cfg.devices))
            return 64

    factory = DemoConnector if args.demo else NetmikoConnector
    reports = collect_all(devices, cfg, factory)

    now = datetime.now()
    out_dir = Path(cfg.report.output_dir)
    out_dir = out_dir if out_dir.is_absolute() else ROOT / out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = now.strftime("%Y%m%d_%H%M%S")

    html_path = out_dir / f"netcheck_{stamp}.html"
    html_path.write_text(render_html(reports, cfg, now), encoding="utf-8")
    attachments = [html_path]
    log.info("HTML report: %s", html_path)

    compact_html = render_html(reports, cfg, now, compact=True)   # no raw CLI dumps
    if cfg.report.pdf and not args.no_pdf:
        pdf_path = out_dir / f"netcheck_{stamp}.pdf"
        if html_to_pdf(compact_html, pdf_path):
            attachments.append(pdf_path)
            log.info("PDF report:  %s", pdf_path)

    s = summarize(reports)
    lines = [f"{r.name:<8}{r.host:<16}{r.status.name:<9}{len([f for f in r.findings if f.severity >= Severity.WARNING])} issue(s)"
             for r in reports]
    print("\n" + "\n".join(lines) + f"\n\nOverall: {s['overall'].name}\n")

    exit_code = {Severity.OK: 0, Severity.INFO: 0, Severity.WARNING: 1, Severity.CRITICAL: 2}[s["overall"]]

    if not args.no_email:
        subject = (f"[NetCheck] {s['overall'].name}: {s['critical']} critical, {s['warning']} warning, "
                   f"{s['ok']} ok - {now:%Y-%m-%d %H:%M}")
        text = "NetCheck summary\n\n" + "\n".join(lines) + "\n\nFull report attached."
        try:
            send_report(cfg.smtp, subject, text, compact_html, attachments)
        except Exception as exc:  # noqa: BLE001 - SMTP/network/auth problems
            log.error("Could not send e-mail: %s", exc)
            return 3
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
