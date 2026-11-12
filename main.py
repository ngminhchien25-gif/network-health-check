#!/usr/bin/env python3
"""NetCheck entry point.

Exit codes (handy for cron / CI):  0 = all OK | 1 = warnings | 2 = critical | 3 = report e-mail failed

Modes
  (default)    one run -> HTML/PDF report -> e-mail every time
  --on-change  one run, e-mail ONLY when a device's status changed (use with cron / Task Scheduler)
  --watch      run forever every --interval seconds, e-mail ONLY on status change
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
from netcheck.monitor import CheckOutcome, run_once, watch
from netcheck.notify import build_html, build_subject, build_text
from netcheck.report import html_to_pdf, render_html, summarize
from netcheck.state import DeviceResult, StateStore

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

    m = p.add_argument_group("automatic monitoring (e-mail only when status changes)")
    m.add_argument("--watch", action="store_true", help="run continuously every --interval seconds")
    m.add_argument("--on-change", action="store_true", help="run once, e-mail only on change (for cron)")
    m.add_argument("--interval", type=int, default=300, help="seconds between checks in --watch mode (default 300)")
    m.add_argument("--confirm", type=int, default=2,
                   help="consecutive runs needed to confirm a new status, avoids flapping (default 2, 1 = immediate)")
    m.add_argument("--reminder-hours", type=float, default=0,
                   help="re-send a reminder every N hours while still failing (0 = off)")
    m.add_argument("--state-file", default=str(ROOT / "logs" / "state.json"), help="where last-known status is kept")
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


# ---------------------------------------------------------------- building blocks
def collect(args, cfg, devices):
    """Run all checks. Returns (reports, now, summary, console_lines) and prints the console table."""
    factory = DemoConnector if args.demo else NetmikoConnector
    reports = collect_all(devices, cfg, factory)
    now = datetime.now()
    s = summarize(reports)
    lines = [f"{r.name:<8}{r.host:<16}{r.status.name:<9}{len([f for f in r.findings if f.severity >= Severity.WARNING])} issue(s)"
             for r in reports]
    print("\n" + "\n".join(lines) + f"\n\nOverall: {s['overall'].name}\n")
    return reports, now, s, lines


def write_report_files(args, cfg, reports, now):
    """Write HTML (+PDF) to the report dir. Returns (attachments, compact_html)."""
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
    return attachments, compact_html


def _status_name(sev) -> str:
    """Severity -> 'OK' | 'WARNING' | 'CRITICAL' (INFO counts as OK, like the exit code does)."""
    return "OK" if sev < Severity.WARNING else sev.name


def _issue_texts(report) -> list[str]:
    out = []
    for f in report.findings:
        if f.severity >= Severity.WARNING:
            text = next((str(getattr(f, a)) for a in ("message", "text", "description", "detail", "title")
                         if getattr(f, a, None)), str(f))
            out.append(f"{f.severity.name}: {text}")
    return out


# ---------------------------------------------------------------- modes
def run_single(args, cfg, devices) -> int:
    reports, now, s, lines = collect(args, cfg, devices)
    attachments, compact_html = write_report_files(args, cfg, reports, now)
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


def run_monitor(args, cfg, devices) -> int:
    """--watch / --on-change: check, compare with last known state, e-mail only on change."""
    if args.watch and args.interval < 10:
        log.error("--interval must be >= 10 seconds")
        return 64

    latest: dict = {}

    def check_fn() -> CheckOutcome:
        reports, now, _s, _lines = collect(args, cfg, devices)
        latest.update(reports=reports, now=now)
        return CheckOutcome([DeviceResult(r.name, _status_name(r.status), _issue_texts(r)) for r in reports])

    def notifier(changes, results, _report_path) -> None:
        # Report files are only written when an alert is actually sent (no file spam every cycle).
        attachments = []
        if latest.get("reports") and any(c.device != "NetCheck" for c in changes):
            attachments, _ = write_report_files(args, cfg, latest["reports"], latest["now"])
        send_report(cfg.smtp, build_subject(changes), build_text(changes, results),
                    build_html(changes, results), attachments)

    store = StateStore(args.state_file, confirm_runs=args.confirm,
                       reminder_after_s=args.reminder_hours * 3600 or None)
    active_notifier = None if args.no_email else notifier

    if args.watch:
        return watch(check_fn, store, active_notifier, args.interval)
    return run_once(check_fn, store, active_notifier)


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

    if args.watch or args.on_change:
        return run_monitor(args, cfg, devices)
    return run_single(args, cfg, devices)


if __name__ == "__main__":
    sys.exit(main())