"""Vòng lặp tự động kiểm tra + gửi mail khi trạng thái đổi.

Hai cách dùng:
  run_once(...)  : chạy 1 lần rồi thoát (dùng với cron / Task Scheduler, state lưu ở file).
  watch(...)     : chạy liên tục mỗi N giây (daemon / service).
"""
from __future__ import annotations

import logging
import signal
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional, Sequence

from .state import Change, DeviceResult, StateStore, severity

log = logging.getLogger("netcheck.monitor")

EXIT_OK, EXIT_WARNING, EXIT_CRITICAL, EXIT_MAIL_FAILED = 0, 1, 2, 3


@dataclass
class CheckOutcome:
    results: list[DeviceResult]
    report_path: Optional[str] = None


Notifier = Callable[[Sequence[Change], Sequence[DeviceResult], Optional[str]], None]


def overall_exit_code(results: Sequence[DeviceResult]) -> int:
    worst = max((severity(r.status) for r in results), default=0)
    return {0: EXIT_OK, 1: EXIT_WARNING}.get(worst, EXIT_CRITICAL)


def run_once(check_fn: Callable[[], CheckOutcome], store: StateStore,
             notifier: Optional[Notifier] = None, now: Optional[datetime] = None) -> int:
    outcome = check_fn()
    changes = store.update(outcome.results, now)

    for c in changes:
        log.warning("THAY ĐỔI %s: %s -> %s [%s]", c.device, c.old, c.new, c.kind)

    if changes and notifier is not None:
        try:
            notifier(changes, outcome.results, outcome.report_path)
        except Exception:
            log.exception("Gửi mail thất bại - KHÔNG lưu state, lần chạy sau sẽ báo lại")
            store.load()                      # bỏ thay đổi trong bộ nhớ
            return EXIT_MAIL_FAILED
    store.save()
    return overall_exit_code(outcome.results)


def watch(check_fn: Callable[[], CheckOutcome], store: StateStore,
          notifier: Optional[Notifier], interval_s: float,
          max_runs: Optional[int] = None, error_alert_after: int = 3,
          stop_event: Optional[threading.Event] = None) -> int:
    stop = stop_event or threading.Event()
    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, lambda *_: stop.set())
            except (ValueError, OSError):
                pass

    code, runs, errors = EXIT_OK, 0, 0
    log.info("Bắt đầu giám sát, chu kỳ %ss", interval_s)
    while not stop.is_set():
        started = time.monotonic()
        try:
            code = run_once(check_fn, store, notifier)
            errors = 0
        except Exception as exc:
            errors += 1
            log.exception("Lần kiểm tra thất bại (%d liên tiếp)", errors)
            # Chính công cụ giám sát hỏng cũng phải báo, nhưng chỉ 1 lần mỗi chuỗi lỗi.
            if notifier is not None and errors == error_alert_after:
                synthetic = Change("NetCheck", "degraded", "OK", "CRITICAL",
                                   [f"Công cụ giám sát lỗi {errors} lần liên tiếp: {exc}"],
                                   added=[f"Công cụ giám sát lỗi {errors} lần liên tiếp: {exc}"])
                try:
                    notifier([synthetic], [DeviceResult("NetCheck", "CRITICAL", synthetic.findings)], None)
                except Exception:
                    log.exception("Không gửi được cảnh báo lỗi giám sát")
        runs += 1
        if max_runs is not None and runs >= max_runs:
            break
        stop.wait(max(0.0, interval_s - (time.monotonic() - started)))
    log.info("Dừng giám sát")
    return code