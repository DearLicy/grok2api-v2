"""Shared runtime exceptions and small helpers used by the registration engine."""
from __future__ import annotations

import time
from typing import Callable, Optional


class RegistrationCancelled(RuntimeError):
    pass


class AccountRetryNeeded(RuntimeError):
    pass


class ProtocolFallback(RuntimeError):
    """A protocol attempt stopped before account creation and is browser-safe."""

    pass


class ProtocolOutcomeUncertain(AccountRetryNeeded):
    """The create request may have reached xAI and must never be replayed."""

    pass


def raise_if_cancelled(cancel_callback: Optional[Callable[[], bool]]) -> None:
    if cancel_callback is not None and cancel_callback():
        raise RegistrationCancelled("任务已停止")


def sleep_with_cancel(seconds: float, cancel_callback: Optional[Callable[[], bool]]) -> None:
    deadline = time.time() + max(float(seconds), 0.0)
    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        time.sleep(min(0.2, max(deadline - time.time(), 0.0)))
    raise_if_cancelled(cancel_callback)


def log_exception(
    label: str,
    exc: BaseException,
    log_callback: Optional[Callable[[str], None]] = None,
) -> None:
    if log_callback is not None:
        log_callback(f"[!] {label}: {exc}")
