"""Composable preflight result helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PreflightCheck:
    """One named preflight check result."""

    name: str
    passed: bool
    messages: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "passed": self.passed,
            "messages": list(self.messages),
        }


@dataclass(frozen=True)
class PreflightReport:
    """Aggregate preflight report."""

    checks: tuple[PreflightCheck, ...]
    optional_checks: tuple[PreflightCheck, ...] = ()

    @property
    def passed(self) -> bool:
        return all(check.passed for check in self.checks)

    @property
    def failures(self) -> tuple[str, ...]:
        messages: list[str] = []
        for check in self.checks:
            if not check.passed:
                messages.extend(check.messages or (f"{check.name} failed",))
        return tuple(messages)

    @property
    def optional_failures(self) -> tuple[str, ...]:
        messages: list[str] = []
        for check in self.optional_checks:
            if not check.passed:
                messages.extend(check.messages or (f"{check.name} failed",))
        return tuple(messages)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "passed": self.passed,
            "checks": [check.to_dict() for check in self.checks],
        }
        if self.optional_checks:
            payload["optional_checks"] = [check.to_dict() for check in self.optional_checks]
        return payload


def check_from_exit_code(name: str, exit_code: int, failure_message: str) -> PreflightCheck:
    """Create a check result from a process-style exit code."""
    if exit_code == 0:
        return PreflightCheck(name=name, passed=True)
    return PreflightCheck(name=name, passed=False, messages=(failure_message,))


def check_from_failures(name: str, failures: list[str] | tuple[str, ...]) -> PreflightCheck:
    """Create a check result from a list of failure messages."""
    normalized = tuple(failures)
    return PreflightCheck(name=name, passed=not normalized, messages=normalized)
