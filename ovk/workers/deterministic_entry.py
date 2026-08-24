"""Subprocess entry point for isolated deterministic/native Python evaluation."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def _install_isolation_audit_hook() -> None:
    """Enforce worker restrictions inside the Python evaluator process.

    Python audit hooks cover interpreter-level file opens, socket operations and
    subprocess creation. This is not advertised as a container boundary; it is
    the enforcement mechanism for the ``local-subprocess.v2`` Python profile.
    """
    deny_network = os.environ.get("OVK_WORKER_DENY_NETWORK") == "1"
    deny_writes = os.environ.get("OVK_WORKER_DENY_WRITES") == "1"

    if not deny_network and not deny_writes:
        return

    network_events = {
        "socket.__new__",
        "socket.bind",
        "socket.connect",
        "socket.getaddrinfo",
        "socket.gethostbyname",
        "socket.gethostbyaddr",
        "socket.getnameinfo",
    }

    def audit(event: str, args: tuple[object, ...]) -> None:
        if deny_network and (event in network_events or event.startswith("socket.")):
            raise PermissionError(f"OVK worker network access denied: {event}")
        if deny_writes and event == "open":
            # CPython audit open(path, mode, flags). Mode may be None for os.open.
            mode = str(args[1] or "") if len(args) > 1 else ""
            flags = int(args[2]) if len(args) > 2 and isinstance(args[2], int) else 0
            write_mode = any(char in mode for char in ("w", "a", "x", "+"))
            write_flags = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
            if write_mode or write_flags:
                raise PermissionError(f"OVK worker filesystem write denied: {args[0] if args else '<unknown>'}")
        if deny_writes and event in {
            "os.remove", "os.rename", "os.rmdir", "os.mkdir", "os.link", "os.symlink",
            "shutil.copyfile", "shutil.copymode", "shutil.copystat",
        }:
            raise PermissionError(f"OVK worker filesystem mutation denied: {event}")

    sys.addaudithook(audit)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run an OVK evaluator in an isolated worker process.")
    parser.add_argument("--evaluator-id", required=True)
    parser.add_argument("--payload-file", required=True)
    args = parser.parse_args(argv)

    # Read the parent-created immutable input before write-denial is installed;
    # read access remains permitted afterwards as well.
    payload = json.loads(Path(args.payload_file).read_text(encoding="utf-8"))
    _install_isolation_audit_hook()

    from ovk.core.deterministic_evaluators import evaluate_deterministic

    result = evaluate_deterministic(args.evaluator_id, payload)
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
