"""Run the Steplight detectors on recorded runs by calling the Node CLI (``steplight analyze``).

Python runs are written with ``meta.analyzed = false``; the detectors live in the Node package. Every
``steplight`` command analyzes unanalyzed runs by itself, so this helper is only for scripts that want the flags
written right away (for example before reading ``steps.jsonl`` directly). It runs a local program and makes no
network call of its own.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from ._log import log_error


def analyze(
    runs_dir: str | Path = ".steplight/runs", run_id: str | None = None, *, command: list[str] | None = None
) -> bool:
    """Analyze one run (or all unanalyzed runs) with the ``steplight`` CLI; True on success.

    ``command`` is the CLI to run; by default ``steplight`` on ``PATH`` (``npm i -D steplight``), else ``npx --no-install steplight``.
    Never raises.
    """
    if command is None:
        found = shutil.which("steplight")
        npx = shutil.which("npx")
        if found:
            command = [found]
        elif npx:
            command = [npx, "--no-install", "steplight"]
        else:
            log_error(
                "analyze",
                "the steplight CLI was not found (npm i -D steplight); commands such as `steplight check` analyze runs themselves",
            )
            return False
    args = [*command, "analyze", run_id if run_id else "--all", "--dir", str(runs_dir)]
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=300, check=False)  # noqa: S603
    except (OSError, subprocess.SubprocessError) as err:
        log_error("analyze", err)
        return False
    if result.returncode != 0:
        log_error("analyze", result.stderr.strip() or result.stdout.strip())
    return result.returncode == 0
