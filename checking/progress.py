"""Live progress display on stderr.

    / [14/37] java       3.4s  handshakes 5/12  /Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home

A background thread redraws the line ten times a second so the spinner and
the clock move while a slow probe (a JVM start, a Spotlight query) runs.
Text wider than the terminal is cut in the middle so the line stays on one
row and the redraw is a plain carriage return.  Disabled
when stderr is not a terminal, so piped and redirected output stay clean.
"""

from __future__ import annotations

import shutil
import sys
import threading
import time

SPINNER = "|/-\\"


class Progress:
    def __init__(self) -> None:
        self.enabled = False
        self._lock = threading.Lock()
        self._step = ""
        self._detail = ""
        self._started = time.monotonic()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._tick = 0
        self._rows = 0  # terminal rows the last draw occupied
        self._io = threading.Lock()

    def start(self, enabled: bool | None = None) -> None:
        self.enabled = sys.stderr.isatty() if enabled is None else enabled
        self._started = time.monotonic()
        if not self.enabled or self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def step(self, index: int, total: int, label: str) -> None:
        width = len(str(total))
        with self._lock:
            self._step = f"[{index:>{width}}/{total}] {label:<9}"
            self._detail = ""
        if self._thread is not None:
            self._draw()

    def detail(self, text: str) -> None:
        with self._lock:
            self._detail = text

    def done(self) -> None:
        if self._thread is not None:
            self._stop.set()
            self._thread.join(1)
            self._thread = None
        if self.enabled:
            sys.stderr.write(self._rewind())
            sys.stderr.flush()
            self._rows = 0

    def emit(self, text: str) -> None:
        """Print a line to stdout above the progress line."""
        with self._io:
            if self.enabled and self._rows:
                sys.stderr.write(self._rewind())
                sys.stderr.flush()
                self._rows = 0
            print(text, flush=True)

    def _rewind(self) -> str:
        """Back to the first row of the previous draw, then clear below."""
        up = f"\033[{self._rows - 1}A" if self._rows > 1 else ""
        return f"\r{up}\033[J"

    def _run(self) -> None:
        while not self._stop.wait(0.1):
            self._draw()

    def _draw(self) -> None:
        with self._lock:
            step, detail = self._step, self._detail
        self._tick += 1
        clock = f"{time.monotonic() - self._started:5.1f}s"
        columns = max(shutil.get_terminal_size((100, 20)).columns, 1)
        text = f"{SPINNER[self._tick % len(SPINNER)]} {step} {clock}  {detail}".rstrip()
        if len(text) >= columns:
            keep = columns - 2
            text = text[:keep // 2] + "…" + text[len(text) - (keep - keep // 2):]
        with self._io:
            sys.stderr.write(self._rewind() + text)
            sys.stderr.flush()
            self._rows = 1


progress = Progress()
