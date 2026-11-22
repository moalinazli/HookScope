"""Small, responsive terminal branding. Never emitted to machine-readable output."""

from __future__ import annotations

import os
import shutil
import sys
from typing import TextIO

# A terminal approximation of the author's N monogram, not a bitmap conversion.
BLOCK_MARK = (
    "    ▲          ",
    "██╗   ██╗     ",
    "███╗  ██║     ",
    "██╔██╗██║     ",
    "██║╚████║     ",
    "╚═╝ ╚═══╝     ",
    "    ◆          ",
)
PLAIN_MARK = (
    "     /\\        ",
    "N\\     |       ",
    "N \\    |       ",
    "N  \\   |       ",
    "N   \\  |       ",
    "N    \\ |       ",
    "     <>         ",
)
CAPTIONS = (
    "HOOKSCOPE",
    "PYTHON STARTUP AUDITOR",
    "MITRE ATT&CK T1546.018",
    "OFFLINE  /  EVIDENCE-FIRST",
    "",
    "NAZLABADI",
    "Mohammad Ali Nazlabadi",
)


def render(*, stream: TextIO | None = None, force: bool = False,
           no_color: bool = False, ascii_only: bool = False,
           width: int | None = None, version: str = "") -> bool:
    """Write the banner only for a TTY unless explicitly forced.

    Under TERM=dumb or a very narrow display use a compact ASCII line.
    """
    stream = stream if stream is not None else sys.stdout
    is_tty = bool(getattr(stream, "isatty", lambda: False)())
    if not force and not is_tty:
        return False
    width = width if width is not None else shutil.get_terminal_size((80, 24)).columns
    if width < 24:
        stream.write("HookScope" + (" " + version if version else "") + "\n")
        return True
    color = (is_tty and not no_color and "NO_COLOR" not in os.environ
             and os.environ.get("TERM", "") != "dumb")
    end = "\x1b[0m" if color else ""
    def tone(text: str, code: str) -> str:
        return ("\x1b[" + code + "m" + text + end) if color else text
    if width < 42 or os.environ.get("TERM") == "dumb":
        stream.write(tone("◆", "38;5;179") + " HOOKSCOPE " + (version + " " if version else "") + "\n")
        stream.write("  PYTHON STARTUP AUDITOR / T1546.018\n")
        stream.write("  NAZLABADI\n")
        return True
    mark = PLAIN_MARK if ascii_only or width < 64 else BLOCK_MARK
    for i, (shape, caption) in enumerate(zip(mark, CAPTIONS)):
        tag = "38;5;179" if i in (5, 6) else "97"
        label = "38;5;179" if i in (5, 6) else ("38;5;80" if i == 0 else "90")
        stream.write(tone(shape, tag) + "  " + tone(caption, label) + "\n")
    if version:
        stream.write(tone(" " * 18 + version + "  •  Read-only scan by default", "90") + "\n")
    return True
