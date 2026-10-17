from __future__ import annotations

import json
import sys

from rich.console import Console


class _JsonStreamConsole:
    def __init__(self):
        self.enabled = True

    def log(self, msg: str, **kw) -> None:
        sys.stdout.write(json.dumps({"event": "log", "message": msg}) + "\n")
        sys.stdout.flush()

    def print(self, *a, **kw) -> None:
        text = " ".join(str(x) for x in a)
        sys.stdout.write(json.dumps({"event": "out", "message": text}) + "\n")
        sys.stdout.flush()


class _QuietConsole:
    def log(self, msg: str, **kw) -> None:
        return

    def print(self, *a, **kw) -> None:
        return


def get_console(quiet: bool = False, no_color: bool = False, plain: bool = False):
    if quiet:
        return _QuietConsole()
    return Console(
        no_color=no_color,
        force_terminal=not plain,
        highlight=False,
        soft_wrap=False,
    )


def get_json_stream_console():
    return _JsonStreamConsole()
