"""Run with python -m fwrule; no privileges or live firewall access required."""

import argparse
import os
from pathlib import Path
import stat
import sys

from . import __version__
from .analysis import analyze
from .model import MAX_BYTES
from .parser import InputError, parse
from .report import render_html, render_json, render_text, safe_text


def main(argv: list[str] | None = None) -> int:
    """Analyze one regular UTF-8 file; never overwrite input or existing reports."""
    parser = argparse.ArgumentParser(description="Explain unreachable rules in an offline IPv4 iptables-save filter export.")
    parser.add_argument("input", type=Path, help="UTF-8 iptables-save file (optional -c counters)")
    parser.add_argument("--format", choices=("text", "json", "html"), default="text")
    parser.add_argument("-o", "--output", type=Path, help="new report file; existing files are never overwritten")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)
    try:
        if not args.input.is_file():
            raise InputError("input must be a regular file")
        with args.input.open("rb") as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise InputError("input must be a regular file")
            payload = source.read(MAX_BYTES + 1)
        if len(payload) > MAX_BYTES:
            raise InputError("input exceeds 2 MiB")
        report = analyze(parse(payload.decode("utf-8-sig")))
        rendered = {"text": render_text, "json": render_json, "html": render_html}[args.format](report)
        if args.output:
            if args.output.resolve() == args.input.resolve():
                raise InputError("output cannot be the input file")
            with args.output.open("x", encoding="utf-8", newline="\n") as target:
                target.write(rendered)
        else:
            sys.stdout.write(rendered)
        return 3 if report["summary"]["inconclusive"] or report["warnings"] else 0
    except (InputError, OSError, UnicodeError) as error:
        print("fwrule: " + safe_text(str(error)), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
