"""Regenerate or verify only this project's synthetic committed demo reports.

Usage: python scripts/demo_reports.py [--check]
Inputs: samples/demo.rules. Outputs: samples/demo-report.{txt,json,html}.
Assumptions: run from any directory with Python 3.10+; synthetic fixture only.
Unlike the user CLI, regeneration deliberately replaces these fixed artifacts.
"""

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fwrule.analysis import analyze
from fwrule.parser import parse
from fwrule.report import render_html, render_json, render_text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="compare without writing")
    args = parser.parse_args()
    report = analyze(parse((ROOT / "samples/demo.rules").read_text(encoding="utf-8")))
    mismatches = []
    for extension, render in (("txt", render_text), ("json", render_json), ("html", render_html)):
        target = ROOT / "samples" / ("demo-report." + extension)
        content = render(report)
        if args.check:
            if not target.exists() or target.read_text(encoding="utf-8") != content:
                mismatches.append(target.name)
        else:
            target.write_text(content, encoding="utf-8", newline="\n")
    if mismatches:
        print("Stale reports: " + ", ".join(mismatches))
        return 1
    print("Demo reports " + ("match current code." if args.check else "regenerated."))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
