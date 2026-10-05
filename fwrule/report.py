"""Terminal, JSON and self-contained HTML output with escaped source text."""

import html
import json
import re


def safe_text(value: str) -> str:
    """Escape non-ASCII and control characters, including directional controls."""
    return value.encode("unicode_escape").decode("ascii")


def render_text(report: dict) -> str:
    summary = report["summary"]
    lines = ["fwrule / offline firewall analysis", report["scope"],
             f"{summary['total_rules']} rules | {summary['proven_unreachable']} proven unreachable | {summary['inconclusive']} inconclusive", ""]
    for result in report["results"]:
        rule = result["rule"]
        lines.extend([f"{rule['chain']} #{rule['number']} / line {rule['line']} / {result['status']}",
                      "  " + safe_text(rule["raw"]), "  " + result["explanation"]])
        if result["zero_hit"]:
            lines.append("  Zero-hit observation; collection window unknown. Not removal advice.")
        if result.get("barrier_lines"):
            lines.append("  Unsupported rule lines: " + ", ".join(map(str, result["barrier_lines"])))
    lines.extend(["", "Coverage notes:"] + ["- " + warning for warning in report["warnings"] + report["limitations"]])
    return "\n".join(lines) + "\n"


def render_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=True) + "\n"


def render_html(report: dict) -> str:
    """Static responsive report; no script, external asset or network request."""
    def escape(value):
        return html.escape(safe_text(value))
    cards = []
    for result in report["results"]:
        rule = result["rule"]
        proof = result["blocker"] is not None
        kind = "proof" if proof else "unknown" if result["status"] == "inconclusive" else "neutral"
        evidence = ""
        if proof:
            blocker = result["blocker"]
            evidence = f'<details><summary>Inspect covering rule · line {blocker["line"]}</summary><pre>{escape(blocker["raw"])}</pre></details>'
        elif result.get("barrier_lines"):
            evidence = '<p class="note">Unsupported rule lines: ' + ", ".join(map(str, result["barrier_lines"])) + '</p>'
        elif result["overlap_count"]:
            evidence = '<p class="note">Overlap lines (up to 8 shown): ' + ", ".join(map(str, result["overlap_lines"])) + '</p>'
        observation = '<span class="counter">0 packets observed · window unknown</span>' if result["zero_hit"] else ""
        cards.append(f'<article class="rule {kind}"><div class="rule-top"><span class="location">{rule["chain"]} / RULE {rule["number"]} / LINE {rule["line"]}</span><span class="badge">{escape(result["status"].replace("_", " "))}</span></div><pre>{escape(rule["raw"])}</pre><p>{escape(result["explanation"])}</p>{observation}{evidence}</article>')
    summary = report["summary"]
    notes = "".join('<li>' + escape(note) + '</li>' for note in report["warnings"] + report["limitations"])
    replacements = {"TOTAL": str(summary["total_rules"]), "PROOFS": str(summary["proven_unreachable"]),
                    "UNKNOWN": str(summary["inconclusive"]), "ZERO": str(summary["zero_hit_observations"]),
                    "CARDS": "\n".join(cards) or '<p>No built-in filter rules to analyze.</p>', "NOTES": notes}
    # Substitute the trusted template once; tokens in quoted source remain data.
    return re.sub(r"@(TOTAL|PROOFS|UNKNOWN|ZERO|CARDS|NOTES)@", lambda match: replacements[match[1]], _HTML)


_HTML = '''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>fwrule — Offline firewall analysis</title><style>
:root{color-scheme:light;--paper:#f5f4f0;--ink:#171815;--muted:#62645f;--blue:#466d9f;--line:#d9dad3}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font-family:Arial,Helvetica,sans-serif}main{max-width:1060px;margin:auto;padding:54px 38px 40px}
header{display:flex;align-items:center;justify-content:space-between;gap:20px;padding-bottom:28px;border-bottom:1px solid var(--line)}.brand{display:flex;align-items:center;gap:17px;font-size:43px;letter-spacing:-2.5px;font-weight:900}.mark{width:48px;height:46px;background:linear-gradient(110deg,#658dbc 50%,#496589 50%);clip-path:polygon(0 0,30% 0,50% 60%,71% 0,100% 0,65% 100%,36% 100%)}.eyebrow,.location{font:10px/1.6 monospace;letter-spacing:1.4px;text-transform:uppercase}.eyebrow{color:var(--muted)}.hero{padding:54px 0 32px}.hero h1{font-size:clamp(38px,6vw,68px);line-height:1.06;letter-spacing:-3px;margin:0 0 22px;max-width:730px}.hero p{max-width:590px;color:var(--muted);font-size:16px;line-height:1.7}.stats{display:grid;grid-template-columns:repeat(3,1fr);border-top:1px solid var(--line);border-bottom:1px solid var(--line);margin:10px 0 38px}.stat{padding:22px 20px 22px 0}.stat+.stat{border-left:1px solid var(--line);padding-left:26px}.stat strong{font-size:37px;letter-spacing:-1px;display:block;margin-bottom:7px}.stat span{font:11px monospace;color:var(--muted)}.section-title{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:18px;gap:12px}.section-title h2{font-size:20px;margin:0}.rule{border:1px solid var(--line);border-left:3px solid #afb3ab;background:#fafaf7;border-radius:3px;margin:0 0 14px;padding:21px 24px}.rule.proof{border-left-color:var(--blue)}.rule.unknown{border-left-color:#91631d}.rule-top{display:flex;justify-content:space-between;gap:15px;align-items:center;flex-wrap:wrap}.location{color:var(--muted);letter-spacing:.8px}.badge{font:11px monospace;border-radius:3px;padding:6px 9px;background:#e9ece5;color:#394137}.proof .badge{background:#e2eaf4;color:#315884}.unknown .badge{background:#eee5d5;color:#76551c}pre{font:12px/1.7 Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere;margin:17px 0;color:#292e29}.rule p{font-size:13px;line-height:1.7;margin:9px 0;color:var(--muted)}.counter{display:inline-block;font:10px/1.6 monospace;color:#725523;background:#f1eadb;padding:5px 8px;margin:4px 0 10px}details{border-top:1px solid var(--line);margin-top:14px;padding-top:12px}summary{cursor:pointer;color:var(--blue);font-size:12px}summary:focus-visible{outline:2px solid var(--blue);outline-offset:4px}.coverage{margin:34px 0;padding:25px 0;border-top:1px solid var(--line);border-bottom:1px solid var(--line)}.coverage h2{font-size:18px}.coverage ul{padding-left:20px;color:var(--muted);font-size:13px;line-height:1.9}footer{font:10px/1.7 monospace;letter-spacing:1.5px;color:var(--muted)}
@media(max-width:600px){main{padding:28px 18px}header{align-items:flex-start}.brand{font-size:34px}.mark{width:35px;height:34px}.eyebrow{font-size:8px;text-align:right}.hero{padding-top:38px}.hero h1{letter-spacing:-1.5px}.stats{gap:0}.stat{padding:18px 8px 18px 0}.stat+.stat{padding-left:12px}.stat strong{font-size:29px}.stat span{font-size:9px}.rule{padding:18px 14px}.section-title .eyebrow{text-align:left}}
@media print{main{max-width:none;padding:10px}.rule{break-inside:avoid}details pre{display:block}.hero{padding-top:24px}}
</style></head><body><main>
<header><div class="brand"><span class="mark" aria-hidden="true"></span>fwrule</div><span class="eyebrow">OFFLINE ANALYSIS<br>IPV4 / FILTER TABLE</span></header>
<section class="hero"><p class="eyebrow">UNDERSTAND YOUR FIREWALL</p><h1>Find rules that<br>never run.</h1><p>See where an earlier rule covers a later one. Every proof includes its blocker; unsupported semantics stay visible as inconclusive.</p></section>
<section class="stats" aria-label="Analysis summary"><div class="stat"><strong>@PROOFS@</strong><span>PROVEN UNREACHABLE</span></div><div class="stat"><strong>@UNKNOWN@</strong><span>INCONCLUSIVE</span></div><div class="stat"><strong>@ZERO@</strong><span>ZERO-HIT OBSERVATIONS</span></div></section>
<div class="section-title"><h2>Rule findings</h2><span class="eyebrow">@TOTAL@ RULES / SINGLE-RULE COVERAGE</span></div>
@CARDS@
<section class="coverage"><h2>Know the limits</h2><ul>@NOTES@</ul></section>
<footer>YOU LEARN IPTABLES AND RULE SHADOWING<br>fwrule 0.1 · EDUCATIONAL ANALYSIS · REVIEW POLICY CHANGES MANUALLY</footer>
</main></body></html>
'''
