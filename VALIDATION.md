# Validation — October 5, 2026

Local educational version is ready for review. Environment: Windows, Python
3.13.7; no Linux kernel or live firewall was exercised.

| Phase | Outcome | Command/evidence |
| --- | --- | --- |
| Tests | PASS | `python -m unittest discover -s tests -v`; 24 test groups, exit 0 |
| Demo reproducibility | PASS | `python scripts/demo_reports.py --check`; exit 0 |
| Source compilation | PASS | `python -m compileall -q fwrule scripts`; exit 0 |
| SAST | PASS | `python -m bandit -r fwrule scripts`; Bandit 1.9.4, zero findings/errors, exit 0 |
| Workflow structure | PASS | Local PyYAML parsing; all five action uses pinned, checkout credential persistence disabled |
| Diff whitespace | PASS | `git diff --check`; exit 0 |
| Browser | PASS | Installed Playwright CLI and Chrome; 1280×900 desktop, 390×844 mobile, no horizontal overflow or console errors; blocker disclosure works |
| Style/type check | NOT RUN | No project style/type checker configured; no tool downloaded for this phase |
| Package build | NOT APPLICABLE | Runs directly as a source CLI; no distributable package build |
| Linux/live semantics | NOT RUN | Independent synthetic evaluator only; real export/kernel validation remains a manual lab task |
| GitHub checks | NOT RUN | Local repository only; eligibility, alerts, protection and hosted workflows unverified |

Private full test/compile/scanner outputs and exit-status manifest are in
`.private/verification/`. Browser snapshots remain ignored under `.playwright-cli/`;
desktop/mobile screenshots and synthetic reports are in `samples/`.

The independent test interpreter evaluates 80 deterministic generated five-rule
configurations over a reduced 768-packet domain per configuration. Every reported
coverage proof must satisfy packet membership containment and earlier first-match
termination. This supports the tested subset; it is not formal verification or
an exhaustive test of iptables semantics.

A 1,000-rule disjoint-source fixture completed in 0.918 seconds in one local run,
with no unreachable findings. This exercises the maximum accepted rule count;
it is not a production benchmark or latency guarantee. The comparison-budget
guard has its own test. Outputs remain bounded by input/rule limits.

Code review covered correctness, simplicity, architecture, untrusted-input and
display boundaries, and bounded comparison work. Fixes included non-filter policy
parsing, Unicode/control-character handling, and one-pass HTML substitution so
template-like comment text stays literal. All regression checks pass.

No dedicated secret scanner executable was available. A targeted signature scan
of project text and local commit history found zero matches for common AWS,
GitHub, API-key and private-key signatures. Manual review found only synthetic
rule evidence and project documentation. This is limited pattern-based evidence,
not proof that every possible secret/private datum is absent.

Actions verified against official GitHub release/tag/commit resources:

| Action release | Immutable commit |
| --- | --- |
| actions/checkout v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| actions/setup-python v7.0.0 | `5fda3b95a4ea91299a34e894583c3862153e4b97` |
| github/codeql-action v4.38.2 | `2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2` |

The CodeQL annotated tag was dereferenced to its commit. Development scanner
versions match the installed environment; no fresh dependency installation or
vulnerability database check was run. No third-party runtime dependencies exist.

Manual review pending before consequential reliance or release: parser support
boundaries, proof assumptions, and Linux lab confirmation. Any publication or
merge remains subject to Jake's authorization. No policy change/removal occurred.
