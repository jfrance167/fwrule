# Successor research and proposal — October 5, 2026

Status: ready for central coordinator review; no successor code started.
Authorization verified by reading the original human messages in coordinator chat
01a10a45-1a24-78b3-9cef-7c461a966d26: Jake authorized coordination/approval of
further work, then requested further labs after completion. The coordinator asked
this workstream to research two candidates and present one concrete plan before
implementation. No new external-action authorization is inferred.

## Candidates and local fit

1. **firewall-counter-window-lab** — compare two time-stamped synthetic counter
   snapshots, exposing rule-identity ambiguity, counter discontinuities and the
   assumptions needed for interval rates. Distinct from fwrule's static coverage
   proofs and from the existing nftables before/after exposure lab.
2. **firewall-policy-change-lab** — compare two bounded supported policies and
   generate synthetic packet witnesses for changed ACCEPT/DROP behavior. Useful
   later, but exact policy-space equivalence requires more review and overlaps
   the current coverage engine more closely.

Recommendation: **build candidate 1** in a separate
`firewall-counter-window-lab/` directory after the coordinator approves this plan.
Narrow local/vault searches found no existing counter-window or policy-diff lab;
this is not an exhaustive search. Inspected fwrule, the existing hardening README,
and retrieved vault Firewall Hardening Evidence. Reuse the tested report-safety,
bounded-input and synthetic-evidence conventions; leave fwrule code unchanged.

## Upstream research

- [retailnext/iptables_exporter](https://github.com/retailnext/iptables_exporter):
  Apache-2.0; last push reported December 15, 2023. Inspected README, live collector,
  export execution, parser, parser tests and dependency manifest. It runs
  `iptables-save -c`, exposes an HTTP metrics listener and documents capabilities.
  Prometheus/kingpin dependencies, vendored code and Gopkg metadata make it a
  broader deployment than this offline learning objective. Existing parser tests
  are evidence of test presence, not current CI success. Open
  [issue 6](https://github.com/retailnext/iptables_exporter/issues/6) reports a modern
  Go module-path build mismatch; we did not reproduce it. Avoid adopting the live
  collection/service architecture; retain counter representation as a reference.
  Any future copied Apache code would require applicable license/notice handling;
  no copying is proposed.
- [kbknapp/iptables_exporter](https://github.com/kbknapp/iptables_exporter): Apache-2.0,
  Rust, last push reported May 8, 2024; metadata comparison only, not source-audited.
- [brb/iptables-diff](https://github.com/brb/iptables-diff): last push reported
  September 27, 2018; README only says WIP. Inspected actual rule/counter parser,
  diff logic and tests. Uses UUID/test dependencies and bundled web assets. No
  root project license or CI was identified in the inspected tree/metadata;
  vendored asset licenses do not establish project licensing. Do not copy/fork it
  without resolving rights and maintenance. Its textual diff is not evidence of
  exact packet-policy equivalence.
- [Prometheus counter functions](https://prometheus.io/docs/prometheus/latest/querying/functions/):
  official docs explain that counter rate/increase calculations account for
  decreases associated with resets. Proposed two-snapshot tool will not emulate
  Prometheus extrapolation or claim it can reconstruct resets between samples.

Sources inspected October 5, 2026. No third-party code was installed/executed,
and no upstream safety, current CI health or vulnerability-free status is claimed.

## Problem and acceptance criteria

Teach why zero counters, no observed increase and static unreachability are
different claims. Produce an offline CLI/report where each reported interval
change has explicit identity, time and continuity assumptions. Correctly withhold
traffic/rate inference when evidence is missing or contradictory.

Initial input is a strict, versioned **JSON snapshot envelope**, not a new
iptables parser: schema version, opaque source identifier, offset-aware capture
time, optional counter-epoch identifier, ordered chains/policies and records
containing position, original rule text and packet/byte counters (or null).
Snapshots are synthetic/manual records; collection and export conversion are
separate future stages. Identifiers and continuity statements are operator-supplied
assertions, not authenticated evidence. No extension to fwrule grammar is proposed.

For matching source and unchanged ordered chain structure, report observed
integer differences. Duplicate rule texts are ambiguous and receive no inferred
delta/rate. Changes, reorder, added/removed rules, missing counters and decreases
get explicit statuses. A decreased packet OR byte counter means discontinuity;
do not guess reset versus wrap. Nondecrease does not prove continuity.

Default: observed values/differences only, no traffic-rate inference. Optional
`--assume-continuity` may expose **conditional** nonnegative deltas/rates only for
unique rules, matching supplied source and non-null epoch assertions, unchanged
chain structure and a positive time interval. Always display the assumption and
hidden-reset limitation. Zero difference never means unreachable or safe to remove.

## Architecture, threats and tradeoffs

Python standard library only: bounded JSON/schema validation -> immutable
snapshots -> exact ordered identity comparison -> observation/conditional-rate
report. Preserve integer counters, calculate elapsed microseconds exactly and
format conditional rates without float NaN/Infinity. Treat rule text as opaque
data; never evaluate its match/action semantics or execute it.

Threats: malformed/oversized JSON, misleading metadata, boolean-as-integer inputs,
incorrect rule pairing, hidden resets, display injection and report disclosure.
Cap each file at 2 MiB, 1,000 records and bounded text/metadata lengths; disallow
duplicate JSON keys, nonfinite numbers and unknown schema fields. Escape output;
exclusive report creation preserves source evidence. No host collection, shell
commands, server, scans, privilege changes or uploads. Actual policy records stay
private; portfolio evidence uses documentation addresses and synthetic identifiers.

Strict JSON and whole-chain identity reduce real-export convenience but keep the
first lab small and honest. A live exporter or semantic policy diff remains an
alternative for a separately researched, approved stage.

## Stages and definitions of done

1. Snapshot contract/parser: documented schema and rejection tests for duplicate
   keys, booleans, uint64 bounds, timestamps, missing fields and resource limits.
2. Comparison: independently specified fixtures for unchanged/active/idle rules,
   duplicates, reorder, additions/removals, source/epoch mismatch, one-counter
   decrease and hidden-reset examples. Default reports never infer traffic rates.
3. CLI/reports: terminal and stable JSON first; a static HTML teaching report if
   useful. End-to-end tests verify exit codes, evidence preservation, conditional
   labels and escaped text. No ambiguity is silently coerced to zero.
4. Portfolio finish: README/demo, MIT/attribution/AI disclosure, state/decisions/
   learning and threat-model docs, focused code review/Bandit/secret checks,
   reproducible examples and appropriate pinned security workflow preparation.
   Manual review precedes consequential reliance; no publication/merge implied.

Worker choice: local qwen3.5:2b extracted three short learning labels from supplied
facts in 7.103 seconds, within a 30-second limit. Raw brief/draft/metadata are in
shared private tooling review/counter-window-*. Reviewed wording was tightened:
interpreting counters requires a time window; counters themselves still function
without one. Codex retained identity/continuity/security decisions. Local drafting
met the bounded criteria; no remote inference or new provider discovery needed.

Next: coordinator checks duplication across workstreams and records concrete plan
approval before successor code. Stop new dispatch at 08:00 Eastern October 6.
