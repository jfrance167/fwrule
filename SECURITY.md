# Security model

This is an educational, offline ruleset analyzer, not a production policy
validator or automatic firewall cleanup tool.

## Trust boundaries

Rule text is untrusted data. The application does not execute exports, invoke
iptables, resolve hostnames or send network requests. It processes only regular
local files and bounds input size, rule count, line length and pair comparisons.
Only documented semantics can support a proof; unsupported rules invalidate
their entire built-in chain. A missing finding never proves reachability.

Reports contain original policy text and may disclose internal network design.
Keep actual exports and generated reports private; the committed demo uses
documentation addresses. Source text is escaped before terminal/HTML display.
HTML contains no script, dynamic uploads, external resources or active links.
Output uses exclusive creation to prevent overwriting evidence.

The input path and directory are assumed to be controlled by the operator.
Filesystem permissions remain the operating system's responsibility; do not
analyze files in directories being concurrently modified by an adversary.

## Review before use

Manual review of the parser's support boundaries and coverage proof logic is
required before relying on findings for consequential policy decisions. Check
the Linux export against actual iptables behavior in an authorized lab; the
current validation is synthetic and Windows-local. No live-policy change is
authorized or automated by this tool.

## Reporting a problem

Provide a minimal synthetic reproducer and relevant Python/tool versions.
Never attach real firewall configurations, credentials, internal addresses or
nonpublic vulnerability evidence to a public issue. Until a private reporting
channel is explicitly configured, coordinate privately with the repository
owner before sharing sensitive details. No security response SLA is promised.

## Supply chain

No third-party runtime dependencies. Development scanner dependencies are
version-pinned; artifact hashes are not locked. Actions are pinned to verified
full commit SHAs with release comments and minimum job permissions. Dependabot
configuration is prepared. These controls do not establish absence of upstream
vulnerabilities. GitHub eligibility, alerts and branch protections have not been
checked because this project has not been published.
