# Decisions

- Original Python standard-library implementation. FFFUU is a semantic reference,
  not imported code; this tool does not inherit its machine-verified guarantees.
- Limit version 0.1 to one preceding terminal rule covering the whole later match
  set. Multiple earlier rules may jointly cover it, but we make no union proof.
- Any unmodeled rule invalidates its whole built-in chain. This avoids guessing
  about effects such as queueing, control flow or packet metadata modification.
- Findings apply within the selected filter chain. Other tables, routing and
  earlier network devices may determine whether packets arrive there.
- No third-party runtime dependencies, shell execution, network access or live
  firewall modification. Reject malformed input; retain unsupported semantics.
