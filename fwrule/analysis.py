"""Single-rule coverage proofs, scoped to supported built-in filter chains."""

from dataclasses import asdict

from .model import MAX_COMPARISONS, Rule, Ruleset
from .parser import InputError


def _contains(outer: tuple[int, int], inner: tuple[int, int]) -> bool:
    return outer[0] <= inner[0] and inner[1] <= outer[1]


def covers(earlier: Rule, later: Rule) -> bool:
    """Whether a supported earlier rule covers all modeled later matches.

    This is a packet-set comparison, not a chain reachability claim by itself.
    The analyzer additionally enforces order, chain and support boundaries.
    """
    return (earlier.protocol in {"all", later.protocol}
            and all(_contains(getattr(earlier, field), getattr(later, field))
                    for field in ("source", "destination", "sport", "dport")))


def overlaps(first: Rule, second: Rule) -> bool:
    """Whether the modeled match sets share packets."""
    return (("all" in {first.protocol, second.protocol} or first.protocol == second.protocol)
            and all(max(getattr(first, field)[0], getattr(second, field)[0])
                    <= min(getattr(first, field)[1], getattr(second, field)[1])
                    for field in ("source", "destination", "sport", "dport")))


def _same_match(first: Rule, second: Rule) -> bool:
    return all(getattr(first, field) == getattr(second, field)
               for field in ("source", "destination", "protocol", "sport", "dport"))


def analyze(ruleset: Ruleset) -> dict:
    """Return JSON-serializable findings with original line/rule evidence.

    Unknown matches may alter packet state or control flow. Conservatively
    invalidate the whole affected chain rather than infer their behavior.
    Counter observations are independent of structural findings.
    """
    barriers = {}
    for rule in ruleset.rules:
        if rule.unsupported:
            barriers.setdefault(rule.chain, []).append(rule.line)
    prior = {}
    results = []
    comparisons = 0
    for rule in ruleset.rules:
        result = {"rule": asdict(rule), "status": "no_single_rule_cover",
                  "explanation": "No single earlier rule proves full coverage. Reachability is not established.",
                  "blocker": None, "overlap_lines": [], "overlap_count": 0,
                  "zero_hit": rule.packets == 0 if rule.packets is not None else None}
        if rule.chain in barriers:
            result.update(status="inconclusive", barrier_lines=barriers[rule.chain],
                          explanation="Unsupported semantics in this chain prevent structural conclusions.")
        else:
            for earlier in prior.get(rule.chain, []):
                comparisons += 1
                if comparisons > MAX_COMPARISONS:
                    raise InputError("comparison budget exceeded")
                if covers(earlier, rule):
                    same_action = earlier.target == rule.target
                    status = ("duplicate" if same_action and _same_match(earlier, rule)
                              else "shadowed_same_action" if same_action else "shadowed_conflicting_action")
                    result.update(status=status,
                                  explanation=f"Rule {earlier.number} at line {earlier.line} matches every modeled packet of this rule and terminates processing with {earlier.target}.",
                                  blocker=asdict(earlier))
                    break
                if overlaps(earlier, rule):
                    result["overlap_count"] += 1
                    if len(result["overlap_lines"]) < 8:
                        result["overlap_lines"].append(earlier.line)
            if result["blocker"] is None and result["overlap_count"]:
                result.update(status="partial_overlap",
                              explanation="Earlier rules overlap this match set. No single-rule full coverage proof was found; combined coverage is not analyzed.")
        prior.setdefault(rule.chain, []).append(rule)
        results.append(result)
    summary = {"total_rules": len(results), "proven_unreachable": sum(item["blocker"] is not None for item in results),
               "inconclusive": sum(item["status"] == "inconclusive" for item in results),
               "partial_overlap": sum(item["status"] == "partial_overlap" for item in results),
               "zero_hit_observations": sum(item["zero_hit"] is True for item in results)}
    return {"schema_version": 1, "scope": "IPv4 filter built-in chains; single earlier terminal rule coverage",
            "summary": summary, "warnings": list(ruleset.warnings), "results": results,
            "limitations": ["No finding is not proof of reachability or safe removal.",
                            "Zero counters describe only the exported observation window; duration is unknown.",
                            "Union coverage, custom-chain flow, NAT, IPv6 and native nftables are not analyzed.",
                            "Proofs concern arrival at a filter chain; other tables and network paths are outside scope."]}
