"""Immutable rules with source provenance; addresses and ports are inclusive."""

from dataclasses import dataclass

MAX_BYTES = 2 * 1024 * 1024
MAX_LINE = 8192
MAX_RULES = 1000
MAX_COMPARISONS = 500_000
CHAINS = frozenset({"INPUT", "OUTPUT", "FORWARD"})


@dataclass(frozen=True)
class Rule:
    chain: str
    number: int
    line: int
    raw: str
    source: tuple[int, int] = (0, 2**32 - 1)
    destination: tuple[int, int] = (0, 2**32 - 1)
    protocol: str = "all"
    sport: tuple[int, int] = (0, 65535)
    dport: tuple[int, int] = (0, 65535)
    target: str = ""
    packets: int | None = None
    unsupported: tuple[str, ...] = ()


@dataclass(frozen=True)
class Ruleset:
    rules: tuple[Rule, ...]
    warnings: tuple[str, ...]
