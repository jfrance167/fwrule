"""Parse a documented subset of iptables-save without executing input."""

import ipaddress
import re
import shlex

from .model import CHAINS, MAX_BYTES, MAX_LINE, MAX_RULES, Rule, Ruleset


class InputError(ValueError):
    """Malformed or oversized input; analysis cannot continue safely."""


def _counter(value: str) -> tuple[int, int]:
    match = re.fullmatch(r"\[([0-9]{1,20}):([0-9]{1,20})\]", value)
    if not match:
        raise InputError("invalid packet/byte counter")
    pair = tuple(int(item) for item in match.groups())
    if max(pair) > 2**64 - 1:
        raise InputError("counter exceeds unsigned 64-bit range")
    return pair


def _network(value: str) -> tuple[int, int]:
    try:
        network = ipaddress.IPv4Network(value, strict=False)
    except ValueError as error:
        raise InputError("expected numeric IPv4 address or CIDR") from error
    return int(network.network_address), int(network.broadcast_address)


def _ports(value: str) -> tuple[int, int]:
    if not re.fullmatch(r"[0-9]{1,5}(:[0-9]{1,5})?", value):
        raise InputError("expected numeric port or closed port range")
    parts = [int(item) for item in value.split(":")]
    low, high = parts[0], parts[-1]
    if not 0 <= low <= high <= 65535:
        raise InputError("invalid port range")
    return low, high


def _rule(tokens: list[str], chain: str, number: int, line: int,
          raw: str, packets: int | None) -> Rule:
    aliases = {"-s": "source", "--source": "source",
               "-d": "destination", "--destination": "destination",
               "-p": "protocol", "--protocol": "protocol",
               "--sport": "sport", "--source-port": "sport",
               "--dport": "dport", "--destination-port": "dport",
               "-j": "target", "--jump": "target"}
    values = {}
    modules = []
    unsupported = []
    index = 0
    comment = False
    while index < len(tokens):
        flag = tokens[index]
        if flag not in aliases and flag not in {"-m", "--match", "--comment"}:
            unsupported.append("unmodeled syntax")
            break  # Never guess the arity or meaning of unknown syntax.
        if index + 1 >= len(tokens):
            raise InputError("missing rule option value")
        value = tokens[index + 1]
        index += 2
        if flag in {"-m", "--match"}:
            modules.append(value)
            continue
        if flag == "--comment":
            if comment:
                raise InputError("duplicate comment option")
            comment = True
            continue
        key = aliases[flag]
        if key in values:
            raise InputError("duplicate rule option")
        if value == "!":
            unsupported.append("negation")
            break
        values[key] = (_network(value) if key in {"source", "destination"}
                       else _ports(value) if key in {"sport", "dport"}
                       else value)
    protocol = values.get("protocol", "all")
    if protocol not in {"all", "tcp", "udp"}:
        unsupported.append("protocol outside all/tcp/udp")
    if values.get("target") not in {"ACCEPT", "DROP", "REJECT"}:
        unsupported.append("unmodeled target or control flow")
    if any(module not in {"tcp", "udp", "comment"} for module in modules):
        unsupported.append("unmodeled match module")
    if any(module in {"tcp", "udp"} and module != protocol for module in modules):
        raise InputError("transport module does not match protocol")
    if comment and "comment" not in modules:
        raise InputError("comment option requires comment module")
    if any(key in values for key in {"sport", "dport"}) and protocol not in {"tcp", "udp"}:
        raise InputError("ports require TCP or UDP")
    return Rule(chain, number, line, raw, packets=packets,
                unsupported=tuple(dict.fromkeys(unsupported)), **values)


def parse(text: str) -> Ruleset:
    """Return preserved rules; reject invalid structure and resource excesses.

    Unsupported semantics are retained as barriers, never silently dropped.
    Other tables are explicitly excluded from the filter-chain analysis.
    """
    if len(text) > MAX_BYTES or len(text.encode("utf-8")) > MAX_BYTES:
        raise InputError("input exceeds 2 MiB")
    if any((ord(char) < 32 and char not in "\t\r\n") or 127 <= ord(char) < 160
           for char in text):
        raise InputError("control characters are not allowed")
    rules = []
    warnings = []
    table = None
    tables = set()
    chains = set()
    counts = {}
    total_rules = 0
    for line, raw in enumerate(text.splitlines(), 1):
        try:
            if len(raw) > MAX_LINE:
                raise InputError("line exceeds 8192 characters")
            if any((ord(char) < 32 and char != "\t") or 127 <= ord(char) < 160
                   for char in raw):
                raise InputError("control characters are not allowed")
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("*"):
                if table is not None or not re.fullmatch(r"\*[a-z]+", stripped):
                    raise InputError("invalid table header or missing COMMIT")
                table = stripped[1:]
                if table in tables:
                    raise InputError("duplicate table")
                tables.add(table)
                chains = set()
                if table != "filter":
                    warnings.append(f"Table {table} excluded; only filter is analyzed.")
                continue
            if stripped == "COMMIT":
                if table is None:
                    raise InputError("COMMIT outside table")
                if table == "filter" and not CHAINS.issubset(chains):
                    raise InputError("filter must declare INPUT, OUTPUT and FORWARD")
                table = None
                continue
            if table is None:
                raise InputError("content outside table")
            if stripped.startswith(":"):
                fields = stripped[1:].split()
                if len(fields) != 3 or not re.fullmatch(r"[A-Za-z0-9_.:+-]{1,64}", fields[0]):
                    raise InputError("invalid chain declaration")
                name, policy, counter = fields
                _counter(counter)
                valid_policy = policy in {"ACCEPT", "DROP", "-"}
                if table == "filter":
                    valid_policy = (policy in {"ACCEPT", "DROP"} if name in CHAINS else policy == "-")
                if name in chains or not valid_policy:
                    raise InputError("duplicate chain or invalid policy")
                chains.add(name)
                continue
            tokens = shlex.split(stripped, comments=False, posix=True)
            packets = None
            if tokens and tokens[0].startswith("["):
                packets = _counter(tokens.pop(0))[0]
            if len(tokens) < 2 or tokens[0] != "-A" or tokens[1] not in chains:
                raise InputError("expected -A with a declared chain")
            total_rules += 1
            if total_rules > MAX_RULES:
                raise InputError("input exceeds 1000 rules")
            if table != "filter":
                continue
            chain = tokens[1]
            counts[chain] = counts.get(chain, 0) + 1
            if chain not in CHAINS:
                warnings.append(f"Line {line}: custom chain excluded from analysis.")
                continue
            rules.append(_rule(tokens[2:], chain, counts[chain], line, raw, packets))
        except ValueError as error:
            raise InputError(f"Line {line}: {error}") from error
    if table is not None:
        raise InputError("missing final COMMIT")
    if "filter" not in tables:
        raise InputError("no filter table found")
    return Ruleset(tuple(rules), tuple(warnings))
