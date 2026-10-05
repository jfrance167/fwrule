import ipaddress
import itertools
import random
import unittest
from unittest.mock import patch

from fwrule.analysis import analyze
from fwrule.parser import InputError, parse
from test_parser import ruleset


def packet_matches(raw, packet):
    """Independent tiny interpreter for generated fixtures, not the analyzer model."""
    tokens = raw.split()
    source, destination, protocol, sport, dport = packet
    checks = {
        "-s": lambda value: ipaddress.IPv4Address(source) in ipaddress.IPv4Network(value),
        "-d": lambda value: ipaddress.IPv4Address(destination) in ipaddress.IPv4Network(value),
        "-p": lambda value: value == "all" or value == protocol,
        "--sport": lambda value: int(value.split(":")[0]) <= sport <= int(value.split(":")[-1]),
        "--dport": lambda value: int(value.split(":")[0]) <= dport <= int(value.split(":")[-1]),
    }
    return all(checks[flag](tokens[index + 1]) for index, flag in enumerate(tokens) if flag in checks)


class AnalysisTests(unittest.TestCase):
    def report(self, *rules):
        return analyze(parse(ruleset(*rules)))

    def test_broad_before_specific_and_reverse(self):
        broad = "-A INPUT -s 10.0.0.0/8 -p tcp --dport 20:100 -j DROP"
        specific = "-A INPUT -s 10.2.0.0/16 -p tcp --dport 22 -j ACCEPT"
        result = self.report(broad, specific)["results"][1]
        self.assertEqual(result["status"], "shadowed_conflicting_action")
        self.assertEqual(result["blocker"]["line"], 5)
        self.assertEqual(self.report(specific, broad)["results"][1]["status"], "partial_overlap")

    def test_duplicate_and_same_action_coverage(self):
        result = self.report("-A INPUT -p tcp -j DROP", "-A INPUT -p tcp -j DROP",
                             "-A INPUT -p tcp --dport 22 -j DROP")["results"]
        self.assertEqual(result[1]["status"], "duplicate")
        self.assertEqual(result[2]["status"], "shadowed_same_action")

    def test_chain_protocol_and_disjoint_boundaries(self):
        base = "-A INPUT -s 10.0.0.0/24 -p tcp --dport 22 -j DROP"
        for later in (base.replace("INPUT", "OUTPUT"), base.replace("tcp", "udp"),
                      base.replace("10.0.0.0", "10.0.1.0"), base.replace("22", "23")):
            with self.subTest(later=later):
                self.assertEqual(self.report(base, later)["results"][1]["status"], "no_single_rule_cover")

    def test_unsupported_semantics_invalidate_entire_chain(self):
        for unknown in ("-j LOG", "-m conntrack --ctstate ESTABLISHED -j ACCEPT", "-j RETURN"):
            result = self.report("-A INPUT -j DROP", "-A INPUT " + unknown,
                                 "-A INPUT -j ACCEPT", "-A OUTPUT -j ACCEPT")["results"]
            self.assertEqual([item["status"] for item in result[:3]], ["inconclusive"] * 3)
            self.assertEqual(result[3]["status"], "no_single_rule_cover")

    def test_counters_do_not_change_structural_conclusions(self):
        rules = ("-A INPUT -j DROP", "-A INPUT -p tcp -j ACCEPT")
        without = self.report(*rules)
        with_counters = self.report("[10:500] " + rules[0], "[0:0] " + rules[1])
        self.assertEqual([r["status"] for r in without["results"]], [r["status"] for r in with_counters["results"]])
        self.assertEqual(with_counters["summary"]["zero_hit_observations"], 1)
        self.assertIsNone(without["results"][0]["zero_hit"])

    def test_union_coverage_is_explicitly_not_proven(self):
        result = self.report("-A INPUT -p tcp --dport 0:1 -j DROP",
                             "-A INPUT -p tcp --dport 2:3 -j DROP",
                             "-A INPUT -p tcp --dport 0:3 -j ACCEPT")["results"][2]
        self.assertEqual(result["status"], "partial_overlap")
        self.assertIsNone(result["blocker"])

    def test_port_endpoints_and_all_protocol(self):
        result = self.report("-A INPUT -j REJECT", "-A INPUT -p udp --sport 0 --dport 65535 -j ACCEPT")
        self.assertEqual(result["summary"]["proven_unreachable"], 1)

    def test_comparison_budget_stops_analysis(self):
        with patch("fwrule.analysis.MAX_COMPARISONS", 0):
            with self.assertRaises(InputError):
                self.report("-A INPUT -j DROP", "-A INPUT -j ACCEPT")

    def test_generated_proofs_against_independent_packet_interpreter(self):
        rng = random.Random(167)
        addresses = ["10.0.0.0/30", "10.0.0.0/31", "10.0.0.2/31"]
        packets = list(itertools.product(range(167772160, 167772164), range(167772160, 167772164),
                                         ("tcp", "udp", "icmp"), range(4), range(4)))
        proofs = 0
        for _ in range(80):
            raw_rules = []
            for _ in range(5):
                protocol = rng.choice(("all", "tcp", "udp"))
                raw = f"-A INPUT -s {rng.choice(addresses)} -d {rng.choice(addresses)} -p {protocol}"
                if protocol != "all":
                    low, high = sorted((rng.randrange(4), rng.randrange(4)))
                    raw += f" --dport {low}:{high}"
                raw_rules.append(raw + " -j " + rng.choice(("DROP", "ACCEPT", "REJECT")))
            report = self.report(*raw_rules)
            for index, finding in enumerate(report["results"]):
                if finding["blocker"] is None:
                    continue
                proofs += 1
                blocker = finding["blocker"]["raw"]
                later = raw_rules[index]
                matched = [packet for packet in packets if packet_matches(later, packet)]
                self.assertTrue(matched)
                self.assertTrue(all(packet_matches(blocker, packet) for packet in matched))
                # Independent first-match traversal never reaches the later rule.
                for packet in matched:
                    first = next(i for i, raw in enumerate(raw_rules) if packet_matches(raw, packet))
                    self.assertLess(first, index)
        self.assertGreater(proofs, 20)
