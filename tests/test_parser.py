import unittest

from fwrule.parser import InputError, parse

HEADER = "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n"


def ruleset(*rules):
    return HEADER + "\n".join(rules) + "\nCOMMIT\n"


class ParserTests(unittest.TestCase):
    def test_addresses_ports_counters_and_provenance(self):
        rule = parse(ruleset("[0:17] -A INPUT -s 10.1.2.3/24 -p tcp -m tcp --dport 0:65535 -j DROP")).rules[0]
        self.assertEqual(rule.source, (167838208, 167838463))
        self.assertEqual((rule.line, rule.number, rule.packets), (5, 1, 0))
        self.assertFalse(rule.unsupported)

    def test_quoted_comment_is_data(self):
        rule = parse(ruleset('-A INPUT -m comment --comment "$(touch /tmp/no) <script>" -j ACCEPT')).rules[0]
        self.assertFalse(rule.unsupported)

    def test_unsupported_rules_preserved(self):
        for value in ("-m conntrack --ctstate ESTABLISHED -j ACCEPT",
                      "! -s 10.0.0.0/8 -j DROP", "-j LOG", "-p icmp -j ACCEPT",
                      "-p tcp --tcp-flags ALL SYN -j DROP"):
            with self.subTest(value=value):
                self.assertTrue(parse(ruleset("-A INPUT " + value)).rules[0].unsupported)

    def test_invalid_inputs(self):
        for value in ("-s example.org -j DROP", "-s 1.2.3.4/33 -j DROP",
                      "-p tcp --dport 65536 -j ACCEPT", "-p udp --dport 10:9 -j DROP",
                      "--dport 80 -j ACCEPT", "-p tcp -m udp -j DROP",
                      "-j DROP -j ACCEPT", "-s", '-m comment --comment "unterminated'):
            with self.subTest(value=value):
                with self.assertRaises(InputError):
                    parse(ruleset("-A INPUT " + value))

    def test_structural_and_resource_errors(self):
        for text in ("", HEADER, HEADER + "COMMIT\nCOMMIT", HEADER + "-A MISSING -j ACCEPT\nCOMMIT",
                     ruleset("-A INPUT -j DROP\x1b"), ruleset("#" + "x" * 8192),
                     ruleset(*["-A INPUT -j DROP"] * 1001), "x" * (2 * 1024 * 1024 + 1)):
            with self.subTest(text=text[:50]):
                with self.assertRaises(InputError):
                    parse(text)

    def test_other_tables_and_custom_chains_are_disclosed(self):
        text = "*nat\n:PREROUTING ACCEPT [0:0]\nCOMMIT\n" + HEADER + ":CUSTOM - [0:0]\n-A CUSTOM -j DROP\n-A INPUT -j CUSTOM\nCOMMIT\n"
        result = parse(text)
        self.assertEqual(len(result.warnings), 2)
        self.assertTrue(result.rules[0].unsupported)

    def test_unicode_line_separator_cannot_hide_control_character(self):
        with self.assertRaises(InputError):
            parse(ruleset("-A INPUT -j DROP\x85"))
