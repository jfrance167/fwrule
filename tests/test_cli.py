import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from fwrule.__main__ import main
from fwrule.analysis import analyze
from fwrule.parser import parse
from fwrule.report import render_html, render_text
from test_parser import ruleset


class CliTests(unittest.TestCase):
    def run_cli(self, text, *args):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            source = Path(directory) / "input.rules"
            source.write_bytes(text if isinstance(text, bytes) else text.encode())
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = main([str(source), *args])
            return code, stdout.getvalue(), stderr.getvalue()

    def test_json_and_exit_codes(self):
        code, output, _ = self.run_cli(ruleset("-A INPUT -j DROP", "-A INPUT -j ACCEPT"), "--format", "json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["summary"]["proven_unreachable"], 1)
        self.assertEqual(self.run_cli(ruleset("-A INPUT -j LOG"))[0], 3)
        self.assertEqual(self.run_cli(b"\xff")[0], 2)
        self.assertEqual(self.run_cli("invalid")[0], 2)

    def test_utf8_bom_and_missing_counter_observation(self):
        code, output, _ = self.run_cli(b"\xef\xbb\xbf" + ruleset("-A INPUT -j DROP").encode(), "--format", "json")
        self.assertEqual(code, 0)
        self.assertIsNone(json.loads(output)["results"][0]["zero_hit"])

    def test_existing_report_and_input_are_preserved(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            source, target = Path(directory) / "in.rules", Path(directory) / "report.html"
            source.write_text(ruleset("-A INPUT -j DROP"))
            target.write_text("keep me")
            original = source.read_bytes()
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main([str(source), "-o", str(target)]), 2)
                self.assertEqual(main([str(source), "-o", str(source)]), 2)
            self.assertEqual(target.read_text(), "keep me")
            self.assertEqual(source.read_bytes(), original)

    def test_html_escapes_source_and_disables_scripts(self):
        report = analyze(parse(ruleset('-A INPUT -m comment --comment "<script>alert(1)</script> & text" -j DROP')))
        page = render_html(report)
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("default-src 'none'", page)
        self.assertNotIn("@CARDS@", page)
        self.assertNotIn("http://", page)

    def test_directional_control_is_escaped_in_visible_source(self):
        report = analyze(parse(ruleset('-A INPUT -m comment --comment "\u202ehidden" -j DROP')))
        for rendered in (render_text(report), render_html(report)):
            self.assertNotIn("\u202e", rendered)
            self.assertIn("\\u202e", rendered)

    def test_template_tokens_in_comments_remain_literal(self):
        report = analyze(parse(ruleset('-A INPUT -m comment --comment "@NOTES@ @CARDS@" -j DROP')))
        page = render_html(report)
        self.assertIn("@NOTES@ @CARDS@", page)

    def test_new_report_output(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            source, target = Path(directory) / "in.rules", Path(directory) / "report.html"
            source.write_text(ruleset("-A INPUT -j DROP"))
            self.assertEqual(main([str(source), "--format", "html", "-o", str(target)]), 0)
            self.assertIn("<!doctype html>", target.read_text(encoding="utf-8"))

    def test_regular_file_and_size_enforcement(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["samples"]), 2)
        self.assertEqual(self.run_cli(b"x" * (2 * 1024 * 1024 + 1))[0], 2)
