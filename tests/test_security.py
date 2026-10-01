"""Regression tests for the input-hardening helpers in scraper.py.

These cover the security-relevant behaviour directly: identifiers taken from the
page DOM must not be able to escape the output directory, and values injected
into the login script must be escaped as JavaScript literals.

Run with:
    python -m unittest discover -s tests -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scraper import (  # noqa: E402
    js_string_literal,
    safe_download_filename,
    safe_path_component,
)


class SafePathComponentTests(unittest.TestCase):
    def test_accepts_plain_identifiers(self):
        self.assertEqual(safe_path_component("123456789"), "123456789")
        self.assertEqual(safe_path_component("peer-story_abc-XYZ"), "peer-story_abc-XYZ")

    def test_rejects_traversal(self):
        for hostile in ("../../etc/passwd", "..\\..\\windows\\system32", "a/b/c", "..", "."):
            result = safe_path_component(hostile)
            self.assertNotIn("/", result)
            self.assertNotIn("\\", result)
            self.assertNotEqual(result, "..")
            self.assertFalse(result.startswith("."))

    def test_rejects_absolute_paths(self):
        for hostile in ("/etc/passwd", "C:\\Windows", "//server/share"):
            result = safe_path_component(hostile)
            self.assertNotIn(os.sep, result)

    def test_empty_and_none_get_stable_fallback(self):
        self.assertEqual(safe_path_component(""), safe_path_component(None))
        self.assertTrue(safe_path_component("").startswith("id_"))

    def test_fallback_is_deterministic_and_distinct(self):
        # A per-process-random hash would break resumable runs.
        self.assertEqual(safe_path_component("نام گروه"), safe_path_component("نام گروه"))
        self.assertNotEqual(safe_path_component("chat a"), safe_path_component("chat b"))

    def test_result_is_length_bounded(self):
        self.assertLessEqual(len(safe_path_component("x" * 5000)), 128)


class SafeDownloadFilenameTests(unittest.TestCase):
    def test_keeps_ordinary_names(self):
        self.assertEqual(safe_download_filename("report.pdf", "fb"), "report.pdf")

    def test_strips_directory_components(self):
        self.assertEqual(safe_download_filename("../../../evil.sh", "fb"), "evil.sh")
        self.assertEqual(safe_download_filename("..\\..\\evil.exe", "fb"), "evil.exe")
        self.assertEqual(safe_download_filename("/etc/passwd", "fb"), "passwd")

    def test_hides_leading_dots(self):
        self.assertFalse(safe_download_filename("....", "fb").startswith("."))
        self.assertFalse(safe_download_filename(".hidden", "fb").startswith("."))

    def test_sanitises_whitespace_and_specials(self):
        self.assertEqual(safe_download_filename("a b c.txt", "fb"), "a_b_c.txt")
        self.assertNotIn(";", safe_download_filename("a;rm -rf.txt", "fb"))

    def test_empty_input_uses_fallback(self):
        self.assertEqual(safe_download_filename("", "fallback"), "fallback")
        self.assertEqual(safe_download_filename("...", "fallback"), "fallback")


class JsStringLiteralTests(unittest.TestCase):
    def test_wraps_plain_value(self):
        self.assertEqual(js_string_literal("abc123"), "'abc123'")

    def assert_balanced_quotes(self, value):
        """The literal must have exactly two unescaped quotes: the wrappers."""
        literal = js_string_literal(value)
        self.assertTrue(literal.startswith("'") and literal.endswith("'"))
        inner = literal[1:-1]
        # Strip escaped quotes, then any remaining quote would break out.
        inner_without_escaped = inner.replace("\\'", "")
        self.assertNotIn("'", inner_without_escaped)
        return literal

    def test_escapes_single_quote_breakout(self):
        # The classic injection: '); malicious(); //
        literal = self.assert_balanced_quotes("a'); alert(1);//")
        self.assertIn("\\'", literal)

    def test_quote_breakouts_over_many_shapes(self):
        for hostile in (
            "'",
            "''",
            "'+alert(1)+'",
            "\\'",
            "a'\\'b",
            "');fetch('http://evil')//",
            "\n'",
        ):
            with self.subTest(hostile=hostile):
                self.assert_balanced_quotes(hostile)

    def test_escapes_backslash_before_quote(self):
        # A trailing backslash must not be able to escape the closing quote.
        literal = js_string_literal("x\\")
        self.assertTrue(literal.endswith("\\\\'"))

    def test_escapes_newlines(self):
        for char in ("\n", "\r"):
            self.assertNotIn(char, js_string_literal(f"a{char}b"))

    def test_escapes_line_separators(self):
        self.assertIn("\\u2028", js_string_literal("a\u2028b"))
        self.assertIn("\\u2029", js_string_literal("a\u2029b"))

    def test_does_not_emit_script_end_tag(self):
        self.assertNotIn("</script>", js_string_literal("</script>"))

    def test_handles_none_and_non_strings(self):
        self.assertEqual(js_string_literal(None), "''")
        self.assertEqual(js_string_literal(42), "'42'")


if __name__ == "__main__":
    unittest.main(verbosity=2)
