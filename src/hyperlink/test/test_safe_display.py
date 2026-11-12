# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from .common import HyperlinkTestCase
from .. import (
    DecodedURL,
    URL,
    URLParseError,
    DEFAULT_SENSITIVE_QUERY_KEYS,
    REDACTION_PLACEHOLDER,
    TRUNCATION_MARKER,
)


# A collection address with repeated tokens, encoded delimiters, encoded
# key casing, undecodable values, and a nested URL query parameter.
SECRET_PASSWORD = "hunter2"
SECRET_TOKEN_ONE = "first-secret-token"
SECRET_TOKEN_TWO = "second-secret-token"
ENCODED_TOKEN_KEY = "%74o%6Ben"  # decodes to "token"
NESTED_URL = (
    "https://api.example.com/v1/data?api_key=inner-secret&q=report"
)
SAMPLE_URL = (
    "https://alice:"
    + SECRET_PASSWORD
    + "@collector.example.com:8443/ingest?token="
    + SECRET_TOKEN_ONE
    + "&token="
    + SECRET_TOKEN_TWO
    + "&TOKEN=caps-token&"
    + ENCODED_TOKEN_KEY
    + "=encoded-key-token&access_token=at-secret&x=1&plain="
    "hello%20world&badpercent=%zz&binary=%ff&redirect="
    + NESTED_URL
    + "#anchor"
)


class TestSafeDisplay(HyperlinkTestCase):
    def test_userinfo_never_displayed(self):
        url = URL.from_text(SAMPLE_URL)
        display = url.safe_display()

        self.assertNotIn(SECRET_PASSWORD, display)
        self.assertNotIn("alice", display)
        self.assertNotIn("@", display)
        self.assertTrue(
            display.startswith("https://collector.example.com:8443")
        )

    def test_sensitive_values_all_masked(self):
        url = URL.from_text(SAMPLE_URL)
        display = url.safe_display()

        for secret in (
            SECRET_TOKEN_ONE,
            SECRET_TOKEN_TWO,
            "caps-token",
            "encoded-key-token",
            "at-secret",
        ):
            self.assertNotIn(secret, display)
        # repeated, capitalized, and percent-encoded keys all handled
        self.assertEqual(display.count("token=" + REDACTION_PLACEHOLDER), 4)
        self.assertIn("TOKEN=" + REDACTION_PLACEHOLDER, display)
        self.assertIn("access_token=" + REDACTION_PLACEHOLDER, display)

    def test_encoded_key_matching_rules_are_explicit(self):
        # the encoded key is rendered decoded, and still matches policy
        url = URL.from_text(SAMPLE_URL)
        display = url.safe_display()
        self.assertIn("token=" + REDACTION_PLACEHOLDER, display)
        self.assertNotIn(ENCODED_TOKEN_KEY, display)
        # custom policy keys use the same decode + casefold rules
        custom = URL.from_text("https://h/?X-Token=abc&other=def")
        shown = custom.safe_display(
            sensitive_query_keys=("x-token",)
        )
        self.assertIn("X-Token=" + REDACTION_PLACEHOLDER, shown)
        self.assertIn("other=def", shown)

    def test_nonsensitive_values_keep_encoded_delimiters(self):
        url = URL.from_text(SAMPLE_URL)
        display = url.safe_display()
        # values are decoded then maximally re-encoded for display
        self.assertIn("plain=hello%20world", display)
        self.assertIn("x=1", display)

    def test_undecodable_values_are_redacted(self):
        url = URL.from_text(SAMPLE_URL)
        display = url.safe_display()
        self.assertNotIn("%zz", display)
        self.assertNotIn("%ff", display)
        self.assertIn("badpercent=" + REDACTION_PLACEHOLDER, display)
        self.assertIn("binary=" + REDACTION_PLACEHOLDER, display)

    def test_nested_url_opt_in_and_depth(self):
        url = URL.from_text(SAMPLE_URL)
        # without recursion the nested value is shown as ordinary text,
        # including its own secrets
        shallow = url.safe_display()
        self.assertIn("inner-secret", shallow)

        deep = url.safe_display(recurse_nested=True)
        self.assertNotIn("inner-secret", deep)
        self.assertIn(
            "api_key=" + REDACTION_PLACEHOLDER, deep
        )
        self.assertIn("q=report", deep)

        # nested URL still has no userinfo
        nested_with_user = URL.from_text(
            "https://h/?u=https://bob:p@inner.example/x?token=z"
        )
        shown = nested_with_user.safe_display(recurse_nested=True)
        self.assertNotIn("bob", shown)
        self.assertNotIn("p@", shown)

    def test_plain_text_is_not_guessed_as_url(self):
        url = URL.from_text(
            "https://h/?note=not%20a%20url%20just%20text"
        )
        shown = url.safe_display(recurse_nested=True)
        self.assertIn("note=not%20a%20url%20just%20text", shown)
        # a literal percent in a decoded value is re-escaped, never raw
        raw = URL.from_text("https://h/?note=100%25%20off")
        self.assertEqual(
            raw.safe_display(recurse_nested=True),
            "https://h/?note=100%25%20off",
        )

        relative = URL.from_text("https://h/?u=relative/path?a=b")
        shown = relative.safe_display(recurse_nested=True)
        self.assertIn("u=relative/path?a=b", shown)

    def test_recursion_depth_is_capped(self):
        innermost = "https://inner/p?token=deep-secret"
        nested = innermost
        for _ in range(5):
            nested = "https://outer/p?u=" + nested
        url = URL.from_text("https://root/p?u=" + nested)
        shown = url.safe_display(recurse_nested=True, max_depth=99)
        # recursion happened at the outer levels
        self.assertIn(
            "u=" + REDACTION_PLACEHOLDER, shown
        )
        # the secret beyond the depth cap never appears either
        self.assertNotIn("deep-secret", shown)

    def test_truncation_is_marked_and_never_looks_complete(self):
        url = URL.from_text(
            "https://example.com/" + ("a" * 100) + "?token=zzz"
        )
        shown = url.safe_display(max_length=60)
        self.assertLessEqual(len(shown), 60)
        self.assertTrue(shown.endswith(TRUNCATION_MARKER))
        self.assertNotIn("zzz", shown)

        # an oversized query is dropped wholesale, not sliced mid-query
        big = URL.from_text(
            "https://example.com/x?long=" + ("z" * 200)
        )
        shown = big.safe_display(max_length=45)
        self.assertTrue(shown.endswith(TRUNCATION_MARKER))
        self.assertNotIn("long=", shown)

    def test_original_url_and_wire_bytes_are_unchanged(self):
        url = URL.from_text(SAMPLE_URL)
        original_text = url.to_text(with_password=True)
        original_bytes = url.to_uri().to_text(with_password=True)
        original_query = url.query
        original_userinfo = url.userinfo

        _ = url.safe_display()
        _ = url.safe_display(recurse_nested=True, max_length=60)

        self.assertEqual(url.to_text(with_password=True), original_text)
        self.assertEqual(
            url.to_uri().to_text(with_password=True), original_bytes
        )
        self.assertEqual(url.query, original_query)
        self.assertEqual(url.userinfo, original_userinfo)
        self.assertEqual(hash(url), hash(URL.from_text(original_text)))

    def test_decoded_url_shares_the_boundary(self):
        durl = DecodedURL.from_text(SAMPLE_URL, lazy=True)
        display = durl.safe_display()
        self.assertNotIn(SECRET_PASSWORD, display)
        self.assertNotIn(SECRET_TOKEN_ONE, display)
        # underlying decoded object is untouched
        self.assertEqual(durl.userinfo[0], "alice")

    def test_repr_respects_the_same_boundary(self):
        url = URL.from_text(SAMPLE_URL)
        rendered = repr(url)
        for secret in (
            SECRET_PASSWORD,
            SECRET_TOKEN_ONE,
            SECRET_TOKEN_TWO,
            "caps-token",
            "encoded-key-token",
            "at-secret",
        ):
            self.assertNotIn(secret, rendered)

        # nested URL parameters are masked recursively in repr too
        self.assertNotIn("inner-secret", rendered)

        durl = DecodedURL.from_text(SAMPLE_URL, lazy=True)
        rendered = repr(durl)
        self.assertNotIn(SECRET_PASSWORD, rendered)
        self.assertNotIn(SECRET_TOKEN_ONE, rendered)
        self.assertNotIn("inner-secret", rendered)

    def test_parse_errors_do_not_leak_secrets(self):
        cases = [
            "https://alice:" + SECRET_PASSWORD + "@[bad?token="
            + SECRET_TOKEN_ONE,
            "https://alice:" + SECRET_PASSWORD + "@bad[host/?token="
            + SECRET_TOKEN_ONE,
            # nested URL tokens in the query must be masked too
            "https://alice:" + SECRET_PASSWORD + "@[bad?redirect="
            + NESTED_URL,
        ]
        for bad in cases:
            with self.assertRaises(URLParseError) as cm:
                URL.from_text(bad)
            message = str(cm.exception)
            self.assertNotIn(SECRET_PASSWORD, message)
            self.assertNotIn("alice", message)
            self.assertNotIn(SECRET_TOKEN_ONE, message)
            self.assertNotIn("inner-secret", message)
            self.assertIn(REDACTION_PLACEHOLDER, message)

    def test_default_sensitive_policy_is_exported(self):
        self.assertIn("token", DEFAULT_SENSITIVE_QUERY_KEYS)
        self.assertIn("access_token", DEFAULT_SENSITIVE_QUERY_KEYS)

    def test_invalid_arguments(self):
        url = URL.from_text("https://h/?a=b")
        with self.assertRaises(ValueError):
            url.safe_display(max_depth=-1)
        with self.assertRaises(ValueError):
            url.safe_display(max_length=len(TRUNCATION_MARKER))
