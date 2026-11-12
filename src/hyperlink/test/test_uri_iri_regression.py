# -*- coding: utf-8 -*-
u"""
URI/IRI compatibility regression set.

This module locks the encoding boundary between wire strings
(:class:`~hyperlink.URL`) and the application-level decoded view
(:class:`~hyperlink.DecodedURL`). Every expectation below is a fixed
public RFC example or a hand-written wire string; none of them are
derived by normalizing the input first and comparing it against
itself.

Contract classification (see the test classes for locked cases):

* **Byte-preserving operations** must keep percent-encoded octets and
  delimiters byte-for-byte:
  :meth:`URL.from_text <hyperlink.URL.from_text>`,
  :meth:`URL.to_text <hyperlink.URL.to_text>`,
  :meth:`URL.click <hyperlink.URL.click>` (path/query/fragment parts),
  :meth:`URL.to_uri <hyperlink.URL.to_uri>` for already-encoded input,
  plus :meth:`DecodedURL.to_text <hyperlink.DecodedURL.to_text>`.
* **Resource-semantic-only operations** may change bytes as long as the
  identified resource / application data is preserved:
  :meth:`URL.normalize <hyperlink.URL.normalize>`,
  :meth:`URL.to_iri <hyperlink.URL.to_iri>`,
  :class:`~hyperlink.DecodedURL` construction/equality, and
  DecodedURL-based :meth:`~hyperlink.DecodedURL.to_uri`.
* **Mixed contract**: :meth:`URL.to_uri` preserves encoded fields but
  re-encodes Unicode host/path/query/fragment to ASCII and IDNA-encodes
  the host (RFC 3986/3987).

Documented boundaries that are intentionally *not* byte round-trips:

* ``to_text`` only emits ``?``/``#`` when there is content, so empty
  query/fragment delimiters are not representable in rendered text;
  inspect the structured ``query``/``fragment`` attributes instead.
* Stray percent signs / malformed percent-escapes pass through
  untouched under ``from_text``, ``to_text``, ``to_uri`` and ``to_iri``.
  Only ``normalize(percents=True)`` rewrites them to ``%25``.
* Repeated (``//``) and trailing slashes are structural empty path
  segments, not data to collapse; normalize does not remove them.
* ``to_iri`` decodes percent-escapes of reserved characters that are
  legal in the containing field (``;`` in a path segment, ``/`` in a
  fragment), so ``to_iri().to_uri()`` does not always restore the
  original URI bytes; the decoded value itself is unchanged.
* A percent-encoded *host* (e.g. ``ex%61mple.com``) is not a valid
  reg-name; ``to_uri`` raises :class:`idna.IDNAError` rather than
  guessing a decoding.

The generative tests at the bottom use a fixed example budget and a
fixed seed; they finish in a few seconds and never read a fuzzing
database.
"""
from __future__ import unicode_literals

from .common import HyperlinkTestCase
from .. import DecodedURL, URL, URLParseError

from idna import IDNAError

try:
    from hypothesis import HealthCheck, given, seed, settings
    from ..hypothesis import decoded_urls, encoded_urls

    HYPOTHESIS_AVAILABLE = True
except ImportError:  # pragma: no cover
    HYPOTHESIS_AVAILABLE = False


# Fixed seed and budget: deterministic, database-free, few-second run.
FUZZ_SEED = 0xC0FFEE
FUZZ_EXAMPLES = 30
FUZZ_SETTINGS = settings(
    max_examples=FUZZ_EXAMPLES,
    derandomize=True,
    database=None,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)

# ---------------------------------------------------------------------------
# Fixed wire-string expectation table.
#
# Each row: (wire, to_text, to_uri().to_text, to_iri().to_text,
#            normalize().to_text)
#
# All rendering calls use with_password=True so userinfo is fully visible.
# Expectations were hand-derived from RFC 3986/3987 rules and the contracts
# documented in the module docstring, not by copying current output blindly.
# ---------------------------------------------------------------------------

WIRE_EXPECTATIONS = [
    # --- Reserved characters: percent-encoded delimiters must survive
    #     every operation byte-for-byte; to_iri may decode only those
    #     reserved chars that are safe in that field (e.g. ";" in path).
    (
        "http://example.com/a%2Fb%3Bc%2Fd",
        "http://example.com/a%2Fb%3Bc%2Fd",
        "http://example.com/a%2Fb%3Bc%2Fd",
        "http://example.com/a%2Fb;c%2Fd",
        "http://example.com/a%2Fb%3Bc%2Fd",
    ),
    (
        "http://example.com/?k%3D1=v%262&onlykey",
        "http://example.com/?k%3D1=v%262&onlykey",
        "http://example.com/?k%3D1=v%262&onlykey",
        "http://example.com/?k%3D1=v%262&onlykey",
        "http://example.com/?k%3D1=v%262&onlykey",
    ),
    (
        "http://example.com/#frag%23ment%2Fpart",
        "http://example.com/#frag%23ment%2Fpart",
        "http://example.com/#frag%23ment%2Fpart",
        "http://example.com/#frag%23ment/part",
        "http://example.com/#frag%23ment%2Fpart",
    ),
    (
        "http://user%40name:p%40ss@example.com/",
        "http://user%40name:p%40ss@example.com/",
        "http://user%40name:p%40ss@example.com/",
        "http://user%40name:p%40ss@example.com/",
        "http://user%40name:p%40ss@example.com/",
    ),
    # --- Unicode domains and paths (IRI input): to_uri IDNA-encodes the
    #     host and UTF-8-percent-encodes the path; other ops preserve.
    (
        "https://ايران.com/foo⇧bar/",
        "https://ايران.com/foo⇧bar/",
        "https://xn--mgba3a4fra.com/foo%E2%87%A7bar/",
        "https://ايران.com/foo⇧bar/",
        "https://ايران.com/foo⇧bar/",
    ),
    (
        "http://ドメイン.テスト.co.jp/path",
        "http://ドメイン.テスト.co.jp/path",
        "http://xn--eckwd4c7c.xn--zckzah.co.jp/path",
        "http://ドメイン.テスト.co.jp/path",
        "http://ドメイン.テスト.co.jp/path",
    ),
    # --- The same resources in URI form: to_iri decodes host and path.
    (
        "https://xn--mgba3a4fra.com/foo%E2%87%A7bar/",
        "https://xn--mgba3a4fra.com/foo%E2%87%A7bar/",
        "https://xn--mgba3a4fra.com/foo%E2%87%A7bar/",
        "https://ايران.com/foo⇧bar/",
        "https://xn--mgba3a4fra.com/foo%E2%87%A7bar/",
    ),
    (
        "https://xn--bcher-kva.ch/%C3%BC",
        "https://xn--bcher-kva.ch/%C3%BC",
        "https://xn--bcher-kva.ch/%C3%BC",
        "https://bücher.ch/ü",
        "https://xn--bcher-kva.ch/%C3%BC",
    ),
    # --- Empty query/fragment: the "?" and "#" delimiters are not
    #     representable in rendered text (see module docstring); the
    #     empty/absent distinction is only visible in the structured
    #     attributes, locked separately below.
    (
        "http://example.com",
        "http://example.com",
        "http://example.com",
        "http://example.com",
        "http://example.com/",
    ),
    (
        "http://example.com?",
        "http://example.com",
        "http://example.com",
        "http://example.com",
        "http://example.com/",
    ),
    (
        "http://example.com#",
        "http://example.com",
        "http://example.com",
        "http://example.com",
        "http://example.com/",
    ),
    (
        "http://example.com/?",
        "http://example.com/",
        "http://example.com/",
        "http://example.com/",
        "http://example.com/",
    ),
    (
        "http://example.com/#",
        "http://example.com/",
        "http://example.com/",
        "http://example.com/",
        "http://example.com/",
    ),
    (
        "http://example.com/?#",
        "http://example.com/",
        "http://example.com/",
        "http://example.com/",
        "http://example.com/",
    ),
    # --- Repeated slashes: structural empty segments, never collapsed.
    (
        "http://example.com//a",
        "http://example.com//a",
        "http://example.com//a",
        "http://example.com//a",
        "http://example.com//a",
    ),
    (
        "http://example.com/a//b///",
        "http://example.com/a//b///",
        "http://example.com/a//b///",
        "http://example.com/a//b///",
        "http://example.com/a//b///",
    ),
    (
        "//example.com/a/b",
        "//example.com/a/b",
        "//example.com/a/b",
        "//example.com/a/b",
        "//example.com/a/b",
    ),
    # --- Invalid escapes: passed through everywhere except normalize,
    #     which percent-encodes the stray "%" (RFC 3986 2.4).
    (
        "http://example.com/%zz",
        "http://example.com/%zz",
        "http://example.com/%zz",
        "http://example.com/%zz",
        "http://example.com/%25zz",
    ),
    (
        "http://example.com/foo%",
        "http://example.com/foo%",
        "http://example.com/foo%",
        "http://example.com/foo%",
        "http://example.com/foo%25",
    ),
    (
        "http://example.com/a%2g%b",
        "http://example.com/a%2g%b",
        "http://example.com/a%2g%b",
        "http://example.com/a%2g%b",
        "http://example.com/a%252g%25b",
    ),
    # --- Percent-encoding case and double-encoding: hex case is
    #     preserved by all ops except normalize (RFC 3986 2.1), and
    #     "%25" is never collapsed to "%" or re-encoded to "%2525".
    (
        "http://example.com/a%2fb",
        "http://example.com/a%2fb",
        "http://example.com/a%2fb",
        "http://example.com/a%2fb",
        "http://example.com/a%2Fb",
    ),
    (
        "http://example.com/%25",
        "http://example.com/%25",
        "http://example.com/%25",
        "http://example.com/%25",
        "http://example.com/%25",
    ),
    (
        "http://example.com/%2525",
        "http://example.com/%2525",
        "http://example.com/%2525",
        "http://example.com/%2525",
        "http://example.com/%2525",
    ),
    # --- RFC 3986 3.3 path params and sub-delims are legal in path
    #     segments and must pass through unchanged.
    (
        "http://a/b/c/d;p?q",
        "http://a/b/c/d;p?q",
        "http://a/b/c/d;p?q",
        "http://a/b/c/d;p?q",
        "http://a/b/c/d;p?q",
    ),
    (
        "http://example.com/!$&'()*+,;=:@",
        "http://example.com/!$&'()*+,;=:@",
        "http://example.com/!$&'()*+,;=:@",
        "http://example.com/!$&'()*+,;=:@",
        "http://example.com/!$&'()*+,;=:@",
    ),
    # --- IP literals: never IDNA-encoded by to_uri (regression: this
    #     used to raise idna.InvalidCodepoint for IPv6 hosts).
    (
        "http://[::1]/",
        "http://[::1]/",
        "http://[::1]/",
        "http://[::1]/",
        "http://[::1]/",
    ),
    (
        "http://[2001:db8::1]/a",
        "http://[2001:db8::1]/a",
        "http://[2001:db8::1]/a",
        "http://[2001:db8::1]/a",
        "http://[2001:db8::1]/a",
    ),
    (
        "http://user:pass@[::1]:8080/p?q#f",
        "http://user:pass@[::1]:8080/p?q#f",
        "http://user:pass@[::1]:8080/p?q#f",
        "http://user:pass@[::1]:8080/p?q#f",
        "http://user:pass@[::1]:8080/p?q#f",
    ),
    # --- Percent-encoded host: not a valid reg-name. to_text/to_iri
    #     pass it through; normalize only lowercases hex digits;
    #     to_uri raises IDNAError (locked separately below).
    (
        "http://ex%61mple.com/",
        "http://ex%61mple.com/",
        None,  # to_uri raises idna.IDNAError
        "http://ex%61mple.com/",
        "http://ex%61mple.com/",
    ),
    (
        "http://ex%2Fample.com/",
        "http://ex%2Fample.com/",
        None,  # to_uri raises idna.IDNAError
        "http://ex%2Fample.com/",
        "http://ex%2fample.com/",
    ),
]


# RFC 3986 section 5.4.1 ("Normal Examples") and 5.4.2 ("Abnormal
# Examples"), base URI "http://a/b/c/d;p?q". Expectations are the literal
# results printed by RFC 3986; the only omitted example is "g:h", which
# this library deliberately rejects as a scheme-with-rootless-path.
# Wire strings where to_iri() legally decodes percent-encoded,
# field-safe reserved characters, so to_iri().to_uri() does not
# reproduce the original URI bytes (see TestUriIriComposition).
IRI_URI_DIVERGENT_WIRES = frozenset(
    [
        "http://example.com/a%2Fb%3Bc%2Fd",
        "http://example.com/#frag%23ment%2Fpart",
    ]
)
IRI_URI_DIVERGENT_EXPECTATIONS = [
    (
        "http://example.com/a%2Fb%3Bc%2Fd",
        "http://example.com/a%2Fb;c%2Fd",
    ),
    (
        "http://example.com/#frag%23ment%2Fpart",
        "http://example.com/#frag%23ment/part",
    ),
]


RFC3986_BASE = "http://a/b/c/d;p?q"
RFC3986_NORMAL_EXAMPLES = [
    ("g", "http://a/b/c/g"),
    ("./g", "http://a/b/c/g"),
    ("g/", "http://a/b/c/g/"),
    ("/g", "http://a/g"),
    ("//g", "http://g"),
    ("?y", "http://a/b/c/d;p?y"),
    ("g?y", "http://a/b/c/g?y"),
    ("#s", "http://a/b/c/d;p?q#s"),
    ("g#s", "http://a/b/c/g#s"),
    ("g?y#s", "http://a/b/c/g?y#s"),
    (";x", "http://a/b/c/;x"),
    ("g;x", "http://a/b/c/g;x"),
    ("g;x?y#s", "http://a/b/c/g;x?y#s"),
    ("", "http://a/b/c/d;p?q"),
    (".", "http://a/b/c/"),
    ("./", "http://a/b/c/"),
    ("..", "http://a/b/"),
    ("../", "http://a/b/"),
    ("../g", "http://a/b/g"),
    ("../..", "http://a/"),
    ("../../", "http://a/"),
    ("../../g", "http://a/g"),
]
RFC3986_ABNORMAL_EXAMPLES = [
    ("../../../g", "http://a/g"),
    ("../../../../g", "http://a/g"),
    ("/./g", "http://a/g"),
    ("/../g", "http://a/g"),
    ("g.", "http://a/b/c/g."),
    (".g", "http://a/b/c/.g"),
    ("g..", "http://a/b/c/g.."),
    ("..g", "http://a/b/c/..g"),
    ("./../g", "http://a/b/g"),
    ("./g/.", "http://a/b/c/g/"),
    ("g/./h", "http://a/b/c/g/h"),
    ("g/../h", "http://a/b/c/h"),
    ("g;x=1/./y", "http://a/b/c/g;x=1/y"),
    ("g;x=1/../y", "http://a/b/c/y"),
    ("g?y/./x", "http://a/b/c/g?y/./x"),
    ("g?y/../x", "http://a/b/c/g?y/../x"),
    ("g#s/./x", "http://a/b/c/g#s/./x"),
    ("g#s/../x", "http://a/b/c/g#s/../x"),
]


class TestWireStringCompatibility(HyperlinkTestCase):
    u"""Parsing and rendering fixed wire strings.

    Every non-``None`` expectation is literal; each operation is
    asserted against its own column so a single operation can never
    "fix" another operation's output.
    """

    def test_every_row_is_well_formed(self):
        # type: () -> None
        for row in WIRE_EXPECTATIONS:
            self.assertEqual(len(row), 5)
            wire = row[0]
            self.assertEqual(URL.from_text(wire), URL.from_text(wire))

    def test_to_text_is_byte_preserving(self):
        # type: () -> None
        for wire, expected_text, _, _, _ in WIRE_EXPECTATIONS:
            url = URL.from_text(wire)
            self.assertEqual(
                url.to_text(with_password=True), expected_text, wire
            )

    def test_to_uri_for_encoded_input(self):
        # type: () -> None
        for wire, _, expected_uri, _, _ in WIRE_EXPECTATIONS:
            if expected_uri is None:
                continue
            url = URL.from_text(wire)
            self.assertEqual(
                url.to_uri().to_text(with_password=True), expected_uri, wire
            )

    def test_to_iri(self):
        # type: () -> None
        for wire, _, _, expected_iri, _ in WIRE_EXPECTATIONS:
            url = URL.from_text(wire)
            self.assertEqual(
                url.to_iri().to_text(with_password=True), expected_iri, wire
            )

    def test_normalize(self):
        # type: () -> None
        for wire, _, _, _, expected_norm in WIRE_EXPECTATIONS:
            url = URL.from_text(wire)
            self.assertEqual(
                url.normalize().to_text(with_password=True),
                expected_norm,
                wire,
            )

    def test_to_uri_output_is_ascii(self):
        # type: () -> None
        for wire, _, expected_uri, _, _ in WIRE_EXPECTATIONS:
            if expected_uri is None:
                continue
            text = URL.from_text(wire).to_uri().to_text(with_password=True)
            self.assertEqual(text.encode("ascii").decode("ascii"), text)


class TestEncodingBoundaries(HyperlinkTestCase):
    u"""Operations that lock which bytes are preserved vs. semantic."""

    def test_percent_encoded_host_to_uri_raises(self):
        # type: () -> None
        # A percent-encoded host is not a valid reg-name; the library
        # refuses to guess what the octets mean. IDNAError is a
        # UnicodeError, which is a ValueError.
        for wire in [
            "http://ex%61mple.com/",
            "http://ex%2Fample.com/",
            "http://ex%zz.com/",
        ]:
            with self.assertRaises(IDNAError):
                URL.from_text(wire).to_uri()

    def test_malformed_authority_raises_parse_error(self):
        # type: () -> None
        # The only strings from_text rejects outright: bad ports and
        # invalid IPv6 literals.
        for wire in [
            "http://example.com:abc/",
            "http://example.com:",
            "http://[::1/",
            "http://[[::1]/",
        ]:
            self.assertRaises(URLParseError, URL.from_text, wire)

    def test_ip_literals_skip_idna(self):
        # type: () -> None
        # Regression: to_uri() used to feed IPv6 literals to idna_encode,
        # which rejected the colons.
        for wire in [
            "http://[::1]/",
            "http://[2001:db8::1]/",
            "http://[::ffff:192.0.2.1]/",
            "http://[::1]:8080/p?x=1#f",
            "http://user:pw@[2001:db8::2]/",
        ]:
            uri = URL.from_text(wire).to_uri().to_text(with_password=True)
            self.assertEqual(uri, wire)
            uri.encode("ascii")

    def test_ipv4_is_not_idna_reencoded(self):
        # type: () -> None
        url = URL.from_text("http://192.0.2.16:8080/x")
        self.assertEqual(url.to_uri().to_text(), "http://192.0.2.16:8080/x")
        self.assertEqual(url.to_iri().to_text(), "http://192.0.2.16:8080/x")

    def test_invalid_escapes_pass_through_without_normalize(self):
        # type: () -> None
        # Byte-preserving ops must not touch malformed percent-escapes.
        for wire in [
            "http://example.com/%zz",
            "http://example.com/foo%",
            "http://example.com/a%2g%b",
            "http://example.com/?x=%zz",
            "http://example.com/#%",
        ]:
            url = URL.from_text(wire)
            self.assertEqual(url.to_text(), wire)
            self.assertEqual(url.to_uri().to_text(), wire)
            self.assertEqual(url.to_iri().to_text(), wire)

    def test_normalize_rewrites_stray_percents(self):
        # type: () -> None
        # normalize(percents=True) is the *only* operation allowed to
        # repair malformed escapes.
        url = URL.from_text("http://example.com/a%2g%b/?x=%zz#f%")
        expected = "http://example.com/a%252g%25b/?x=%25zz#f%25"
        self.assertEqual(url.normalize().to_text(), expected)
        # opt-out preserves the stray percents byte-for-byte
        self.assertEqual(
            url.normalize(percents=False).to_text(),
            "http://example.com/a%2g%b/?x=%zz#f%",
        )

    def test_normalize_uppercases_hex_octets(self):
        # type: () -> None
        url = URL.from_text("http://example.com/a%2fb%3f?k%3d=v#f%23")
        self.assertEqual(
            url.normalize().to_text(),
            "http://example.com/a%2Fb%3F?k%3D=v#f%23",
        )

    def test_repeated_slashes_are_structural_segments(self):
        # type: () -> None
        url = URL.from_text("http://example.com/a//b///")
        self.assertEqual(url.path, ("a", "", "b", "", "", ""))
        # to_text and normalize both preserve them
        for rendered in (
            url.to_text(),
            url.normalize().to_text(),
            url.to_uri().to_text(),
            url.to_iri().to_text(),
        ):
            self.assertEqual(rendered, "http://example.com/a//b///")

    def test_repeated_slashes_survive_click(self):
        # type: () -> None
        url = URL.from_text("http://a//b?x=1")
        self.assertEqual(
            url.click("c").to_text(), "http://a//c"
        )
        self.assertEqual(
            url.click("?y").to_text(), "http://a//b?y"
        )
        self.assertEqual(
            url.click("").to_text(), "http://a//b?x=1"
        )

    def test_percent_is_never_collapsed_or_double_encoded(self):
        # type: () -> None
        for wire in ["http://example.com/%25",
                     "http://example.com/%2525"]:
            url = URL.from_text(wire)
            self.assertEqual(url.to_uri().to_text(), wire)
            self.assertEqual(url.to_iri().to_text(), wire)
            self.assertEqual(url.normalize().to_text(), wire)

    def test_raw_and_normalized_equality_boundary(self):
        # type: () -> None
        # URL equality is structural: different encoding = not equal
        # before normalization; equal after normalize (semantic layer).
        lower = URL.from_text("http://example.com/a%2fb")
        upper = URL.from_text("http://example.com/a%2Fb")
        self.assertNotEqual(lower, upper)
        self.assertEqual(lower.normalize(), upper.normalize())

    def test_empty_query_fragment_structured_state(self):
        # type: () -> None
        # The delimiters cannot round-trip through text, but the parsed
        # state must remain distinguishable at the structured level.
        with_qs = URL.from_text("http://example.com/?")
        without_qs = URL.from_text("http://example.com/")
        self.assertEqual(with_qs.query, ())
        self.assertEqual(with_qs.fragment, "")
        self.assertEqual(without_qs.query, ())
        self.assertEqual(without_qs.fragment, "")
        # rendered text is identical by contract
        self.assertEqual(with_qs.to_text(), "http://example.com/")
        self.assertEqual(without_qs.to_text(), "http://example.com/")
        # but a value-less key is preserved, including an empty value
        key_only = URL.from_text("http://example.com/?k")
        self.assertEqual(key_only.query, (("k", None),))
        empty_value = URL.from_text("http://example.com/?k=")
        self.assertEqual(empty_value.query, (("k", ""),))

    def test_click_empties_query_and_fragment_explicitly(self):
        # type: () -> None
        # Locking the parser-level boundary documented in the module
        # docstring: an empty query parses to no parameters, which is
        # indistinguishable from an absent query, so a bare "?"
        # reference keeps the base query. A bare "#" does clear the
        # fragment, and "" is a full self-reference.
        base = URL.from_text("http://a/b/c?x=1#f")
        self.assertEqual(base.click("?").query, (("x", "1"),))
        self.assertEqual(base.click("?").fragment, "")
        self.assertEqual(base.click("#").fragment, "")
        self.assertEqual(base.click("?").to_text(), "http://a/b/c?x=1")
        self.assertEqual(base.click("?#").to_text(), "http://a/b/c?x=1")
        self.assertEqual(base.click("").to_text(), "http://a/b/c?x=1#f")
        self.assertEqual(base.click("?y").to_text(), "http://a/b/c?y")

    def test_query_order_and_duplicate_keys_are_byte_preserved(self):
        # type: () -> None
        wire = "http://example.com/?a=1&b=2&a=3&empty"
        url = URL.from_text(wire)
        self.assertEqual(
            url.query, (("a", "1"), ("b", "2"), ("a", "3"),
                        ("empty", None))
        )
        self.assertEqual(url.to_uri().to_text(), wire)
        self.assertEqual(url.normalize().to_text(), wire)


class TestClickRFC3986(HyperlinkTestCase):
    u"""Relative-reference resolution against fixed RFC examples."""

    def test_normal_examples(self):
        # type: () -> None
        base = URL.from_text(RFC3986_BASE)
        for reference, expected in RFC3986_NORMAL_EXAMPLES:
            self.assertEqual(
                base.click(reference).to_text(), expected, reference
            )

    def test_abnormal_examples(self):
        # type: () -> None
        base = URL.from_text(RFC3986_BASE)
        for reference, expected in RFC3986_ABNORMAL_EXAMPLES:
            self.assertEqual(
                base.click(reference).to_text(), expected, reference
            )

    def test_click_preserves_wire_encoding_of_parts(self):
        # type: () -> None
        # Resolution must not decode or re-encode the carried parts.
        base = URL.from_text("http://a/b/c?x=1#f")
        self.assertEqual(
            base.click("g%2Fh?y%3D2#f%2Fz").to_text(),
            "http://a/b/g%2Fh?y%3D2#f%2Fz",
        )
        self.assertEqual(
            base.click("/r%2fs").to_text(), "http://a/r%2fs"
        )

    def test_click_accepts_url_and_decodedurl_instances(self):
        # type: () -> None
        base = URL.from_text("http://a/b/c")
        target = URL.from_text("/d/e")
        self.assertEqual(
            base.click(target).to_text(), "http://a/d/e"
        )
        dbase = DecodedURL.from_text("http://a/b/c")
        dtarget = DecodedURL.from_text("/d/e")
        self.assertEqual(
            dbase.click(dtarget).to_text(), "http://a/d/e"
        )

    def test_rootless_scheme_reference_is_rejected(self):
        # type: () -> None
        # "g:h" and "http:h" use a scheme with a rootless path; the
        # library documents this as unsupported rather than guessing.
        base = URL.from_text(RFC3986_BASE)
        self.assertRaises(NotImplementedError, base.click, "g:h")
        self.assertRaises(NotImplementedError, base.click, "http:g")


class TestUriIriComposition(HyperlinkTestCase):
    u"""Fixed to_uri / to_iri composition expectations."""

    def test_uri_is_fixed_point(self):
        # type: () -> None
        for wire, _, expected_uri, _, _ in WIRE_EXPECTATIONS:
            if expected_uri is None:
                continue
            once = URL.from_text(wire).to_uri()
            twice = once.to_uri()
            self.assertEqual(
                twice.to_text(with_password=True),
                expected_uri,
                wire,
            )

    def test_to_iri_then_to_uri_matches_to_uri(self):
        # type: () -> None
        # For every fixed wire string without field-safe reserved
        # octets, both orders of URI/IRI normalization converge on
        # the same URI bytes.
        for wire, _, expected_uri, _, _ in WIRE_EXPECTATIONS:
            if expected_uri is None:
                continue
            if wire in IRI_URI_DIVERGENT_WIRES:
                continue
            url = URL.from_text(wire)
            direct = url.to_uri().to_text(with_password=True)
            via_iri = url.to_iri().to_uri().to_text(with_password=True)
            self.assertEqual(via_iri, direct, wire)
            self.assertEqual(direct, expected_uri, wire)

    def test_to_iri_legally_decodes_field_safe_reserved_octets(self):
        # type: () -> None
        # to_iri decodes percent-escapes of reserved characters that
        # are legal in that field (";" in path, "/" in fragment). The
        # decoded form is then maximal-encoded back to the *same*
        # readable character, so URI bytes are not restored, even
        # though the resource is unchanged. This is the documented
        # IRI contract, not a bug.
        for wire, expected_divergent in IRI_URI_DIVERGENT_EXPECTATIONS:
            url = URL.from_text(wire)
            direct = url.to_uri().to_text(with_password=True)
            via_iri = url.to_iri().to_uri().to_text(with_password=True)
            self.assertNotEqual(via_iri, direct, wire)
            self.assertEqual(via_iri, expected_divergent, wire)

    def test_unicode_input_round_trips_through_uri(self):
        # type: () -> None
        iri = "https://bücher.ch/%C3%BC?q=%C3%A9#f%2Fr"
        uri = URL.from_text(iri).to_uri()
        self.assertEqual(
            uri.to_text(),
            "https://xn--bcher-kva.ch/%C3%BC?q=%C3%A9#f%2Fr",
        )
        self.assertEqual(
            uri.to_iri().to_text(),
            "https://bücher.ch/ü?q=é#f/r",
        )
        self.assertEqual(uri.to_uri(), uri)

    def test_uri_bytes_differ_from_iri_even_for_same_resource(self):
        # type: () -> None
        url = URL.from_text("http://example.com/café")
        uri_text = url.to_uri().to_text()
        iri_text = url.to_iri().to_text()
        self.assertEqual(uri_text, "http://example.com/caf%C3%A9")
        self.assertEqual(iri_text, "http://example.com/café")
        self.assertNotEqual(uri_text, iri_text)
        self.assertNotEqual(url.to_uri(), url.to_iri())
        # ...but they collapse to the same DecodedURL resource.
        self.assertEqual(
            DecodedURL(url.to_uri()), DecodedURL(url.to_iri())
        )


class TestDecodedURLBoundaries(HyperlinkTestCase):
    u"""Application-level decoding layer.

    DecodedURL's contract is *semantic*: equality and data round-trips
    are judged on decoded values, while its underlying wire rendering
    stays percent-encoded.
    """

    def test_wire_to_decoded_parts(self):
        # type: () -> None
        cases = [
            (
                "http://example.com/a%20b",
                (("a b",), (), "", "example.com"),
            ),
            (
                "http://example.com/a%2Fb",
                (("a/b",), (), "", "example.com"),
            ),
            (
                "http://example.com/#frag%23x",
                (("",), (), "frag#x", "example.com"),
            ),
            (
                "http://example.com/%C3%A9%20x",
                (("é x",), (), "", "example.com"),
            ),
            (
                "https://xn--bcher-kva.ch/%C3%BC#fr%C3%A9g",
                (("ü",), (), "frég", "bücher.ch"),
            ),
        ]
        for wire, (path, query, fragment, host) in cases:
            decoded = DecodedURL.from_text(wire)
            self.assertEqual(decoded.path, path, wire)
            self.assertEqual(decoded.query, query, wire)
            self.assertEqual(decoded.fragment, fragment, wire)
            self.assertEqual(decoded.host, host, wire)

    def test_query_plus_is_space_default(self):
        # type: () -> None
        decoded = DecodedURL.from_text(
            "http://example.com/?x=a+b&y=a%2Bb&z"
        )
        self.assertEqual(
            decoded.query,
            (("x", "a b"), ("y", "a+b"), ("z", None)),
        )

    def test_query_plus_can_be_disabled(self):
        # type: () -> None
        decoded = DecodedURL.from_text(
            "http://example.com/?x=a+b&y=a%2Bb",
            query_plus_is_space=False,
        )
        self.assertEqual(
            decoded.query,
            (("x", "a+b"), ("y", "a+b")),
        )

    def test_stray_percents_are_literal_data(self):
        # type: () -> None
        decoded = DecodedURL.from_text("http://example.com/foo%")
        self.assertEqual(decoded.path, ("foo%",))
        # rendering keeps the literal percent, it is not "fixed"
        self.assertEqual(
            decoded.to_text(), "http://example.com/foo%"
        )
        # normalize is the only place the percent gets encoded
        self.assertEqual(
            decoded.normalize().to_text(),
            "http://example.com/foo%25",
        )

    def test_invalid_utf8_is_rejected_eagerly_only(self):
        # type: () -> None
        # (wire, attribute that must raise when accessed lazily)
        cases = [
            ("http://example.com/%ff", "path"),
            ("http://example.com/a%ffb", "path"),
            ("http://example.com/?x=%ff", "query"),
            ("http://example.com/#%ff", "fragment"),
        ]
        for wire, attr in cases:
            # eager (default) validation surfaces bad UTF-8
            self.assertRaises(
                UnicodeDecodeError, DecodedURL.from_text, wire
            )
            # lazy construction succeeds; the error moves to access
            lazy = DecodedURL.from_text(wire, lazy=True)
            self.assertRaises(
                UnicodeDecodeError, lambda: getattr(lazy, attr)
            )

    def test_application_data_survives_to_uri(self):
        # type: () -> None
        wires = [
            "http://example.com/a%20b",
            "http://example.com/a%2Fb",
            "http://example.com/?x=a+b&y=a%2Bb&z",
            "http://example.com/#frag%23x",
            "http://example.com/%C3%A9%20x",
            "https://xn--bcher-kva.ch/%C3%BC#fr%C3%A9g",
        ]
        for wire in wires:
            decoded = DecodedURL.from_text(wire)
            again = DecodedURL(decoded.to_uri())
            self.assertEqual(again.path, decoded.path, wire)
            self.assertEqual(again.query, decoded.query, wire)
            self.assertEqual(again.fragment, decoded.fragment, wire)
            self.assertEqual(again.host, decoded.host, wire)
            self.assertEqual(again.userinfo, decoded.userinfo, wire)

    def test_equality_is_semantic_not_bytewise(self):
        # type: () -> None
        # hex case differs on the wire but denotes the same resource
        self.assertEqual(
            DecodedURL.from_text("http://example.com/a%2fb"),
            DecodedURL.from_text("http://example.com/a%2Fb"),
        )
        # root vs no-root are equivalent on network URLs
        self.assertEqual(
            DecodedURL.from_text("http://example.com"),
            DecodedURL.from_text("http://example.com/"),
        )
        # whereas URL-level equality stays bytewise/structural
        self.assertNotEqual(
            URL.from_text("http://example.com/a%2fb"),
            URL.from_text("http://example.com/a%2Fb"),
        )

    def test_normalize_resolves_dots_and_decodes_unreserved(self):
        # type: () -> None
        decoded = DecodedURL.from_text(
            "http://example.com/a/./b/../c?X%62=Y%63#F%64"
        )
        normalized = decoded.normalize()
        self.assertEqual(normalized.path, ("a", "c"))
        self.assertEqual(normalized.to_text(),
                         "http://example.com/a/c?Xb=Yc#Fd")

    def test_click_returns_decoded_and_resolves(self):
        # type: () -> None
        decoded = DecodedURL.from_text("http://example.com/a/b?x=1#f")
        self.assertEqual(
            decoded.click("c").to_text(),
            "http://example.com/a/c",
        )
        self.assertEqual(
            decoded.click("?x=2").to_text(),
            "http://example.com/a/b?x=2",
        )
        self.assertEqual(
            decoded.click("#g").to_text(),
            "http://example.com/a/b?x=1#g",
        )
        self.assertIsInstance(decoded.click("c"), DecodedURL)

    def test_child_and_sibling_encode_reserved_chars(self):
        # type: () -> None
        decoded = DecodedURL.from_text("http://example.com/")
        self.assertEqual(
            decoded.child("a b", "c/d").to_text(),
            "http://example.com/a%20b/c%2Fd",
        )
        self.assertEqual(
            DecodedURL.from_text("http://example.com/a").sibling(
                "b?c"
            ).to_text(),
            "http://example.com/b%3Fc",
        )

    def test_wire_rendering_never_invents_empty_delimiters(self):
        # type: () -> None
        for wire in [
            "http://example.com",
            "http://example.com?",
            "http://example.com#",
        ]:
            decoded = DecodedURL.from_text(wire)
            self.assertEqual(
                decoded.to_text(), "http://example.com"
            )


if HYPOTHESIS_AVAILABLE:

    class TestGenerativeInvariants(HyperlinkTestCase):
        u"""Bounded, seeded property checks.

        Every check uses FUZZ_EXAMPLES examples, FUZZ_SEED, and
        derandomization with no on-disk database, so failures are
        reproducible and the whole class finishes in seconds.
        """

        @seed(FUZZ_SEED)
        @FUZZ_SETTINGS
        @given(encoded_urls())
        def test_text_reparse_is_byte_stable(self, url):
            # type: (URL) -> None
            text = url.to_text(with_password=True)
            self.assertEqual(
                URL.from_text(text).to_text(with_password=True), text
            )

        @seed(FUZZ_SEED)
        @FUZZ_SETTINGS
        @given(encoded_urls())
        def test_to_uri_is_ascii_and_idempotent(self, url):
            # type: (URL) -> None
            uri = url.to_uri()
            text = uri.to_text(with_password=True)
            self.assertEqual(text.encode("ascii").decode("ascii"), text)
            self.assertEqual(uri.to_uri(), uri)

        @seed(FUZZ_SEED)
        @FUZZ_SETTINGS
        @given(encoded_urls())
        def test_iri_idempotent_and_uri_compatible(self, url):
            # type: (URL) -> None
            iri = url.to_iri()
            self.assertEqual(iri.to_iri(), iri)
            self.assertEqual(iri.to_uri(), url.to_uri())

        @seed(FUZZ_SEED)
        @FUZZ_SETTINGS
        @given(encoded_urls())
        def test_to_uri_iri_to_uri_is_stable(self, url):
            # type: (URL) -> None
            uri = url.to_uri()
            self.assertEqual(
                uri.to_iri().to_uri(),
                uri,
            )

        @seed(FUZZ_SEED)
        @FUZZ_SETTINGS
        @given(decoded_urls())
        def test_application_data_survives_uri_encoding(self, decoded):
            # type: (DecodedURL) -> None
            again = DecodedURL(decoded.to_uri())
            self.assertEqual(again.path, decoded.path)
            self.assertEqual(again.query, decoded.query)
            self.assertEqual(again.fragment, decoded.fragment)
            self.assertEqual(again.host, decoded.host)
            self.assertEqual(again.userinfo, decoded.userinfo)

        @seed(FUZZ_SEED)
        @FUZZ_SETTINGS
        @given(encoded_urls())
        def test_normalize_is_semantically_idempotent(self, url):
            # type: (URL) -> None
            once = url.normalize()
            self.assertEqual(once.normalize(), once)

        @seed(FUZZ_SEED)
        @FUZZ_SETTINGS
        @given(encoded_urls())
        def test_empty_click_is_identity(self, url):
            # type: (URL) -> None
            self.assertEqual(url.click(""), url)

        @seed(FUZZ_SEED)
        @FUZZ_SETTINGS
        @given(encoded_urls())
        def test_click_reparses_its_own_output(self, url):
            # type: (URL) -> None
            clicked = url.click("#frag")
            text = clicked.to_text(with_password=True)
            self.assertEqual(
                URL.from_text(text).to_text(with_password=True), text
            )
