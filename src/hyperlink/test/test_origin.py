# -*- coding: utf-8 -*-
"""Tests for :class:`hyperlink.Origin` and the ``same_origin`` interface.

The matrices below double as the report of the normalization basis:
each case states the inputs and the normalized origin they map to.
"""

from __future__ import unicode_literals

from .common import HyperlinkTestCase
from .. import URL, DecodedURL, Origin, URLParseError, parse


# (left, right, expected same_origin) pairs sharing a normalization
# basis, grouped by the rule under test.

UNICODE_ASCII_MATRIX = [
    # IDNA: Unicode U-label and punycode A-label forms are one origin
    (u"http://bücher.de/", u"http://xn--bcher-kva.de/", True),
    (u"https://bücher.de/", u"https://xn--bcher-kva.de/", True),
    # UTS#46 case folding applies to both Unicode and ASCII forms
    (u"http://BÜCHER.de/", u"http://xn--bcher-kva.de/", True),
    (u"http://EXAMPLE.com/", u"http://example.com/", True),
    # IDNA in subdomains, mixed with ASCII labels
    (u"http://www.bücher.de/", u"http://www.xn--bcher-kva.de/", True),
    # different names stay different
    (u"http://bücher.de/", u"http://xn--bcher-kva.com/", False),
    (u"http://example.com/", u"http://example.org/", False),
]

PORT_MATRIX = [
    # explicit default port == omitted port
    (u"http://example.com/", u"http://example.com:80/", True),
    (u"https://example.com/", u"https://example.com:443/", True),
    (u"http://example.com:80/", u"http://example.com:80/", True),
    # non-default port is significant
    (u"http://example.com/", u"http://example.com:8080/", False),
    (u"http://example.com:8080/", u"http://example.com:8081/", False),
    # scheme is significant even on the same effective port
    (u"http://example.com:443/", u"https://example.com/", False),
    (u"http://example.com/", u"https://example.com/", False),
    # schemes without a registered default port: omitted == omitted
    (u"foo://example.com/", u"foo://example.com/", True),
    (u"foo://example.com/", u"foo://example.com:9/", False),
]

IP_MATRIX = [
    # IPv6 spellings normalize to one canonical form
    (u"http://[::1]/", u"http://[0:0:0:0:0:0:0:1]/", True),
    (u"http://[::1]/", u"http://[0:0::0:1]:80/", True),
    (u"http://[2001:DB8::1]/", u"http://[2001:db8:0:0:0:0:0:1]/", True),
    (u"http://[::1]/", u"http://[::2]/", False),
    # IPv4 dotted quads compare textually
    (u"http://127.0.0.1/", u"http://127.0.0.1:80/", True),
    (u"http://127.0.0.1/", u"http://127.0.0.2/", False),
    # an IP and a hostname are never the same origin
    (u"http://127.0.0.1/", u"http://localhost/", False),
]

OPAQUE_MATRIX = [
    # hostless URLs get scheme-tagged opaque origins, not one empty origin
    (u"mailto:a@example.com", u"mailto:b@example.com", True),
    (u"data:text/plain,x", u"data:text/html,y", True),
    (u"file:///etc/passwd", u"file:///other/path", True),
    (u"mailto:a@example.com", u"data:text/plain,x", False),
    (u"mailto:a@example.com", u"file:///etc/passwd", False),
    (
        u"urn:isbn:0451450523",
        u"urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66",
        True,
    ),
    # opaque origins never equal tuple origins
    (u"file:///etc/passwd", u"http://example.com/", False),
]

IGNORED_PARTS_MATRIX = [
    # userinfo, path, query, and fragment never enter the origin
    (u"http://user:pass@example.com/a?x=1#f", u"http://example.com/", True),
    (u"http://a@example.com/1?x=1", u"http://b@example.com/2?y=2#z", True),
    (u"https://example.com", u"https://example.com/deep/path/?q#frag", True),
]


class TestSameOriginMatrix(HyperlinkTestCase):
    def _check_matrix(self, matrix):
        for left_text, right_text, expected in matrix:
            left, right = URL.from_text(left_text), URL.from_text(right_text)
            self.assertEqual(
                left.same_origin(right),
                expected,
                "%r vs %r" % (left_text, right_text),
            )
            # symmetry
            self.assertEqual(
                right.same_origin(left),
                expected,
                "%r vs %r (reversed)" % (left_text, right_text),
            )
            # equality of origins agrees with same_origin
            self.assertEqual(left.origin == right.origin, expected)
            self.assertEqual(
                hash(left.origin) == hash(right.origin),
                expected,
                "hash mismatch for %r vs %r" % (left_text, right_text),
            )

    def test_unicode_ascii_matrix(self):
        self._check_matrix(UNICODE_ASCII_MATRIX)

    def test_port_matrix(self):
        self._check_matrix(PORT_MATRIX)

    def test_ip_matrix(self):
        self._check_matrix(IP_MATRIX)

    def test_opaque_matrix(self):
        self._check_matrix(OPAQUE_MATRIX)

    def test_ignored_parts_matrix(self):
        self._check_matrix(IGNORED_PARTS_MATRIX)

    def test_decoded_url_support(self):
        # DecodedURL exposes the same interface, in both directions
        dec = DecodedURL.from_text(u"http://bücher.de/a?x=1")
        enc = URL.from_text(u"http://xn--bcher-kva.de/")
        self.assertTrue(dec.same_origin(enc))
        self.assertTrue(enc.same_origin(dec))
        self.assertEqual(dec.origin, enc.origin)
        # parse() returns DecodedURL by default
        self.assertTrue(
            parse(u"https://example.com:443").same_origin(
                parse(u"https://example.com", decoded=False)
            )
        )

    def test_origin_does_not_change_url_equality(self):
        # URL's own equality contract is untouched: no normalization,
        # no default-port folding beyond the existing behavior
        self.assertNotEqual(
            URL.from_text(u"http://bücher.de/"),
            URL.from_text(u"http://xn--bcher-kva.de/"),
        )
        self.assertNotEqual(
            URL.from_text(u"http://EXAMPLE.com/"),
            URL.from_text(u"http://example.com/"),
        )
        self.assertNotEqual(
            URL.from_text(u"http://a@example.com/"),
            URL.from_text(u"http://b@example.com/"),
        )
        # ...while all of these pairs share an origin
        self.assertTrue(
            URL.from_text(u"http://bücher.de/").same_origin(
                URL.from_text(u"http://xn--bcher-kva.de/")
            )
        )

    def test_origin_does_not_mutate_url(self):
        url = URL.from_text(u"http://BÜCHER.de:8080/a/../b?x=1#f")
        before = url.to_text()
        url.origin
        url.same_origin(URL.from_text(u"http://example.com/"))
        self.assertEqual(url.to_text(), before)
        dec = DecodedURL.from_text(u"http://bücher.de/")
        dec_before = dec.to_text()
        dec.origin
        self.assertEqual(dec.to_text(), dec_before)


class TestOriginNormalizationBasis(HyperlinkTestCase):
    """The origin object retains the normalized values used as the
    comparison basis."""

    def test_idna_basis(self):
        origin = URL.from_text(u"http://BÜCHER.de/").origin
        self.assertEqual(origin.scheme, u"http")
        self.assertEqual(origin.host, u"xn--bcher-kva.de")
        self.assertEqual(origin.port, 80)
        self.assertFalse(origin.is_opaque)

    def test_ipv6_basis(self):
        origin = URL.from_text(u"http://[0:0:0:0:0:0:0:1]:8080/").origin
        self.assertEqual(origin.host, u"::1")
        self.assertEqual(origin.port, 8080)

    def test_default_port_basis(self):
        self.assertEqual(
            URL.from_text(u"https://example.com/").origin.port, 443
        )
        self.assertIsNone(URL.from_text(u"foo://example.com/").origin.port)

    def test_opaque_basis(self):
        origin = URL.from_text(u"MAILTO:a@example.com").origin
        self.assertTrue(origin.is_opaque)
        self.assertEqual(origin.scheme, u"mailto")
        self.assertIsNone(origin.host)
        self.assertIsNone(origin.port)

    def test_scheme_case_normalized(self):
        self.assertEqual(
            URL.from_text(u"HTTP://example.com/").origin,
            URL.from_text(u"http://example.com/").origin,
        )


class TestOriginSerialization(HyperlinkTestCase):
    def _all_matrix_texts(self):
        texts = []
        for matrix in (
            UNICODE_ASCII_MATRIX,
            PORT_MATRIX,
            IP_MATRIX,
            OPAQUE_MATRIX,
            IGNORED_PARTS_MATRIX,
        ):
            texts.extend(t for pair in matrix for t in pair[:2])
        return texts

    def test_text_round_trip(self):
        for text in self._all_matrix_texts():
            origin = URL.from_text(text).origin
            restored = Origin.from_text(origin.to_text())
            self.assertEqual(origin, restored, text)
            self.assertEqual(hash(origin), hash(restored))
            self.assertEqual(origin.to_text(), restored.to_text())

    def test_round_trip_preserves_comparison(self):
        # serializing and restoring an origin must not change any
        # same-origin verdict
        for matrix in (UNICODE_ASCII_MATRIX, PORT_MATRIX, OPAQUE_MATRIX):
            for left_text, right_text, expected in matrix:
                left = Origin.from_text(
                    URL.from_text(left_text).origin.to_text()
                )
                right = Origin.from_text(
                    URL.from_text(right_text).origin.to_text()
                )
                self.assertEqual(
                    left == right,
                    expected,
                    "%r vs %r" % (left_text, right_text),
                )

    def test_to_text_formats(self):
        self.assertEqual(
            URL.from_text(u"http://example.com:8080/").origin.to_text(),
            u"http://example.com:8080",
        )
        self.assertEqual(
            URL.from_text(u"http://example.com/").origin.to_text(),
            u"http://example.com:80",
        )
        self.assertEqual(
            URL.from_text(u"http://[::1]/").origin.to_text(),
            u"http://[::1]:80",
        )
        self.assertEqual(
            URL.from_text(u"foo://example.com/").origin.to_text(),
            u"foo://example.com",
        )
        self.assertEqual(
            URL.from_text(u"mailto:a@b").origin.to_text(), u"opaque:mailto"
        )

    def test_from_text_normalizes(self):
        # hand-written origin text gets the same normalization basis
        self.assertEqual(
            Origin.from_text(u"http://BÜCHER.de"),
            Origin.from_text(u"http://xn--bcher-kva.de:80"),
        )
        self.assertEqual(
            Origin.from_text(u"http://[0:0:0:0:0:0:0:1]:80"),
            Origin.from_text(u"http://[::1]"),
        )

    def test_from_text_invalid(self):
        self.assertRaises(URLParseError, Origin.from_text, u"")
        self.assertRaises(URLParseError, Origin.from_text, u"example.com")
        self.assertRaises(URLParseError, Origin.from_text, u"http://")
        self.assertRaises(
            URLParseError, Origin.from_text, u"http://example.com:abc"
        )
        self.assertRaises(URLParseError, Origin.from_text, u"http://[::1")
        self.assertRaises(ValueError, Origin, u"", u"example.com")
        self.assertRaises(ValueError, Origin, u"http", u"")
        self.assertRaises(ValueError, Origin.opaque, u"")


class TestOriginInterface(HyperlinkTestCase):
    def test_relative_url_has_no_origin(self):
        for text in (u"/relative/path", u"?query=1", u"", u"//host/path"):
            url = URL.from_text(text)
            self.assertRaises(URLParseError, lambda: url.origin)
            self.assertRaises(
                URLParseError, url.same_origin, URL.from_text(u"/other")
            )

    def test_same_origin_type_check(self):
        url = URL.from_text(u"http://example.com/")
        self.assertRaises(TypeError, url.same_origin, u"http://example.com/")
        self.assertRaises(TypeError, url.same_origin, None)

    def test_origin_equality_against_other_types(self):
        origin = URL.from_text(u"http://example.com/").origin
        self.assertFalse(origin == u"http://example.com:80")
        self.assertTrue(origin != u"http://example.com:80")
        self.assertNotEqual(origin, None)

    def test_origin_repr(self):
        origin = URL.from_text(u"http://example.com/").origin
        self.assertEqual(
            repr(origin), "Origin(scheme='http', host='example.com', port=80)"
        )
        self.assertEqual(
            repr(URL.from_text(u"mailto:a@b").origin),
            "Origin.opaque('mailto')",
        )

    def test_origins_usable_in_sets(self):
        urls = [
            u"http://example.com/",
            u"http://example.com:80/a",
            u"http://EXAMPLE.com/b?x#y",
            u"https://example.com/",
            u"mailto:a@b",
            u"mailto:c@d",
        ]
        origins = {URL.from_text(t).origin for t in urls}
        self.assertEqual(len(origins), 3)

    def test_decoded_url_delegation(self):
        dec = DecodedURL.from_text(u"http://example.com/")
        self.assertEqual(
            dec.origin, URL.from_text(u"http://example.com/").origin
        )
        self.assertRaises(
            URLParseError,
            DecodedURL.from_text(u"/relative").same_origin,
            dec,
        )
