"""Tests for app.utils.url"""
import pytest
from app.utils.url import normalise_url, InvalidURLError


class TestNormaliseUrl:
    def test_adds_https_scheme(self):
        assert normalise_url("example.com") == "https://example.com"

    def test_preserves_https(self):
        assert normalise_url("https://example.com") == "https://example.com"

    def test_preserves_http(self):
        assert normalise_url("http://example.com") == "http://example.com"

    def test_strips_trailing_slash(self):
        assert normalise_url("https://example.com/") == "https://example.com"

    def test_strips_deep_trailing_slash(self):
        assert normalise_url("https://example.com/app/") == "https://example.com/app"

    def test_lowercases_scheme_and_host(self):
        assert normalise_url("HTTPS://EXAMPLE.COM") == "https://example.com"

    def test_drops_fragment(self):
        assert normalise_url("https://example.com#section") == "https://example.com"

    def test_preserves_path(self):
        assert normalise_url("https://example.com/app/v2") == "https://example.com/app/v2"

    def test_raises_on_empty(self):
        with pytest.raises(InvalidURLError):
            normalise_url("")

    def test_raises_on_whitespace_only(self):
        with pytest.raises(InvalidURLError):
            normalise_url("   ")

    def test_strips_input_whitespace(self):
        assert normalise_url("  example.com  ") == "https://example.com"
