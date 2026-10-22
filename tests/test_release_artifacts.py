"""Release cleanup never rewrites reviewed source or strips functional icons.

Author: Daniel Hallman
"""

from __future__ import annotations

import base64
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "service" / "scripts"))

import server


@pytest.mark.parametrize(
    "name,data",
    [
        ("app.js", b'const greeting = "Hello";\r\n// Keep exact spacing.\r\n'),
        ("settings.json", b'{ "hello": true, "items": [ 1, 2 ] }\n'),
        ("page.html", b'<!doctype html>\r\n<html lang="en"><p>Hello</p></html>'),
        ("notes.md", b"# Hello\r\n\r\nKeep  two spaces.\r\n"),
        ("data.csv", b"name,value\r\nhello,123\r\n"),
    ],
)
def test_deterministic_no_change_is_exact_and_never_calls_backend(name, data, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("release cleanup called rewrite/normalization backend")

    monkeypatch.setattr(server, "_apply_layer_b", forbidden)
    monkeypatch.setattr(server, "clean_text", forbidden)
    monkeypatch.setattr(server, "run_text_detectors", forbidden)
    result = server._clean_payload(data, name, {"deterministic_only": True})
    assert result["status"] == "inspected_no_change"
    assert result["report"]["release_ready"] is True
    assert result["report"]["review_required"] is False
    assert result["report"]["input_sha256"] == result["report"]["output_sha256"]
    assert base64.b64decode(result["cleaned"]) == data


@pytest.mark.parametrize("name", ["app.js", "settings.json", "main.rs", "page.html"])
def test_source_defaults_to_deterministic_even_with_existing_rewrite_default(name, monkeypatch):
    monkeypatch.setattr(server, "_DEFAULT_STRATEGY", "paraphrase@0.8")
    monkeypatch.setattr(server, "_apply_layer_b", lambda *a, **k: pytest.fail("model called"))
    assert server._clean_payload(b"hello", name, {})["status"] == "inspected_no_change"


def test_real_html_ai_metadata_removed_with_functional_font_glyphs_preserved():
    css = '.menu::after{content:"\uf078";font-family:"Font Awesome 5 Free";color:red}.mobile::before{content:"\uf0c9";font-family:"Font Awesome 5 Free"}'
    source = (
        '<!doctype html>\r\n<html><head><meta name="ai-generated" content="true"><style>'
        + css
        + "</style></head><body>Keep this.</body></html>"
    )
    result = server._clean_payload(
        source.encode(), "index.html", {"deterministic_only": True, "also_layer_a_text": False}
    )
    assert result["status"] == "cleaned"
    assert result["report"]["review_required"] is True
    assert result["report"]["release_ready"] is True
    assert base64.b64decode(result["cleaned"]).decode() == source.replace(
        '<meta name="ai-generated" content="true">', ""
    )
    assert len(result["report"]["after"]["preserved_functional_unicode"]) == 2
    assert result["report"]["after"]["applicable_unicode"]["suspicious_total"] == 0


def test_font_glyph_only_html_is_unchanged():
    source = (
        b'<style>.menu:before{content:"'
        + "\uf0c9".encode()
        + b'";font-family:"Font Awesome 5 Free"}</style>'
    )
    result = server._clean_payload(source, "index.html", {})
    assert result["status"] == "inspected_no_change"
    assert base64.b64decode(result["cleaned"]) == source


def test_bad_css_string_ends_at_newline_without_swallowing_later_valid_icons():
    source = '<style>.broken{content:"unterminated\n;font-family:"unknown"}.menu:before{cursor:pointer;color:var(--black);content:"\uf0c9";font-family:"Font Awesome 5 Free";font-weight:700;font-size:14px}</style>'
    result = server._clean_payload(source.encode(), "index.html", {})
    assert result["status"] == "inspected_no_change"
    assert len(result["report"]["after"]["preserved_functional_unicode"]) == 1
    assert base64.b64decode(result["cleaned"]) == source.encode()


def test_glyph_inside_bad_css_string_is_still_unresolved():
    source = '<style>.broken{content:"\uf0c9\n;font-family:"Font Awesome 5 Free"}.menu{content:"\uf078";font-family:"Font Awesome 5 Free"}</style>'
    result = server._clean_payload(source.encode(), "index.html", {})
    assert result["status"] == "requires_review"
    assert len(result["report"]["after"]["preserved_functional_unicode"]) == 1
    assert result["report"]["after"]["applicable_unicode"]["suspicious_total"] == 1


@pytest.mark.parametrize(
    "source",
    [
        'const text="\uf0c9";',
        "<p>\uf0c9</p>",
        '<script>const css = `.x{content:"\uf0c9";font-family:"Font Awesome 5 Free"}`;</script>',
        '<style>.x{content:"\uf0c9";font-family:"Unverified Font"}</style>',
        '<style>.x{content:"\uf0c9";font-family:"Font Awesome 5 Free"}</style>\uf0c9',
        '<style>/* .x{content:"\uf0c9";font-family:"Font Awesome 5 Free"} */</style>',
        '<style>.x{content:"\uf0c9";font-family:"Font Awesome 5 Free";font-family:"Unverified"}</style>',
        '<style>.x{content:"\uf0c9";font-family:"Unverified";font-family:"Font Awesome 5 Free"}</style>',
        '<style>.x{content:"\uf0c9";font-family:"Font Awesome 5 Free";font:12px Unverified}</style>',
        '<style>.x{content:"\uf0c9";content:"other";font-family:"Font Awesome 5 Free"}</style>',
    ],
)
def test_private_use_outside_verified_css_context_requires_review(source):
    name = "app.js" if source.startswith("const") else "page.html"
    data = source.encode()
    result = server._clean_payload(data, name, {"deterministic_only": True})
    assert result["status"] == "requires_review"
    assert result["report"]["release_ready"] is False
    assert base64.b64decode(result["cleaned"]) == data


def test_metadata_strings_in_scripts_are_never_edited():
    data = b'<script>const example = \'<meta name="ai-generated" content="true">\';</script>'
    result = server._clean_payload(data, "page.html", {})
    assert result["status"] == "requires_review"
    assert base64.b64decode(result["cleaned"]) == data


def test_zero_width_source_value_is_not_silently_changed():
    data = 'const exact = "hello\u200bworld";'.encode()
    result = server._clean_payload(data, "app.js", {})
    assert result["status"] == "requires_review"
    assert base64.b64decode(result["cleaned"]) == data


@pytest.mark.parametrize(
    "name,data", [("unknown.bin", b"hello"), ("app.js", b"bad\xff"), ("data.json", b"\x00\x00\x00")]
)
def test_unknown_binary_and_invalid_utf8_fail_closed(name, data):
    with pytest.raises(ValueError):
        server._clean_payload(data, name, {"deterministic_only": True})


@pytest.mark.parametrize(
    "option,value",
    [
        ("strategy", "paraphrase@0.8"),
        ("nfkc", True),
        ("detect_after", True),
        ("normalize_spaces", True),
    ],
)
def test_rewrite_and_normalization_options_are_rejected(option, value):
    with pytest.raises(ValueError, match="cannot rewrite"):
        server._clean_payload(b"hello", "app.js", {"deterministic_only": True, option: value})


def test_option_contract_is_boolean():
    assert server._parse_clean_options({"deterministic_only": True}) == {"deterministic_only": True}
    with pytest.raises(ValueError):
        server._parse_clean_options({"deterministic_only": "true"})


def test_inspection_exception_never_becomes_success(monkeypatch):
    import release_artifacts

    monkeypatch.setattr(
        release_artifacts,
        "inspect_text",
        lambda *a, **k: (_ for _ in ()).throw(ValueError("inspection unavailable")),
    )
    with pytest.raises(ValueError, match="inspection unavailable"):
        server._clean_payload(b"hello", "app.js", {})
