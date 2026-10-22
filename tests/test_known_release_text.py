"""Bounded known release-text inspection, exact bytes and no rewrite paths.

Author: Daniel Hallman
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest
import release_artifacts as release
import server

VALID = [
    (
        "sitemap.xml",
        b'<?xml version="1.0" encoding="UTF-8"?>\r\n<urlset xmlns="urn:test"><url>https://example.test/a&amp;b</url></urlset>\r\n',
    ),
    ("bundle.mjs.sha256", b"a" * 64 + b"  bundle.mjs\r\n"),
    ("_headers", b"/*\r\n  X-Content-Type-Options: nosniff\r\n"),
    ("_redirects", b"/embedded /index.html 200\n"),
    ("LICENSE", b"Copyright Example\nPermission is hereby granted.\n"),
]


@pytest.mark.parametrize("name,data", VALID)
@pytest.mark.parametrize("explicit", [False, True])
def test_known_release_text_inspect_and_clean_preserve_exact_bytes_without_backends(
    name, data, explicit, monkeypatch
):
    for target in (
        "_apply_layer_b",
        "clean_text",
        "run_text_detectors",
        "run_all_text_detectors",
        "score_text_stylometry",
        "inspect_container",
        "classify_bytes",
    ):
        monkeypatch.setattr(
            server, target, lambda *a, **kw: pytest.fail("backend or generic route called")
        )
    result = server._clean_payload(data, name, {"deterministic_only": True} if explicit else {})
    report = result["report"]
    expected = hashlib.sha256(data).hexdigest()
    assert result["status"] == "inspected_no_change"
    assert report["mode"] == "deterministic_only"
    assert report["changed"] is False and report["actions"] == []
    assert report["release_ready"] is True and report["review_required"] is False
    assert report["input_sha256"] == report["output_sha256"] == expected
    assert base64.b64decode(result["cleaned"]) == data
    assert report["before"]["format_inspection"]["inspection_only"] is True
    inspected = server._inspect_payload(data, name, False)
    assert inspected["kind"] == "text" and inspected["suspicious"]["verdict"] is False
    assert inspected["report"]["input_sha256"] == inspected["report"]["output_sha256"] == expected
    assert inspected["report"]["release_ready"] is True


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"<root>",
        b"<a/><b/>",
        b"<root>&undefined;</root>",
        b"<x:root/>",
        b"<!DOCTYPE root><root/>",
        b'<!DOCTYPE root SYSTEM "file:///no-such-local-file"><root/>',
        b'<!DOCTYPE root [<!ENTITY x "expanded">]><root>&x;</root>',
        b'<!DOCTYPE root [<!ENTITY % x SYSTEM "https://no-such-host.invalid/test">%x;]><root/>',
        b'<!ENTITY x "expanded"><root/>',
        b'<?xml version="1.1"?><root/>',
        b'<?xml version="1.0" encoding="ISO-8859-1"?><root/>',
        b"<root>bad\xff</root>",
        b"<root>\x00</root>",
    ],
)
def test_malformed_unsupported_or_unsafe_xml_is_refused(data):
    with pytest.raises(ValueError):
        server._clean_payload(data, "sitemap.xml", {})
    with pytest.raises(ValueError):
        server._inspect_payload(data, "sitemap.xml", False)


def test_xml_comments_cdata_and_predefined_references_are_preserved():
    data = b"<root><!-- <!DOCTYPE example> -->&amp;&lt;<![CDATA[<!ENTITY text>]]></root>"
    assert base64.b64decode(server._clean_payload(data, "data.xml", {})["cleaned"]) == data


@pytest.mark.parametrize(
    "data,finding",
    [
        (b"<root><c2pa>manifest</c2pa></root>", "explicit_xml_c2pa_metadata"),
        (b"<?c2pa manifest?><root/>", "explicit_xml_c2pa_metadata"),
        (b"<?generator OpenAI?><root/>", "explicit_xml_ai_generator"),
        (b'<root xmlns:p="urn:c2pa:manifest"><p:manifest/></root>', "explicit_xml_c2pa_metadata"),
        (b'<root ai-generated="true"/>', "explicit_xml_ai_provenance"),
        (b"<root><ai-generated>true</ai-generated></root>", "explicit_xml_ai_provenance"),
        (b"<root><generator>OpenAI</generator></root>", "explicit_xml_ai_generator"),
        (b"<root><generator>Op<![CDATA[enAI]]></generator></root>", "explicit_xml_ai_generator"),
        (b'<root generator="ChatGPT"/>', "explicit_xml_ai_generator"),
        (b'<root><meta name="generator" content="Claude"/></root>', "explicit_xml_ai_generator"),
        (
            b'<root><meta xmlns:x="urn:test" name="generator" content="OpenAI" x:content="Human"/></root>',
            "explicit_xml_ai_generator",
        ),
        (
            b'<root><meta xmlns:a="urn:a" xmlns:b="urn:b" a:name="generator" b:name="other" content="OpenAI"/></root>',
            "explicit_xml_ai_generator",
        ),
        (b'<root><meta property="c2pa" content="manifest"/></root>', "explicit_xml_c2pa_metadata"),
        (b"<root><provenance>record</provenance></root>", "explicit_xml_provenance_metadata"),
    ],
)
def test_xml_explicit_parsed_metadata_requires_review_without_output(data, finding):
    result = server._clean_payload(data, "data.xml", {})
    assert result["status"] == "requires_review" and "cleaned" not in result
    assert finding in result["report"]["before"]["metadata_findings"]
    assert result["report"]["release_ready"] is False
    assert (
        result["report"]["input_sha256"]
        == result["report"]["output_sha256"]
        == hashlib.sha256(data).hexdigest()
    )
    inspected = server._inspect_payload(data, "data.xml", False)
    assert inspected["report"]["review_required"] is True
    assert inspected["suspicious"]["verdict"] is True
    assert inspected["suspicious"]["classes"]["release_metadata"]["present"] is True
    if finding == "explicit_xml_provenance_metadata":
        assert inspected["report"]["has_ai_metadata"] is False
        assert inspected["report"]["has_c2pa"] is False


@pytest.mark.parametrize(
    "data",
    [
        b"<urlset><url><loc>https://example.test/openai/c2pa?ai-generated=true</loc></url></urlset>",
        b'<root href="https://example.test/c2pa/openai">ChatGPT is an example.</root>',
        b"<root><generator>WordPress</generator></root>",
        b'<root generator="Jane Smith"/>',
        b'<root><meta name="generator" content="Human editor"/></root>',
        b'<root xmlns:a="urn:a" xmlns:b="urn:b" a:name="generator" b:name="other" content="OpenAI"/>',
        b'<?xml-stylesheet type="text/xsl" href="https://example.test/c2pa/openai.xsl"?><root/>',
        b"<root><!-- <c2pa>metadata example</c2pa> --><![CDATA[<ai-generated>]]></root>",
    ],
)
def test_xml_functional_urls_text_and_ordinary_generators_are_not_provenance_findings(data):
    result = server._clean_payload(data, "data.xml", {})
    assert result["status"] == "inspected_no_change"
    assert result["report"]["before"]["metadata_findings"] == []
    assert base64.b64decode(result["cleaned"]) == data


def test_xml_metadata_character_accumulation_is_bounded(monkeypatch):
    monkeypatch.setattr(release, "MAX_XML_METADATA_CHARS", 4)
    with pytest.raises(ValueError, match="metadata field"):
        server._clean_payload(
            b"<root><generator>abc<![CDATA[de]]></generator></root>", "data.xml", {}
        )
    with pytest.raises(ValueError, match="metadata field"):
        server._clean_payload(b'<root generator="abcde"/>', "data.xml", {})


@pytest.mark.parametrize(
    "setting,data",
    [
        ("MAX_XML_DEPTH", b"<a><b><c/></b></a>"),
        ("MAX_XML_ELEMENTS", b"<a><b/><c/></a>"),
        ("MAX_XML_ATTRIBUTES", b'<a b="1" c="2" d="3"/>'),
        ("MAX_XML_ATTRIBUTES", b'<a xmlns:b="urn:b" xmlns:c="urn:c" xmlns:d="urn:d"/>'),
    ],
)
def test_xml_structural_work_is_bounded(setting, data, monkeypatch):
    monkeypatch.setattr(release, setting, 2)
    with pytest.raises(ValueError, match="limits"):
        server._clean_payload(data, "data.xml", {})


def test_xml_old_parser_is_refused(monkeypatch):
    monkeypatch.setattr(release.expat, "version_info", (2, 5, 0))
    with pytest.raises(ValueError, match=r"2\.6\.0"):
        server._clean_payload(b"<root/>", "data.xml", {})


@pytest.mark.parametrize(
    "line",
    [
        b"",
        b"g" * 64 + b"  app.js",
        b"a" * 63 + b"  app.js",
        b"a" * 65 + b"  app.js",
        b"a" * 64 + b" app.js",
        b"a" * 64 + b"  ../app.js",
        b"a" * 64 + b"  /app.js",
        b"a" * 64 + b"  dir/app.js",
        b"a" * 64 + b"  -app.js",
        b"a" * 64 + b"  app name.js",
        b"a" * 64 + b"  app.js\n\n",
        b"a" * 64 + b"  app.js\rnext",
        b"a" * 64 + b"  app.js\r",
        (b"a" * 64 + b"  app.js\n") * 2,
    ],
)
def test_checksum_syntax_requires_hex_and_unique_safe_basenames(line):
    with pytest.raises(ValueError):
        server._clean_payload(line, "app.sha256", {})
    with pytest.raises(ValueError):
        server._inspect_payload(line, "app.sha256", False)


def test_checksum_binary_mode_and_uppercase_hex_are_preserved_without_target_claim():
    data = b"ABCDEF01" * 8 + b" *app.js\n" + b"12345678" * 8 + b"  other.js"
    result = server._clean_payload(data, "files.sha256", {})
    assert base64.b64decode(result["cleaned"]) == data
    assert result["report"]["before"]["format_inspection"]["target_hashes_verified"] is False


@pytest.mark.parametrize(
    "name",
    [
        "_Headers",
        "_redirects.bak",
        "license",
        "LICENSES",
        "custom",
        "data.sha512",
        "data.xml.backup",
    ],
)
def test_arbitrary_unknown_names_are_not_release_text(name):
    assert release.known_release_text(name) is False
    assert release.automatic_release_mode(name) is False
    with pytest.raises(ValueError):
        server._clean_payload(b"plain text", name, {})
    with pytest.raises(ValueError):
        server._clean_payload(b"plain text", name, {"deterministic_only": True})
    assert server._inspect_payload(b"plain text", name, False)["kind"] == "unknown"


@pytest.mark.parametrize("name", ["LICENSE", "_headers", "_redirects", "data.xml", "data.sha256"])
@pytest.mark.parametrize(
    "data", [b"PK\x03\x04not-text", b"bad\xff", b"text\0binary", b"x" * 8192 + b"\x1b"]
)
def test_binary_non_utf8_and_controls_are_refused_in_every_new_format(name, data):
    with pytest.raises(ValueError):
        server._clean_payload(data, name, {})
    with pytest.raises(ValueError):
        server._inspect_payload(data, name, False)


def test_bounded_sizes_and_checksum_entry_count(monkeypatch):
    monkeypatch.setattr(release, "MAX_KNOWN_TEXT_BYTES", 8)
    with pytest.raises(ValueError, match="size"):
        server._clean_payload(b"x" * 9, "LICENSE", {})
    monkeypatch.setattr(release, "MAX_CHECKSUM_BYTES", 8)
    with pytest.raises(ValueError, match="size"):
        server._inspect_payload(b"a" * 64 + b"  app.js", "files.sha256", False)
    monkeypatch.setattr(release, "MAX_CHECKSUM_BYTES", 1024)
    monkeypatch.setattr(release, "MAX_CHECKSUM_LINES", 1)
    with pytest.raises(ValueError, match="line count"):
        server._clean_payload(b"a" * 64 + b"  a.js\n" + b"b" * 64 + b"  b.js", "files.sha256", {})


@pytest.mark.parametrize(
    "name,data",
    [
        ("LICENSE", "a\u200bb".encode()),
        ("_headers", "/*\n X-Note: a\u200bb".encode()),
        ("data.xml", "<a>hello\u200bthere</a>".encode()),
    ],
)
def test_unicode_findings_remain_unresolved_without_byte_changes(name, data):
    result = server._clean_payload(data, name, {})
    assert result["status"] == "requires_review"
    assert result["report"]["changed"] is False and result["report"]["release_ready"] is False
    assert "cleaned" not in result
    assert (
        result["report"]["input_sha256"]
        == result["report"]["output_sha256"]
        == hashlib.sha256(data).hexdigest()
    )
    inspected = server._inspect_payload(data, name, False)
    assert inspected["suspicious"]["verdict"] is True
    assert inspected["suspicious"]["classes"]["layer_a_unicode"]["signals"]["suspicious_total"] == 1


@pytest.mark.parametrize(
    "option",
    ["nfkc", "normalize_spaces", "strategy", "strip_all_metadata", "detect_before", "detect_after"],
)
def test_inspection_only_rejects_transform_and_detector_options(option):
    with pytest.raises(ValueError, match="cannot rewrite"):
        server._clean_payload(b"license text", "LICENSE", {option: True})
    with pytest.raises(ValueError, match="detectors"):
        server._inspect_payload(b"license text", "LICENSE", True)
    with pytest.raises(ValueError, match="detectors"):
        server._detect_payload(b"license text", "LICENSE")


def test_capability_and_openapi_agree():
    assert server.capabilities()["cleaning_modes"]["known_release_text_inspection"] is True
    props = server.openapi_spec()["paths"]["/capabilities"]["get"]["responses"]["200"]["content"][
        "application/json"
    ]["schema"]["properties"]
    assert "known_release_text_inspection" in props["cleaning_modes"]["properties"]


@pytest.mark.skipif(
    not os.environ.get("KNOWN_RELEASE_ACCEPTANCE_CLIENT"),
    reason="explicit installed native client only",
)
def test_native_client_refuses_known_text_findings_and_invalid_formats_without_writes(tmp_path):
    service = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    environment = {
        **os.environ,
        "WATERMARKS_SERVICE_URL": f"http://127.0.0.1:{service.server_port}",
    }
    client = os.environ["KNOWN_RELEASE_ACCEPTANCE_CLIENT"]
    try:
        for filename, content in [
            ("data.xml", b"<root><c2pa/></root>"),
            ("_headers", "/*\n X-Note: a\u200bb".encode()),
            ("bad.xml", b"<root>"),
            ("bad.sha256", b"not a checksum"),
        ]:
            source, output = tmp_path / filename, tmp_path / "output"
            source.write_bytes(content)
            before = source.stat()
            for arguments in (["--output", str(output)], ["--in-place"]):
                result = subprocess.run(
                    [client, "--deterministic-only", *arguments, str(source)],
                    env=environment,
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
                assert result.returncode != 0 and not output.exists()
                assert source.read_bytes() == content
                assert sorted(path.name for path in tmp_path.iterdir()) == [filename]
                after = source.stat()
                assert (before.st_ino, before.st_size, before.st_mtime_ns) == (
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                )
            source.unlink()
    finally:
        service.shutdown()
        service.server_close()
        thread.join(timeout=5)


@pytest.mark.skipif(
    not (
        os.environ.get("KNOWN_RELEASE_ACCEPTANCE_MANIFEST")
        and os.environ.get("KNOWN_RELEASE_ACCEPTANCE_CLIENT")
    ),
    reason="explicit operator assets and installed native client only",
)
def test_actual_release_assets_through_http_and_native_client(tmp_path):
    manifest = json.loads(Path(os.environ["KNOWN_RELEASE_ACCEPTANCE_MANIFEST"]).read_text())
    destination = Path(os.environ.get("KNOWN_RELEASE_ACCEPTANCE_RECEIPTS", str(tmp_path)))
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    service = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    environment = {
        **os.environ,
        "WATERMARKS_SERVICE_URL": f"http://127.0.0.1:{service.server_port}",
    }
    client, receipts = os.environ["KNOWN_RELEASE_ACCEPTANCE_CLIENT"], []
    try:
        for item in manifest:
            source, label = Path(item["path"]), item["label"]
            assert re.fullmatch(r"[a-z0-9-]+", label)
            before, data = source.stat(), source.read_bytes()
            expected = hashlib.sha256(data).hexdigest()
            assert release.known_release_text(source.name)
            inspected = subprocess.run(
                [client, "--inspect", str(source)],
                env=environment,
                capture_output=True,
                timeout=30,
                check=False,
            )
            assert inspected.returncode == 0, inspected.stderr
            inspection = json.loads(inspected.stdout)
            assert inspection["kind"] == "text" and inspection["suspicious"]["verdict"] is False
            output = destination / f"{label}.inspected"
            reports = []
            for options in ([], ["--deterministic-only"]):
                result = subprocess.run(
                    [client, *options, "--json-report", "--output", str(output), str(source)],
                    env=environment,
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
                assert result.returncode == 0, result.stderr
                output.chmod(0o600)
                assert output.read_bytes() == data
                report, _ = json.JSONDecoder().raw_decode(result.stderr.decode())
                assert (
                    report["status"] == "inspected_no_change"
                    and report["mode"] == "deterministic_only"
                )
                assert report["input_sha256"] == report["output_sha256"] == expected
                assert (
                    report["changed"] is False
                    and report["release_ready"] is True
                    and report["actions"] == []
                )
                reports.append(report)
            after = source.stat()
            assert (before.st_ino, before.st_size, before.st_mtime_ns) == (
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            )
            assert source.read_bytes() == data
            receipts.append(
                {
                    "source": str(source),
                    "source_stat_unchanged": True,
                    "input_sha256": expected,
                    "output_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
                    "inspection": inspection,
                    "automatic_and_explicit_reports": reports,
                }
            )
        receipt = destination / "native-acceptance.json"
        receipt.write_text(json.dumps(receipts, indent=2) + "\n")
        receipt.chmod(0o600)
    finally:
        service.shutdown()
        service.server_close()
        thread.join(timeout=5)
