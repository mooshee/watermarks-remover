"""Bounded Wasm metadata/framing proof and actual operator artifact acceptance.

Author: Daniel Hallman
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest
import server
import wasm_metadata as wasm


def u32(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    return bytes(result + bytes([value]))


def name(value):
    value = value.encode("utf-8") if isinstance(value, str) else value
    return u32(len(value)) + value


def section(kind, body):
    return bytes([kind]) + u32(len(body)) + body


def custom(label, body):
    return section(0, name(label) + body)


def module(*extras):
    # Type/function/code framing; bodies are opaque, never executed or disassembled.
    return (
        b"\0asm\x01\0\0\0"
        + section(1, b"\x01\x60\0\0")
        + section(3, b"\x01\0")
        + section(10, b"\x01\x02\0\x0b")
        + b"".join(extras)
    )


def producers(field="processed-by", producer="rustc", version="1.98.1"):
    return custom("producers", b"\x01" + name(field) + b"\x01" + name(producer) + name(version))


def features(feature="bulk-memory", prefix=b"+"):
    return custom("target_features", b"\x01" + prefix + name(feature))


def test_supported_metadata_exact_bytes_and_functional_names_are_not_prose():
    symbol = "openai_c2pa_\u200b_symbol"
    names = section(1, b"\x01\0" + name(symbol))
    data = module(custom("name", names), producers(), features())
    result = wasm.clean_wasm(data, {})
    assert result["status"] == "inspected_no_change"
    assert result["report"]["release_ready"] is True
    assert result["report"]["changed"] is False
    assert result["report"]["actions"] == []
    assert base64.b64decode(result["cleaned"]) == data
    assert (
        result["report"]["input_sha256"]
        == result["report"]["output_sha256"]
        == hashlib.sha256(data).hexdigest()
    )
    assert symbol not in str(result["report"])


@pytest.mark.parametrize(
    "data", [b"", b"\0asm", b"\0asm\x01\0\0\0", b"\0asm\x02\0\0\0", b"\0asm\x0d\0\x01\0"]
)
def test_magic_only_truncated_and_noncore_version_refused(data):
    with pytest.raises(ValueError):
        wasm.inspect_wasm(data)


@pytest.mark.parametrize(
    "tail",
    [
        b"\0",
        b"\0\x80",
        b"\0\xff\xff\xff\xff\x1f",
        b"\0\x80\x80\x80\x80\x80\0",
        b"\0\x0a\x01x",
        b"\xff\0",
    ],
)
def test_section_framing_overflow_overlong_leb_and_truncation_refused(tail):
    with pytest.raises(ValueError):
        wasm.inspect_wasm(module() + tail)


def test_spec_permits_padded_uleb_within_u32_bound_without_normalization():
    data = module() + b"\0\x87\0" + name("future")
    result = wasm.clean_wasm(data, {})
    assert result["status"] == "requires_review"
    assert "cleaned" not in result


@pytest.mark.parametrize(
    "label", ["unknown", "linking", "reloc.CODE", "c2pa", "ai_provenance", "synthid"]
)
def test_unknown_and_actual_provenance_custom_metadata_require_review_no_output(label):
    data = module(custom(label, b"opaque\xff\0"))
    result = wasm.clean_wasm(data, {})
    assert result["status"] == "requires_review"
    assert result["report"]["release_ready"] is False
    assert result["report"]["changed"] is False
    assert "cleaned" not in result
    findings = result["report"]["before"]["findings"]
    assert "unsupported_custom_metadata" in findings
    if label in {"c2pa", "ai_provenance", "synthid"}:
        assert "explicit_provenance_custom_section" in findings


@pytest.mark.parametrize("extra", [section(1, b"\0"), section(3, b"\0"), section(10, b"\0")])
def test_duplicate_standard_sections_refused(extra):
    with pytest.raises(ValueError, match="duplicate"):
        wasm.inspect_wasm(module(extra))


def test_standard_order_and_function_body_extent_checked():
    with pytest.raises(ValueError, match="out of order"):
        wasm.inspect_wasm(module(section(2, b"\0")))
    with pytest.raises(ValueError, match="count mismatch"):
        wasm.inspect_wasm(b"\0asm\x01\0\0\0" + section(3, b"\x01\0"))
    with pytest.raises(ValueError, match="truncated"):
        wasm.inspect_wasm(b"\0asm\x01\0\0\0" + section(3, b"\x01\0") + section(10, b"\x01\x03\0"))
    with pytest.raises(ValueError, match="empty function"):
        wasm.inspect_wasm(b"\0asm\x01\0\0\0" + section(3, b"\x01\0") + section(10, b"\x01\0"))
    result = wasm.clean_wasm(module(section(14, b"\0")), {})
    assert result["status"] == "requires_review" and "cleaned" not in result


def test_data_count_order_and_consistency():
    data = b"\0asm\x01\0\0\0" + section(12, b"\0") + section(11, b"\0")
    assert wasm.clean_wasm(data, {})["status"] == "inspected_no_change"
    with pytest.raises(ValueError, match="data-count"):
        wasm.inspect_wasm(b"\0asm\x01\0\0\0" + section(12, b"\x01") + section(11, b"\0"))


@pytest.mark.parametrize(
    "body",
    [
        b"\x01\x05x",
        b"\x01\x01\xff",
        b"\0\0\0",
        b"\x01\x03\x02\0\0",
        b"\x01\x05\x02\0" + name("a") + b"\0" + name("b"),
    ],
)
def test_malformed_name_metadata_refused(body):
    with pytest.raises(ValueError):
        wasm.inspect_wasm(module(custom("name", body)))


def test_unknown_name_subsection_requires_review():
    result = wasm.clean_wasm(module(custom("name", section(99, b"opaque"))), {})
    assert result["status"] == "requires_review" and "cleaned" not in result


def test_producers_and_target_features_reject_trailing_duplicate_and_invalid_fields():
    data = module(producers(), producers())
    with pytest.raises(ValueError, match="duplicate known"):
        wasm.inspect_wasm(data)
    result = wasm.clean_wasm(module(producers(producer="AI-generated by ChatGPT")), {})
    assert result["status"] == "requires_review" and "cleaned" not in result
    result = wasm.clean_wasm(
        module(producers(field="future-field"), features("future-feature")), {}
    )
    assert result["status"] == "requires_review" and "cleaned" not in result
    with pytest.raises(ValueError, match="prefix"):
        wasm.inspect_wasm(module(features(prefix=b"?")))
    with pytest.raises(ValueError, match="trailing"):
        wasm.inspect_wasm(module(custom("producers", b"\0extra")))
    with pytest.raises(ValueError, match="duplicate producer"):
        wasm.inspect_wasm(
            module(custom("producers", b"\x02" + name("sdk") + b"\0" + name("sdk") + b"\0"))
        )


@pytest.mark.parametrize("generator", ["OpenAI", "ChatGPT", "Anthropic", "Claude", "Gemini"])
def test_contextual_producer_generator_names_and_version_metadata_require_review(generator):
    for data in (
        module(producers(producer=generator)),
        module(producers(version=f"1.0 ({generator})")),
    ):
        result = wasm.clean_wasm(data, {})
        assert result["status"] == "requires_review" and "cleaned" not in result
        assert "explicit_provenance_producer_metadata" in result["report"]["before"]["findings"]
    # Matching is bounded and does not scan compiler/linker functional name strings.
    safe = module(producers(producer="rustc", version="1.98.1"), features())
    assert wasm.clean_wasm(safe, {})["status"] == "inspected_no_change"


@pytest.mark.parametrize(
    "generator",
    [
        "OpenAI, Inc.",
        "ChatGPT+API",
        "+OpenAI",
        "openai!",
        "[cHaTgPt]",
        "{ANTHROPIC}",
        "=claude;",
        "#gemini?",
        "_OpenAI_",
        "OpenAI_API",
        "sdk_OpenAI",
        "OpenAI\\tool",
    ],
)
def test_punctuation_cannot_hide_provenance_in_producer_names_or_versions(generator):
    for data in (module(producers(producer=generator)), module(producers(version=generator))):
        result = server._clean_payload(data, "program.wasm", {})
        assert result["status"] == "requires_review" and "cleaned" not in result
        assert result["report"]["release_ready"] is False
        inspected = server._inspect_payload(data, "program.wasm", False)
        assert inspected["suspicious"]["verdict"] is True
        assert "explicit_provenance_producer_metadata" in inspected["report"]["findings"]


@pytest.mark.parametrize(
    "producer",
    [
        "rustc",
        "wasm-bindgen",
        "clang",
        "NotOpenAI",
        "OpenAIMath",
        "OpenAI2",
        "2OpenAI",
        "πOpenAI",
        "OpenAIπ",
    ],
)
def test_vendor_substrings_in_ordinary_producer_tokens_are_preserved(producer):
    data = module(producers(producer=producer, version="1.2.3+toolchain"))
    result = wasm.clean_wasm(data, {})
    assert result["status"] == "inspected_no_change"
    assert base64.b64decode(result["cleaned"]) == data


def test_punctuated_vendor_functional_names_remain_opaque_and_unchanged():
    symbol = "OpenAI, Inc./ChatGPT+API"
    data = module(custom("name", section(1, b"\x01\0" + name(symbol))), producers())
    result = wasm.clean_wasm(data, {})
    assert result["status"] == "inspected_no_change"
    assert base64.b64decode(result["cleaned"]) == data
    assert symbol not in str(result["report"])


def test_explicit_work_bounds(monkeypatch):
    monkeypatch.setattr(wasm, "MAX_SECTIONS", 2)
    with pytest.raises(ValueError, match="section count"):
        wasm.inspect_wasm(module())
    monkeypatch.setattr(wasm, "MAX_SECTIONS", 4096)
    monkeypatch.setattr(wasm, "MAX_METADATA_BYTES", 2)
    with pytest.raises(ValueError, match="metadata bytes"):
        wasm.inspect_wasm(module(features()))
    monkeypatch.setattr(wasm, "MAX_METADATA_BYTES", 16 << 20)
    monkeypatch.setattr(wasm, "MAX_STRING", 2)
    with pytest.raises(ValueError, match="string outside"):
        wasm.inspect_wasm(module(features()))


@pytest.mark.parametrize(
    "option",
    [
        "strategy",
        "style",
        "nfkc",
        "aggressive_homoglyphs",
        "normalize_spaces",
        "remove_pixel",
        "remove_audio_watermark",
        "strip_all_metadata",
        "detect_before",
        "detect_after",
    ],
)
def test_transform_or_detector_request_refused(option):
    with pytest.raises(ValueError, match="transformations"):
        wasm.clean_wasm(module(), {option: True})


@pytest.mark.parametrize("filename", ["program", "program.wasm", "program.rs", "program.png"])
def test_magic_routes_without_backend_calls_and_detectors_refuse(filename, monkeypatch):
    for backend in (
        "clean_text",
        "_apply_layer_b",
        "run_all_text_detectors",
        "score_text_stylometry",
        "clean_image",
        "inspect_image",
        "run_synthid_score",
    ):
        monkeypatch.setattr(server, backend, lambda *a, **kw: pytest.fail("backend called"))
    data = module(producers(), features())
    result = server._clean_payload(data, filename, {})
    assert result["kind"] == "executable" and result["status"] == "inspected_no_change"
    assert base64.b64decode(result["cleaned"]) == data
    assert server._inspect_payload(data, filename, False)["suspicious"]["verdict"] is False
    with pytest.raises(ValueError, match="detectors"):
        server._inspect_payload(data, filename, True)
    with pytest.raises(ValueError, match="detectors"):
        server._detect_payload(data, filename)
    assert server.capabilities()["cleaning_modes"]["wasm_core_v1_metadata_inspection"] is True


@pytest.mark.skipif(
    not os.environ.get("WASM_ACCEPTANCE_CLIENT"), reason="explicit installed native client only"
)
def test_actual_native_client_http_nochange_and_review_refuses_output_backup(tmp_path):
    service = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    environment = {
        **os.environ,
        "WATERMARKS_SERVICE_URL": f"http://127.0.0.1:{service.server_port}",
    }
    source, output = tmp_path / "program.wasm", tmp_path / "inspected.wasm"
    data = module(producers(), features())
    source.write_bytes(data)
    client = os.environ["WASM_ACCEPTANCE_CLIENT"]
    try:
        result = subprocess.run(
            [client, "--deterministic-only", "--json-report", "--output", str(output), str(source)],
            env=environment,
            capture_output=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert source.read_bytes() == output.read_bytes() == data
        output.unlink()
        for content in (
            module(custom("c2pa", b"manifest")),
            module(custom("unknown", b"metadata")),
            module(producers(producer="OpenAI, Inc.")),
            module(producers(version="ChatGPT+API")),
            module()[:-1],
        ):
            source.write_bytes(content)
            before = source.stat()
            for arguments in (["--output", str(output)], ["--in-place"]):
                result = subprocess.run(
                    [client, "--deterministic-only", "--json-report", *arguments, str(source)],
                    env=environment,
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
                assert result.returncode != 0
                assert not output.exists() and source.read_bytes() == content
                assert sorted(path.name for path in tmp_path.iterdir()) == ["program.wasm"]
                after = source.stat()
                assert (before.st_ino, before.st_size, before.st_mtime_ns) == (
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                )
    finally:
        service.shutdown()
        service.server_close()
        thread.join(timeout=5)


@pytest.mark.skipif(
    not os.environ.get("WASM_ACCEPTANCE_ARTIFACT"), reason="explicit operator artifact only"
)
def test_explicit_operator_artifact_read_only_acceptance(tmp_path):
    path = Path(os.environ["WASM_ACCEPTANCE_ARTIFACT"])
    expected = os.environ["WASM_ACCEPTANCE_SHA256"]
    before, data = path.stat(), path.read_bytes()
    assert hashlib.sha256(data).hexdigest() == expected
    report = wasm.inspect_wasm(data)
    if os.environ.get("WASM_ACCEPTANCE_REPORT"):
        Path(os.environ["WASM_ACCEPTANCE_REPORT"]).write_text(json.dumps(report, indent=2) + "\n")
    assert report["release_ready"] is True, report
    assert report["input_sha256"] == report["output_sha256"] == expected
    assert base64.b64decode(wasm.clean_wasm(data, {})["cleaned"]) == data
    if client := os.environ.get("WASM_ACCEPTANCE_CLIENT"):
        service = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        thread = threading.Thread(target=service.serve_forever, daemon=True)
        thread.start()
        output = tmp_path / "inspected.wasm"
        try:
            result = subprocess.run(
                [
                    client,
                    "--deterministic-only",
                    "--json-report",
                    "--output",
                    str(output),
                    str(path),
                ],
                env={
                    **os.environ,
                    "WATERMARKS_SERVICE_URL": f"http://127.0.0.1:{service.server_port}",
                },
                capture_output=True,
                timeout=30,
                check=False,
            )
            assert result.returncode == 0, result.stderr
            assert output.read_bytes() == data
            if receipt := os.environ.get("WASM_ACCEPTANCE_REPORT"):
                Path(receipt).with_suffix(".native-client.json").write_text(
                    json.dumps(
                        {
                            "client": client,
                            "exit_code": result.returncode,
                            "transport": "loopback_http",
                            "input_sha256": expected,
                            "output_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
                            "status": "inspected_no_change",
                            "source_unchanged": path.read_bytes() == data,
                        },
                        indent=2,
                    )
                    + "\n"
                )
        finally:
            service.shutdown()
            service.server_close()
            thread.join(timeout=5)
    after = path.stat()
    assert (before.st_ino, before.st_size, before.st_mtime_ns) == (
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )
